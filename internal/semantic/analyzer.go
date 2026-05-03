package semantic

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Analyzer runs the semantic layer for SecurePrompt. Safe for concurrent use.
type Analyzer struct {
	cfg    Config
	client *hfClient
}

// New creates an Analyzer from config. Pass an empty Config{} (Enabled=false)
// to get a no-op analyzer.
func New(cfg Config) *Analyzer {
	cfg.applyDefaults()

	// Resolve HF token: explicit config value wins; env var as fallback.
	if cfg.HFToken == "" {
		cfg.HFToken = os.Getenv("HF_TOKEN")
	}

	return &Analyzer{
		cfg:    cfg,
		client: newHFClient(cfg.APIBase, cfg.HFToken, cfg.TimeoutMs),
	}
}

// Enabled reports whether this analyzer will perform semantic scans.
func (a *Analyzer) Enabled() bool { return a != nil && a.cfg.Enabled }

// Config returns the resolved configuration (defaults applied).
func (a *Analyzer) Config() Config { return a.cfg }

// ShouldEscalate reports whether the rules-layer score falls in the borderline
// band where semantic analysis adds value.
func (a *Analyzer) ShouldEscalate(rulesScore float64) bool {
	if a == nil || !a.cfg.Enabled {
		return false
	}
	return rulesScore >= a.cfg.EscalationBand.Low &&
		rulesScore <= a.cfg.EscalationBand.High
}

// FuseScores combines the rules score with the semantic score using the
// configured FusionWeight (default: semantic 0.6, rules 0.4).
func (a *Analyzer) FuseScores(rulesScore, semanticScore float64) float64 {
	w := a.cfg.FusionWeight
	fused := rulesScore*(1-w) + semanticScore*w
	if fused > 1.0 {
		return 1.0
	}
	if fused < 0 {
		return 0
	}
	return fused
}

// Scan runs all configured HF models in parallel and returns aggregated
// findings.
func (a *Analyzer) Scan(ctx context.Context, req ScanRequest) *Result {
	start := time.Now()
	result := &Result{}

	if !a.cfg.Enabled {
		result.Skipped = true
		result.SkipReason = "semantic layer disabled in config"
		return result
	}

	scanMode := req.ScanMode
	if scanMode == "" {
		scanMode = "input"
	}

	activeModels := a.modelsForMode(scanMode)
	if len(activeModels) == 0 {
		result.Skipped = true
		result.SkipReason = fmt.Sprintf("no models active for scan_mode=%s", scanMode)
		return result
	}

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(a.cfg.TimeoutMs)*time.Millisecond)
	defer cancel()

	type modelResult struct {
		findings []Finding
		err      error
		modelID  string
	}
	ch := make(chan modelResult, len(activeModels))
	var wg sync.WaitGroup

	for _, m := range activeModels {
		wg.Add(1)
		go func(model ModelConfig) {
			defer wg.Done()
			findings, err := a.runModel(callCtx, model, req, scanMode)
			ch <- modelResult{findings: findings, err: err, modelID: model.ID}
		}(m)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var allFindings []Finding
	var errMsgs []string

	for mr := range ch {
		result.Models = append(result.Models, mr.modelID)
		if mr.err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", mr.modelID, mr.err.Error()))
			continue
		}
		allFindings = append(allFindings, mr.findings...)
	}

	if len(errMsgs) > 0 {
		result.Error = strings.Join(errMsgs, "; ")
		// Fail-closed: every model failed and operator opted out of fail-open
		// → treat as high risk so the fusion step can promote to BLOCK.
		if len(allFindings) == 0 && !a.cfg.FailOpen {
			result.Score = 0.9
			result.LatencyMs = elapsedMs(start)
			return result
		}
	}

	result.Findings = allFindings
	result.Score = aggregateScore(allFindings)
	result.LatencyMs = elapsedMs(start)
	return result
}

// modelsForMode returns the configured models filtered by scan mode and the
// disabled flag.
func (a *Analyzer) modelsForMode(scanMode string) []ModelConfig {
	src := a.cfg.ActiveModels()
	out := make([]ModelConfig, 0, len(src))
	for _, m := range src {
		if m.InputOnly && scanMode != "input" {
			continue
		}
		if m.ResponseOnly && scanMode != "response" {
			continue
		}
		out = append(out, m)
	}
	return out
}

// runModel dispatches to the correct HF task handler.
func (a *Analyzer) runModel(ctx context.Context, model ModelConfig, req ScanRequest, scanMode string) ([]Finding, error) {
	switch model.Task {
	case "text-classification":
		return a.runTextClassification(ctx, model, req, scanMode)
	case "token-classification":
		return a.runTokenClassification(ctx, model, req, scanMode)
	default:
		return nil, fmt.Errorf("unsupported task: %s", model.Task)
	}
}

// runTextClassification handles injection/jailbreak classifier models.
func (a *Analyzer) runTextClassification(ctx context.Context, model ModelConfig, req ScanRequest, scanMode string) ([]Finding, error) {
	items, err := a.client.ClassifyText(ctx, model.ID, req.Content)
	if err != nil {
		return nil, err
	}

	threshold := model.Threshold
	if threshold == 0 {
		threshold = 0.7
	}

	findings := make([]Finding, 0, len(items))
	for _, item := range items {
		if !isInjectionLabel(item.Label) {
			continue
		}
		if item.Score < threshold {
			continue
		}
		findings = append(findings, Finding{
			Type:       labelToFindingType(item.Label),
			Confidence: item.Score,
			Model:      model.ID,
			Label:      item.Label,
			Evidence:   fmt.Sprintf("classifier=%s score=%.3f", item.Label, item.Score),
			ScanMode:   scanMode,
		})
	}
	return findings, nil
}

// runTokenClassification handles PII entity-detection models.
func (a *Analyzer) runTokenClassification(ctx context.Context, model ModelConfig, req ScanRequest, scanMode string) ([]Finding, error) {
	items, err := a.client.ClassifyTokens(ctx, model.ID, req.Content)
	if err != nil {
		return nil, err
	}

	threshold := model.Threshold
	if threshold == 0 {
		threshold = 0.85
	}

	seen := make(map[string]bool)
	findings := make([]Finding, 0, len(items))
	for _, item := range items {
		label := item.Label()
		if label == "" || label == "O" || label == "LABEL_0" {
			continue
		}
		if item.Score < threshold {
			continue
		}
		findingType := piiTypeFromLabel(label)
		if seen[findingType] {
			continue
		}
		seen[findingType] = true

		// Partially redact the matched word so evidence does not leak PII
		// itself into logs/audit.
		word := item.Word
		if len(word) > 4 {
			word = word[:2] + strings.Repeat("*", len(word)-2)
		}

		findings = append(findings, Finding{
			Type:       findingType,
			Confidence: item.Score,
			Model:      model.ID,
			Label:      label,
			Evidence:   fmt.Sprintf("entity=%s match=%q offset=%d-%d", label, word, item.Start, item.End),
			ScanMode:   scanMode,
			Start:      item.Start,
			End:        item.End,
		})
	}
	return findings, nil
}

// aggregateScore returns the maximum confidence across all findings.
func aggregateScore(findings []Finding) float64 {
	highest := 0.0
	for _, f := range findings {
		if f.Confidence > highest {
			highest = f.Confidence
		}
	}
	return highest
}

// labelToFindingType maps raw HF classifier labels to internal finding types.
func labelToFindingType(label string) string {
	switch strings.ToUpper(label) {
	case "INJECTION", "PROMPT_INJECTION":
		return "semantic_prompt_injection"
	case "JAILBREAK":
		return "semantic_jailbreak"
	case "MALICIOUS":
		return "semantic_malicious"
	case "UNSAFE":
		return "semantic_unsafe"
	case "1", "YES", "LABEL_1":
		return "semantic_injection"
	default:
		return "semantic_" + strings.ToLower(strings.ReplaceAll(label, " ", "_"))
	}
}

func elapsedMs(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}
