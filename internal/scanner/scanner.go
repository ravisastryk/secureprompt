// Package scanner is the v2 façade over SecurePrompt's detection / policy /
// rewriter / audit / session components. It exposes three entry points:
//
//   - Scan          — pre-flight (input) scanning of a user prompt
//   - ScanResponse  — post-flight (output) scanning of an LLM response
//   - DualLayerScan — convenience wrapper that runs Scan, calls the LLM via a
//     caller-supplied closure, then runs ScanResponse on the
//     result. Blocks at either layer surface as DualLayerResult.
//
// Why a separate package?
//
//   - Output scanning runs different detectors than input (PII echo,
//     secret-in-code, injection relay) and uses output-calibrated scoring
//     weights. Co-locating both modes in `detector` would muddy that split.
//   - The façade is the SDK-style entry point external integrators consume; it
//     hides the fact that scanning is composed of five engines internally.
//   - It lets the HTTP handler stay thin: it parses JSON, then delegates to
//     Scan or ScanResponse depending on Context.ScanMode.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ravisastryk/secureprompt/internal/audit"
	"github.com/ravisastryk/secureprompt/internal/detector"
	"github.com/ravisastryk/secureprompt/internal/models"
	"github.com/ravisastryk/secureprompt/internal/policy"
	"github.com/ravisastryk/secureprompt/internal/rewriter"
	"github.com/ravisastryk/secureprompt/internal/semantic"
	"github.com/ravisastryk/secureprompt/internal/session"
)

// Scanner orchestrates input and output scanning. Concurrency-safe: all
// embedded engines are safe for concurrent use.
type Scanner struct {
	detector          *detector.Engine
	policy            *policy.Engine
	rewriter          *rewriter.Engine
	audit             *audit.Logger
	sessions          *session.Store
	responseDetectors []ResponseDetector
	// semanticAnalyzer is the optional semantic-analysis layer. Nil
	// disables it; callers inject one via SetSemanticAnalyzer at startup
	// when config enables it.
	semanticAnalyzer *semantic.Analyzer
}

// New builds a Scanner with the production set of detectors and a fresh
// in-memory audit log + session store.
func New(hmacSecret string) *Scanner {
	return &Scanner{
		detector: detector.NewEngine(),
		policy:   policy.NewEngine(),
		rewriter: rewriter.NewEngine(),
		audit:    audit.NewLogger(hmacSecret),
		sessions: session.NewStore(),
		responseDetectors: []ResponseDetector{
			&PIIEchoDetector{},
			&SecretInCodeDetector{},
			&InjectionRelayDetector{},
		},
	}
}

// NewWithDeps builds a Scanner with caller-supplied components. Used by tests
// and by the HTTP server which already owns its own audit logger and session
// store. A nil component falls back to a freshly-constructed default.
func NewWithDeps(d *detector.Engine, p *policy.Engine, rw *rewriter.Engine, a *audit.Logger, s *session.Store) *Scanner {
	if d == nil {
		d = detector.NewEngine()
	}
	if p == nil {
		p = policy.NewEngine()
	}
	if rw == nil {
		rw = rewriter.NewEngine()
	}
	if a == nil {
		a = audit.NewLogger("")
	}
	if s == nil {
		s = session.NewStore()
	}
	return &Scanner{
		detector: d,
		policy:   p,
		rewriter: rw,
		audit:    a,
		sessions: s,
		responseDetectors: []ResponseDetector{
			&PIIEchoDetector{},
			&SecretInCodeDetector{},
			&InjectionRelayDetector{},
		},
	}
}

// AuditEntries returns the audit log; exposed for the API server's /v1/audit
// endpoint when the Scanner is the canonical owner of audit state.
func (s *Scanner) AuditEntries() []models.AuditEntry { return s.audit.Entries() }

// SetSemanticAnalyzer attaches the semantic-analysis layer. Pass nil to
// disable. Safe to call once at startup before any scans are dispatched.
func (s *Scanner) SetSemanticAnalyzer(a *semantic.Analyzer) { s.semanticAnalyzer = a }

// SemanticEnabled reports whether a non-nil, enabled semantic analyzer is
// attached. Useful for /health probes and start-up logging.
func (s *Scanner) SemanticEnabled() bool { return s.semanticAnalyzer.Enabled() }

// ScanRequest is the input for both Scan and ScanResponse.
type ScanRequest struct {
	EventID       string
	TenantID      string
	SessionID     string
	Content       string
	PolicyProfile string
	Context       *models.ExecutionContext
}

// ScanResult is the unified scan result for both input and output paths.
type ScanResult struct {
	EventID       string
	RiskLevel     models.RiskLevel
	RiskScore     int
	Findings      []models.Finding
	SafeRewrite   string
	LatencyMs     float64
	PolicyProfile string
	ScanMode      models.ScanMode
	Signature     string
	Reasoning     string
	Factors       []string
	CausalChain   []string

	// Semantic carries the semantic-layer outcome. Nil when no analyzer is
	// attached; non-nil with Skipped=true when the rules score was already
	// decisive.
	Semantic *semantic.Result
}

// Scan performs pre-send (input) scanning. Equivalent behavior to the original
// /v1/prescan path: the standard six detectors run in parallel, the policy
// engine evaluates findings against the named profile, REVIEW/BLOCK results
// produce a safe rewrite, and an HMAC-signed audit entry is appended.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if err := validate(req); err != nil {
		return nil, err
	}
	start := time.Now()

	req = withDefaults(req, models.ScanModeInput)

	signals := s.sessions.Snapshot(req.TenantID, req.SessionID)
	findings := s.detector.Scan(req.Content)
	decision := s.policy.Evaluate(req.PolicyProfile, findings, req.Context, signals)

	semResult := s.fuseSemantic(ctx, req.Content, "input", &decision)

	safeRewrite := ""
	if decision.RiskLevel != models.RiskSafe && len(findings) > 0 {
		safeRewrite = s.rewriter.Rewrite(req.Content, findings)
	}

	s.sessions.Record(req.TenantID, req.SessionID, decision.RiskLevel, findings)
	sig := s.audit.Log(req.EventID, req.TenantID, req.SessionID,
		decision.RiskLevel, decision.RiskScore, len(findings), req.PolicyProfile)

	return &ScanResult{
		EventID:       req.EventID,
		RiskLevel:     decision.RiskLevel,
		RiskScore:     decision.RiskScore,
		Findings:      findings,
		SafeRewrite:   safeRewrite,
		LatencyMs:     elapsedMs(start),
		PolicyProfile: req.PolicyProfile,
		ScanMode:      models.ScanModeInput,
		Signature:     sig,
		Reasoning:     decision.Reasoning,
		Factors:       decision.Confirmations,
		CausalChain:   inputCausalChain(decision.RiskLevel),
		Semantic:      semResult,
	}, nil
}

// ScanResponse performs post-LLM (output) scanning. It runs the standard six
// input detectors PLUS the response-only detectors (PII echo, secret-in-code,
// injection relay) and applies output-calibrated scoring weights. The policy
// engine then renders the final RiskLevel.
//
// Why run the standard detectors too? An LLM response is just text — secrets
// and injection patterns can land there directly (especially via RAG). The
// response-only detectors add coverage for output-specific shapes the input
// detectors miss (e.g. "Email: alice@example.com" without "my email is").
func (s *Scanner) ScanResponse(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if err := validate(req); err != nil {
		return nil, err
	}
	start := time.Now()

	req = withDefaults(req, models.ScanModeResponse)

	signals := s.sessions.Snapshot(req.TenantID, req.SessionID)

	// Standard detectors are still useful — secrets/injection in raw output.
	standard := s.detector.Scan(req.Content)
	// Output-only detectors run sequentially; their bodies are cheap regex.
	responseFindings := s.runResponseDetectors(req.Content)
	all := dedupe(append(append([]models.Finding{}, standard...), responseFindings...))

	// Output-calibrated risk score; the policy engine still gates the final
	// RiskLevel using its own profile rules so behavior stays consistent.
	overrideScore, factors := computeResponseRiskScore(all, req.Context)
	decision := s.policy.Evaluate(req.PolicyProfile, all, req.Context, signals)
	if overrideScore > decision.RiskScore {
		decision.RiskScore = overrideScore
	}
	if len(factors) > 0 {
		decision.Confirmations = append(decision.Confirmations, factors...)
		decision.Reasoning = fmt.Sprintf("%s [%s]", decision.Reasoning, strings.Join(factors, "; "))
	}
	// Promote REVIEW → BLOCK in response mode when the calibrated score is
	// extreme. This is the "data already assembled by the model" tax.
	if decision.RiskLevel == models.RiskReview && decision.RiskScore >= 90 {
		decision.RiskLevel = models.RiskBlock
		decision.Reasoning += " [response mode: high-confidence leak elevated to BLOCK]"
	}

	semResult := s.fuseSemantic(ctx, req.Content, "response", &decision)

	// Token-classification semantic findings (PII spans) flow into the
	// rewriter so safe_rewrite masks the same characters the model flagged.
	all = mergeSemanticSpans(all, semResult)

	safeRewrite := ""
	if decision.RiskLevel != models.RiskSafe && len(all) > 0 {
		safeRewrite = s.rewriter.Rewrite(req.Content, all)
	}

	s.sessions.Record(req.TenantID, req.SessionID, decision.RiskLevel, all)
	sig := s.audit.Log(req.EventID, req.TenantID, req.SessionID,
		decision.RiskLevel, decision.RiskScore, len(all), req.PolicyProfile)

	return &ScanResult{
		EventID:       req.EventID,
		RiskLevel:     decision.RiskLevel,
		RiskScore:     decision.RiskScore,
		Findings:      all,
		SafeRewrite:   safeRewrite,
		LatencyMs:     elapsedMs(start),
		PolicyProfile: req.PolicyProfile,
		ScanMode:      models.ScanModeResponse,
		Signature:     sig,
		Reasoning:     decision.Reasoning,
		Factors:       decision.Confirmations,
		CausalChain:   responseCausalChain(decision.RiskLevel),
		Semantic:      semResult,
	}, nil
}

// fuseSemantic invokes the optional semantic layer and updates the rule
// engine's PolicyDecision in place when the fused score exceeds the original.
//
// Score scales:
//   - PolicyDecision.RiskScore is an integer in [0, 100].
//   - semantic.ScanWithFusion uses floats in [0.0, 1.0].
//
// Behavior:
//   - Returns nil when no analyzer is attached (rules-only mode).
//   - Returns a non-nil Result with Skipped=true when semantic is disabled,
//     out of band, or every model failed under fail_open.
//   - When semantic actually ran, the fused score replaces RiskScore (only
//     when higher), reasoning is annotated, and RiskLevel is promoted only
//     when the fused score crosses a stricter threshold than the rule layer
//     already chose.
func (s *Scanner) fuseSemantic(ctx context.Context, content, scanMode string, decision *models.PolicyDecision) *semantic.Result {
	if !s.semanticAnalyzer.Enabled() {
		return nil
	}

	rulesScore := float64(decision.RiskScore) / 100.0
	fused, semResult := semantic.ScanWithFusion(ctx, s.semanticAnalyzer, rulesScore, semantic.ScanRequest{
		Content:   content,
		ScanMode:  scanMode,
		StartTime: time.Now(),
	})

	// Skipped or no useful escalation: leave the decision untouched.
	if semResult == nil || semResult.Skipped || fused <= rulesScore {
		return semResult
	}

	newScore := int(fused * 100)
	if newScore > decision.RiskScore {
		decision.RiskScore = newScore
	}

	// Promote RiskLevel only when fusion crossed a stricter threshold.
	// 0.30 → at least REVIEW (consistent with the strict block threshold
	// in the spec); 0.80 → BLOCK once REVIEW already fires.
	switch decision.RiskLevel {
	case models.RiskSafe:
		if fused >= 0.30 {
			decision.RiskLevel = models.RiskReview
			decision.Reasoning = appendReason(decision.Reasoning,
				fmt.Sprintf("semantic layer raised score to %.2f → REVIEW", fused))
		}
	case models.RiskReview:
		if fused >= 0.80 {
			decision.RiskLevel = models.RiskBlock
			decision.Reasoning = appendReason(decision.Reasoning,
				fmt.Sprintf("semantic layer raised score to %.2f → BLOCK", fused))
		}
	}

	if len(semResult.Findings) > 0 {
		decision.Confirmations = append(decision.Confirmations,
			fmt.Sprintf("semantic: %d HF finding(s) across %d model(s)",
				len(semResult.Findings), len(semResult.Models)))
	}
	return semResult
}

func appendReason(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + " [" + addition + "]"
}

// mergeSemanticSpans converts token-classification semantic findings (which
// carry character offsets) into models.Finding entries with a Location set,
// so the rewriter masks the same span. Text-classification findings (no
// span) are skipped — promotion happens via the fused score, not redaction.
//
// Conservative: only entries with a positive span and a recognized PII type
// are merged; everything else is left to the score-fusion path.
func mergeSemanticSpans(rules []models.Finding, sem *semantic.Result) []models.Finding {
	if sem == nil || sem.Skipped || len(sem.Findings) == 0 {
		return rules
	}
	merged := rules
	for _, f := range sem.Findings {
		if f.End <= f.Start {
			continue
		}
		category, severity, ok := classifySemantic(f.Type)
		if !ok {
			continue
		}
		merged = append(merged, models.Finding{
			Category:   category,
			Type:       semanticRedactionLabel(f.Type),
			Detail:     f.Evidence,
			Confidence: f.Confidence,
			Severity:   severity,
			Location:   &models.Location{Start: f.Start, End: f.End},
		})
	}
	return dedupe(merged)
}

// classifySemantic maps a semantic finding Type onto a rules-side
// (category, severity) pair. Returns ok=false for types that should not
// drive redaction (e.g. text-classification injection findings).
func classifySemantic(semType string) (models.DetectionCategory, string, bool) {
	switch {
	case strings.HasPrefix(semType, "semantic_pii_"):
		return models.CategoryPII, "high", true
	default:
		return "", "", false
	}
}

// semanticRedactionLabel produces a short, uppercase label that ends up
// inside the [REDACTED_X] tag the rewriter inserts. Drops the "semantic_"
// prefix so output reads "[REDACTED_PII_SSN]" not "[REDACTED_SEMANTIC_PII_SSN]".
func semanticRedactionLabel(semType string) string {
	t := strings.TrimPrefix(semType, "semantic_")
	return strings.ToUpper(t)
}

// DualLayerRequest bundles input + LLM-call closure + output scan into one
// operation. The LLMCaller is the only piece SecurePrompt does not own; it can
// wrap any provider (OpenAI, Anthropic, local model) since it is just a
// `func(prompt string) (string, error)`.
type DualLayerRequest struct {
	EventID       string
	TenantID      string
	SessionID     string
	Input         string
	PolicyProfile string
	Context       *models.ExecutionContext
	LLMCaller     func(prompt string) (string, error)
}

// DualLayerResult is the combined input + output scan outcome. If Blocked is
// true, BlockedAt names the layer ("input" or "output") and BlockReason names
// the first finding type that triggered the block.
type DualLayerResult struct {
	InputScan   *ScanResult
	OutputScan  *ScanResult
	FinalOutput string
	Blocked     bool
	BlockedAt   string
	BlockReason string
}

// DualLayerScan runs the canonical end-to-end flow:
//
//  1. Scan input. BLOCK → return without calling LLM. REVIEW → use safe rewrite.
//  2. Call LLM via the supplied closure.
//  3. Scan response. BLOCK → return blocked, do not surface output. REVIEW →
//     return the redacted output.
//
// Errors from the input scan, LLM caller, and output scan all bubble up
// individually so the caller can distinguish "scanner broke" from "LLM broke".
func (s *Scanner) DualLayerScan(ctx context.Context, req DualLayerRequest) (*DualLayerResult, error) {
	if req.LLMCaller == nil {
		return nil, errors.New("LLMCaller is required")
	}
	out := &DualLayerResult{}

	inputResult, err := s.Scan(ctx, ScanRequest{
		EventID:       req.EventID,
		TenantID:      req.TenantID,
		SessionID:     req.SessionID,
		Content:       req.Input,
		PolicyProfile: req.PolicyProfile,
		Context:       req.Context,
	})
	if err != nil {
		return nil, fmt.Errorf("input scan failed: %w", err)
	}
	out.InputScan = inputResult

	prompt := req.Input
	switch inputResult.RiskLevel {
	case models.RiskBlock:
		out.Blocked = true
		out.BlockedAt = "input"
		out.BlockReason = firstFindingType(inputResult.Findings)
		return out, nil
	case models.RiskReview:
		if inputResult.SafeRewrite != "" {
			prompt = inputResult.SafeRewrite
		}
	}

	llmResponse, err := req.LLMCaller(prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM call failed: %w", err)
	}

	outputResult, err := s.ScanResponse(ctx, ScanRequest{
		// New event id: the output decision must be auditable separately.
		TenantID:      req.TenantID,
		SessionID:     req.SessionID,
		Content:       llmResponse,
		PolicyProfile: req.PolicyProfile,
		Context:       req.Context,
	})
	if err != nil {
		return nil, fmt.Errorf("output scan failed: %w", err)
	}
	out.OutputScan = outputResult

	switch outputResult.RiskLevel {
	case models.RiskBlock:
		out.Blocked = true
		out.BlockedAt = "output"
		out.BlockReason = firstFindingType(outputResult.Findings)
	case models.RiskReview:
		if outputResult.SafeRewrite != "" {
			out.FinalOutput = outputResult.SafeRewrite
		} else {
			out.FinalOutput = llmResponse
		}
	default:
		out.FinalOutput = llmResponse
	}
	return out, nil
}

// runResponseDetectors runs every response-only detector against content and
// concatenates their findings. They are cheap regex passes so we run them
// sequentially; if benchmarks ever justify it, this is the obvious place to
// add a goroutine pool similar to detector.Engine.Scan.
func (s *Scanner) runResponseDetectors(content string) []models.Finding {
	out := make([]models.Finding, 0, len(s.responseDetectors))
	for _, d := range s.responseDetectors {
		out = append(out, d.Detect(content)...)
	}
	return out
}

// dedupe removes duplicate findings (same Category+Type+Location) that can
// arise when the standard detectors and the response detectors both fire on
// the same span (e.g. an SSN that the input PII detector also matched).
func dedupe(in []models.Finding) []models.Finding {
	seen := make(map[string]bool, len(in))
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		key := string(f.Category) + "|" + f.Type
		if f.Location != nil {
			key = fmt.Sprintf("%s|%d-%d", key, f.Location.Start, f.Location.End)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// validate enforces the minimum invariants every entry point relies on.
func validate(req ScanRequest) error {
	if strings.TrimSpace(req.Content) == "" {
		return errors.New("content is required")
	}
	return nil
}

// withDefaults fills the missing fields a caller is allowed to omit. Defaults
// match the existing /v1/prescan handler so behavior is identical when the
// scanner replaces the inline pipeline.
func withDefaults(req ScanRequest, mode models.ScanMode) ScanRequest {
	if req.EventID == "" {
		req.EventID = "evt_" + shortRandHex()
	}
	if req.PolicyProfile == "" {
		req.PolicyProfile = "strict"
	}
	if req.Context == nil {
		req.Context = &models.ExecutionContext{}
	}
	if req.Context.ScanMode == "" {
		req.Context.ScanMode = mode
	}
	return req
}

func firstFindingType(findings []models.Finding) string {
	for _, f := range findings {
		if f.Category == models.CategoryOK {
			continue
		}
		return f.Type
	}
	return ""
}

func elapsedMs(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func inputCausalChain(level models.RiskLevel) []string {
	return []string{
		"prompt_received",
		"input_detectors_triggered",
		"input_risk_score_computed",
		"policy_evaluated",
		strings.ToLower(string(level)) + "_decision_made",
	}
}

func responseCausalChain(level models.RiskLevel) []string {
	return []string{
		"llm_response_received",
		"output_detectors_triggered",
		"response_risk_score_computed",
		"response_policy_evaluated",
		strings.ToLower(string(level)) + "_decision_made",
	}
}
