// Package policy evaluates aggregated findings against a named profile
// (strict, moderate, permissive) and returns a risk decision.
package policy

import (
	"fmt"
	"strings"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// Engine evaluates findings against the selected policy profile.
type Engine struct{}

// NewEngine creates a new policy engine.
func NewEngine() *Engine { return &Engine{} }

// Evaluate applies the named profile to the findings and returns a decision.
func (e *Engine) Evaluate(profile string, findings []models.Finding, ctx *models.ExecutionContext, signals models.SessionSignals) models.PolicyDecision {
	if len(findings) == 0 {
		return models.PolicyDecision{RiskLevel: models.RiskSafe, RiskScore: 0, Reasoning: "No issues detected"}
	}

	maxSeverity := highestSeverity(findings)
	hasSecrets := hasCategory(findings, models.CategorySecrets)
	hasMalware := hasCategory(findings, models.CategoryMalware)
	hasInjection := hasCategory(findings, models.CategoryPromptInjection)
	hasPII := hasCategory(findings, models.CategoryPII)
	hasExfiltration := hasCategory(findings, models.CategoryDataExfil)
	hasRiskyOps := hasCategory(findings, models.CategoryRiskyOps)
	privileged := hasPrivilegedTools(ctx)

	score, factors := calculateAdaptiveScore(findings, ctx, signals)

	var decision models.PolicyDecision
	switch profile {
	case "strict":
		decision = evaluateStrict(maxSeverity, hasSecrets, hasMalware, hasInjection, hasPII, hasExfiltration, hasRiskyOps, privileged, signals, score)
	case "permissive":
		decision = evaluatePermissive(maxSeverity, hasSecrets, hasMalware, hasInjection, hasExfiltration, hasRiskyOps, privileged, signals, score)
	default: // moderate
		decision = evaluateModerate(maxSeverity, hasSecrets, hasMalware, hasInjection, hasPII, hasExfiltration, hasRiskyOps, privileged, signals, score)
	}

	decision.RiskScore = score
	decision.Confirmations = factors
	if len(factors) > 0 {
		decision.Reasoning = fmt.Sprintf("%s [%s]", decision.Reasoning, strings.Join(factors, "; "))
	}

	return decision
}

func evaluateStrict(maxSev string, secrets, malware, injection, pii, exfiltration, riskyOps, privileged bool, signals models.SessionSignals, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Strict policy: critical finding or secret/malware detected"
	case privileged && (injection || exfiltration || riskyOps):
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Strict policy: privileged tools with attack-like prompt"
	case signals.RecentAttackEscalation && (injection || exfiltration):
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Strict policy: repeated attack behavior escalated this session"
	case pii || maxSev == "high":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Strict policy: PII or high-severity finding"
	case injection || maxSev == "medium":
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Strict policy: injection attempt or medium-severity finding"
	default:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Strict policy: low-severity finding flagged for review"
	}
	return d
}

func evaluateModerate(maxSev string, secrets, malware, injection, pii, exfiltration, riskyOps, privileged bool, signals models.SessionSignals, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Moderate policy: critical finding or secret/malware detected"
	case privileged && (injection || exfiltration || riskyOps):
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Moderate policy: privileged tools raise attack prompt to block"
	case signals.RecentAttackEscalation && score >= 70:
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Moderate policy: repeated risky session activity escalated to block"
	case pii || injection:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Moderate policy: PII or injection flagged for review"
	case exfiltration || riskyOps:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Moderate policy: suspicious operational prompt flagged for review"
	default:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Moderate policy: finding flagged for review"
	}
	return d
}

func evaluatePermissive(maxSev string, secrets, malware, injection, exfiltration, riskyOps, privileged bool, signals models.SessionSignals, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Permissive policy: only critical findings blocked"
	case privileged && (injection || exfiltration || riskyOps) && score >= 75:
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Permissive policy: privileged agent context made the prompt too risky"
	case signals.RecentAttackEscalation && score >= 80:
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Permissive policy: repeated risky session activity escalated to block"
	default:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Permissive policy: non-critical finding, review recommended"
	}
	return d
}

func highestSeverity(findings []models.Finding) string {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	max := 0
	maxLabel := "low"
	for _, f := range findings {
		if v, ok := order[f.Severity]; ok && v > max {
			max = v
			maxLabel = f.Severity
		}
	}
	return maxLabel
}

func hasCategory(findings []models.Finding, cat models.DetectionCategory) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func calculateScore(findings []models.Finding) int {
	score := 0
	weights := map[string]int{"low": 10, "medium": 25, "high": 50, "critical": 80}
	for _, f := range findings {
		if w, ok := weights[f.Severity]; ok {
			score += w
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func calculateAdaptiveScore(findings []models.Finding, ctx *models.ExecutionContext, signals models.SessionSignals) (int, []string) {
	score := calculateScore(findings)
	factors := make([]string, 0, 6)

	categories := map[models.DetectionCategory]bool{}
	for _, f := range findings {
		categories[f.Category] = true
	}

	if len(categories) >= 2 {
		score += 10 * (len(categories) - 1)
		factors = append(factors, fmt.Sprintf("cross-signal evidence across %d categories", len(categories)))
	}

	if categories[models.CategoryPromptInjection] && categories[models.CategoryDataExfil] {
		score += 20
		factors = append(factors, "injection paired with exfiltration intent")
	}
	if categories[models.CategorySecrets] && categories[models.CategoryDataExfil] {
		score += 15
		factors = append(factors, "secret exposure paired with extraction behavior")
	}
	if categories[models.CategoryMalware] && categories[models.CategoryRiskyOps] {
		score += 15
		factors = append(factors, "malware intent paired with destructive operations")
	}

	if hasPrivilegedTools(ctx) && (categories[models.CategoryPromptInjection] || categories[models.CategoryDataExfil] || categories[models.CategoryRiskyOps]) {
		score += 15
		factors = append(factors, "privileged tool access increases blast radius")
	}

	if signals.RepeatedInjectionAttempts && categories[models.CategoryPromptInjection] {
		score += 10
		factors = append(factors, "repeat injection behavior in this session")
	}
	if signals.RepeatedExfiltrationHints && categories[models.CategoryDataExfil] {
		score += 10
		factors = append(factors, "repeat exfiltration behavior in this session")
	}
	if signals.RecentBlocks > 0 && len(findings) > 0 {
		score += 5
		factors = append(factors, "recent blocked activity from same session")
	}

	if score > 100 {
		score = 100
	}

	return score, factors
}

func hasPrivilegedTools(ctx *models.ExecutionContext) bool {
	if ctx == nil {
		return false
	}
	for _, capability := range ctx.ToolCapabilities {
		switch strings.ToLower(capability) {
		case "shell", "terminal", "filesystem-write", "database", "browser", "network":
			return true
		}
	}
	return false
}
