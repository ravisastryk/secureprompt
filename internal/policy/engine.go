// Package policy evaluates aggregated findings against a named profile
// (strict, moderate, permissive) and returns a risk decision.
package policy

import (
	"github.com/ravisastryk/secureprompt/internal/models"
)

// Engine evaluates findings against the selected policy profile.
type Engine struct{}

// NewEngine creates a new policy engine.
func NewEngine() *Engine { return &Engine{} }

// Evaluate applies the named profile to the findings and returns a decision.
func (e *Engine) Evaluate(profile string, findings []models.Finding) models.PolicyDecision {
	if len(findings) == 0 {
		return models.PolicyDecision{RiskLevel: models.RiskSafe, RiskScore: 0, Reasoning: "No issues detected"}
	}

	maxSeverity := highestSeverity(findings)
	hasSecrets := hasCategory(findings, models.CategorySecrets)
	hasMalware := hasCategory(findings, models.CategoryMalware)
	hasInjection := hasCategory(findings, models.CategoryPromptInjection)
	hasPII := hasCategory(findings, models.CategoryPII)

	var decision models.PolicyDecision
	decision.RiskScore = calculateScore(findings)

	switch profile {
	case "strict":
		decision = evaluateStrict(maxSeverity, hasSecrets, hasMalware, hasInjection, hasPII, decision.RiskScore)
	case "permissive":
		decision = evaluatePermissive(maxSeverity, hasSecrets, hasMalware, decision.RiskScore)
	default: // moderate
		decision = evaluateModerate(maxSeverity, hasSecrets, hasMalware, hasInjection, hasPII, decision.RiskScore)
	}

	return decision
}

func evaluateStrict(maxSev string, secrets, malware, injection, pii bool, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Strict policy: critical finding or secret/malware detected"
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

func evaluateModerate(maxSev string, secrets, malware, injection, pii bool, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Moderate policy: critical finding or secret/malware detected"
	case pii || injection:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Moderate policy: PII or injection flagged for review"
	default:
		d.RiskLevel = models.RiskReview
		d.Reasoning = "Moderate policy: finding flagged for review"
	}
	return d
}

func evaluatePermissive(maxSev string, secrets, malware bool, score int) models.PolicyDecision {
	d := models.PolicyDecision{RiskScore: score}
	switch {
	case secrets || malware || maxSev == "critical":
		d.RiskLevel = models.RiskBlock
		d.Reasoning = "Permissive policy: only critical findings blocked"
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
