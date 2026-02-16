package detector

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// InjectionDetector scans for prompt injection, jailbreak, and role override attempts.
type InjectionDetector struct{}

func (d *InjectionDetector) Name() string                       { return "injection" }
func (d *InjectionDetector) Category() models.DetectionCategory { return models.CategoryPromptInjection }

type injectionRule struct {
	pattern    *regexp.Regexp
	detail     string
	severity   string
	confidence float64
}

var injectionPatterns = []injectionRule{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`), "Attempt to override system instructions", "high", 0.88},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|guidelines?|rules?)`), "Disregard instructions attempt", "high", 0.87},
	{regexp.MustCompile(`(?i)(reveal|show|display|print|output)\s+.{0,20}\b(system\s*prompt|original\s*instructions?|hidden\s*prompt)\b`), "System prompt extraction attempt", "high", 0.85},
	{regexp.MustCompile(`(?i)\bact\s*(as|like)\b.{0,30}\b(unrestricted|unfiltered|jailbroken|DAN)\b`), "Jailbreak attempt (DAN-style)", "critical", 0.92},
	{regexp.MustCompile(`(?i)\bpretend\b.{0,30}\b(no\s*rules|no\s*restrictions|unlimited)\b`), "Attempt to remove restrictions", "high", 0.85},
	{regexp.MustCompile(`(?i)\byou\s*are\s*now\b.{0,30}\b(free|unrestricted|evil|unfiltered)\b`), "Role override attempt", "high", 0.82},
	{regexp.MustCompile(`(?i)\bforget\b.{0,30}\b(everything|all|rules|training|instructions)\b`), "Memory/training override attempt", "high", 0.80},
	{regexp.MustCompile(`(?i)\b(sudo|admin|root)\s*mode\b`), "Privilege escalation attempt", "high", 0.88},
	{regexp.MustCompile(`(?i)\bdeveloper\s*mode\b.{0,20}\b(enabled?|on|active|activated)\b`), "Developer mode bypass attempt", "high", 0.85},
	{regexp.MustCompile(`(?i)\[\s*system\s*\]|\<\s*system\s*\>|##\s*system`), "System tag injection", "critical", 0.90},
	{regexp.MustCompile("(?i)" + "`" + "`" + "`" + `\s*(system|instruction|prompt)`), "Code block injection attempt", "medium", 0.75},
	{regexp.MustCompile(`(?i)\b(print|output|echo|display)\b.{0,20}\b(instructions?|prompt|rules|guidelines)\b`), "Instruction extraction attempt", "medium", 0.78},
	{regexp.MustCompile(`(?i)\brepeat\b.{0,30}\b(above|previous|system)\b.{0,20}\b(text|message|prompt|instructions)\b`), "Prompt repetition attack", "medium", 0.80},
}

func (d *InjectionDetector) Detect(content string) []models.Finding {
	var findings []models.Finding

	for _, rule := range injectionPatterns {
		if rule.pattern.MatchString(content) {
			findings = append(findings, models.Finding{
				Category:   models.CategoryPromptInjection,
				Type:       "INJECTION_PATTERN",
				Detail:     rule.detail,
				Confidence: rule.confidence,
				Severity:   rule.severity,
			})
		}
	}

	return findings
}
