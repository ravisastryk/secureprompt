package detector

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// PIIDetector scans for personally identifiable information.
type PIIDetector struct{}

func (d *PIIDetector) Name() string                       { return "pii" }
func (d *PIIDetector) Category() models.DetectionCategory { return models.CategoryPII }

type piiRule struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
}

var piiPatterns = []piiRule{
	// SSN — explicit context first (higher priority)
	{regexp.MustCompile(`(?i)(my\s+)?(ssn|social\s*security\s*(number)?)\s*(is|:)\s*\d{3}[-.\s]?\d{2,3}[-.\s]?\d{4}`), "US_SSN_EXPLICIT", "SSN with explicit context detected", "critical"},
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "US_SSN", "US Social Security Number format detected", "critical"},

	// Credit cards
	{regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), "VISA_CARD", "Visa credit card number detected", "critical"},
	{regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), "MASTERCARD", "Mastercard number detected", "critical"},
	{regexp.MustCompile(`\b3[47][0-9]{13}\b`), "AMEX_CARD", "American Express card detected", "critical"},
	{regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), "CREDIT_CARD_16", "16-digit card number detected", "critical"},

	// Identity documents
	{regexp.MustCompile(`(?i)\b(passport|license|licence)\s*(number|no|#|num)\.?\s*:?\s*[A-Z0-9]{6,12}\b`), "ID_DOCUMENT", "Identity document number detected", "high"},
	{regexp.MustCompile(`\b[A-Z]{2}\d{6}[A-Z]?\b`), "UK_NINO", "UK National Insurance Number detected", "critical"},

	// Phone numbers (lower severity — PII but less sensitive)
	{regexp.MustCompile(`\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`), "PHONE_NUMBER", "Phone number detected", "medium"},

	// Email in sensitive context
	{regexp.MustCompile(`(?i)(my|personal|private)\s+email\s*(is|:)\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), "EMAIL_PERSONAL", "Personal email shared", "medium"},
}

func (d *PIIDetector) Detect(content string) []models.Finding {
	var findings []models.Finding

	for _, rule := range piiPatterns {
		locs := rule.pattern.FindStringIndex(content)
		if locs != nil {
			f := models.Finding{
				Category:   models.CategoryPII,
				Type:       rule.label,
				Detail:     rule.detail,
				Confidence: 0.85,
				Severity:   rule.severity,
				Location:   &models.Location{Start: locs[0], End: locs[1]},
			}
			findings = append(findings, f)
		}
	}

	return findings
}
