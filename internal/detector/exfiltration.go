package detector

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// ExfiltrationDetector scans for bulk data extraction and exfiltration attempts.
type ExfiltrationDetector struct{}

func (d *ExfiltrationDetector) Name() string                       { return "exfiltration" }
func (d *ExfiltrationDetector) Category() models.DetectionCategory { return models.CategoryDataExfil }

var exfilPatterns = []struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
}{
	{regexp.MustCompile(`(?i)\b(dump|export|extract|download)\s+(all|every|entire)\s+(customer|user|employee|patient|record|data)`), "BULK_EXTRACT", "Bulk data extraction attempt", "high"},
	{regexp.MustCompile(`(?i)\b(list|show|give|send)\s+(me\s+)?(all|every)\s+(user|customer|employee|patient)s?\b.{0,30}\b(password|email|ssn|salary|address|phone)`), "PII_DUMP", "Attempt to dump PII fields", "critical"},
	{regexp.MustCompile(`(?i)\bmysqldump\b|\bpg_dump\b|\bmongodump\b`), "DB_DUMP_CMD", "Database dump command detected", "high"},
	{regexp.MustCompile(`(?i)\bSELECT\s+\*\s+FROM\b.{0,30}\b(user|customer|employee|patient|account|credential)`), "SELECT_STAR_SENSITIVE", "SELECT * from sensitive table", "high"},
	{regexp.MustCompile(`(?i)\b(generate|create|make)\s+(a\s+)?(csv|spreadsheet|report)\s+(of|with|containing)\s+(all|every)`), "BULK_REPORT", "Bulk report generation attempt", "medium"},
	{regexp.MustCompile(`(?i)\b(scrape|crawl|harvest)\s+(all|every|the\s+entire)`), "DATA_SCRAPING", "Data scraping attempt", "high"},
}

func (d *ExfiltrationDetector) Detect(content string) []models.Finding {
	var findings []models.Finding

	for _, rule := range exfilPatterns {
		if rule.pattern.MatchString(content) {
			findings = append(findings, models.Finding{
				Category:   models.CategoryDataExfil,
				Type:       rule.label,
				Detail:     rule.detail,
				Confidence: 0.82,
				Severity:   rule.severity,
			})
		}
	}

	return findings
}
