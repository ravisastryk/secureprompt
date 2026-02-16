package detector

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// RiskyOpsDetector scans for destructive commands and privilege escalation.
type RiskyOpsDetector struct{}

func (d *RiskyOpsDetector) Name() string                       { return "riskyops" }
func (d *RiskyOpsDetector) Category() models.DetectionCategory { return models.CategoryRiskyOps }

type riskyRule struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
}

var riskyPatterns = []riskyRule{
	// Filesystem destruction
	{regexp.MustCompile(`(?i)\brm\s+-r?f\s+/`), "RM_RF_ROOT", "Recursive force delete from root", "critical"},
	{regexp.MustCompile(`(?i)\brm\s+-rf\b`), "RM_RF", "Recursive force delete command", "high"},
	{regexp.MustCompile(`(?i)\bmkfs\b`), "FORMAT_DISK", "Disk format command detected", "critical"},
	{regexp.MustCompile(`(?i)\bdd\s+if=.+of=/dev/`), "DD_OVERWRITE", "Direct disk overwrite via dd", "critical"},

	// Database destruction
	{regexp.MustCompile(`(?i)\bDROP\s+(DATABASE|TABLE|SCHEMA)\b`), "DROP_DB", "DROP DATABASE/TABLE command detected", "critical"},
	{regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`), "TRUNCATE_TABLE", "TRUNCATE TABLE command detected", "high"},
	{regexp.MustCompile(`(?i)\bDELETE\s+FROM\b.{0,20}\bWHERE\s+1\s*=\s*1\b`), "DELETE_ALL", "DELETE all rows detected", "high"},

	// Privilege escalation
	{regexp.MustCompile(`(?i)\bchmod\s+777\b`), "CHMOD_777", "World-writable permissions", "high"},
	{regexp.MustCompile(`(?i)\bchmod\s+[0-7]*777\b`), "CHMOD_OPEN", "Overly permissive chmod", "high"},
	{regexp.MustCompile(`(?i)\bchown\s+root\b`), "CHOWN_ROOT", "Changing ownership to root", "medium"},

	// Process / system control
	{regexp.MustCompile(`(?i)\bkill\s+-9\s+-1\b`), "KILL_ALL", "Kill all processes", "critical"},
	{regexp.MustCompile(`(?i)\bkillall\b`), "KILLALL", "Kill all by name", "high"},
	{regexp.MustCompile(`(?i)\bshutdown\b|\breboot\b|\bhalt\b`), "SHUTDOWN", "System shutdown/reboot command", "high"},

	// Firewall / security
	{regexp.MustCompile(`(?i)\biptables\s+-F\b`), "FLUSH_IPTABLES", "Flush firewall rules", "critical"},
	{regexp.MustCompile(`(?i)\bufw\s+disable\b`), "DISABLE_UFW", "Disable UFW firewall", "high"},
	{regexp.MustCompile(`(?i)\bsetenforce\s+0\b`), "DISABLE_SELINUX", "Disable SELinux", "high"},

	// Windows specific
	{regexp.MustCompile(`(?i)\breg\s+delete\b`), "REG_DELETE", "Windows registry delete", "high"},
	{regexp.MustCompile(`(?i)\bformat\s+[A-Z]:\b`), "FORMAT_DRIVE", "Format Windows drive", "critical"},
}

func (d *RiskyOpsDetector) Detect(content string) []models.Finding {
	var findings []models.Finding

	for _, rule := range riskyPatterns {
		if rule.pattern.MatchString(content) {
			findings = append(findings, models.Finding{
				Category:   models.CategoryRiskyOps,
				Type:       rule.label,
				Detail:     rule.detail,
				Confidence: 0.90,
				Severity:   rule.severity,
			})
		}
	}

	return findings
}
