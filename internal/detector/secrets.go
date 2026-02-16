package detector

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/models"
)

type secretPattern struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
	confidence float64
}

// SecretsDetector scans for API keys, tokens, private keys, and connection strings.
type SecretsDetector struct{}

func (d *SecretsDetector) Name() string                       { return "secrets" }
func (d *SecretsDetector) Category() models.DetectionCategory { return models.CategorySecrets }

var secretPatterns = []secretPattern{
	// OpenAI
	{regexp.MustCompile(`\bsk-[A-Za-z0-9]{4,}\b`), "OPENAI_API_KEY", "OpenAI API key detected", "critical", 0.95},
	{regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{4,}\b`), "OPENAI_PROJECT_KEY", "OpenAI project key detected", "critical", 0.95},

	// AWS
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS_ACCESS_KEY", "AWS access key ID detected", "critical", 0.98},
	{regexp.MustCompile(`(?i)aws[_\s-]?secret[_\s-]?access[_\s-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}`), "AWS_SECRET_KEY", "AWS secret access key detected", "critical", 0.95},

	// GitHub
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,}\b`), "GITHUB_PAT", "GitHub personal access token detected", "critical", 0.97},
	{regexp.MustCompile(`\bgho_[A-Za-z0-9]{36,}\b`), "GITHUB_OAUTH", "GitHub OAuth token detected", "critical", 0.97},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), "GITHUB_PAT_NEW", "GitHub PAT (new format) detected", "critical", 0.97},

	// Slack
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "SLACK_TOKEN", "Slack token detected", "critical", 0.94},

	// Private keys
	{regexp.MustCompile(`-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----`), "PRIVATE_KEY", "Private key block detected", "critical", 0.99},

	// JWT / Bearer tokens
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`), "JWT_TOKEN", "JWT token detected", "high", 0.90},
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`), "BEARER_TOKEN", "Bearer token detected", "high", 0.85},

	// Connection strings
	{regexp.MustCompile(`(?i)mongodb(\+srv)?://[^\s]{10,}`), "MONGODB_URI", "MongoDB connection string detected", "critical", 0.92},
	{regexp.MustCompile(`(?i)postgres(ql)?://[^\s]{10,}`), "POSTGRES_URI", "PostgreSQL connection string detected", "critical", 0.92},
	{regexp.MustCompile(`(?i)mysql://[^\s]{10,}`), "MYSQL_URI", "MySQL connection string detected", "critical", 0.92},
	{regexp.MustCompile(`(?i)redis://[^\s]{10,}`), "REDIS_URI", "Redis connection string detected", "critical", 0.92},

	// Generic key=value patterns
	{regexp.MustCompile(`(?i)(api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)\s*[=:]\s*["']?[A-Za-z0-9_\-/+=]{16,}["']?`), "GENERIC_SECRET", "Generic secret/key assignment detected", "high", 0.80},

	// Anthropic
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), "ANTHROPIC_KEY", "Anthropic API key detected", "critical", 0.96},

	// Google
	{regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`), "GOOGLE_API_KEY", "Google API key detected", "critical", 0.95},

	// Stripe
	{regexp.MustCompile(`\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b`), "STRIPE_KEY", "Stripe API key detected", "critical", 0.97},

	// Sendgrid
	{regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), "SENDGRID_KEY", "SendGrid API key detected", "critical", 0.96},
}

func (d *SecretsDetector) Detect(content string) []models.Finding {
	var findings []models.Finding

	for _, sp := range secretPatterns {
		locs := sp.pattern.FindStringIndex(content)
		if locs != nil {
			f := models.Finding{
				Category:   models.CategorySecrets,
				Type:       sp.label,
				Detail:     sp.detail,
				Confidence: sp.confidence,
				Severity:   sp.severity,
				Location:   &models.Location{Start: locs[0], End: locs[1]},
			}
			findings = append(findings, f)
		}
	}

	return findings
}

// SecretPatterns returns the compiled patterns for use by the rewriter.
func SecretPatterns() []secretPattern {
	return secretPatterns
}
