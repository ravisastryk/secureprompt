// Package models defines shared types used across all SecurePrompt packages.
package models

// DetectionCategory classifies the type of threat detected.
type DetectionCategory string

const (
	CategorySecrets         DetectionCategory = "SECRETS"
	CategoryPromptInjection DetectionCategory = "PROMPT_INJECTION"
	CategoryPII             DetectionCategory = "PII"
	CategoryRiskyOps        DetectionCategory = "RISKY_OPERATIONS"
	CategoryDataExfil       DetectionCategory = "DATA_EXFILTRATION"
	CategoryMalware         DetectionCategory = "MALWARE_INTENT"
	CategoryOK              DetectionCategory = "OK"
)

// RiskLevel represents the final decision for a scanned prompt.
type RiskLevel string

const (
	RiskSafe   RiskLevel = "SAFE"
	RiskReview RiskLevel = "REVIEW"
	RiskBlock  RiskLevel = "BLOCK"
)

// Finding represents a single detection result from a detector.
type Finding struct {
	Category   DetectionCategory `json:"category"`
	Type       string            `json:"type"`
	Detail     string            `json:"detail"`
	Confidence float64           `json:"confidence"`
	Severity   string            `json:"severity"` // low, medium, high, critical
	Location   *Location         `json:"location,omitempty"`
}

// Location marks the character offsets where an issue was found.
type Location struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Redaction records what was redacted and where.
type Redaction struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Label string `json:"label"`
}

// ExecutionContext describes the runtime environment the prompt can influence.
type ExecutionContext struct {
	ToolCapabilities []string `json:"tool_capabilities,omitempty"`
	TrustLevel       string   `json:"trust_level,omitempty"`
}

// PrescanRequest is the JSON body sent to POST /v1/prescan.
type PrescanRequest struct {
	EventID       string            `json:"event_id"`
	TenantID      string            `json:"tenant_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	Content       string            `json:"content"`
	PolicyProfile string            `json:"policy_profile,omitempty"`
	Context       *ExecutionContext `json:"context,omitempty"`
}

// PrescanResponse is the JSON body returned from POST /v1/prescan.
type PrescanResponse struct {
	EventID           string    `json:"event_id"`
	TenantID          string    `json:"tenant_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	PolicyProfile     string    `json:"policy_profile"`
	RiskLevel         RiskLevel `json:"risk_level"`
	RiskScore         int       `json:"risk_score"`
	Findings          []Finding `json:"findings"`
	SafeRewrite       string    `json:"safe_rewrite,omitempty"`
	Timestamp         string    `json:"timestamp"`
	ProcessingTimeMs  int64     `json:"processing_time_ms"`
	DecisionSignature string    `json:"decision_signature"`
	Reasoning         string    `json:"reasoning,omitempty"`
	DecisionFactors   []string  `json:"decision_factors,omitempty"`
}

// PolicyDecision is the intermediate result from the policy engine.
type PolicyDecision struct {
	RiskLevel     RiskLevel
	RiskScore     int
	Reasoning     string
	Confirmations []string
}

// SessionSignals captures recent behavior for a tenant/session pair.
type SessionSignals struct {
	Key                       string   `json:"key"`
	RecentScans               int      `json:"recent_scans"`
	RecentReviews             int      `json:"recent_reviews"`
	RecentBlocks              int      `json:"recent_blocks"`
	RecentCategories          []string `json:"recent_categories,omitempty"`
	RepeatedInjectionAttempts bool     `json:"repeated_injection_attempts"`
	RepeatedExfiltrationHints bool     `json:"repeated_exfiltration_hints"`
	RecentAttackEscalation    bool     `json:"recent_attack_escalation"`
}

// AuditEntry is a single immutable record in the audit log.
type AuditEntry struct {
	EventID       string    `json:"event_id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	Timestamp     string    `json:"timestamp"`
	RiskLevel     RiskLevel `json:"risk_level"`
	RiskScore     int       `json:"risk_score"`
	FindingCount  int       `json:"finding_count"`
	PolicyProfile string    `json:"policy_profile"`
	Signature     string    `json:"signature"`
	PrevSignature string    `json:"prev_signature"`
}
