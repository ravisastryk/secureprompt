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

// ScanMode distinguishes between input (pre-send) and response (post-LLM) scanning.
// Empty / "input" runs the standard pre-flight scan. "response" runs output scanning
// with response-only detectors and output-calibrated risk weights.
type ScanMode string

const (
	ScanModeInput    ScanMode = "input"
	ScanModeResponse ScanMode = "response"
)

// ExecutionContext describes the runtime environment the prompt can influence.
// ScanMode selects between pre-send (input) and post-LLM (response) scanning.
type ExecutionContext struct {
	ToolCapabilities []string `json:"tool_capabilities,omitempty"`
	TrustLevel       string   `json:"trust_level,omitempty"`
	ScanMode         ScanMode `json:"scan_mode,omitempty"`
}

// PrescanRequest is the JSON body sent to POST /v1/prescan.
type PrescanRequest struct {
	EventID       string            `json:"event_id"`
	TenantID      string            `json:"tenant_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	Content       string            `json:"content"`
	PolicyProfile string            `json:"policy_profile,omitempty"`
	Context       *ExecutionContext `json:"context,omitempty"`

	// Document, when present, triggers pre-flight document scanning: the
	// document is scanned and (if not blocked) its sanitized text is
	// appended to Content before the standard scan runs.
	Document *DocumentInput `json:"document,omitempty"`
}

// DocumentInput carries an attached document for pre-flight scanning.
// Data is base64-encoded in the JSON payload and decoded to raw bytes by
// encoding/json automatically.
type DocumentInput struct {
	Data          []byte `json:"data"`
	Filename      string `json:"filename,omitempty"`
	StripMetadata bool   `json:"strip_metadata,omitempty"`
}

// PrescanResponse is the JSON body returned from POST /v1/prescan.
type PrescanResponse struct {
	EventID           string    `json:"event_id"`
	TenantID          string    `json:"tenant_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	PolicyProfile     string    `json:"policy_profile"`
	ScanMode          ScanMode  `json:"scan_mode,omitempty"`
	RiskLevel         RiskLevel `json:"risk_level"`
	RiskScore         int       `json:"risk_score"`
	Findings          []Finding `json:"findings"`
	SafeRewrite       string    `json:"safe_rewrite,omitempty"`
	Timestamp         string    `json:"timestamp"`
	ProcessingTimeMs  int64     `json:"processing_time_ms"`
	DecisionSignature string    `json:"decision_signature"`
	Reasoning         string    `json:"reasoning,omitempty"`
	DecisionFactors   []string  `json:"decision_factors,omitempty"`
	CausalChain       []string  `json:"causal_chain,omitempty"`

	// Semantic-layer fields (only present when the layer is enabled and
	// actually ran; keys omit when zero).
	SemanticScore      float64           `json:"semantic_score,omitempty"`
	SemanticLatencyMs  float64           `json:"semantic_latency_ms,omitempty"`
	SemanticModelsUsed []string          `json:"semantic_models_used,omitempty"`
	SemanticFindings   []SemanticFinding `json:"semantic_findings,omitempty"`
	SemanticSkipped    bool              `json:"semantic_skipped,omitempty"`
	SemanticSkipReason string            `json:"semantic_skip_reason,omitempty"`
	SemanticError      string            `json:"semantic_error,omitempty"`

	// DocScan summarizes the pre-flight document scan (present only when a
	// document was attached to the request).
	DocScan *DocScanSummary `json:"doc_scan,omitempty"`
}

// DocScanSummary is attached to PrescanResponse when a document was scanned.
type DocScanSummary struct {
	DocType        string  `json:"doc_type"`
	Decision       string  `json:"doc_decision"`
	RiskScore      float64 `json:"doc_risk_score"`
	FindingsCount  int     `json:"doc_findings_count"`
	LatencyMs      float64 `json:"doc_latency_ms"`
	MetadataFields int     `json:"doc_metadata_fields_scanned"`
}

// SemanticFinding is the API-shape of a single HuggingFace-derived detection.
// It mirrors the internal/semantic Finding type so the api package does not
// have to import the implementation.
type SemanticFinding struct {
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Model      string  `json:"model"`
	Label      string  `json:"label"`
	Evidence   string  `json:"evidence"`
	ScanMode   string  `json:"scan_mode"`
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
