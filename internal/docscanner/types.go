// Package docscanner implements pre-flight security scanning for document and
// multimodal content before it reaches RAG ingestion or the LLM.
//
// Four threats addressed:
//
//  1. Adversarial Document Embedding — zero-width Unicode, RTLO overrides,
//     white-on-white instructions in PDF/DOCX that survive text extraction.
//  2. RAG Corpus Poisoning via Metadata — EXIF Author/Subject/Keywords,
//     PDF Info dictionary, DOCX core properties carrying injection payloads.
//  3. Steganographic / Multimodal Injection — base64-encoded images passed
//     in multimodal prompts, decoded and scanned for hidden instructions.
//  4. Structured Data Injection — CSV/JSON fields, SQL comments, Jupyter
//     notebook cells carrying LLM directive payloads.
//
// All processing is pure Go standard library — zero new module dependencies.
package docscanner

// DocType classifies the content passed for scanning.
type DocType string

const (
	DocTypePDF      DocType = "pdf"
	DocTypeDOCX     DocType = "docx"
	DocTypePlainTxt DocType = "txt"
	DocTypeCSV      DocType = "csv"
	DocTypeJSON     DocType = "json"
	DocTypeNotebook DocType = "ipynb"
	DocTypeImageB64 DocType = "image_b64" // base64-encoded image in multimodal prompt
	DocTypeUnknown  DocType = "unknown"
)

// ScanRequest is the input to the document scanner.
// Content must be the raw bytes of the document (for file types) or the
// base64-encoded data URI for images.
type ScanRequest struct {
	// Content is the raw document bytes.
	Content []byte

	// DocType hints the parser. Leave empty for auto-detection.
	DocType DocType

	// Filename is optional; used for MIME sniffing and audit logging.
	Filename string

	// StripMetadata: if true, returns sanitized bytes with EXIF/XMP stripped.
	// Used as the pre-embedding hook for RAG pipelines.
	StripMetadata bool

	// ScanExtractedText: if true, run the full SecurePrompt text scanner
	// on the extracted text (injection, PII, credentials).
	ScanExtractedText bool
}

// Finding is a single security issue found in the document.
type Finding struct {
	Type     string `json:"type"`     // e.g. "zero_width_injection", "metadata_injection_payload"
	Severity string `json:"severity"` // "critical", "high", "medium", "low"
	Evidence string `json:"evidence"` // redacted snippet or offset
	Offset   int    `json:"offset"`   // byte/char offset in extracted text, -1 if N/A
	Source   string `json:"source"`   // "body", "metadata", "exif", "embedded_image"
}

// ScanResult is the output of the document scanner.
type ScanResult struct {
	// RiskScore is 0.0–1.0, aggregated across all findings.
	RiskScore float64 `json:"risk_score"`

	// Decision mirrors the text scanner: "ALLOW", "REVIEW", "BLOCK".
	Decision string `json:"decision"`

	// Findings lists every detected issue.
	Findings []Finding `json:"findings,omitempty"`

	// ExtractedText is the plain-text content extracted from the document,
	// sanitized of zero-width characters and RTLO overrides.
	ExtractedText string `json:"extracted_text,omitempty"`

	// SanitizedBytes contains the document bytes with metadata stripped.
	// Populated only when ScanRequest.StripMetadata == true.
	SanitizedBytes []byte `json:"-"`

	// Metadata is the key-value pairs read from document metadata fields
	// (EXIF, PDF Info, DOCX core properties, XMP).
	Metadata map[string]string `json:"metadata,omitempty"`

	// LatencyMs is the time taken to complete the scan.
	LatencyMs float64 `json:"latency_ms"`

	// DocType is the detected document type.
	DocType DocType `json:"doc_type"`
}
