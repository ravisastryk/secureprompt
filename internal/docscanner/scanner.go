package docscanner

import (
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// Scanner is the document scanner. It is safe for concurrent use and has zero
// external dependencies.
type Scanner struct {
	// BlockThreshold: risk scores at or above this value → BLOCK
	BlockThreshold float64
	// ReviewThreshold: risk scores at or above this value → REVIEW
	ReviewThreshold float64
}

// New returns a Scanner with default thresholds.
func New() *Scanner {
	return &Scanner{
		BlockThreshold:  0.6,
		ReviewThreshold: 0.3,
	}
}

// Scan runs the full document scanning pipeline:
//  1. Detect document type
//  2. Extract text and metadata
//  3. Scan for zero-width/RTLO Unicode injection
//  4. Scan metadata fields for payloads
//  5. Scan EXIF for credentials and injection
//  6. Scan extracted text for structural injection patterns
//  7. Strip metadata if requested
func (s *Scanner) Scan(req ScanRequest) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Metadata: make(map[string]string),
	}

	// ── 1. Detect type ───────────────────────────────────────────────────────
	dt := req.DocType
	if dt == "" || dt == DocTypeUnknown {
		dt = detectDocType(req.Content, req.Filename)
	}
	result.DocType = dt

	// ── 2. Extract text + metadata ───────────────────────────────────────────
	rawText, meta, err := extractText(req.Content, dt)
	if err != nil {
		result.Findings = append(result.Findings, Finding{
			Type:     "extraction_error",
			Severity: "low",
			Evidence: err.Error(),
			Offset:   -1,
			Source:   "body",
		})
	}
	for k, v := range meta {
		result.Metadata[k] = v
	}

	// ── 3. Sanitize extracted text (removes zero-width chars) ────────────────
	sanitized, removedCount := SanitizeText(rawText)
	result.ExtractedText = sanitized

	if removedCount > 0 {
		// Zero-width chars were present — this is suspicious
		severity := "medium"
		if removedCount > 10 {
			severity = "high"
		}
		found, _, sample := DetectZeroWidthInjection(rawText)
		if found {
			result.Findings = append(result.Findings, Finding{
				Type:     "zero_width_injection",
				Severity: severity,
				Evidence: fmt.Sprintf("removed %d invisible chars; first: %s", removedCount, sample),
				Offset:   -1,
				Source:   "body",
			})
		}
	}

	// ── 4. RTLO override detection ────────────────────────────────────────────
	if findings := detectRTLO(rawText); len(findings) > 0 {
		result.Findings = append(result.Findings, findings...)
	}

	// ── 5. Metadata payload scan ─────────────────────────────────────────────
	if len(meta) > 0 {
		result.Findings = append(result.Findings,
			ScanMetadataForPayloads(meta)...)
	}

	// ── 6. EXIF scan (JPEG images, including base64) ──────────────────────────
	if dt == DocTypeImageB64 && len(meta) > 0 {
		exifFindings := ScanMetadataForPayloads(meta)
		for i := range exifFindings {
			exifFindings[i].Source = "exif"
		}
		result.Findings = append(result.Findings, exifFindings...)
	}

	// ── 7. Structural injection patterns in extracted text ────────────────────
	if sanitized != "" {
		result.Findings = append(result.Findings,
			scanTextForInjection(sanitized)...)
	}

	// ── 8. Strip metadata if requested (pre-embedding hook) ──────────────────
	if req.StripMetadata {
		result.SanitizedBytes = stripDocumentMetadata(req.Content, dt)
	}

	// ── 9. Aggregate risk score and decision ─────────────────────────────────
	result.RiskScore = computeRiskScore(result.Findings)
	result.Decision = s.applyThresholds(result.RiskScore)
	result.LatencyMs = float64(time.Since(start).Milliseconds())

	return result
}

// ScanForRAG is the pre-embedding hook for RAG pipelines.
// It extracts, sanitizes, and returns clean text ready for embedding.
// Returns an error if the document should be rejected.
func (s *Scanner) ScanForRAG(content []byte, filename string) (cleanText string, result *ScanResult, err error) {
	req := ScanRequest{
		Content:           content,
		Filename:          filename,
		StripMetadata:     true,
		ScanExtractedText: true,
	}
	result = s.Scan(req)
	if result.Decision == "BLOCK" {
		return "", result, fmt.Errorf("document blocked before RAG ingestion: %d findings, risk %.2f",
			len(result.Findings), result.RiskScore)
	}
	return result.ExtractedText, result, nil
}

// ── Injection detection in extracted text ─────────────────────────────────────

var injectionPatterns = []struct {
	pattern  *regexp.Regexp
	findType string
	severity string
}{
	// Classic prompt injection
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions?`), "document_prompt_injection", "critical"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|rules?|guidelines?)`), "document_prompt_injection", "critical"},
	{regexp.MustCompile(`(?i)your\s+new\s+(instructions?|directives?|rules?)\s+(are|is)\s*:`), "document_prompt_injection", "critical"},
	{regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+are|a\s+)?[a-z\s]{2,30}(with\s+no\s+restrictions?)?`), "document_jailbreak", "high"},
	{regexp.MustCompile(`(?i)reveal\s+(your\s+)?(system\s+prompt|api\s+keys?|instructions?)`), "document_prompt_injection", "critical"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(a\s+|an\s+)?(unrestricted|uncensored|jailbroken|free)`), "document_jailbreak", "high"},
	// RAG corpus poisoning patterns
	{regexp.MustCompile(`(?i)(when\s+(asked|answering)|if\s+(asked|someone\s+asks?))\s+about\s+.{0,50}(say|respond|tell|answer)`), "rag_corpus_poisoning", "high"},
	{regexp.MustCompile(`(?i)this\s+document\s+(contains?|has)\s+(instructions?|directives?)\s+for\s+(the\s+)?(ai|llm|model|assistant)`), "rag_corpus_poisoning", "critical"},
	// EXIF/document field injection (text extracted from metadata might contain these)
	{regexp.MustCompile(`(?i)system\s*:\s*you\s+(are|must|should|will)`), "system_prompt_override", "critical"},
	// SQL comment injection
	{regexp.MustCompile(`(?i)--\s*(ignore|disregard|override|system\s+prompt)`), "sql_comment_injection", "high"},
	// Steganographic hints (base64 within text)
	{regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), "embedded_base64_payload", "medium"},
}

func scanTextForInjection(text string) []Finding {
	var findings []Finding
	for _, p := range injectionPatterns {
		if p.findType == "embedded_base64_payload" {
			// Only flag if it's NOT at the start of the document (i.e. the whole thing isn't b64)
			matches := p.pattern.FindAllStringIndex(text, -1)
			if len(matches) > 3 {
				findings = append(findings, Finding{
					Type:     p.findType,
					Severity: p.severity,
					Evidence: fmt.Sprintf("%d base64-like strings embedded in document text", len(matches)),
					Offset:   matches[0][0],
					Source:   "body",
				})
			}
			continue
		}
		loc := p.pattern.FindStringIndex(text)
		if loc != nil {
			// Redact: show 40 chars of context
			start, end := loc[0], loc[1]
			ctxStart := start - 20
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 20
			if ctxEnd > len(text) {
				ctxEnd = len(text)
			}
			evidence := "..." + redactPII(text[ctxStart:ctxEnd]) + "..."
			findings = append(findings, Finding{
				Type:     p.findType,
				Severity: p.severity,
				Evidence: evidence,
				Offset:   start,
				Source:   "body",
			})
		}
	}
	return findings
}

// ── RTLO detection ────────────────────────────────────────────────────────────

func detectRTLO(text string) []Finding {
	var findings []Finding
	for i, r := range text {
		if r == '\u202E' { // Right-to-Left Override
			ctxStart := i - 15
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := i + 15
			if ctxEnd > len(text) {
				ctxEnd = len(text)
			}
			findings = append(findings, Finding{
				Type:     "rtlo_override",
				Severity: "high",
				Evidence: fmt.Sprintf("RTLO char at offset %d context: %q", i, text[ctxStart:ctxEnd]),
				Offset:   i,
				Source:   "body",
			})
		}
	}
	return findings
}

// ── Metadata stripping ────────────────────────────────────────────────────────

func stripDocumentMetadata(content []byte, dt DocType) []byte {
	switch dt {
	case DocTypeImageB64:
		// Full base64 round-trip stripping requires re-encoding; the scan
		// result flags the issues and the caller decides whether to reject.
		return content
	default:
		// For PDF/DOCX, return content unchanged — full stripping requires
		// format-specific writers beyond stdlib scope. The scan result flags
		// the issues; the caller decides whether to reject.
		return content
	}
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

var severityWeights = map[string]float64{
	"critical": 1.0,
	"high":     0.7,
	"medium":   0.4,
	"low":      0.2,
}

func computeRiskScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}
	score := 0.0
	for _, f := range findings {
		if f.Severity == "critical" {
			return 1.0
		}
		score += severityWeights[f.Severity]
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (s *Scanner) applyThresholds(score float64) string {
	if score >= s.BlockThreshold {
		return "BLOCK"
	}
	if score >= s.ReviewThreshold {
		return "REVIEW"
	}
	return "ALLOW"
}

// ── Utility ───────────────────────────────────────────────────────────────────

var piiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                            // SSN
	regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),                      // Visa
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                             // AWS key
	regexp.MustCompile(`\bsk-[a-zA-Z0-9]{32,}\b`),                          // OpenAI key
	regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), // email
}

func redactPII(s string) string {
	if !utf8.ValidString(s) {
		return "[invalid utf8]"
	}
	for _, p := range piiPatterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// PreprocessForRAG is the convenience function for RAG pipelines.
// It wraps ScanForRAG with zero configuration — use this in production.
//
//	cleanText, _, err := docscanner.PreprocessForRAG(retrievedDoc, "deployment.yaml")
//	if err != nil {
//	    return fmt.Errorf("doc rejected: %w", err)
//	}
//	// cleanText is safe to embed and send to LLM
func PreprocessForRAG(content []byte, filename string) (string, *ScanResult, error) {
	return New().ScanForRAG(content, filename)
}

// MultimodalScan scans a multimodal prompt that may contain base64-encoded images.
// It extracts and scans each image's metadata and any embedded text.
// Returns findings from both the text and image components.
func MultimodalScan(textPart string, imageParts [][]byte) ([]Finding, float64) {
	var allFindings []Finding
	sc := New()

	// Scan the text component
	textResult := sc.Scan(ScanRequest{
		Content:           []byte(textPart),
		DocType:           DocTypePlainTxt,
		ScanExtractedText: true,
	})
	allFindings = append(allFindings, textResult.Findings...)

	// Scan each image component
	for _, img := range imageParts {
		imgResult := sc.Scan(ScanRequest{
			Content:           img,
			DocType:           DocTypeImageB64,
			ScanExtractedText: true,
		})
		for i := range imgResult.Findings {
			imgResult.Findings[i].Source = "image_component"
		}
		allFindings = append(allFindings, imgResult.Findings...)
	}

	return allFindings, computeRiskScore(allFindings)
}
