package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/ravisastryk/secureprompt/internal/docscanner"
	"github.com/ravisastryk/secureprompt/internal/models"
)

// DocumentAttachment is a document passed alongside a prompt for pre-flight
// scanning. Data holds the raw document bytes.
type DocumentAttachment struct {
	Data          []byte
	Filename      string
	StripMetadata bool
}

// ScanWithDocument runs document pre-flight scanning, then the standard input
// scan on the assembled content.
//
// Flow:
//  1. The document is scanned first (zero-width / metadata / structured
//     injection, EXIF, etc.).
//  2. If the document is BLOCK, the LLM-bound prompt is never assembled — a
//     blocked ScanResult is returned immediately.
//  3. Otherwise the document's sanitized text is appended to req.Content and
//     the normal Scan pipeline runs over the combined text.
//
// A zero-length doc.Data degrades to a plain Scan.
func (s *Scanner) ScanWithDocument(ctx context.Context, req ScanRequest, doc DocumentAttachment) (*ScanResult, error) {
	if len(doc.Data) == 0 {
		return s.Scan(ctx, req)
	}

	docResult := docscanner.New().Scan(docscanner.ScanRequest{
		Content:           doc.Data,
		Filename:          doc.Filename,
		StripMetadata:     doc.StripMetadata,
		ScanExtractedText: true,
	})

	summary := &models.DocScanSummary{
		DocType:        string(docResult.DocType),
		Decision:       docResult.Decision,
		RiskScore:      docResult.RiskScore,
		FindingsCount:  len(docResult.Findings),
		LatencyMs:      docResult.LatencyMs,
		MetadataFields: len(docResult.Metadata),
	}

	// Document blocked → don't assemble the prompt at all.
	if docResult.Decision == "BLOCK" {
		return s.blockedDocResult(req, docResult, summary), nil
	}

	// Append sanitized document text to the prompt before the standard scan.
	if docResult.ExtractedText != "" {
		req.Content = strings.TrimSpace(req.Content + "\n\n[Document Content]\n" + docResult.ExtractedText)
	}

	res, err := s.Scan(ctx, req)
	if err != nil {
		return nil, err
	}
	res.DocScan = summary
	return res, nil
}

// blockedDocResult builds a BLOCK ScanResult from a document scan without
// invoking the text scanner, and appends an audit entry so the block is
// recorded on the same chain.
func (s *Scanner) blockedDocResult(req ScanRequest, dr *docscanner.ScanResult, summary *models.DocScanSummary) *ScanResult {
	req = withDefaults(req, models.ScanModeInput)

	findings := make([]models.Finding, 0, len(dr.Findings))
	for _, f := range dr.Findings {
		findings = append(findings, models.Finding{
			Category:   docCategory(f.Type),
			Type:       f.Type,
			Detail:     f.Evidence,
			Confidence: 0.9,
			Severity:   f.Severity,
		})
	}

	riskScore := int(dr.RiskScore * 100)
	sig := s.audit.Log(req.EventID, req.TenantID, req.SessionID,
		models.RiskBlock, riskScore, len(findings), req.PolicyProfile)

	return &ScanResult{
		EventID:       req.EventID,
		RiskLevel:     models.RiskBlock,
		RiskScore:     riskScore,
		Findings:      findings,
		PolicyProfile: req.PolicyProfile,
		ScanMode:      models.ScanModeInput,
		Signature:     sig,
		Reasoning: fmt.Sprintf("Document blocked at pre-flight: %d finding(s), risk %.2f",
			len(findings), dr.RiskScore),
		CausalChain: []string{"document_received", "doc_scanner_triggered", "doc_blocked"},
		DocScan:     summary,
	}
}

// docCategory maps a docscanner finding type to a SecurePrompt detection
// category so blocked-document findings slot into the existing taxonomy.
func docCategory(findingType string) models.DetectionCategory {
	switch {
	case strings.Contains(findingType, "credential"):
		return models.CategorySecrets
	case strings.Contains(findingType, "exfil"):
		return models.CategoryDataExfil
	default:
		// injection, jailbreak, poisoning, override, zero_width, rtlo, …
		return models.CategoryPromptInjection
	}
}
