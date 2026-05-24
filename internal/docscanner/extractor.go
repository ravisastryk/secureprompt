package docscanner

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ── Type detection ────────────────────────────────────────────────────────────

// detectDocType sniffs content bytes and filename to identify document type.
func detectDocType(content []byte, filename string) DocType {
	if len(content) < 4 {
		return DocTypeUnknown
	}
	// Magic bytes
	switch {
	case bytes.HasPrefix(content, []byte("%PDF")):
		return DocTypePDF
	case bytes.HasPrefix(content, []byte("PK\x03\x04")):
		// ZIP container: could be DOCX, XLSX, IPYNB
		if strings.HasSuffix(strings.ToLower(filename), ".docx") {
			return DocTypeDOCX
		}
		if strings.HasSuffix(strings.ToLower(filename), ".ipynb") {
			return DocTypeNotebook
		}
		// Peek inside zip for [Content_Types].xml -> DOCX
		if isOOXML(content) {
			return DocTypeDOCX
		}
		return DocTypeUnknown
	case bytes.HasPrefix(content, []byte("data:image/")) || bytes.HasPrefix(content, []byte("iVBORw0KGgo")) || bytes.HasPrefix(content, []byte("/9j/")):
		return DocTypeImageB64
	}
	// Text heuristics
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".ipynb"):
		return DocTypeJSON
	case strings.HasSuffix(lower, ".csv"):
		return DocTypeCSV
	case strings.HasSuffix(lower, ".txt"), strings.HasSuffix(lower, ".md"):
		return DocTypePlainTxt
	}
	// Try JSON parse
	if json.Valid(content) {
		if bytes.Contains(content, []byte(`"nbformat"`)) {
			return DocTypeNotebook
		}
		return DocTypeJSON
	}
	return DocTypePlainTxt
}

func isOOXML(data []byte) bool {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		if f.Name == "[Content_Types].xml" {
			return true
		}
	}
	return false
}

// ── Extractors ────────────────────────────────────────────────────────────────

// extractText dispatches to the right extractor for the detected type.
func extractText(content []byte, dt DocType) (text string, meta map[string]string, err error) {
	meta = make(map[string]string)
	switch dt {
	case DocTypePDF:
		text, meta, err = extractPDF(content)
	case DocTypeDOCX:
		text, meta, err = extractDOCX(content)
	case DocTypeCSV:
		text = extractCSV(content)
	case DocTypeJSON, DocTypeNotebook:
		text, err = extractJSONOrNotebook(content)
	case DocTypePlainTxt:
		text = string(content)
	case DocTypeImageB64:
		// For images, extracted "text" is the metadata map rendered as text
		meta, err = extractImageMetadata(content)
		for k, v := range meta {
			text += fmt.Sprintf("%s: %s\n", k, v)
		}
	default:
		text = string(content) // best-effort
	}
	return
}

// ── PDF text extraction (pure stdlib, no cgo) ────────────────────────────────
// Extracts visible text by finding BT/ET blocks and string literals in PDF streams.
// Not a full PDF renderer — sufficient to catch injected text in most real PDFs.

var (
	rePDFStream    = regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)
	rePDFStr       = regexp.MustCompile(`\(([^)\\]|\\.)*\)`)
	rePDFInfo      = regexp.MustCompile(`(?s)/Info\s+<<(.*?)>>`)
	rePDFMetaField = regexp.MustCompile(`/(Title|Author|Subject|Keywords|Producer|Creator)\s*\(([^)]*)\)`)
	rePDFBTET      = regexp.MustCompile(`(?s)BT\s+(.*?)\s+ET`)
	rePDFTj        = regexp.MustCompile(`\(([^)]*)\)\s*T[jJ]`)
)

// extractPDF returns (text, meta, error); the error is always nil today but
// the signature stays uniform with the other extractors dispatched by
// extractText.
//
//nolint:unparam // uniform extractor signature
func extractPDF(data []byte) (string, map[string]string, error) {
	meta := make(map[string]string)
	var sb strings.Builder

	// Extract metadata from /Info dictionary
	if m := rePDFInfo.FindSubmatch(data); m != nil {
		for _, match := range rePDFMetaField.FindAllSubmatch(m[1], -1) {
			meta[string(match[1])] = unescapePDFString(string(match[2]))
		}
	}

	// Extract text from BT...ET blocks across all streams
	for _, stream := range rePDFStream.FindAllSubmatch(data, -1) {
		raw := stream[1]
		for _, block := range rePDFBTET.FindAllSubmatch(raw, -1) {
			for _, tj := range rePDFTj.FindAllSubmatch(block[1], -1) {
				sb.WriteString(unescapePDFString(string(tj[1])))
				sb.WriteByte(' ')
			}
		}
		// Also capture raw string literals — catches content outside BT/ET
		for _, s := range rePDFStr.FindAll(raw, -1) {
			inner := s[1 : len(s)-1]
			if utf8.Valid(inner) && len(inner) > 3 {
				sb.Write(inner)
				sb.WriteByte(' ')
			}
		}
	}
	return sb.String(), meta, nil
}

func unescapePDFString(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\(`, "(")
	s = strings.ReplaceAll(s, `\)`, ")")
	return s
}

// ── DOCX extraction via ZIP+XML ───────────────────────────────────────────────

func extractDOCX(data []byte) (string, map[string]string, error) {
	meta := make(map[string]string)
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", meta, fmt.Errorf("docx zip: %w", err)
	}

	var sb strings.Builder
	for _, f := range r.File {
		switch f.Name {
		case "word/document.xml":
			txt, err := xmlTextContent(f)
			if err == nil {
				sb.WriteString(txt)
			}
		case "docProps/core.xml":
			for k, v := range extractDOCXCoreProps(f) {
				meta[k] = v
			}
		case "docProps/app.xml":
			for k, v := range extractDOCXCoreProps(f) {
				meta["app_"+k] = v
			}
		}
	}
	return sb.String(), meta, nil
}

func xmlTextContent(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()

	var sb strings.Builder
	dec := xml.NewDecoder(rc)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return sb.String(), nil // return partial on error
		}
		if cd, ok := tok.(xml.CharData); ok {
			sb.Write(cd)
			sb.WriteByte(' ')
		}
	}
	return sb.String(), nil
}

func extractDOCXCoreProps(f *zip.File) map[string]string {
	props := make(map[string]string)
	rc, err := f.Open()
	if err != nil {
		return props
	}
	defer func() { _ = rc.Close() }()

	dec := xml.NewDecoder(rc)
	var currentEl string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			currentEl = t.Name.Local
		case xml.CharData:
			if currentEl != "" && len(bytes.TrimSpace(t)) > 0 {
				props[currentEl] = string(t)
			}
		case xml.EndElement:
			currentEl = ""
		}
	}
	return props
}

// ── CSV extraction ─────────────────────────────────────────────────────────────

func extractCSV(data []byte) string {
	// Return all cell values concatenated — attackers embed directives in cells
	return string(data)
}

// ── JSON / Jupyter Notebook extraction ────────────────────────────────────────

// extractJSONOrNotebook returns (text, error); the error is always nil today
// but the signature stays uniform with the other extractors.
//
//nolint:unparam // uniform extractor signature
func extractJSONOrNotebook(data []byte) (string, error) {
	// For Jupyter notebooks: extract all cell source fields
	var nb map[string]any
	if err := json.Unmarshal(data, &nb); err != nil {
		return string(data), nil
	}
	if cells, ok := nb["cells"].([]any); ok {
		// It's a notebook
		var sb strings.Builder
		for _, cell := range cells {
			m, ok := cell.(map[string]any)
			if !ok {
				continue
			}
			switch src := m["source"].(type) {
			case []any:
				for _, line := range src {
					if s, ok := line.(string); ok {
						sb.WriteString(s)
					}
				}
				sb.WriteByte('\n')
			case string:
				sb.WriteString(src)
				sb.WriteByte('\n')
			}
		}
		return sb.String(), nil
	}
	// Regular JSON: serialize back to string for text scanning
	return string(data), nil
}

// ── Text sanitization — Unicode attack characters ─────────────────────────────

// zeroWidthChars lists Unicode code points used for invisible injection.
// These are removed from extracted text before scanning and embedding.
var zeroWidthChars = []rune{
	'\u200B', // Zero Width Space
	'\u200C', // Zero Width Non-Joiner
	'\u200D', // Zero Width Joiner
	'\u200E', // Left-to-Right Mark
	'\u200F', // Right-to-Left Mark
	'\u202A', // Left-to-Right Embedding
	'\u202B', // Right-to-Left Embedding
	'\u202C', // Pop Directional Formatting
	'\u202D', // Left-to-Right Override
	'\u202E', // Right-to-Left Override (RTLO)
	'\u2060', // Word Joiner
	'\u2061', // Function Application
	'\u2062', // Invisible Times
	'\u2063', // Invisible Separator
	'\u2064', // Invisible Plus
	'\uFEFF', // BOM / Zero Width No-Break Space
	'\u00AD', // Soft Hyphen
	'\u034F', // Combining Grapheme Joiner
}

// SanitizeText removes zero-width and control characters from text.
// Returns the sanitized text and the count of characters removed.
func SanitizeText(text string) (sanitized string, removed int) {
	zwSet := make(map[rune]bool, len(zeroWidthChars))
	for _, r := range zeroWidthChars {
		zwSet[r] = true
	}
	var sb strings.Builder
	for _, r := range text {
		if zwSet[r] {
			removed++
			continue
		}
		// Also strip non-printable control characters (except \t \n \r)
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			removed++
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String(), removed
}

// DetectZeroWidthInjection returns true if the text contains zero-width
// characters that could be used to hide instructions.
func DetectZeroWidthInjection(text string) (found bool, count int, sample string) {
	zwSet := make(map[rune]bool, len(zeroWidthChars))
	for _, r := range zeroWidthChars {
		zwSet[r] = true
	}
	var positions []int
	for i, r := range text {
		if zwSet[r] {
			count++
			if len(positions) < 3 {
				positions = append(positions, i)
			}
		}
	}
	if count > 0 {
		// Sample: 20 chars of context around first occurrence
		if len(positions) > 0 {
			pos := positions[0]
			start := pos - 10
			if start < 0 {
				start = 0
			}
			end := pos + 10
			if end > len(text) {
				end = len(text)
			}
			sample = fmt.Sprintf("offset %d: %q", pos, text[start:end])
		}
		return true, count, sample
	}
	return false, 0, ""
}
