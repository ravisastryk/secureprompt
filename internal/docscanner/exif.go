package docscanner

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// ── EXIF reading and stripping ────────────────────────────────────────────────
// Pure Go, no external libraries. Reads JPEG EXIF segments (APP1/0xFFE1)
// and PNG tEXt/iTXt chunks. Strips them for the pre-embedding hook.

// JPEG markers used by the EXIF reader/stripper.
const (
	jpegAPP1 = 0xFFE1
	jpegSOS  = 0xFFDA
)

// EXIFData holds parsed EXIF metadata fields.
type EXIFData struct {
	Fields map[string]string // tag name → value
	// Raw is the original APP1 segment bytes (for stripping)
	Raw []byte
	// Offset is the byte offset in the JPEG where APP1 starts
	Offset int
}

// knownEXIFTags maps EXIF tag IDs to human-readable names.
// Only the most security-relevant tags are listed.
var knownEXIFTags = map[uint16]string{
	0x010E: "ImageDescription",
	0x010F: "Make",
	0x0110: "Model",
	0x0131: "Software",
	0x013B: "Artist",
	0x8298: "Copyright",
	0x9286: "UserComment",
	0xA004: "RelatedSoundFile",
	0x013C: "HostComputer",
	0x9C9B: "XPTitle",
	0x9C9C: "XPComment",
	0x9C9D: "XPAuthor",
	0x9C9E: "XPKeywords",
	0x9C9F: "XPSubject",
	// GPS tags that could contain location data
	0x8825: "GPSInfo",
}

// ReadJPEGEXIF parses EXIF metadata from JPEG bytes.
// Returns nil if no EXIF is found.
func ReadJPEGEXIF(data []byte) (*EXIFData, error) {
	if len(data) < 4 {
		return nil, nil
	}
	// Check JPEG SOI
	if data[0] != 0xFF || data[1] != 0xD8 {
		return nil, nil // not JPEG
	}

	exif := &EXIFData{Fields: make(map[string]string)}
	pos := 2

	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			break
		}
		marker := uint16(data[pos])<<8 | uint16(data[pos+1])
		segLen := int(binary.BigEndian.Uint16(data[pos+2:])) + 2 // includes length bytes

		if marker == jpegAPP1 && pos+10 < len(data) {
			// Check for "Exif\x00\x00" header
			if string(data[pos+4:pos+8]) == "Exif" {
				exif.Offset = pos
				if pos+segLen <= len(data) {
					exif.Raw = data[pos : pos+segLen]
					exif.Fields = parseIFD(data[pos+4:pos+segLen], 8)
				}
			}
		}
		if marker == uint16(jpegSOS) {
			break // image data begins, stop parsing
		}
		pos += segLen
	}

	if len(exif.Fields) == 0 && exif.Raw == nil {
		return nil, nil
	}
	return exif, nil
}

// parseIFD parses an EXIF IFD (Image File Directory) starting at offset.
// data should start at the "Exif\x00\x00" header.
func parseIFD(data []byte, offset int) map[string]string {
	fields := make(map[string]string)
	if offset+8 > len(data) {
		return fields
	}

	// Determine byte order
	var bo binary.ByteOrder
	if len(data) < 6 {
		return fields
	}
	switch {
	case data[0] == 'I' && data[1] == 'I':
		bo = binary.LittleEndian
	case data[0] == 'M' && data[1] == 'M':
		bo = binary.BigEndian
	default:
		return fields // invalid
	}

	// IFD0 offset
	if offset+4 > len(data) {
		return fields
	}
	ifdOffset := int(bo.Uint32(data[4:]))
	if ifdOffset+2 > len(data) {
		return fields
	}

	numEntries := int(bo.Uint16(data[ifdOffset:]))
	for i := 0; i < numEntries; i++ {
		entryOffset := ifdOffset + 2 + i*12
		if entryOffset+12 > len(data) {
			break
		}
		tag := bo.Uint16(data[entryOffset:])
		dataType := bo.Uint16(data[entryOffset+2:])
		count := bo.Uint32(data[entryOffset+4:])
		valueOffset := entryOffset + 8

		name, known := knownEXIFTags[tag]
		if !known {
			continue
		}

		value := readEXIFValue(data, bo, dataType, count, valueOffset)
		if value != "" {
			fields[name] = value
		}
	}
	return fields
}

// readEXIFValue extracts the string value of an EXIF entry.
func readEXIFValue(data []byte, bo binary.ByteOrder, dataType uint16, count uint32, valueOffset int) string {
	if valueOffset+4 > len(data) {
		return ""
	}
	switch dataType {
	case 2: // ASCII
		var strOffset int
		if count <= 4 {
			strOffset = valueOffset
		} else {
			strOffset = int(bo.Uint32(data[valueOffset:]))
		}
		if strOffset+int(count) > len(data) {
			return ""
		}
		return strings.TrimRight(string(data[strOffset:strOffset+int(count)]), "\x00")
	case 7: // UNDEFINED (used for UserComment)
		var rawOffset int
		if count <= 4 {
			rawOffset = valueOffset
		} else {
			if valueOffset+4 > len(data) {
				return ""
			}
			rawOffset = int(bo.Uint32(data[valueOffset:]))
		}
		if rawOffset+int(count) > len(data) || count == 0 {
			return ""
		}
		raw := data[rawOffset : rawOffset+int(count)]
		// UserComment has an 8-byte encoding prefix
		if len(raw) > 8 {
			raw = raw[8:]
		}
		return strings.TrimRight(string(raw), "\x00 ")
	}
	return ""
}

// StripJPEGEXIF removes all APP1 (EXIF) segments from JPEG bytes.
// Returns the stripped bytes, ready for safe RAG embedding.
func StripJPEGEXIF(data []byte) ([]byte, int) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return data, 0
	}
	var out bytes.Buffer
	out.Write(data[:2]) // SOI
	pos := 2
	stripped := 0

	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			out.Write(data[pos:])
			break
		}
		marker := uint16(data[pos])<<8 | uint16(data[pos+1])
		segLen := int(binary.BigEndian.Uint16(data[pos+2:])) + 2

		if marker == jpegAPP1 {
			// Skip this segment entirely
			stripped++
		} else {
			if pos+segLen > len(data) {
				out.Write(data[pos:])
				break
			}
			out.Write(data[pos : pos+segLen])
		}
		if marker == uint16(jpegSOS) {
			// Append rest of image data
			out.Write(data[pos+segLen:])
			break
		}
		pos += segLen
	}
	return out.Bytes(), stripped
}

// ── Image metadata extraction (base64) ───────────────────────────────────────

// extractImageMetadata decodes a base64 image (data URI or raw b64) and
// reads EXIF and any embedded text metadata.
func extractImageMetadata(data []byte) (map[string]string, error) {
	meta := make(map[string]string)

	// Strip data URI prefix if present
	raw := data
	if bytes.HasPrefix(data, []byte("data:")) {
		idx := bytes.IndexByte(data, ',')
		if idx >= 0 && idx < len(data)-1 {
			mimeEnd := bytes.IndexByte(data[:idx], ';')
			if mimeEnd > 5 {
				meta["mime_type"] = string(data[5:mimeEnd])
			}
			raw = data[idx+1:]
		}
	}

	// Decode base64
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(decoded, bytes.TrimSpace(raw))
	if err != nil {
		// Try URL-safe variant
		n, err = base64.URLEncoding.Decode(decoded, bytes.TrimSpace(raw))
		if err != nil {
			return meta, fmt.Errorf("base64 decode: %w", err)
		}
	}
	decoded = decoded[:n]
	meta["decoded_size_bytes"] = fmt.Sprintf("%d", n)

	// JPEG EXIF
	if exif, _ := ReadJPEGEXIF(decoded); exif != nil {
		for k, v := range exif.Fields {
			meta["exif_"+k] = v
		}
	}

	// PNG tEXt chunks
	if bytes.HasPrefix(decoded, []byte("\x89PNG\r\n\x1a\n")) {
		for k, v := range readPNGTextChunks(decoded) {
			meta["png_"+k] = v
		}
	}

	return meta, nil
}

// readPNGTextChunks reads tEXt and iTXt chunks from a PNG file.
func readPNGTextChunks(data []byte) map[string]string {
	result := make(map[string]string)
	pos := 8 // skip PNG signature
	for pos+12 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[pos:]))
		chunkType := string(data[pos+4 : pos+8])
		var chunkData []byte
		if pos+8+chunkLen <= len(data) {
			chunkData = data[pos+8 : pos+8+chunkLen]
		}
		if chunkType == "tEXt" || chunkType == "iTXt" {
			idx := bytes.IndexByte(chunkData, 0)
			if idx > 0 && idx < len(chunkData)-1 {
				key := string(chunkData[:idx])
				val := string(chunkData[idx+1:])
				result[key] = strings.TrimRight(val, "\x00")
			}
		}
		if chunkType == "IEND" {
			break
		}
		pos += 12 + chunkLen
	}
	return result
}

// ScanMetadataForPayloads checks EXIF/document metadata values for
// injection patterns — attackers embed directives in Author, Title, Keywords.
func ScanMetadataForPayloads(meta map[string]string) []Finding {
	var findings []Finding
	injectionPhrases := []string{
		"ignore previous",
		"ignore all previous",
		"disregard",
		"your new instructions",
		"act as",
		"you are now",
		"system prompt",
		"reveal your",
		"new directive",
		"override",
		"forget everything",
	}

	for field, value := range meta {
		lower := strings.ToLower(value)
		for _, phrase := range injectionPhrases {
			if strings.Contains(lower, phrase) {
				evidence := value
				if len(evidence) > 80 {
					evidence = evidence[:80] + "..."
				}
				findings = append(findings, Finding{
					Type:     "metadata_injection_payload",
					Severity: "high",
					Evidence: fmt.Sprintf("field=%s value=%q", field, evidence),
					Offset:   -1,
					Source:   "metadata",
				})
				break
			}
		}
		// Check for credential patterns in metadata
		if looksLikeCredential(value) {
			findings = append(findings, Finding{
				Type:     "metadata_credential_exposure",
				Severity: "critical",
				Evidence: fmt.Sprintf("field=%s contains credential-like value", field),
				Offset:   -1,
				Source:   "metadata",
			})
		}
	}
	return findings
}

func looksLikeCredential(s string) bool {
	// AKIA... pattern (AWS access key)
	if strings.Contains(s, "AKIA") && len(s) > 16 {
		return true
	}
	// sk-... pattern (OpenAI, Anthropic)
	if strings.Contains(s, "sk-") && len(s) > 20 {
		return true
	}
	// ghp_ / github_pat_ GitHub token
	if strings.Contains(s, "ghp_") || strings.Contains(s, "github_pat_") {
		return true
	}
	return false
}
