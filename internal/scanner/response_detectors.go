// Package scanner provides post-response (output) scanning for SecurePrompt.
//
// This file defines detectors that only make sense for LLM output, complementing
// the standard six input detectors (secrets, injection, PII, riskyops, exfiltration,
// malware). The same regex/finding model is reused so output findings flow through
// the existing rewriter and audit log unchanged.
//
//   - pii_echo_v1        PII patterns relaxed for output (no "my SSN is" preamble);
//     the LLM is now the speaker, so any PII in the response is
//     a leak signal regardless of how the user phrased the input.
//   - secret_in_code_v1  Secrets specifically embedded inside ```code fences``` or
//     `inline code`. These are higher risk because users tend to
//     copy/paste code blocks straight into a terminal.
//   - injection_relay_v1 The LLM repeats injection text it absorbed from RAG context
//     or tool output, e.g. "the document says: ignore all
//     previous instructions...". Catches indirect attacks the
//     input scan can't see (the malicious context arrived later).
package scanner

import (
	"regexp"

	"github.com/ravisastryk/secureprompt/internal/detector"
	"github.com/ravisastryk/secureprompt/internal/models"
)

// ResponseDetector is the interface every output-only detector implements.
// It mirrors detector.Detector but is kept distinct so the input/output
// detector sets can evolve independently.
type ResponseDetector interface {
	Name() string
	Category() models.DetectionCategory
	Detect(content string) []models.Finding
}

// ─── PII Echo ────────────────────────────────────────────────────────────────

// PIIEchoDetector finds PII anywhere in LLM output. Unlike the input PII detector
// (which only flags PII with explicit user context like "my SSN is..."), this
// detector flags any PII pattern in the response — the LLM is the speaker now,
// so plain "SSN: 078-05-1120" or "Email: alice@example.com" is a leak.
type PIIEchoDetector struct{}

func (d *PIIEchoDetector) Name() string                       { return "pii_echo_v1" }
func (d *PIIEchoDetector) Category() models.DetectionCategory { return models.CategoryPII }

type piiEchoRule struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
}

var piiEchoPatterns = []piiEchoRule{
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "US_SSN", "SSN echoed in LLM response", "critical"},
	{regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), "VISA_CARD", "Visa card echoed in LLM response", "critical"},
	{regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), "MASTERCARD", "Mastercard echoed in LLM response", "critical"},
	{regexp.MustCompile(`\b3[47][0-9]{13}\b`), "AMEX_CARD", "Amex card echoed in LLM response", "critical"},
	{regexp.MustCompile(`\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b`), "CREDIT_CARD_16", "16-digit card echoed in LLM response", "critical"},
	// Email anywhere in output (no "my email is" gate — LLM should not echo emails)
	{regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`), "EMAIL", "Email address echoed in LLM response", "high"},
	// Phone numbers in output
	{regexp.MustCompile(`\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`), "PHONE_NUMBER", "Phone number echoed in LLM response", "medium"},
	// UK NI
	{regexp.MustCompile(`\b[A-Z]{2}\d{6}[A-Z]?\b`), "UK_NINO", "UK National Insurance number echoed in LLM response", "critical"},
}

func (d *PIIEchoDetector) Detect(content string) []models.Finding {
	return scanFirstMatchPerRule(content, piiEchoForEach, models.CategoryPII)
}

// piiEchoForEach is split out to keep Detect simple and testable.
func piiEchoForEach(yield func(pattern *regexp.Regexp, label, detail, severity string)) {
	for _, r := range piiEchoPatterns {
		yield(r.pattern, r.label, r.detail, r.severity)
	}
}

// ─── Secret in Code Blocks ───────────────────────────────────────────────────

// SecretInCodeDetector finds secret patterns embedded inside fenced code blocks
// or inline code. LLMs frequently put real or real-looking API keys inside
// ```examples```, and users routinely copy-paste those into terminals.
//
// Strategy: extract every code block / inline code span, then run the existing
// secret patterns against each span. This intentionally produces a *separate*
// finding from any plain-text secret already found by SecretsDetector — the
// in-code variant carries higher severity because it is "ready to run".
type SecretInCodeDetector struct{}

func (d *SecretInCodeDetector) Name() string                       { return "secret_in_code_v1" }
func (d *SecretInCodeDetector) Category() models.DetectionCategory { return models.CategorySecrets }

// fencedCodeBlock matches ```...``` (multi-line). Non-greedy.
var fencedCodeBlock = regexp.MustCompile("(?s)```[^\\n]*\\n?(.*?)```")

// inlineCode matches `...` (single line, no backtick inside).
var inlineCode = regexp.MustCompile("`([^`\\n]+)`")

func (d *SecretInCodeDetector) Detect(content string) []models.Finding {
	var findings []models.Finding
	spans := extractCodeSpans(content)
	for _, span := range spans {
		for _, f := range detector.ScanSecretsIn(span.text) {
			// Re-anchor location to the original content offsets.
			if f.Location != nil {
				f.Location = &models.Location{
					Start: span.start + f.Location.Start,
					End:   span.start + f.Location.End,
				}
			}
			// Distinct Type so dedupe does not collapse this into the
			// standard SECRETS finding at the same offsets — the in-code
			// variant carries higher severity and different remediation.
			f.Type += "_IN_CODE"
			f.Detail = "Secret embedded in code block: " + f.Detail
			f.Severity = "critical"
			findings = append(findings, f)
		}
	}
	return findings
}

type codeSpan struct {
	start int
	end   int
	text  string
}

func extractCodeSpans(content string) []codeSpan {
	var spans []codeSpan
	for _, m := range fencedCodeBlock.FindAllStringSubmatchIndex(content, -1) {
		// m[2..3] is the capture group (the fence body).
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		spans = append(spans, codeSpan{
			start: m[2],
			end:   m[3],
			text:  content[m[2]:m[3]],
		})
	}
	for _, m := range inlineCode.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		// Skip inline matches that overlap a fenced match.
		if overlapsAnyFence(m[2], m[3], spans) {
			continue
		}
		spans = append(spans, codeSpan{
			start: m[2],
			end:   m[3],
			text:  content[m[2]:m[3]],
		})
	}
	return spans
}

func overlapsAnyFence(start, end int, fences []codeSpan) bool {
	for _, f := range fences {
		if start < f.end && end > f.start {
			return true
		}
	}
	return false
}

// ─── Injection Relay ─────────────────────────────────────────────────────────

// InjectionRelayDetector spots cases where the LLM output is repeating injection
// text it absorbed from RAG context or tool output. This is the *indirect*
// injection signal — the input scan can't see it because the malicious payload
// arrived between input scan and output (e.g. via vector search).
type InjectionRelayDetector struct{}

func (d *InjectionRelayDetector) Name() string { return "injection_relay_v1" }
func (d *InjectionRelayDetector) Category() models.DetectionCategory {
	return models.CategoryPromptInjection
}

type injectionRelayRule struct {
	pattern  *regexp.Regexp
	label    string
	detail   string
	severity string
}

var injectionRelayPatterns = []injectionRelayRule{
	// Classic relay phrasing: "the document/context says: ignore..."
	{regexp.MustCompile(`(?i)(the\s+(document|context|tool|page|file|email|message)\s+(says|reads|contains|states))[:\s]+.{0,40}\bignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)`), "RELAY_IGNORE_PREVIOUS", "LLM relayed an 'ignore previous instructions' injection from external context", "critical"},
	// Bare relay of override directives in output
	{regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`), "OUTPUT_IGNORE_DIRECTIVE", "Output contains 'ignore previous instructions' directive", "high"},
	{regexp.MustCompile(`(?i)\bdisregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|guidelines?|rules?)`), "OUTPUT_DISREGARD_DIRECTIVE", "Output contains 'disregard previous instructions' directive", "high"},
	// LLM repeating its own system prompt or instructions back
	{regexp.MustCompile(`(?i)\b(here\s+is|this\s+is)\s+my\s+(system\s+prompt|original\s+instructions?|hidden\s+prompt)\b`), "SYSTEM_PROMPT_DISCLOSURE", "Output discloses LLM system prompt", "critical"},
	// Common indirect-injection markers from real-world attacks
	{regexp.MustCompile(`(?i)\[\s*(system|assistant|user)\s*\][:\s]+\bignore\b`), "OUTPUT_ROLE_TAG_INJECTION", "Output contains role-tagged injection directive", "critical"},
	// "You are now..." role override repeated in output
	{regexp.MustCompile(`(?i)\byou\s+are\s+now\b.{0,40}\b(unrestricted|jailbroken|free|unfiltered|DAN)\b`), "OUTPUT_ROLE_OVERRIDE", "Output contains role override directive", "high"},
}

func (d *InjectionRelayDetector) Detect(content string) []models.Finding {
	var findings []models.Finding
	for _, r := range injectionRelayPatterns {
		loc := r.pattern.FindStringIndex(content)
		if loc == nil {
			continue
		}
		findings = append(findings, models.Finding{
			Category:   models.CategoryPromptInjection,
			Type:       r.label,
			Detail:     r.detail,
			Confidence: 0.85,
			Severity:   r.severity,
			Location:   &models.Location{Start: loc[0], End: loc[1]},
		})
	}
	return findings
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// scanFirstMatchPerRule applies a per-rule iterator and produces one finding per
// matching rule (location anchored to the first match).
func scanFirstMatchPerRule(
	content string,
	iter func(yield func(pattern *regexp.Regexp, label, detail, severity string)),
	cat models.DetectionCategory,
) []models.Finding {
	var findings []models.Finding
	iter(func(pattern *regexp.Regexp, label, detail, severity string) {
		loc := pattern.FindStringIndex(content)
		if loc == nil {
			return
		}
		findings = append(findings, models.Finding{
			Category:   cat,
			Type:       label,
			Detail:     detail,
			Confidence: 0.85,
			Severity:   severity,
			Location:   &models.Location{Start: loc[0], End: loc[1]},
		})
	})
	return findings
}
