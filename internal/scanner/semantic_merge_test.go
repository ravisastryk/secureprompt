package scanner

import (
	"strings"
	"testing"

	"github.com/ravisastryk/secureprompt/internal/models"
	"github.com/ravisastryk/secureprompt/internal/rewriter"
	"github.com/ravisastryk/secureprompt/internal/semantic"
)

func TestMergeSemanticSpans_NilOrSkipped(t *testing.T) {
	rules := []models.Finding{{Category: models.CategoryPII, Type: "X"}}
	if got := mergeSemanticSpans(rules, nil); len(got) != 1 {
		t.Fatalf("nil result should pass rules through unchanged, got %d", len(got))
	}
	if got := mergeSemanticSpans(rules, &semantic.Result{Skipped: true}); len(got) != 1 {
		t.Fatalf("skipped result should pass rules through unchanged, got %d", len(got))
	}
}

func TestMergeSemanticSpans_PIIBecomesRedactable(t *testing.T) {
	sem := &semantic.Result{
		Findings: []semantic.Finding{
			{Type: "semantic_pii_ssn", Confidence: 0.99, Start: 35, End: 47, Evidence: "entity=SSN"},
			// Skipped: no span.
			{Type: "semantic_prompt_injection", Confidence: 0.95, Start: 0, End: 0},
			// Skipped: non-PII type.
			{Type: "semantic_jailbreak", Confidence: 0.95, Start: 1, End: 5},
		},
	}
	merged := mergeSemanticSpans(nil, sem)
	if len(merged) != 1 {
		t.Fatalf("expected 1 redactable finding, got %d (%+v)", len(merged), merged)
	}
	got := merged[0]
	if got.Category != models.CategoryPII {
		t.Errorf("category = %q, want PII", got.Category)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.Type != "PII_SSN" {
		t.Errorf("type label = %q, want PII_SSN", got.Type)
	}
	if got.Location == nil || got.Location.Start != 35 || got.Location.End != 47 {
		t.Errorf("location = %+v, want {35,47}", got.Location)
	}
}

func TestRewriter_MasksSemanticSpan(t *testing.T) {
	// End-to-end: rules layer found nothing, semantic returned an SSN span;
	// after merge the rewriter must mask exactly that span.
	content := "The customer's SSN is 078-05-1120 — please file it."
	start := strings.Index(content, "078-05-1120")
	if start < 0 {
		t.Fatal("test fixture: SSN substring missing")
	}
	end := start + len("078-05-1120")

	sem := &semantic.Result{
		Findings: []semantic.Finding{
			{Type: "semantic_pii_ssn", Confidence: 0.97, Start: start, End: end},
		},
	}
	merged := mergeSemanticSpans(nil, sem)
	rw := rewriter.NewEngine()
	got := rw.Rewrite(content, merged)
	if !strings.Contains(got, "[REDACTED_PII_SSN]") {
		t.Errorf("expected redaction tag in output, got %q", got)
	}
	if strings.Contains(got, "078-05-1120") {
		t.Errorf("SSN was not masked; got %q", got)
	}
}

func TestMergeSemanticSpans_DedupesAgainstRules(t *testing.T) {
	// Same character span detected by both layers should appear once.
	rules := []models.Finding{
		{
			Category: models.CategoryPII,
			Type:     "PII_SSN",
			Severity: "high",
			Location: &models.Location{Start: 10, End: 21},
		},
	}
	sem := &semantic.Result{
		Findings: []semantic.Finding{
			{Type: "semantic_pii_ssn", Confidence: 0.99, Start: 10, End: 21},
		},
	}
	merged := mergeSemanticSpans(rules, sem)
	if len(merged) != 1 {
		t.Errorf("dedupe should collapse identical PII_SSN span; got %d entries: %+v", len(merged), merged)
	}
}
