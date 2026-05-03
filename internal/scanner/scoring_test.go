package scanner

import (
	"testing"

	"github.com/ravisastryk/secureprompt/internal/models"
)

func TestComputeResponseRiskScore_Empty(t *testing.T) {
	score, factors := computeResponseRiskScore(nil, nil)
	if score != 0 {
		t.Fatalf("empty findings should score 0, got %d", score)
	}
	if len(factors) != 0 {
		t.Fatalf("empty findings should produce no factors, got %v", factors)
	}
}

func TestComputeResponseRiskScore_PIIWeightHigherThanMalware(t *testing.T) {
	pii := []models.Finding{{Category: models.CategoryPII, Severity: "high"}}
	mal := []models.Finding{{Category: models.CategoryMalware, Severity: "high"}}

	piiScore, _ := computeResponseRiskScore(pii, nil)
	malScore, _ := computeResponseRiskScore(mal, nil)

	if piiScore <= malScore {
		t.Fatalf("PII output (%d) should weigh more than malware output (%d)", piiScore, malScore)
	}
}

func TestComputeResponseRiskScore_SecretInCodeIsTopWeight(t *testing.T) {
	secret := []models.Finding{{Category: models.CategorySecrets, Severity: "critical"}}
	exfil := []models.Finding{{Category: models.CategoryDataExfil, Severity: "critical"}}

	sScore, _ := computeResponseRiskScore(secret, nil)
	eScore, _ := computeResponseRiskScore(exfil, nil)

	if sScore <= eScore {
		t.Fatalf("SECRETS in response should outweigh exfil intent, secret=%d exfil=%d", sScore, eScore)
	}
}

func TestComputeResponseRiskScore_CrossCategoryBonus(t *testing.T) {
	multi := []models.Finding{
		{Category: models.CategoryPII, Severity: "high"},
		{Category: models.CategorySecrets, Severity: "high"},
	}
	single := []models.Finding{{Category: models.CategoryPII, Severity: "high"}}

	multiScore, factors := computeResponseRiskScore(multi, nil)
	singleScore, _ := computeResponseRiskScore(single, nil)

	if multiScore <= singleScore {
		t.Fatalf("cross-category bonus expected: multi=%d single=%d", multiScore, singleScore)
	}
	var hasCross bool
	for _, f := range factors {
		if contains(f, "cross-category") {
			hasCross = true
		}
	}
	if !hasCross {
		t.Fatalf("expected cross-category factor, got %v", factors)
	}
}

func TestComputeResponseRiskScore_ContextAmplifier(t *testing.T) {
	findings := []models.Finding{{Category: models.CategoryPII, Severity: "high"}}

	bare, _ := computeResponseRiskScore(findings, nil)
	withTools, _ := computeResponseRiskScore(findings, &models.ExecutionContext{
		ToolCapabilities: []string{"shell", "database", "browser"},
	})
	elevated, factors := computeResponseRiskScore(findings, &models.ExecutionContext{
		ToolCapabilities: []string{"shell"},
		TrustLevel:       "elevated",
	})

	if withTools <= bare {
		t.Fatalf("tool capabilities should amplify; bare=%d withTools=%d", bare, withTools)
	}
	if elevated <= bare {
		t.Fatalf("elevated trust should amplify; bare=%d elevated=%d", bare, elevated)
	}
	var hasElevated bool
	for _, f := range factors {
		if contains(f, "elevated") {
			hasElevated = true
		}
	}
	if !hasElevated {
		t.Fatalf("expected 'elevated' factor, got %v", factors)
	}
}

func TestComputeResponseRiskScore_Capped100(t *testing.T) {
	heavy := []models.Finding{
		{Category: models.CategorySecrets, Severity: "critical"},
		{Category: models.CategoryPII, Severity: "critical"},
		{Category: models.CategoryPromptInjection, Severity: "critical"},
		{Category: models.CategoryDataExfil, Severity: "critical"},
	}
	score, _ := computeResponseRiskScore(heavy, &models.ExecutionContext{
		ToolCapabilities: []string{"shell", "database", "browser", "network"},
		TrustLevel:       "elevated",
	})
	if score != 100 {
		t.Fatalf("expected score capped at 100, got %d", score)
	}
}

func TestComputeResponseRiskScore_UnknownCategoryFallsBackToOne(t *testing.T) {
	// A finding with an unmapped category should use multiplier 1.0 (not 0).
	score, _ := computeResponseRiskScore([]models.Finding{
		{Category: models.DetectionCategory("UNKNOWN_CAT"), Severity: "critical"},
	}, nil)
	if score == 0 {
		t.Fatal("unknown category should default to multiplier 1.0, not 0")
	}
}

func TestShortRandHex(t *testing.T) {
	a := shortRandHex()
	b := shortRandHex()
	if len(a) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(a))
	}
	if a == b {
		t.Fatalf("two consecutive calls should differ; got %q twice", a)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
