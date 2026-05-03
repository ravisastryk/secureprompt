// Package scanner — output-calibrated scoring.
//
// The input policy engine (policy.calculateAdaptiveScore) weights every
// category roughly equally and then applies cross-signal bonuses. That model
// is correct for input — a malware-intent prompt and a PII prompt both
// represent user *intent* and should score similarly.
//
// For *output*, intent is no longer the right axis. The model is the speaker,
// so the relevant question is "how damaging if this text leaves the boundary?"
// Categories therefore carry different multipliers in response mode:
//
//   - SECRETS  ×1.20  — code is meant to be copied/run; leaked keys are immediate compromise.
//   - PII      ×1.30  — data already assembled by the model; raw extraction risk.
//   - INJECT   ×1.10  — relayed injections compromise downstream agents.
//   - EXFIL    ×1.00  — equivalent risk in/out (a request to dump becomes a dump).
//   - RISKY    ×0.70  — a generated rm -rf is harmless until the user runs it.
//   - MALWARE  ×0.40  — the model talking about malware ≠ user weaponising it.
//
// Privileged-tool context still amplifies (an elevated agent's *output* can
// be auto-fed back into tools). That amplifier mirrors the input scorer.
package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ravisastryk/secureprompt/internal/models"
)

var responseSeverityWeights = map[string]int{
	"low":      10,
	"medium":   25,
	"high":     50,
	"critical": 80,
}

var responseCategoryMultipliers = map[models.DetectionCategory]float64{
	models.CategorySecrets:         1.20,
	models.CategoryPII:             1.30,
	models.CategoryPromptInjection: 1.10,
	models.CategoryDataExfil:       1.00,
	models.CategoryRiskyOps:        0.70,
	models.CategoryMalware:         0.40,
}

// computeResponseRiskScore returns a 0–100 integer score plus the explanatory
// factors that contributed (so the caller can surface them in Reasoning /
// CausalChain). It does NOT call the policy engine — the caller still does
// that. We just provide a parallel score the engine can compare against.
func computeResponseRiskScore(findings []models.Finding, ctx *models.ExecutionContext) (int, []string) {
	if len(findings) == 0 {
		return 0, nil
	}

	var raw float64
	categories := map[models.DetectionCategory]bool{}
	for _, f := range findings {
		w := float64(responseSeverityWeights[f.Severity])
		mult, ok := responseCategoryMultipliers[f.Category]
		if !ok {
			mult = 1.0
		}
		raw += w * mult
		categories[f.Category] = true
	}

	factors := make([]string, 0, 4)

	// Cross-signal evidence: multiple categories firing in output is rare and
	// strongly suggests a real leak (vs. a single false-positive regex hit).
	if len(categories) >= 2 {
		raw += float64(10 * (len(categories) - 1))
		factors = append(factors, fmt.Sprintf("response: cross-category evidence across %d categories", len(categories)))
	}

	// Context amplifier mirrors the input scorer. An elevated agent whose
	// output is auto-consumed downstream is the highest-blast-radius case.
	amplifier := 1.0
	if ctx != nil {
		for _, cap := range ctx.ToolCapabilities {
			switch cap {
			case "shell", "terminal", "filesystem-write":
				amplifier += 0.15
			case "database":
				amplifier += 0.15
			case "browser", "network":
				amplifier += 0.10
			}
		}
		if ctx.TrustLevel == "elevated" {
			amplifier *= 1.2
			factors = append(factors, "response: elevated trust level amplifies output risk")
		}
	}

	score := int(raw * amplifier)
	if score > 100 {
		score = 100
	}
	return score, factors
}

// shortRandHex returns 16 random hex characters; used for default event ids.
func shortRandHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
