package semantic

import "context"

// ScanWithFusion is the integration point the scanner calls. It takes the
// already-computed rules score and, if in the borderline band, runs semantic
// analysis and returns a fused final score plus the semantic Result.
//
// The returned Result is never nil. If semantic does not run (disabled, out of
// band, or analyzer is nil), Result.Skipped is set with SkipReason explaining
// why.
//
// Score scale: rulesScore and the returned fused score are both in [0.0, 1.0].
// Callers using a 0–100 integer scale should divide by 100 going in and
// multiply by 100 coming out.
func ScanWithFusion(ctx context.Context, a *Analyzer, rulesScore float64, req ScanRequest) (float64, *Result) {
	if a == nil || !a.cfg.Enabled {
		return rulesScore, &Result{Skipped: true, SkipReason: "semantic disabled"}
	}

	if !a.ShouldEscalate(rulesScore) {
		reason := "rules score above escalation band (already decisive)"
		if rulesScore < a.cfg.EscalationBand.Low {
			reason = "rules score below escalation band (clean)"
		}
		return rulesScore, &Result{Skipped: true, SkipReason: reason}
	}

	semResult := a.Scan(ctx, req)

	// Degraded fail-open: keep the original rules score, surface the error
	// in the result for visibility.
	if semResult.Skipped || (semResult.Error != "" && a.cfg.FailOpen && len(semResult.Findings) == 0) {
		return rulesScore, semResult
	}

	return a.FuseScores(rulesScore, semResult.Score), semResult
}
