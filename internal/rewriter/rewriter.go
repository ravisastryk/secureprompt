// Package rewriter produces a sanitized version of the prompt by redacting
// detected secrets and PII, then appending safety guidance.
package rewriter

import (
	"fmt"
	"sort"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// Engine generates safe rewrites by redacting sensitive content.
type Engine struct{}

// NewEngine creates a new rewrite engine.
func NewEngine() *Engine { return &Engine{} }

// Rewrite takes the original content and findings, returns a redacted version.
func (e *Engine) Rewrite(content string, findings []models.Finding) string {
	if len(findings) == 0 {
		return content
	}

	// Collect all location-based findings, sorted by start position descending
	// so we can replace from the end without breaking earlier offsets.
	type replacement struct {
		start int
		end   int
		label string
	}
	var reps []replacement

	for _, f := range findings {
		if f.Location != nil && f.Location.Start >= 0 && f.Location.End > f.Location.Start {
			reps = append(reps, replacement{
				start: f.Location.Start,
				end:   f.Location.End,
				label: f.Type,
			})
		}
	}

	// Sort descending by start position
	sort.Slice(reps, func(i, j int) bool { return reps[i].start > reps[j].start })

	redacted := content
	for _, r := range reps {
		if r.end <= len(redacted) {
			tag := fmt.Sprintf("[REDACTED_%s]", r.label)
			redacted = redacted[:r.start] + tag + redacted[r.end:]
		}
	}

	return redacted
}
