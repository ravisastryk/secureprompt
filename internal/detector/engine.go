// Package detector provides the detection engine that orchestrates all
// individual detectors (secrets, injection, PII, etc.) in parallel.
package detector

import (
	"sync"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// Detector is the interface every category-specific detector implements.
type Detector interface {
	Name() string
	Category() models.DetectionCategory
	Detect(content string) []models.Finding
}

// Engine runs all registered detectors against a prompt concurrently.
type Engine struct {
	detectors []Detector
}

// NewEngine creates a detection engine with all built-in detectors.
func NewEngine() *Engine {
	return &Engine{
		detectors: []Detector{
			&SecretsDetector{},
			&InjectionDetector{},
			&PIIDetector{},
			&RiskyOpsDetector{},
			&ExfiltrationDetector{},
			&MalwareDetector{},
		},
	}
}

// Scan runs every detector in parallel and returns aggregated findings.
func (e *Engine) Scan(content string) []models.Finding {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []models.Finding
	)

	for _, d := range e.detectors {
		wg.Add(1)
		go func(det Detector) {
			defer wg.Done()
			results := det.Detect(content)
			if len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(d)
	}

	wg.Wait()
	return findings
}
