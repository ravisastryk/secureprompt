package session

import (
	"fmt"
	"sync"

	"github.com/ravisastryk/secureprompt/internal/models"
)

const maxRecentCategories = 6

// Store keeps a short in-memory history of tenant/session behavior.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*profile
}

type profile struct {
	recentScans      int
	recentReviews    int
	recentBlocks     int
	recentCategories []models.DetectionCategory
}

// NewStore creates a fresh in-memory session store.
func NewStore() *Store {
	return &Store{sessions: make(map[string]*profile)}
}

// Snapshot returns current behavioral signals for a request.
func (s *Store) Snapshot(tenantID, sessionID string) models.SessionSignals {
	key := sessionKey(tenantID, sessionID)

	s.mu.RLock()
	p := s.sessions[key]
	s.mu.RUnlock()

	if p == nil {
		return models.SessionSignals{Key: key}
	}

	signals := models.SessionSignals{
		Key:              key,
		RecentScans:      p.recentScans,
		RecentReviews:    p.recentReviews,
		RecentBlocks:     p.recentBlocks,
		RecentCategories: stringifyCategories(p.recentCategories),
	}

	injectionCount := 0
	exfilCount := 0
	for _, cat := range p.recentCategories {
		switch cat {
		case models.CategoryPromptInjection:
			injectionCount++
		case models.CategoryDataExfil:
			exfilCount++
		}
	}

	signals.RepeatedInjectionAttempts = injectionCount >= 2
	signals.RepeatedExfiltrationHints = exfilCount >= 2
	signals.RecentAttackEscalation = p.recentBlocks > 0 && (signals.RepeatedInjectionAttempts || signals.RepeatedExfiltrationHints)

	return signals
}

// Record updates the behavioral profile after a decision is made.
func (s *Store) Record(tenantID, sessionID string, risk models.RiskLevel, findings []models.Finding) {
	key := sessionKey(tenantID, sessionID)

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.sessions[key]
	if p == nil {
		p = &profile{}
		s.sessions[key] = p
	}

	p.recentScans++
	switch risk {
	case models.RiskReview:
		p.recentReviews++
	case models.RiskBlock:
		p.recentBlocks++
	}

	for _, finding := range findings {
		p.recentCategories = append(p.recentCategories, finding.Category)
		if len(p.recentCategories) > maxRecentCategories {
			p.recentCategories = p.recentCategories[len(p.recentCategories)-maxRecentCategories:]
		}
	}
}

func sessionKey(tenantID, sessionID string) string {
	if tenantID == "" && sessionID == "" {
		return "anonymous"
	}
	return fmt.Sprintf("%s:%s", tenantID, sessionID)
}

func stringifyCategories(categories []models.DetectionCategory) []string {
	out := make([]string, 0, len(categories))
	for _, cat := range categories {
		out = append(out, string(cat))
	}
	return out
}
