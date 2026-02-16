// Package audit provides an append-only, HMAC-signed audit log where
// each entry's signature chains to the previous entry for tamper detection.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ravisastryk/secureprompt/internal/models"
)

// Logger maintains an in-memory, chained audit log.
type Logger struct {
	mu            sync.RWMutex
	entries       []models.AuditEntry
	hmacSecret    []byte
	prevSignature string
}

// NewLogger creates a logger with the given HMAC secret.
func NewLogger(secret string) *Logger {
	return &Logger{hmacSecret: []byte(secret)}
}

// Log records a new audit entry and returns its HMAC signature.
func (l *Logger) Log(eventID string, risk models.RiskLevel, score int, findingCount int, profile string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s|%s",
		eventID, time.Now().UTC().Format(time.RFC3339), risk, score, findingCount, profile, l.prevSignature)

	mac := hmac.New(sha256.New, l.hmacSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	entry := models.AuditEntry{
		EventID:       eventID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		RiskLevel:     risk,
		RiskScore:     score,
		FindingCount:  findingCount,
		PolicyProfile: profile,
		Signature:     sig,
		PrevSignature: l.prevSignature,
	}

	l.entries = append(l.entries, entry)
	l.prevSignature = sig

	return sig
}

// Entries returns a copy of all audit entries.
func (l *Logger) Entries() []models.AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]models.AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}
