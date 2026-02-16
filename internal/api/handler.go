// Package api wires together the detection engine, policy engine,
// rewriter, and audit logger behind HTTP endpoints.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ravisastryk/secureprompt/internal/audit"
	"github.com/ravisastryk/secureprompt/internal/detector"
	"github.com/ravisastryk/secureprompt/internal/middleware"
	"github.com/ravisastryk/secureprompt/internal/models"
	"github.com/ravisastryk/secureprompt/internal/policy"
	"github.com/ravisastryk/secureprompt/internal/rewriter"
	"github.com/ravisastryk/secureprompt/internal/util"
)

// Server holds all dependencies for the API.
type Server struct {
	detector *detector.Engine
	policy   *policy.Engine
	rewriter *rewriter.Engine
	audit    *audit.Logger

	mu    sync.RWMutex
	stats Stats
}

// Stats tracks scan metrics.
type Stats struct {
	TotalScans int            `json:"total_scans"`
	ByDecision map[string]int `json:"by_decision"`
}

// NewServer creates a fully-wired API server.
func NewServer(hmacSecret string) *Server {
	return &Server{
		detector: detector.NewEngine(),
		policy:   policy.NewEngine(),
		rewriter: rewriter.NewEngine(),
		audit:    audit.NewLogger(hmacSecret),
		stats:    Stats{ByDecision: map[string]int{"SAFE": 0, "REVIEW": 0, "BLOCK": 0}},
	}
}

// RegisterRoutes mounts all endpoints on the default mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", middleware.CORS(s.handleHealth))
	mux.HandleFunc("/v1/prescan", middleware.CORS(s.handlePrescan))
	mux.HandleFunc("/v1/audit", middleware.CORS(s.handleAudit))
	mux.HandleFunc("/v1/stats", middleware.CORS(s.handleStats))

	// Serve dashboard from web/static/ (falls back to embedded index if dir missing)
	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/", fs)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	util.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "secureprompt",
		"version": "1.0.0",
	})
}

func (s *Server) handlePrescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req models.PrescanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Content == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "content is required"})
		return
	}

	// Defaults
	if req.EventID == "" {
		req.EventID = "evt_" + util.ShortUUID()
	}
	if req.PolicyProfile == "" {
		req.PolicyProfile = "strict"
	}

	start := time.Now()

	// 1. Detect
	findings := s.detector.Scan(req.Content)

	// 2. Policy decision
	decision := s.policy.Evaluate(req.PolicyProfile, findings)

	// 3. Rewrite (only for REVIEW/BLOCK with findings)
	safeRewrite := ""
	if decision.RiskLevel != models.RiskSafe && len(findings) > 0 {
		safeRewrite = s.rewriter.Rewrite(req.Content, findings)
	}

	// 4. Audit log
	sig := s.audit.Log(req.EventID, decision.RiskLevel, decision.RiskScore, len(findings), req.PolicyProfile)

	// 5. Stats
	s.mu.Lock()
	s.stats.TotalScans++
	s.stats.ByDecision[string(decision.RiskLevel)]++
	s.mu.Unlock()

	elapsed := time.Since(start)

	// If no findings, return a single OK finding for clarity
	if len(findings) == 0 {
		findings = []models.Finding{{
			Category:   models.CategoryOK,
			Type:       "NONE",
			Detail:     "No security issues detected",
			Confidence: 1.0,
			Severity:   "none",
		}}
	}

	resp := models.PrescanResponse{
		EventID:           req.EventID,
		TenantID:          req.TenantID,
		SessionID:         req.SessionID,
		PolicyProfile:     req.PolicyProfile,
		RiskLevel:         decision.RiskLevel,
		RiskScore:         decision.RiskScore,
		Findings:          findings,
		SafeRewrite:       safeRewrite,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		ProcessingTimeMs:  elapsed.Milliseconds(),
		DecisionSignature: sig,
	}

	log.Printf("[%s] %s | score=%d | findings=%d | %dms",
		resp.RiskLevel, req.EventID, resp.RiskScore, len(findings), elapsed.Milliseconds())

	util.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	util.WriteJSON(w, http.StatusOK, map[string]interface{}{"entries": s.audit.Entries()})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	util.WriteJSON(w, http.StatusOK, s.stats)
}
