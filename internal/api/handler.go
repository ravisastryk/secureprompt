// Package api wires together the detection engine, policy engine,
// rewriter, and audit logger behind HTTP endpoints.
package api

import (
	"context"
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
	"github.com/ravisastryk/secureprompt/internal/scanner"
	"github.com/ravisastryk/secureprompt/internal/semantic"
	"github.com/ravisastryk/secureprompt/internal/session"
	"github.com/ravisastryk/secureprompt/internal/util"
)

// Server holds all dependencies for the API.
type Server struct {
	detector *detector.Engine
	policy   *policy.Engine
	rewriter *rewriter.Engine
	audit    *audit.Logger
	sessions *session.Store
	scanner  *scanner.Scanner // façade; reused for scan_mode=response

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
	det := detector.NewEngine()
	pol := policy.NewEngine()
	rw := rewriter.NewEngine()
	aud := audit.NewLogger(hmacSecret)
	sess := session.NewStore()
	return &Server{
		detector: det,
		policy:   pol,
		rewriter: rw,
		audit:    aud,
		sessions: sess,
		// Scanner shares the same audit logger + session store so the audit
		// chain stays unbroken regardless of whether a request hits the input
		// or the response path.
		scanner: scanner.NewWithDeps(det, pol, rw, aud, sess),
		stats:   Stats{ByDecision: map[string]int{"SAFE": 0, "REVIEW": 0, "BLOCK": 0}},
	}
}

// SetSemanticAnalyzer attaches the semantic-analysis layer to the underlying
// scanner. Pass nil to disable. Safe to call once at startup before any
// requests are served.
func (s *Server) SetSemanticAnalyzer(a *semantic.Analyzer) {
	s.scanner.SetSemanticAnalyzer(a)
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
	if req.Context == nil {
		req.Context = &models.ExecutionContext{}
	}

	// Dispatch on scan_mode. Default = input (pre-flight); "response" runs the
	// v2 output scanner which adds PII-echo / secret-in-code / injection-relay
	// detectors and applies output-calibrated risk weights.
	mode := req.Context.ScanMode
	if mode == "" {
		mode = models.ScanModeInput
	}

	start := time.Now()
	var (
		result *scanner.ScanResult
		err    error
	)
	scanReq := scanner.ScanRequest{
		EventID:       req.EventID,
		TenantID:      req.TenantID,
		SessionID:     req.SessionID,
		Content:       req.Content,
		PolicyProfile: req.PolicyProfile,
		Context:       req.Context,
	}
	switch {
	case req.Document != nil && len(req.Document.Data) > 0:
		// Pre-flight document scanning (input mode only).
		result, err = s.scanner.ScanWithDocument(context.Background(), scanReq, scanner.DocumentAttachment{
			Data:          req.Document.Data,
			Filename:      req.Document.Filename,
			StripMetadata: req.Document.StripMetadata,
		})
	case mode == models.ScanModeResponse:
		result, err = s.scanner.ScanResponse(context.Background(), scanReq)
	default:
		result, err = s.scanner.Scan(context.Background(), scanReq)
	}
	if err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Stats
	s.mu.Lock()
	s.stats.TotalScans++
	s.stats.ByDecision[string(result.RiskLevel)]++
	s.mu.Unlock()

	elapsed := time.Since(start)

	findings := result.Findings
	// If no findings, return a single OK finding for clarity (preserved from v1).
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
		EventID:           result.EventID,
		TenantID:          req.TenantID,
		SessionID:         req.SessionID,
		PolicyProfile:     result.PolicyProfile,
		ScanMode:          result.ScanMode,
		RiskLevel:         result.RiskLevel,
		RiskScore:         result.RiskScore,
		Findings:          findings,
		SafeRewrite:       result.SafeRewrite,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		ProcessingTimeMs:  elapsed.Milliseconds(),
		DecisionSignature: result.Signature,
		Reasoning:         result.Reasoning,
		DecisionFactors:   result.Factors,
		CausalChain:       result.CausalChain,
	}
	if sem := result.Semantic; sem != nil {
		resp.SemanticScore = sem.Score
		resp.SemanticLatencyMs = sem.LatencyMs
		resp.SemanticModelsUsed = sem.Models
		resp.SemanticSkipped = sem.Skipped
		resp.SemanticSkipReason = sem.SkipReason
		resp.SemanticError = sem.Error
		if len(sem.Findings) > 0 {
			resp.SemanticFindings = make([]models.SemanticFinding, len(sem.Findings))
			for i, f := range sem.Findings {
				resp.SemanticFindings[i] = models.SemanticFinding{
					Type:       f.Type,
					Confidence: f.Confidence,
					Model:      f.Model,
					Label:      f.Label,
					Evidence:   f.Evidence,
					ScanMode:   f.ScanMode,
				}
			}
		}
	}
	resp.DocScan = result.DocScan

	log.Printf("[%s] %s | mode=%s | score=%d | findings=%d | %dms",
		resp.RiskLevel, result.EventID, resp.ScanMode, resp.RiskScore, len(findings), elapsed.Milliseconds())

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
