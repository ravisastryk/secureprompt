// SecurePrompt — Pre-flight + post-response security gateway for AI prompts.
//
// Usage:
//
//	go run ./cmd/secureprompt
//	# or
//	go build -o secureprompt ./cmd/secureprompt && ./secureprompt
//
// Configuration is loaded from configs/secureprompt.yaml (path overridable via
// SP_CONFIG) with environment variables taking precedence. The semantic
// analysis layer is opt-in via SP_SEMANTIC=true and a HuggingFace token in
// HF_TOKEN.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ravisastryk/secureprompt/internal/api"
	"github.com/ravisastryk/secureprompt/internal/config"
	"github.com/ravisastryk/secureprompt/internal/semantic"
)

func main() {
	configPath := os.Getenv("SP_CONFIG")
	if configPath == "" {
		configPath = "configs/secureprompt.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	srv := api.NewServer(cfg.Audit.Secret)

	// Semantic analysis layer (optional, config-driven).
	if cfg.Semantic.Enabled {
		analyzer := semantic.New(cfg.Semantic)
		srv.SetSemanticAnalyzer(analyzer)

		modelIDs := make([]string, 0, len(cfg.Semantic.ActiveModels()))
		for _, m := range cfg.Semantic.ActiveModels() {
			modelIDs = append(modelIDs, m.ID)
		}
		// Operator-supplied config values; gosec G706 doesn't apply.
		log.Printf("[semantic] enabled | profile=%s | models=%v | timeout=%dms | escalation_band=[%.2f,%.2f]", //nolint:gosec // G706: log values are operator-supplied config, not request input
			cfg.Semantic.Profile, modelIDs, analyzer.Config().TimeoutMs,
			analyzer.Config().EscalationBand.Low, analyzer.Config().EscalationBand.High)
		if analyzer.Config().HFToken == "" {
			log.Printf("[semantic] HF_TOKEN not set; using unauthenticated HF API (~1000 req/hour limit)")
		}
	} else {
		log.Printf("[semantic] disabled (rules-only mode); enable via SP_SEMANTIC=true HF_TOKEN=hf_...")
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	port := fmt.Sprintf("%d", cfg.Server.Port)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              SecurePrompt API                                ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Port:     %-48s  ║\n", port)
	fmt.Println("║  Policy:   strict (default)                                  ║")
	fmt.Printf("║  Semantic: %-48s  ║\n", semanticBadge(cfg.Semantic.Enabled))
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Endpoints:                                                  ║")
	fmt.Println("║    GET  /health      -> Health check                         ║")
	fmt.Println("║    POST /v1/prescan  -> Scan a prompt (input or response)    ║")
	fmt.Println("║    GET  /v1/audit    -> View audit log                       ║")
	fmt.Println("║    GET  /v1/stats    -> View statistics                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func semanticBadge(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled (rules-only)"
}
