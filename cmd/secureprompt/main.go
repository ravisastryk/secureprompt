// SecurePrompt — Pre-flight security layer for AI prompts.
//
// Usage:
//
//	go run ./cmd/secureprompt
//	# or
//	go build -o secureprompt ./cmd/secureprompt && ./secureprompt
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ravisastryk/secureprompt/internal/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		hmacSecret = "secureprompt-dev-secret" // #nosec G101 -- non-secret development fallback
	}

	srv := api.NewServer(hmacSecret)

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              SecurePrompt API v1.0                           ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Port:    %-49s  ║\n", port)
	fmt.Println("║  Policy:  strict (default)                                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Endpoints:                                                  ║")
	fmt.Println("║    GET  /health      -> Health check                         ║")
	fmt.Println("║    POST /v1/prescan  -> Scan a prompt                        ║")
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
