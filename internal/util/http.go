// Package util provides common utility functions used across the application.
package util

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoder.Encode only fails on broken pipes / unencodable values; the
	// status header is already committed so there is nothing useful we can
	// do beyond the default behavior of dropping the rest of the body.
	_ = json.NewEncoder(w).Encode(v)
}

// ShortUUID generates a short 8-byte random hex string for use as event IDs.
func ShortUUID() string {
	b := make([]byte, 8)
	// crypto/rand.Read on supported platforms only fails if the OS RNG is
	// unavailable, which is fatal regardless. Ignoring n is intentional.
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
