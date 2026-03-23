// Package util provides common utility functions used across the application.
package util

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ShortUUID generates a short 8-byte random hex string for use as event IDs.
func ShortUUID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}