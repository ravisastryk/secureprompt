// Package config loads SecurePrompt's runtime configuration from
// configs/secureprompt.yaml (optional) and environment variables.
//
// Order of precedence (highest first):
//  1. Environment variables (SP_*, HF_TOKEN, etc.)
//  2. YAML file at the resolved path
//  3. Hard-coded defaults
//
// The YAML file is intentionally optional: setting SP_SEMANTIC=true and
// HF_TOKEN=... is enough to turn on the v2 semantic layer in CI/dev.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/ravisastryk/secureprompt/internal/semantic"
)

// AppConfig is the root configuration object. Add new sections as new
// `yaml:"…"`-tagged fields.
type AppConfig struct {
	Server   ServerConfig    `yaml:"server"`
	Audit    AuditConfig     `yaml:"audit"`
	Semantic semantic.Config `yaml:"semantic"`
}

// ServerConfig holds HTTP server tuning.
type ServerConfig struct {
	Port int `yaml:"port"`
}

// AuditConfig holds audit-log signing settings.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Secret  string `yaml:"secret"`
}

// Defaults returns a fresh AppConfig with safe defaults applied.
func Defaults() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{Port: 8080},
		Audit: AuditConfig{
			Enabled: true,
			// #nosec G101 -- non-secret development fallback; production
			// must override via env var or config file.
			Secret: "secureprompt-dev-secret",
		},
	}
}

// Load reads YAML from path if it exists, then applies env overrides on top.
// A missing file is not an error — defaults are returned.
func Load(path string) (*AppConfig, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path is trusted at startup
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// File optional; carry on with defaults.
	default:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// applyEnvOverrides lets operators override config without editing YAML.
// Only the v2-semantic and a few legacy server settings are exposed; add new
// overrides here when new operator-tunable fields are introduced.
func applyEnvOverrides(cfg *AppConfig) {
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("SP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("HMAC_SECRET"); v != "" {
		cfg.Audit.Secret = v
	}
	if v := os.Getenv("SP_AUDIT_SECRET"); v != "" {
		cfg.Audit.Secret = v
	}

	switch os.Getenv("SP_SEMANTIC") {
	case "true", "1", "yes":
		cfg.Semantic.Enabled = true
	case "false", "0", "no":
		cfg.Semantic.Enabled = false
	}
	if v := os.Getenv("HF_TOKEN"); v != "" {
		cfg.Semantic.HFToken = v
	}
	if v := os.Getenv("SP_SEMANTIC_PROFILE"); v != "" {
		cfg.Semantic.Profile = v
	}
	if v := os.Getenv("SP_SEMANTIC_TIMEOUT"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			cfg.Semantic.TimeoutMs = ms
		}
	}
	if v := os.Getenv("SP_SEMANTIC_API_BASE"); v != "" {
		cfg.Semantic.APIBase = v
	}
}
