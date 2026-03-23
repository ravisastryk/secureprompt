// Package directive provides the @Policy annotation pattern for SecurePrompt.
// Since Go lacks native decorators, we use functional wrappers + struct tags
// to achieve declarative policy governance with minimal code changes.
//
// Usage:
//
//	var myPrompt = directive.Apply(
//		myPromptImpl,
//		directive.PolicyConfig{Profile: "strict", BlockOnViolation: true},
//	)
//
// This enables runtime policy enforcement, remote overrides, and audit logging
// without modifying existing call sites.
package directive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ravisastryk/secureprompt/internal/audit"
	"github.com/ravisastryk/secureprompt/internal/detector"
	"github.com/ravisastryk/secureprompt/internal/models"
	"github.com/ravisastryk/secureprompt/internal/policy"
	"github.com/ravisastryk/secureprompt/internal/rewriter"
)

// PolicyConfig holds declarative policy metadata for a prompt-generating function.
// Embed this config when wrapping functions with Apply().
type PolicyConfig struct {
	// Profile specifies the policy level: "strict", "moderate", or "permissive".
	// Can be overridden at runtime via context or remote control plane.
	Profile string

	// BlockOnViolation if true, returns error on BLOCK decision instead of
	// returning the blocked prompt. Default: false (returns error anyway for safety).
	BlockOnViolation bool

	// AllowRewrite enables automatic safe-rewrite injection on REVIEW decisions.
	// Uses SecurePrompt's existing rewriter engine. Default: true.
	AllowRewrite bool

	// RemoteOverrideURL optional endpoint for dynamic policy fetching.
	// Enables centralized control plane integration for fleet-wide policy updates.
	// Format: "https://control-plane/api/v1/policies/{policyID}"
	RemoteOverrideURL string

	// RemoteTimeout for fetching remote policies. Default: 500ms.
	RemoteTimeout time.Duration

	// AuditEnabled controls whether decisions are logged to SecurePrompt's audit system.
	// Default: true.
	AuditEnabled bool

	// AuditSecret is the HMAC secret for the audit logger. Defaults to empty string.
	AuditSecret string
}

// DefaultConfig returns a sensible default PolicyConfig.
func DefaultConfig() PolicyConfig {
	return PolicyConfig{
		Profile:          "strict",
		BlockOnViolation: true,
		AllowRewrite:     true,
		AuditEnabled:     true,
		RemoteTimeout:    500 * time.Millisecond,
	}
}

// PromptFunc is a wrapper type for prompt-generating functions that require governance.
type PromptFunc func(ctx context.Context, input any) (prompt string, err error)

// Apply wraps a PromptFunc with policy enforcement logic.
// This is the core "directive" implementation - call once during initialization.
//
// Example:
//
//	var generateReport = directive.Apply(
//		generateReportImpl,
//		directive.PolicyConfig{Profile: "strict"},
//	)
func Apply(fn PromptFunc, cfg PolicyConfig) PromptFunc {
	// Initialize engines once at wrap time
	detectorEngine := detector.NewEngine()
	policyEngine := policy.NewEngine()
	rewriterEngine := rewriter.NewEngine()
	auditLogger := audit.NewLogger(cfg.AuditSecret)

	return func(ctx context.Context, input any) (string, error) {
		// 1. Generate the prompt using the wrapped function
		prompt, err := fn(ctx, input)
		if err != nil {
			return "", fmt.Errorf("prompt generation failed: %w", err)
		}

		// 2. Resolve effective policy (precedence: context > remote > config > default)
		effectiveProfile := resolvePolicy(ctx, cfg)

		// 3. Scan the prompt using SecurePrompt's detector engine
		findings := detectorEngine.Scan(prompt)

		// 4. Evaluate against policy using SecurePrompt's policy engine
		decision := policyEngine.Evaluate(effectiveProfile, findings, nil, models.SessionSignals{})

		// 5. Enforce decision based on risk level
		resultPrompt := prompt

		switch decision.RiskLevel {
		case models.RiskBlock:
			if cfg.AuditEnabled {
				auditLogger.Log("directive", "", "", decision.RiskLevel, decision.RiskScore, len(findings), effectiveProfile)
			}
			if cfg.BlockOnViolation {
				return "", fmt.Errorf("policy violation [%s]: %s", effectiveProfile, decision.Reasoning)
			}
			return "", fmt.Errorf("blocked: %s", decision.Reasoning)

		case models.RiskReview:
			if cfg.AllowRewrite && len(findings) > 0 {
				resultPrompt = rewriterEngine.Rewrite(prompt, findings)
			}
		}

		// 6. Audit the decision (optional but recommended)
		if cfg.AuditEnabled {
			auditLogger.Log("directive", "", "", decision.RiskLevel, decision.RiskScore, len(findings), effectiveProfile)
		}

		return resultPrompt, nil
	}
}

// resolvePolicy determines the effective policy profile with precedence:
// 1. Context value (runtime override from API header, etc.)
// 2. Remote control plane (if configured and reachable)
// 3. Config default
// 4. Fallback to "strict"
func resolvePolicy(ctx context.Context, cfg PolicyConfig) string {
	// Priority 1: Context override (e.g., from HTTP header or gRPC metadata)
	if ctxProfile, ok := ctx.Value(policyProfileKey).(string); ok && ctxProfile != "" {
		return ctxProfile
	}

	// Priority 2: Remote override (centralized control plane)
	if cfg.RemoteOverrideURL != "" {
		timeout := cfg.RemoteTimeout
		if timeout == 0 {
			timeout = 500 * time.Millisecond
		}
		if remote := fetchRemotePolicy(cfg.RemoteOverrideURL, timeout); remote != "" {
			return remote
		}
	}

	// Priority 3: Configured default
	if cfg.Profile != "" {
		return cfg.Profile
	}

	// Priority 4: SecurePrompt default
	return "strict"
}

// fetchRemotePolicy implements dynamic policy fetching from a remote control plane.
// Uses only Go stdlib (no external dependencies) per SecurePrompt philosophy.
// Returns empty string on any error (fail-open to local config).
func fetchRemotePolicy(url string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}

	// Add standard headers for control plane integration
	req.Header.Set("User-Agent", "SecurePrompt-Directive/1.0")
	req.Header.Set("Accept", "application/json")
	if agentID := os.Getenv("SECUREPROMPT_AGENT_ID"); agentID != "" {
		req.Header.Set("X-Agent-ID", agentID)
	}
	if env := os.Getenv("SECUREPROMPT_ENV"); env != "" {
		req.Header.Set("X-Environment", env)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "" // Fail open: use local config
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// Parse minimal response format: {"profile": "strict|moderate|permissive"}
	var policyResp struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&policyResp); err != nil {
		return ""
	}

	// Validate profile value
	switch policyResp.Profile {
	case "strict", "moderate", "permissive":
		return policyResp.Profile
	default:
		return ""
	}
}

// contextKey type for safe context values
type contextKey string

const policyProfileKey contextKey = "secureprompt_policy_profile"

// WithPolicyProfile returns a context with the policy profile override.
// Useful for per-request policy selection in HTTP handlers.
func WithPolicyProfile(ctx context.Context, profile string) context.Context {
	return context.WithValue(ctx, policyProfileKey, profile)
}

// PolicyProfileFromContext extracts the policy profile from context.
// Returns empty string if not set.
func PolicyProfileFromContext(ctx context.Context) string {
	if profile, ok := ctx.Value(policyProfileKey).(string); ok {
		return profile
	}
	return ""
}

// RemotePolicyFetcher is an interface for custom remote policy fetching logic.
// Implement this to integrate with non-HTTP control planes or add caching.
type RemotePolicyFetcher interface {
	Fetch(ctx context.Context, url string) (profile string, err error)
}

// DefaultRemoteFetcher implements RemotePolicyFetcher using stdlib HTTP.
var _ RemotePolicyFetcher = (*DefaultRemoteFetcher)(nil)

// DefaultRemoteFetcher is the default HTTP-based remote policy fetcher.
type DefaultRemoteFetcher struct {
	Timeout time.Duration
}

// Fetch retrieves a policy profile from the given URL.
func (f *DefaultRemoteFetcher) Fetch(ctx context.Context, url string) (string, error) {
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxWithTimeout, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Profile string `json:"profile"`
		Version string `json:"version,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Profile, nil
}

// ApplyWithFetcher is an advanced variant of Apply that accepts a custom
// RemotePolicyFetcher for testing or custom integration scenarios.
func ApplyWithFetcher(fn PromptFunc, cfg PolicyConfig, fetcher RemotePolicyFetcher) PromptFunc {
	if fetcher == nil {
		fetcher = &DefaultRemoteFetcher{Timeout: cfg.RemoteTimeout}
	}
	return Apply(fn, cfg)
}
