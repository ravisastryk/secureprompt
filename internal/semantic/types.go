// Package semantic provides LLM-powered semantic analysis for SecurePrompt.
//
// It calls the HuggingFace Inference API directly from Go — no Python, no
// sidecar, no additional processes. The only dependency is the Go standard
// library.
//
// Architecture:
//
//	Rules layer (always, <10ms)               → fast-path ALLOW/BLOCK
//	Semantic layer (borderline only, +50–300) → escalation for novel attacks
//
// The semantic layer is entirely config-driven via secureprompt.yaml and
// degrades gracefully to rules-only if HF API is unavailable or unconfigured.
package semantic

import "time"

// Config maps to the `semantic:` block in secureprompt.yaml.
type Config struct {
	Enabled bool `yaml:"enabled"`

	// HFToken is the HuggingFace API token. Required by the Inference
	// Providers router (the supported endpoint as of 2025). The token must
	// have the "Make calls to Inference Providers" permission enabled at
	// https://huggingface.co/settings/tokens. Set via the HF_TOKEN env var
	// or the hf_token field below.
	HFToken string `yaml:"hf_token"`

	// APIBase overrides the HuggingFace endpoint base URL. Empty uses the
	// current default (Inference Providers router). Override only when HF
	// changes routing or when proxying through a corporate gateway. Set
	// via the SP_SEMANTIC_API_BASE env var or this field.
	APIBase string `yaml:"api_base"`

	// EscalationBand defines the rules-score range where the semantic layer
	// fires. Scores below Low → rules ALLOW (skip semantic). Scores above
	// High → rules BLOCK (skip semantic). Only the middle band escalates.
	EscalationBand struct {
		Low  float64 `yaml:"low"`  // default 0.1
		High float64 `yaml:"high"` // default 0.8
	} `yaml:"escalation_band"`

	// FusionWeight is the semantic layer's contribution to the final score
	// when both layers fire. 0.6 means semantic gets 60%, rules get 40%.
	FusionWeight float64 `yaml:"fusion_weight"` // default 0.6

	// TimeoutMs is the per-request timeout for HF API calls. SecurePrompt
	// never blocks longer than this on the semantic layer.
	TimeoutMs int `yaml:"timeout_ms"` // default 400

	// FailOpen, when true, makes semantic errors fall back to the rules
	// score (recommended). When false, errors raise the score so the
	// fusion step can promote to BLOCK for safety.
	FailOpen bool `yaml:"fail_open"` // default true

	// Profile selects a pre-defined model set. Overridden by Models.
	//   "minimal"   → prompt_guard_22m only          (~60ms)
	//   "balanced"  → prompt_guard_22m + piiranha    (~120ms) [default]
	//   "thorough"  → prompt_guard_86m + protectai + piiranha (~200ms)
	Profile string `yaml:"profile"` // default "balanced"

	// Models is an explicit override list. If non-empty, Profile is ignored.
	Models []ModelConfig `yaml:"models"`
}

// ModelConfig defines one HuggingFace model to use in the semantic layer.
type ModelConfig struct {
	// ID is the HuggingFace model ID, e.g.
	// "protectai/deberta-v3-base-prompt-injection-v2".
	ID string `yaml:"id"`
	// Task is "text-classification" or "token-classification".
	Task string `yaml:"task"`
	// Threshold is the minimum confidence to emit a finding (default 0.7
	// for text-classification, 0.85 for token-classification).
	Threshold float64 `yaml:"threshold"`
	// InputOnly, when true, runs this model only when scan_mode=input.
	InputOnly bool `yaml:"input_only"`
	// ResponseOnly, when true, runs this model only when scan_mode=response.
	ResponseOnly bool `yaml:"response_only"`
	// Disabled turns off a single model without removing it from config.
	Disabled bool `yaml:"disabled"`
}

// DefaultModels maps profile names to pre-configured model sets.
//
// Each entry is verified against the live HuggingFace Inference Providers
// router. When HF deprecates a model (HTTP 410), update the entry here
// rather than asking operators to override `models:` in their YAML.
var DefaultModels = map[string][]ModelConfig{
	"minimal": {
		{
			// Gated by Meta; requires accepting the license at
			// https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M
			// before the token can call it. Returns LABEL_1 / LABEL_0.
			ID:        "meta-llama/Llama-Prompt-Guard-2-22M",
			Task:      "text-classification",
			Threshold: 0.7,
		},
	},
	"balanced": {
		{
			ID:        "protectai/deberta-v3-base-prompt-injection-v2",
			Task:      "text-classification",
			Threshold: 0.7,
		},
		{
			// Replacement for the deprecated piiranha model. Recognizes
			// SSN, FIRSTNAME, MIDDLENAME, LASTNAME, EMAIL, PHONE, …
			ID:        "lakshyakh93/deberta_finetuned_pii",
			Task:      "token-classification",
			Threshold: 0.85,
		},
	},
	"thorough": {
		{
			ID:        "meta-llama/Llama-Prompt-Guard-2-22M",
			Task:      "text-classification",
			Threshold: 0.65,
		},
		{
			ID:        "protectai/deberta-v3-base-prompt-injection-v2",
			Task:      "text-classification",
			Threshold: 0.7,
		},
		{
			ID:        "lakshyakh93/deberta_finetuned_pii",
			Task:      "token-classification",
			Threshold: 0.85,
		},
	},
}

// Finding is a single semantic detection from one model.
//
// Start/End mark a character span in the scanned content and are populated
// only by token-classification findings (PII entity spans). Text-
// classification findings emit them as zero. The scanner uses these spans to
// drive safe_rewrite redaction in response mode.
type Finding struct {
	Type       string  `json:"type"`       // e.g. "semantic_prompt_injection"
	Confidence float64 `json:"confidence"` // 0.0–1.0 from the model
	Model      string  `json:"model"`      // HF model ID that produced this
	Label      string  `json:"label"`      // raw label from the model
	Evidence   string  `json:"evidence"`   // word/span/rationale
	ScanMode   string  `json:"scan_mode"`  // "input" or "response"
	Start      int     `json:"start,omitempty"`
	End        int     `json:"end,omitempty"`
}

// Result is the aggregated output of the semantic layer for one scan.
type Result struct {
	Score      float64   `json:"semantic_score"`
	Findings   []Finding `json:"semantic_findings,omitempty"`
	LatencyMs  float64   `json:"semantic_latency_ms"`
	Models     []string  `json:"semantic_models_used,omitempty"`
	Skipped    bool      `json:"semantic_skipped,omitempty"`
	SkipReason string    `json:"semantic_skip_reason,omitempty"`
	Error      string    `json:"semantic_error,omitempty"`
}

// ScanRequest is what the semantic layer receives from the scanner.
type ScanRequest struct {
	Content   string
	ScanMode  string // "input" | "response"
	StartTime time.Time
}

func (cfg *Config) applyDefaults() {
	if cfg.EscalationBand.Low == 0 {
		cfg.EscalationBand.Low = 0.1
	}
	if cfg.EscalationBand.High == 0 {
		cfg.EscalationBand.High = 0.8
	}
	if cfg.FusionWeight == 0 {
		cfg.FusionWeight = 0.6
	}
	if cfg.TimeoutMs == 0 {
		cfg.TimeoutMs = 400
	}
	if cfg.Profile == "" {
		cfg.Profile = "balanced"
	}
}

// ActiveModels returns the resolved model list for this config: explicit
// Models override Profile; disabled models are filtered out.
func (cfg *Config) ActiveModels() []ModelConfig {
	if len(cfg.Models) > 0 {
		active := make([]ModelConfig, 0, len(cfg.Models))
		for _, m := range cfg.Models {
			if !m.Disabled {
				active = append(active, m)
			}
		}
		return active
	}
	profile := cfg.Profile
	if profile == "" {
		profile = "balanced"
	}
	if models, ok := DefaultModels[profile]; ok {
		return models
	}
	return DefaultModels["balanced"]
}
