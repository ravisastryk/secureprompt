package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultHFAPIBase points at the current HuggingFace Inference Providers
// router. The legacy `api-inference.huggingface.co/models` route was retired
// for most community models in 2025; the router below is the supported path
// and accepts the same request/response shapes for text- and
// token-classification. Override via Config.APIBase if HF moves it again.
const defaultHFAPIBase = "https://router.huggingface.co/hf-inference/models"

// hfClient is the pure-Go HuggingFace Inference API client. It handles
// text-classification and token-classification tasks. No Python, no external
// dependencies — only net/http from the stdlib.
type hfClient struct {
	apiBase    string
	token      string
	httpClient *http.Client
}

func newHFClient(apiBase, token string, timeoutMs int) *hfClient {
	if apiBase == "" {
		apiBase = defaultHFAPIBase
	}
	return &hfClient{
		apiBase: apiBase,
		token:   token,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutMs) * time.Millisecond,
		},
	}
}

// ── Text Classification ───────────────────────────────────────────────────────

type hfTextClassRequest struct {
	Inputs     string         `json:"inputs"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type hfTextClassItem struct {
	Label string  `json:"label"`
	Score float64 `json:"score"`
}

// ClassifyText calls a text-classification model on the HF Inference API.
// Returns all label/score pairs the model produced.
func (c *hfClient) ClassifyText(ctx context.Context, modelID, text string) ([]hfTextClassItem, error) {
	payload := hfTextClassRequest{
		Inputs: text,
		Parameters: map[string]any{
			"function_to_apply": "softmax",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	raw, err := c.post(ctx, modelID, body)
	if err != nil {
		return nil, err
	}

	// HF can return either:
	//   [{label, score}, ...]          (flat array)
	//   [[{label, score}, ...]]        (nested array — batch of 1)
	var flat []hfTextClassItem
	if err := json.Unmarshal(raw, &flat); err == nil && len(flat) > 0 && flat[0].Label != "" {
		return flat, nil
	}

	var nested [][]hfTextClassItem
	if err := json.Unmarshal(raw, &nested); err == nil && len(nested) > 0 {
		return nested[0], nil
	}

	return nil, fmt.Errorf("unexpected response format from %s: %.200s", modelID, raw)
}

// ── Token Classification ──────────────────────────────────────────────────────

type hfTokenClassRequest struct {
	Inputs     string         `json:"inputs"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type hfTokenClassItem struct {
	EntityGroup string  `json:"entity_group"`
	Entity      string  `json:"entity"`
	Score       float64 `json:"score"`
	Word        string  `json:"word"`
	Start       int     `json:"start"`
	End         int     `json:"end"`
}

// Label returns entity_group if set, else entity.
func (t hfTokenClassItem) Label() string {
	if t.EntityGroup != "" {
		return t.EntityGroup
	}
	return t.Entity
}

// ClassifyTokens calls a token-classification model on the HF Inference API.
func (c *hfClient) ClassifyTokens(ctx context.Context, modelID, text string) ([]hfTokenClassItem, error) {
	payload := hfTokenClassRequest{
		Inputs: text,
		Parameters: map[string]any{
			"aggregation_strategy": "simple",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	raw, err := c.post(ctx, modelID, body)
	if err != nil {
		return nil, err
	}

	var items []hfTokenClassItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("token-class unmarshal (%s): %w — body: %.200s", modelID, err, raw)
	}
	return items, nil
}

// ── Core HTTP ─────────────────────────────────────────────────────────────────

func (c *hfClient) post(ctx context.Context, modelID string, body []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", c.apiBase, modelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hf api call to %s: %w", modelID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return raw, nil
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("model %s is loading (503) — retry in a few seconds", modelID)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("hf rate limit hit for %s — set HF_TOKEN for higher limits", modelID)
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("hf api %s returned 401 — check HF_TOKEN is set and not expired", modelID)
	case http.StatusForbidden:
		return nil, fmt.Errorf("hf api %s returned 403 — token lacks 'Make calls to Inference Providers' permission. Edit the token at https://huggingface.co/settings/tokens and enable that scope (or create a Read token)", modelID)
	case http.StatusNotFound:
		return nil, fmt.Errorf("hf api %s returned 404 at %s — the endpoint may have moved; override with semantic.api_base / SP_SEMANTIC_API_BASE", modelID, c.apiBase)
	case http.StatusGone:
		return nil, fmt.Errorf("hf api %s returned 410 — model is deprecated by hf-inference. Pick a working replacement and override semantic.models in configs/secureprompt.yaml", modelID)
	default:
		return nil, fmt.Errorf("hf api %s returned %d: %.200s", modelID, resp.StatusCode, raw)
	}
}

// ── Label interpretation helpers ──────────────────────────────────────────────

// isInjectionLabel reports whether the label from a text-classification model
// indicates a detected attack (injection or jailbreak), not a benign result.
func isInjectionLabel(label string) bool {
	upper := strings.ToUpper(label)
	switch upper {
	case "INJECTION", "JAILBREAK", "PROMPT_INJECTION", "MALICIOUS", "UNSAFE":
		return true
	case "1", "YES", "LABEL_1":
		return true
	}
	return strings.Contains(upper, "INJECT")
}

// piiTypeFromLabel maps HF entity_group labels to internal PII type names.
func piiTypeFromLabel(label string) string {
	upper := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(label), "PII_"))
	// gosec G101 false-positive: these are PII *category labels*, not credentials.
	m := map[string]string{ //nolint:gosec // G101: PII type labels, not secret values
		"SSN":                  "semantic_pii_ssn",
		"SOCIALSECURITYNUMBER": "semantic_pii_ssn",
		"CREDITCARDNUMBER":     "semantic_pii_credit_card",
		"CREDIT_CARD":          "semantic_pii_credit_card",
		"ACCOUNTNUMBER":        "semantic_pii_account_number",
		"EMAIL":                "semantic_pii_email",
		"EMAILADDRESS":         "semantic_pii_email",
		"PHONE":                "semantic_pii_phone",
		"PHONENUMBER":          "semantic_pii_phone",
		"PASSPORT":             "semantic_pii_passport",
		"DRIVERLICENSE":        "semantic_pii_driver_license",
		"DATEOFBIRTH":          "semantic_pii_dob",
		"DATE_OF_BIRTH":        "semantic_pii_dob",
		"PERSON":               "semantic_pii_person_name",
		"FIRSTNAME":            "semantic_pii_person_name",
		"LASTNAME":             "semantic_pii_person_name",
		"LOCATION":             "semantic_pii_location",
		"STREETADDRESS":        "semantic_pii_address",
		"ZIPCODE":              "semantic_pii_zip",
		"IP":                   "semantic_pii_ip",
		"IPADDRESS":            "semantic_pii_ip",
		"USERNAME":             "semantic_pii_username",
	}
	if v, ok := m[upper]; ok {
		return v
	}
	return "semantic_pii_" + strings.ToLower(upper)
}
