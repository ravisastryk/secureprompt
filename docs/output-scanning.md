# Output Scanning (v2 Dual-Layer Security)

Pre-flight scanning catches the prompts a user sends. It cannot catch what
the model says back. v2 adds a second layer that scans LLM responses
before they are returned, persisted, or rendered.

## Why scan output

Three failure modes are invisible to input scanning:

1. **PII echo from RAG.** A retrieval step pulls customer records into
   context; the model includes them in its summary. The user prompt was
   clean — the leak happens in the response.
2. **Secrets in generated code.** Models routinely embed real-looking API
   keys in code samples. Code blocks have outsized blast radius because
   users copy-paste them straight into terminals.
3. **Indirect injection relay.** Malicious instructions embedded in a
   tool result or retrieved document take over the model between input
   and output. The pre-flight scan never saw them — but the response
   carries the relayed directives.

## Architecture

```
                  ┌──────────────────┐
   user prompt ──▶│  Scan (input)    │──BLOCK──▶ refuse
                  └────────┬─────────┘
                           │ ALLOW / safe rewrite
                           ▼
                     ┌─────────┐
                     │   LLM   │   (any provider)
                     └────┬────┘
                          ▼
                  ┌──────────────────┐
   final output ◀─│ ScanResponse     │──BLOCK──▶ refuse
                  └──────────────────┘
                  REVIEW → redacted rewrite
```

Both layers feed into the same HMAC-chained audit log.

## Entry points

The `internal/scanner` package is the v2 façade over the existing
detector / policy / rewriter / audit / session components:

```go
func (s *Scanner) Scan(ctx, req)         (*ScanResult, error)       // input
func (s *Scanner) ScanResponse(ctx, req) (*ScanResult, error)       // output
func (s *Scanner) DualLayerScan(ctx, req) (*DualLayerResult, error) // both
```

## Output detectors

### `pii_echo_v1`

The input PII detector requires explicit user context (`my SSN is...`).
In output, the model is the speaker — `"SSN: 078-05-1120"` with no
preamble is a leak signal. Bare-form patterns: SSN, Visa / MC / Amex /
16-digit cards, UK NINO, email anywhere, country-coded phone.

### `secret_in_code_v1`

Extracts every fenced code block and inline code span, then runs the
existing secret patterns inside each. Always `severity: critical`. Type
suffixed with `_IN_CODE` (e.g. `OPENAI_API_KEY_IN_CODE`) so dedupe
preserves it alongside any plain-text secret finding.

### `injection_relay_v1`

The response side of indirect injection — the model repeating
instructions absorbed from RAG / tool output:

- `"the document says: ignore previous instructions..."`
- Bare `"ignore all previous instructions"` / `"disregard all..."` in output
- `"here is my system prompt: ..."` (system prompt disclosure)
- Role-tag injection: `[system]: ignore everything`
- `"you are now jailbroken / unrestricted / DAN"` directives

## Risk scoring (response-calibrated)

Per-category multipliers on top of the existing severity weights:

| Category            | Multiplier | Rationale                                              |
|---------------------|------------|--------------------------------------------------------|
| `PII`               | **×1.30**  | Data already assembled by the model — raw leak         |
| `SECRETS`           | **×1.20**  | Code is meant to be copied / executed                  |
| `PROMPT_INJECTION`  | ×1.10      | Relayed injection compromises downstream agents        |
| `DATA_EXFILTRATION` | ×1.00      | Equivalent risk in / out                               |
| `RISKY_OPERATIONS`  | ×0.70      | A generated `rm -rf` is harmless until run             |
| `MALWARE_INTENT`    | **×0.40**  | Model talking about malware ≠ user weaponising it      |

Multi-category evidence earns +10 / extra-category. Privileged-tool and
elevated-trust amplifiers mirror the input scorer. The output score is
computed in parallel with the policy engine; the higher of the two wins.
A REVIEW verdict with response score ≥ 90 is promoted to BLOCK.

## API: `scan_mode=response`

```http
POST /v1/prescan
Content-Type: application/json

{
  "content": "<llm response text>",
  "policy_profile": "strict",
  "context": { "scan_mode": "response" }
}
```

Response gains:

```json
{
  "scan_mode": "response",
  "causal_chain": [
    "llm_response_received",
    "output_detectors_triggered",
    "response_risk_score_computed",
    "response_policy_evaluated",
    "block_decision_made"
  ]
}
```

All v1 fields preserved.

## Go API: `DualLayerScan`

```go
res, err := scanner.DualLayerScan(ctx, scanner.DualLayerRequest{
    Input:         userPrompt,
    PolicyProfile: "strict",
    Context:       agentCtx,
    LLMCaller: func(prompt string) (string, error) {
        return openaiClient.Complete(ctx, prompt) // any provider
    },
})
```

- **Input BLOCK** → LLM not called; `BlockedAt = "input"`.
- **Input REVIEW** → safe rewrite forwarded.
- **Input ALLOW** → original prompt forwarded.
- **Output BLOCK** → response not surfaced; `BlockedAt = "output"`.
- **Output REVIEW** → `FinalOutput` is the redacted rewrite.
- **Output ALLOW** → `FinalOutput` is the raw LLM response.

## Audit

Both input and output scans append HMAC-signed entries to the same
chained log. An auditor sees adjacent input/output entries for a
`DualLayerScan` request:

```
evt_a1b2  | INPUT  | sess-42 | RISK: REVIEW | sig=…
evt_a1b3  | OUTPUT | sess-42 | RISK: BLOCK  | prev=…
```

A single tampered entry breaks the chain regardless of which layer wrote it.
