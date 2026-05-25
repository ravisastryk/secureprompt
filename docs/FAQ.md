# SecurePrompt — FAQ

> **Quick answers for the most common questions.**
> Full docs: [README](../README.md) · [API reference](API.md) · [github.com/ravisastryk/secureprompt](https://github.com/ravisastryk/secureprompt)

---

## General

**What is SecurePrompt?**
A security gateway that scans LLM prompts for leaked credentials, PII, prompt injection, and malware intent — before they reach the model, and after the model responds.

**Who is it for?**
Any team building with LLMs: internal chatbots, RAG pipelines, agentic systems, or developer tools like Cursor and Copilot proxied through an API gateway.

**Is it open source?**
Yes — MIT licensed. Every line of code is public. Zero external dependencies.

**What languages / frameworks does it support?**
Any language that can make an HTTP POST. Native Go library also available. Python, TypeScript, Java, and curl all work against the REST API.

---

## Detection

**What does SecurePrompt detect?**
Nine detectors in parallel: API keys & credentials, PII (SSN, credit cards, email), prompt injection & jailbreaks, risky system commands, data exfiltration patterns, malware intent, plus three output-only detectors (PII echo, secrets in generated code, injection relay).

**Can it detect indirect prompt injection — attacks hidden in documents an agent retrieves?**
Yes. v3 adds `PreprocessForRAG()` — scan every document before it enters your vector store. Catches zero-width Unicode injection, RTLO overrides, and injection phrases in PDF, DOCX, CSV, JSON, and Jupyter notebooks.

**Does the semantic layer (v2) catch obfuscated attacks that bypass regex?**
Yes. Leetspeak, Unicode homoglyphs, and polite malware requests score high on the HuggingFace classifier even when regex detectors miss them. The fused score is `rules × 0.4 + semantic × 0.6`.

**What is the false positive rate?**
Low with `moderate` policy; near-zero with `permissive`. The `strict` profile is intentionally aggressive — designed for customer-facing agents where a missed injection is worse than a false positive.

**Can it be bypassed?**
Any static ruleset can be probed. The semantic layer is non-deterministic and harder to tune against. The goal is to raise attacker cost — not claim 100% coverage (no scanner can).

---

## Performance

**What is the latency overhead?**
P50: 4ms (rules only). The semantic layer adds 60–200ms, but only fires on the ~15% of prompts that score between 0.1 and 0.8. Average production overhead is under 6ms.

**What throughput can one instance handle?**
~250 req/sec (rules only). Scale horizontally — the server is stateless.

**What if SecurePrompt is unavailable?**
`fail_open: true` (default): scan call times out, LLM call proceeds normally — no user impact. `fail_open: false`: block on unavailability. Choose based on your risk tolerance.

---

## Integration

**How do I add it to an existing LLM call? How many lines of code?**
Three lines. POST to `/v1/prescan`, check `decision`, proceed or block:
```go
resp, _ := http.Post("http://secureprompt:8080/v1/prescan", "application/json",
    strings.NewReader(`{"content":"`+prompt+`","policy_profile":"strict"}`))
// check resp.decision: "ALLOW" | "REVIEW" | "BLOCK"
```

**Does it work with OpenAI, Anthropic, Azure OpenAI, Bedrock, self-hosted Llama?**
Yes — SecurePrompt scans text content, not the API format. Model-agnostic by design.

**Does it work with LangChain or LlamaIndex?**
Yes. Add a prescan call in the document ingestion callback and the LLM call callback. Both frameworks have hook interfaces for this. First-class middleware integrations are planned.

**What is the `@Policy` directive?**
A Go higher-order function that wraps your LLM-calling function. Zero changes at call sites — scanning is enforced automatically on every invocation.

**Does it work in air-gapped / on-premises environments?**
Yes. Set `SP_SEMANTIC=false` to disable HuggingFace API calls. The rules layer runs fully offline with no outbound network calls.

---

## Deployment

**What are the deployment options?**
Three: (1) embedded Go library — zero network hop, (2) REST sidecar — language-agnostic, deploy alongside your LLM endpoint, (3) `@Policy` directive — zero call-site changes.

**Does it run in Kubernetes?**
Yes. Stateless container, runs as non-root, no persistent storage. Liveness/readiness probe at `/health`.

**Does it work on Lambda / serverless?**
Not recommended — cold start latency conflicts with synchronous pre-flight scanning. Use a containerized always-on deployment (ECS Fargate, Cloud Run, Container Apps) with minimum instances = 1.

**Can I use it with Cursor, GitHub Copilot, or Claude Code?**
Yes — deploy it as an API proxy between the IDE tool and the LLM provider endpoint. Every assembled context is scanned before leaving your network. Intercepts the credential and PII leaks that "Privacy Mode" doesn't cover.

---

## Compliance & Audit

**What does the audit log contain?**
Decision, risk score, findings (type + severity + offset — never raw PII), causal chain, session ID, timestamp, and HMAC-SHA256 signature. The raw prompt content is not stored by default.

**What compliance frameworks does the audit log satisfy?**
SOC 2 Type II, EU AI Act Article 13 (decision traceability), HIPAA (due diligence for healthcare AI), GDPR Article 22 (automated decision audit rights).

**Is the audit log tamper-evident?**
Yes — each entry is HMAC-SHA256 signed. Any post-write modification changes the signature, detectable by recomputing against your audit secret.

---

## Limitations

**Does it stop malicious insiders?**
No. SecurePrompt catches accidental leaks and externally-injected attacks. Intentional insider exfiltration requires identity controls and behavioral monitoring.

**Does it fix LLM hallucinations?**
No. SecurePrompt is a security scanner, not a quality filter. Pair it with structured output validation for correctness.

**Does it scan images / video / audio for steganographic injection?**
Partially (v3 reads EXIF metadata and PNG text chunks). Full pixel-level steganographic analysis is on the v4 roadmap.

**Does it catch security vulnerabilities in LLM-generated code?**
The `secret_in_code_v1` detector catches credentials embedded in generated code. For logical vulnerabilities (SQL injection, XSS in generated code), use a SAST tool (gosec, Semgrep, CodeQL) alongside SecurePrompt.

**Does it protect against model supply chain attacks (poisoned fine-tuning)?**
No. That requires model provenance verification and training data auditing — out of scope for an inference-time scanner.

**Our LLM provider already does content filtering. Is SecurePrompt redundant?**
No. Provider filtering catches what the model outputs. SecurePrompt catches what goes *in* — credentials and PII in your prompts, injection attempts in assembled context. Complementary, not redundant.

---

## Contributing

**How do I contribute?**
Open an issue or PR at [github.com/ravisastryk/secureprompt](https://github.com/ravisastryk/secureprompt). SDK ports (Python, TypeScript), LangChain/LlamaIndex integrations, and new detector patterns are most wanted.

**Where do I report a security vulnerability in SecurePrompt itself?**
Open a GitHub security advisory (private) or email the maintainer directly. Do not open a public issue for security vulnerabilities.

---

