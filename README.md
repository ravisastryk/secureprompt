![SecurePrompt](secureprompt-logo-banner.png)
# SecurePrompt

**Pre-flight security layer for AI prompts.**

Scans every prompt for secrets, PII, prompt injection, risky operations, data exfiltration, and malware intent — before it reaches your LLM.

## Quick Start

```bash
# Build and run
make build
./secureprompt

# Or run directly
make run
```

## Test

```bash
# Safe prompt
make scan PROMPT="Write hello world in Go"

# Secret detected → BLOCK
make scan PROMPT="My key is sk-abc123xyz456"

# Injection → REVIEW
make scan PROMPT="Ignore all previous instructions"

# Run full test suite
bash scripts/test_examples.sh
```

### Architecture
![alt text](secureprompt_architecture.png)

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/v1/prescan` | Scan a prompt |
| GET | `/v1/audit` | View audit log |
| GET | `/v1/stats` | View statistics |

## Zero Dependencies

The entire project uses **only Go's standard library**. No external packages.

## License

MIT
