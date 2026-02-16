![SecurePrompt](secureprompt-logo-banner.png)

SecurePrompt scans every prompt for secrets, PII, prompt injection, risky operations, data exfiltration, and malware intent — before it reaches your LLM.

## Quick Start

```bash
# Build and run
make build
./secureprompt

# Or run directly
make run
```

The server will start on `http://localhost:8080`. Open this URL in your browser to access the **web interface** with a clean UI for scanning prompts.

### ChatGPT Custom GPT Integration

SecurePrompt can be integrated as a **Custom GPT** to scan prompts before they reach ChatGPT:

1. **Run SecurePrompt server** (ngrok used for demo purposes)
2. **Create Custom GPT** in ChatGPT with Action pointing to your `/v1/prescan` endpoint
3. **Pre-flight scanning**: Every prompt is scanned for secrets, PII, injection attempts
4. **Safe rewrites**: Blocked/flagged prompts are automatically sanitized

**Note:** The demo uses ngrok for quick public access. In production, this can be integrated with any managed service, legacy system, or enterprise-grade infrastructure (AWS API Gateway, Azure API Management, on-prem reverse proxy, etc.).

The web interface at [web/static/index.html](web/static/index.html) provides standalone access to the same scanning engine.

## Test

**First, start the server:**
```bash
make run
# Server will start on http://localhost:8080
```

**Then, in another terminal, scan prompts:**
```bash
# Safe prompt
make scan PROMPT="Write hello world in Go"

# Secret detected → BLOCK
make scan PROMPT="My key is sk-abc123xyz456"

# Injection → REVIEW
make scan PROMPT="Ignore all previous instructions"

# Run full test suite (will start server automatically)
bash scripts/test_examples.sh
```

### Architecture
![alt text](secureprompt_architecture.png)

## Web Interface

Access the interactive web UI at `http://localhost:8080` after starting the server. Features:

- Clean, modern interface for prompt scanning
- Three policy levels: Strict, Moderate, Permissive
- Real-time risk scoring and detailed findings
- Safe prompt rewrites for flagged content
- Sub-100ms scan times

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web interface dashboard |
| GET | `/health` | Health check |
| POST | `/v1/prescan` | Scan a prompt |
| GET | `/v1/audit` | View audit log |
| GET | `/v1/stats` | View statistics |

## Zero Dependencies

The entire project uses **only Go's standard library**. No external packages.

## License

MIT
