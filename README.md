# envaultx

[![PyPI](https://img.shields.io/pypi/v/envaultx)](https://pypi.org/project/envaultx)
[![Python](https://img.shields.io/pypi/pyversions/envaultx)](https://pypi.org/project/envaultx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **What your LLM sees, stays safe.**

Every time you paste code into an LLM, send a document to an API, or build an agent that reads files — there is a non-zero chance that API keys, database passwords, and personal data travel with the content. This happens constantly and mostly by accident.

**envaultx** sits between your application and any LLM API. Before text leaves your system, it detects and redacts sensitive content — replacing secrets with typed, numbered placeholders stored in an ephemeral in-memory vault. The process is fully reversible: if you need original values back, the vault restores them.

```
"postgres://admin:hunter2@prod.db.internal:5432/users"
                           ↓ envaultx
"postgres://[DB_USER_1]:[DB_PASSWORD_1]@[HOSTNAME_1]:5432/[DB_NAME_1]"
```

---

## Why envaultx?

- **Zero infrastructure** — pure Python, no external services, no database, no cloud dependency
- **Reversible** — redaction is stateful; original values can be restored from the vault after the LLM responds
- **Model-agnostic** — works with Anthropic, OpenAI, or any LLM SDK
- **Layered detection** — fast regex patterns first, Shannon entropy heuristics second, optional spaCy NLP third
- **Non-blocking** — envaultx informs and redacts; the caller decides what to do next
- **Three surfaces** — use it as a Python library, a shell pipe, or an MCP server for agent pipelines

---

## Installation

```bash
# Core library + CLI (no optional deps)
pip install envaultx

# With the Anthropic wrapper
pip install "envaultx[anthropic]"

# With the OpenAI wrapper
pip install "envaultx[openai]"

# With NLP-based PII detection (spaCy)
pip install "envaultx[nlp]"
python -m spacy download en_core_web_sm

# With encrypted vault serialization
pip install "envaultx[crypto]"

# Everything
pip install "envaultx[all]"
```

**Requires Python 3.9+.**

---

## Quickstart

### Python library

```python
from envaultx import Envault

ev = Envault()

# Inspect what would be redacted — without modifying anything
result = ev.scan("My key is sk-proj-abc123XYZdef456GHI789jkl012MN")
print(result.risk_level)    # "high"
print(result.has_secrets)   # True
print(result.summary)       # {"OPENAI_KEY": 1}
```

```python
# Redact — replace secrets with typed placeholders
safe, vault = ev.redact(
    "Connect to postgres://admin:hunter2@prod.db.internal:5432/users"
)
# safe  → "Connect to postgres://[DB_USER_1]:[DB_PASSWORD_1]@[HOSTNAME_1]:5432/[DB_NAME_1]"
# vault → Vault(4 entries)

# Send `safe` to the LLM...

# Restore — put original values back from an LLM response
restored = ev.restore("The password [DB_PASSWORD_1] is weak.", vault)
# → "The password hunter2 is weak."
```

```python
# Sanitize — one-way, no vault, no restoration possible
clean = ev.sanitize("Contact me at alice@example.com or +1-555-867-5309")
# → "Contact me at [REDACTED] or [REDACTED]"
```

### Drop-in SDK wrappers

Replace your existing Anthropic or OpenAI client with `AnthropicVault` / `OpenAIVault`. The API is identical — envaultx intercepts every message before it leaves your process.

```python
import anthropic
from envaultx.wrappers import AnthropicVault

client = AnthropicVault(
    anthropic_client=anthropic.Anthropic(api_key="..."),
    on_detection=lambda result: print(f"Redacted: {result.summary}"),
)

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": "Review this config: DB_PASSWORD=hunter2 HOST=prod.internal"
    }],
)
# Secrets were automatically redacted before the API call.
# Access the vault from the response if you need to restore values:
vault = response._vault
```

```python
import openai
from envaultx.wrappers import OpenAIVault

client = OpenAIVault(openai_client=openai.OpenAI(api_key="..."))
# Usage is identical to openai.OpenAI
```

### CLI

Pipe any text through envaultx in a shell script or CI/CD pipeline.

```bash
# Scan a file and report detections (exits 1 if secrets found)
envaultx scan --file config.py
envaultx scan --file .env --format json

# Redact via pipe — safe to feed directly into another tool
cat config.py | envaultx redact --stdin | llm-tool --prompt "explain this"

# Save the vault so you can restore later
envaultx redact --file document.txt --output safe.txt --vault-out vault.enc --vault-password "$SESSION_KEY"

# Restore placeholders in an LLM response
envaultx restore --vault vault.enc --vault-password "$SESSION_KEY" --file response.txt

# One-way sanitization (no vault written)
cat user_data.csv | envaultx redact --stdin --sanitize > safe_data.csv

# List all built-in detection patterns
envaultx patterns
envaultx patterns --format json
```

**Exit codes:** `0` = clean / success · `1` = secrets detected · `2` = I/O error · `3` = config error · `4` = invalid arguments

### MCP server

Run envaultx as an [MCP](https://modelcontextprotocol.io) server so any agent or tool that speaks the Model Context Protocol can call it directly.

```bash
envaultx mcp                              # stdio transport (Claude Desktop, default)
envaultx mcp --transport http --port 8080 # HTTP transport
```

**Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "envaultx": {
      "command": "envaultx",
      "args": ["mcp"]
    }
  }
}
```

Available MCP tools:

| Tool | Description |
|---|---|
| `redact_text` | Redact secrets from text, returns a `session_id` for later restoration |
| `scan_text` | Inspect detections without modifying the text |
| `scan_external_content` | Stricter scan for web/file content — also detects prompt injection |
| `restore_text` | Restore placeholders in an LLM response using a `session_id` |
| `list_vault_sessions` | List active in-memory vault sessions |
| `clear_vault_session` | Permanently clear a session from memory |

Sessions are in-memory only and expire after 1 hour of inactivity.

---

## What envaultx detects

### Layer 1 — Pattern matching (always on)

Regex detection of well-known secret formats. Every match includes a confidence score.

| Category | Example | Confidence |
|---|---|---|
| `OPENAI_KEY` | `sk-proj-...` | 1.0 |
| `ANTHROPIC_KEY` | `sk-ant-api03-...` | 1.0 |
| `AWS_ACCESS_KEY` | `AKIA...` | 1.0 |
| `AWS_SECRET_KEY` | 40-char base64 adjacent to AWS context | 0.95 |
| `GITHUB_TOKEN` | `ghp_...`, `ghs_...` | 1.0 |
| `STRIPE_KEY` | `sk_live_...`, `sk_test_...` | 1.0 |
| `STRIPE_WEBHOOK` | `whsec_...` | 1.0 |
| `GOOGLE_API_KEY` | `AIza...` | 1.0 |
| `SLACK_TOKEN` | `xoxb-...`, `xoxp-...` | 1.0 |
| `SLACK_WEBHOOK` | `https://hooks.slack.com/services/...` | 1.0 |
| `SENDGRID_KEY` | `SG....` | 1.0 |
| `TWILIO_SID` | `AC` + 32 hex chars | 1.0 |
| `JWT_TOKEN` | Three base64url segments | 0.95 |
| `PRIVATE_KEY_PEM` | `-----BEGIN * PRIVATE KEY-----` | 1.0 |
| `DB_CONNECTION_STRING` | `postgres://user:pass@host/db` | 0.95 |
| `DB_USER` / `DB_PASSWORD` | Components of a connection string | 0.9 / 0.95 |
| `BEARER_TOKEN` | `Authorization: Bearer ...` | 0.9 |
| `BASIC_AUTH` | `Authorization: Basic ...` | 0.95 |
| `EMAIL` | RFC 5322 email addresses | 0.85 |
| `PHONE_NUMBER` | E.164 and common national formats | 0.8 |
| `CREDIT_CARD` | Luhn-validated 13–19 digit sequences | 0.95 |
| `SSN` | US Social Security Numbers | 0.95 |
| `IBAN` | International Bank Account Numbers | 0.9 |
| `IP_ADDRESS_PRIVATE` | `10.x`, `192.168.x`, `172.16-31.x` | 0.7 |
| `HOSTNAME_INTERNAL` | `.internal`, `.local`, `.corp` hostnames | 0.75 |

### Layer 2 — Entropy heuristics (always on)

Detects secrets that don't match known formats by computing Shannon entropy. Confidence is adjusted by context:

- Variable name contains `key`, `secret`, `token`, `password` → +0.2
- Right-hand side of an assignment → +0.1
- Looks like a UUID → −0.3 (likely not a secret)

### Layer 3 — NLP / spaCy (opt-in)

Enable with `nlp=True` or `--nlp` flag. Requires `pip install "envaultx[nlp]"`.

Detects PII in natural language prose: names in personal context, physical addresses, phone numbers and emails that Layer 1 misses due to non-standard formatting.

### Prompt injection detection

`scan_external()` and the `scan_external_content` MCP tool apply stricter rules for content fetched from external sources (web pages, uploaded files, API responses). Any content containing imperative AI-directed instructions ("ignore previous instructions", "you are now", "forget everything") is flagged as `PROMPT_INJECTION`.

---

## How the vault works

```
Original text:    "api_key = sk-proj-abc123..."
                              ↓ redact()
Redacted text:    "api_key = [OPENAI_KEY_1]"

Vault (in-memory): { "[OPENAI_KEY_1]": "sk-proj-abc123..." }

LLM response:     "The key [OPENAI_KEY_1] has been rotated."
                              ↓ restore()
Restored:         "The key sk-proj-abc123... has been rotated."
```

- The vault lives only in memory — nothing is ever written to disk by envaultx itself
- The same secret value always maps to the same placeholder within a session (deduplication)
- Placeholders are typed and numbered: `[OPENAI_KEY_1]`, `[EMAIL_3]`, `[DB_PASSWORD_1]`
- For cross-process use, serialize the vault to encrypted bytes (requires `envaultx[crypto]`):

```python
# Encrypt
encrypted = vault.to_encrypted_bytes(password="session-secret")

# Decrypt in another process
from envaultx import Vault
restored_vault = Vault.from_encrypted_bytes(encrypted, password="session-secret")
```

---

## Configuration

envaultx looks for config in this order:

1. `ENVAULT_CONFIG` environment variable (path to a TOML file)
2. `.envaultx.toml` in the current directory
3. `~/.config/envaultx/config.toml`

Copy `.envaultx.toml.example` to `.envaultx.toml` to get started:

```toml
[detection]
threshold = 0.5                        # redact anything with confidence >= this
nlp = false                            # enable spaCy NLP layer
exclude_categories = []                # e.g. ["IP_ADDRESS_PRIVATE", "PHONE_NUMBER"]

[entropy]
min_string_length = 20
base64_threshold = 4.5
hex_threshold = 3.5

[mcp]
transport = "stdio"
port = 8080
session_timeout_minutes = 60
```

All values can be overridden with environment variables:

| Variable | Effect |
|---|---|
| `ENVAULT_THRESHOLD` | Confidence threshold (e.g. `0.7`) |
| `ENVAULT_NLP` | Enable NLP layer (`true` / `false`) |
| `ENVAULT_EXCLUDE` | Comma-separated categories to skip |
| `ENVAULT_MCP_PORT` | MCP HTTP port |

---

## What envaultx is not

- **Not a security gateway** — envaultx redacts and reports; it does not block requests
- **Not persistent storage** — the vault is session-scoped and in-memory only
- **Not a secrets manager** — use Vault, AWS Secrets Manager, etc. for production secret storage
- **Not a git scanner** — use [TruffleHog](https://github.com/trufflesecurity/trufflehog) or [gitleaks](https://github.com/gitleaks/gitleaks) for history scanning
- **Not a network proxy** — envaultx operates on text in your process, not at the network layer

---

## License

MIT
