# Recommended MCP Servers

MCP (Model Context Protocol) servers extend an LLM agent's capabilities with live tools.
The following servers are recommended when using this skill for WAF rule management.

A ready-to-merge configuration template is at `assets/mcp-servers.json`.

---

## Chrome DevTools MCP

**Repository**: <https://github.com/ChromeDevTools/chrome-devtools-mcp>
**npm**: `chrome-devtools-mcp`

### What It Does

Gives the agent control of a live Chrome browser via Chrome DevTools Protocol.
The agent can navigate pages, take screenshots, inspect network requests,
read console messages, and run JavaScript — all without the user switching windows.

### Why It Matters for WAF Work

| Use Case | How |
|----------|-----|
| **CRS Sandbox testing** | Navigate to `https://sandbox.coreruleset.org/` with attack payloads and inspect response headers/body for matched rules |
| **WAF response verification** | Submit requests through the browser and verify block pages, status codes, and response headers |
| **Network request inspection** | Use `list_network_requests` / `get_network_request` to see full request/response pairs including WAF-injected headers |
| **Screenshot evidence** | Capture visual proof of block pages or application behavior for incident reports |
| **Console error detection** | Detect client-side errors caused by overly aggressive WAF rules (e.g., blocked inline scripts) |
| **Performance tracing** | Measure latency impact of WAF rules on page load via DevTools performance traces |

### Configuration

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    }
  }
}
```

Options:
- `--headless=true` — run without visible browser window (CI/automated pipelines)
- `--isolated=true` — use temporary profile, cleaned up on exit
- `--browser-url=http://127.0.0.1:9222` — connect to an already-running Chrome instance

### Example Agent Workflow

1. `navigate_page` to `https://sandbox.coreruleset.org/?file=/etc/passwd`
2. `take_snapshot` to read the response content
3. `list_network_requests` to inspect response status and WAF headers
4. `take_screenshot` for evidence attachment in `REPORT.md`

---

## Context7

**npm**: `@upstash/context7-mcp`
**Website**: <https://context7.com>

### What It Does

Retrieves **up-to-date documentation and code examples** from library repositories
indexed by Context7. The agent calls `resolve-library-id` to find the library,
then `query-docs` to get current docs for a specific question.

### Why It Matters for WAF Work

Training data goes stale. ModSecurity directives change, CRS adds new rules and
configuration options, Coraza evolves its API, and go-ftw updates its test format.
Context7 gives the agent **live documentation** so it can answer with current facts
rather than outdated training knowledge.

### Available Libraries

| Library ID | Covers |
|------------|--------|
| `/owasp-modsecurity/ModSecurity` | ModSecurity v3 engine — directives, SecRule syntax, variables, operators, transforms, phases |
| `/coreruleset/coreruleset` | OWASP CRS v4.x — rule files, configuration, paranoia levels, anomaly scoring, exclusion packages |
| `/corazawaf/coraza` | Coraza WAF engine — Go API, directives compatibility, configuration |
| `/coreruleset/go-ftw` | go-ftw v2 — test file format, CLI flags, cloud mode, `.ftw.yaml` config |
| `/coreruleset/crs-toolchain` | crs-toolchain v2 — regex assembly, `fp-finder`, `regex generate`, `regex compare` |

### Configuration

```json
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp@latest"]
    }
  }
}
```

### Example Agent Queries

| Task | Library ID | Query |
|------|-----------|-------|
| Check if `@ipMatch` supports CIDR in ModSec v3 | `/owasp-modsecurity/ModSecurity` | `Does @ipMatch support CIDR notation?` |
| Find CRS paranoia level 2 SQLi rules | `/coreruleset/coreruleset` | `Which SQL injection rules activate at paranoia level 2?` |
| Coraza directive compatibility | `/corazawaf/coraza` | `Which ModSecurity directives are not supported in Coraza?` |
| go-ftw test file format | `/coreruleset/go-ftw` | `What is the YAML test file format for go-ftw v2?` |
| Regex assembly processors | `/coreruleset/crs-toolchain` | `What processors are available in .ra regex assembly files?` |

### When to Use Context7 vs Skill References

- **Skill references** (`references/*.md`) — curated, opinionated guidance tuned for agent workflows.
  Load these first for task-specific steering.
- **Context7** — live upstream docs. Use when:
  - A directive/operator/variable is not covered in skill references
  - You need to verify whether a feature exists in a specific version
  - The user asks about bleeding-edge or recently-released functionality
  - You need exact API signatures or CLI flag names

---

## Installation

### Cursor

Merge `assets/mcp-servers.json` into your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    },
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp@latest"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add chrome-devtools npx chrome-devtools-mcp@latest
claude mcp add context7 npx -- -y @upstash/context7-mcp@latest
```

### Other MCP Clients

Copy the `mcpServers` entries from `assets/mcp-servers.json` into your client's
MCP configuration file. Consult your client's documentation for the config path.

---

## Prerequisites

- **Node.js v20.19+** and **npm** — required by both MCP servers (they run via `npx`)
- **Chrome** (stable channel) — required by Chrome DevTools MCP
- **Network access** — Context7 fetches docs from its API at runtime

---

## Verified Against

- Chrome DevTools MCP v0.17.0 (Feb 2026) — <https://github.com/ChromeDevTools/chrome-devtools-mcp>
- Context7 MCP (Feb 2026) — <https://context7.com>
- Context7 library IDs verified Feb 2026 via context7.com
