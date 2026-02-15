# WAF Rule Management AgentSkill

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Developer-led security skill for ModSecurity v3, Coraza, and OWASP CRS. Supports rule writing, validation, testing, tuning, and OpenAPI-to-WAF positive security approaches.

## Goal and Audience

This skill is designed to help:
- **Developers** write and test safer custom WAF rules during feature delivery.
- **System administrators** operate and tune ModSecurity/Coraza + CRS in production.
- **Security teams** monitor attacks/false positives and improve WAF security posture over time.

Primary goal: provide practical tooling and repeatable workflows to **manage, monitor, and continuously improve WAF security posture**.

## Why Many `references/` Files

The references are intentionally split into small files for **progressive loading**:
- Load only the guidance needed for the current task (rules, logs, regex, sandbox, etc.).
- Reduce context bloat and preserve cache efficiency in agent sessions.
- Keep high-signal docs focused and easier to maintain.

Operationally: `SKILL.md` is the router, `references/` are on-demand deep dives, and `scripts/` are executable helpers.

## Tool Requirements (Required vs Optional)

Install baseline dependencies:

```bash
bash scripts/install_tools.sh
```

| Tool | Requirement | Purpose | Install |
|------|-------------|---------|---------|
| Python 3.8+ | **Required** | Run skill scripts | System package manager |
| PyYAML | **Required** | `openapi_to_rules.py` | `python3 -m pip install pyyaml` |
| Go (toolchain) | **Required** | Install Go-based tools | [Go install guide](https://go.dev/doc/install) |
| go-ftw | **Required** | WAF regression testing | `go install github.com/coreruleset/go-ftw/v2@latest` |
| crs-toolchain | **Required** | Regex assembly, FP tooling | `go install github.com/coreruleset/crs-toolchain/v2@latest` |
| Docker or Finch | **Required** for local integration tests | Local CRS+Albedo test environment | [Docker](https://docker.com) / [Finch](https://runfinch.com) |
| crslang | **Optional (strongly recommended)** | Primary parser-based rule validation | `git clone https://github.com/coreruleset/crslang && cd crslang && go build` |
| modsec-rules-check / rules-check | **Optional (recommended for legacy parity)** | Official legacy ModSecurity parser validation | Package manager or build from [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) |

Validation behavior:

- `validate_rule.py` uses `crslang` first.
- Then it uses `modsec-rules-check`/`rules-check` if installed.
- Regex checks are fallback only if parser tools are unavailable.

## Quick Start

> **Container runtime**: All `docker` commands below work with `finch` as a drop-in replacement. Replace `docker` with `finch` if Docker is not installed. Scripts auto-detect the available runtime.

```bash
# Validate rule syntax
python scripts/validate_rule.py rule.conf

# Quick payload test (no setup) — CRS Sandbox
curl -i \
  -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd"

# Full local testing — CRS + Albedo + go-ftw (or: finch compose ...)
docker compose -f assets/docker/docker-compose.yaml up -d       # ModSecurity
docker compose -f assets/docker/docker-compose.coraza.yaml up -d # Coraza
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

# Generate positive-security rules from OpenAPI
python scripts/openapi_to_rules.py openapi.yaml -o rules.conf
```

## What's Included

### Scripts

| Script | Purpose |
|--------|---------|
| `validate_rule.py` | SecRule syntax validation (crslang → legacy → regex fallback) |
| `lint_crs_rule.py` | CRS convention checker (ID range, tags, severity) |
| `lint_regex.py` | Lint `@rx` patterns for ReDoS risk and performance |
| `openapi_to_rules.py` | OpenAPI 3.x → ModSec v3 positive-security rules |
| `analyze_log.py` | Audit log parser (JSON + Native format) |
| `generate_ftw_test.py` | go-ftw v2 test YAML generator |
| `generate_exclusion.py` | FP exclusion rule generator (runtime/configure-time) |
| `install_tools.sh` | Install all required + optional tools |
| `new_incident.sh` | Scaffold incident workspace directory |
| `assemble_rules.sh` | Assemble incident rules into WAF custom-rules.conf |

### References

27 focused reference documents covering: rule writing, testing, tuning, regex, deployment, incident response, OpenAPI, migration, and more. See `SKILL.md` for the routing index.

### Assets

- `assets/docker/docker-compose.yaml` — ModSecurity + CRS + Albedo test environment
- `assets/docker/.ftw.yaml` — go-ftw target configuration

## Direct Tooling Checklist

Prefer direct commands over wrappers for reproducibility and easier issue reporting.

- [ ] Use latest stable versions of `go-ftw`, `crs-toolchain`, and `crslang` unless policy requires pinning.
- [ ] Record exact versions and image tags in every ticket or incident note.
- [ ] Use explicit `docker compose`, `go-ftw`, and `curl` commands with full method/header/body details.
- [ ] Attach request/response artifacts and matched rule output when filing CRS issues.
- [ ] Cross-check behavior on both ModSecurity and Coraza when relevant.

## Official Resources

| Project | GitHub | Docs |
|---------|--------|------|
| OWASP CRS | <https://github.com/coreruleset/coreruleset> | <https://coreruleset.org/docs/> |
| ModSecurity v3 | <https://github.com/owasp-modsecurity/ModSecurity> | <https://modsecurity.org> |
| Coraza WAF | <https://github.com/corazawaf/coraza> | <https://coraza.io/docs/> |
| go-ftw | <https://github.com/coreruleset/go-ftw> | |
| crs-toolchain | <https://github.com/coreruleset/crs-toolchain> | <https://coreruleset.org/docs/development/crs_toolchain/> |
| crslang | <https://github.com/coreruleset/crslang> | |
| CRS Sandbox | | <https://coreruleset.org/docs/6-development/6-4-using-the-crs-sandbox/> |

## Recommended MCP Servers

Two MCP servers extend agent capabilities for WAF work. A merge-ready config is at `assets/mcp-servers.json`.

| Server | Purpose | npm Package |
|--------|---------|-------------|
| [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) | Browser automation — CRS Sandbox testing, WAF response inspection, screenshot evidence | `chrome-devtools-mcp` |
| [Context7](https://context7.com) | Live documentation for ModSecurity, CRS, Coraza, go-ftw, crs-toolchain | `@upstash/context7-mcp` |

### Quick Setup (Cursor)

Merge into `.cursor/mcp.json` in your project root:

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

### Quick Setup (Claude Code)

```bash
claude mcp add chrome-devtools npx chrome-devtools-mcp@latest
claude mcp add context7 npx -- -y @upstash/context7-mcp@latest
```

**Prerequisites**: Node.js v20.19+, npm, Chrome (stable) for DevTools MCP.

For detailed use cases, Context7 library IDs, and example agent workflows see [references/recommended-mcp-servers.md](references/recommended-mcp-servers.md).

## Installation as Skill

Copy `waf-rule-management/` to your agent's skills directory:

| Agent | Project-Level Path | User-Level Path |
|-------|-------------------|-----------------|
| Cline | `.cline/skills/waf-rule-management/` or `.agents/skills/waf-rule-management/` | `~/.cline/skills/waf-rule-management/` |
| Claude Code | `.claude/skills/waf-rule-management/` | `~/.claude/skills/waf-rule-management/` |
| Cursor | `.cursor/skills/waf-rule-management/` | `~/.cursor/skills/waf-rule-management/` |
| Gemini CLI | `.gemini/skills/waf-rule-management/` | `~/.gemini/skills/waf-rule-management/` |
| GitHub Copilot | `.github/skills/waf-rule-management/` | `~/.copilot/skills/waf-rule-management/` |
| Kiro | `.kiro/skills/waf-rule-management/` | `~/.kiro/skills/waf-rule-management/` |
| OpenAI Codex | `.agents/skills/waf-rule-management/` | `~/.agents/skills/waf-rule-management/` |
| Roo Code | `.roo/skills/waf-rule-management/` | `~/.roo/skills/waf-rule-management/` |
| Windsurf | `.windsurf/skills/waf-rule-management/` | `~/.codeium/windsurf/skills/waf-rule-management/` |

Or use the one-liner: `npx ai-agent-skills install etiennemunnich/crs-agent-skill --agent <agent>`

Ensure scripts are executable: `chmod +x scripts/*.sh`

## Third-Party Tools and Licenses

| Tool | Purpose | License |
|------|---------|---------|
| [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) | WAF engine | Apache-2.0 |
| [Coraza](https://github.com/corazawaf/coraza) | WAF engine (Go) | Apache-2.0 |
| [OWASP CRS](https://github.com/coreruleset/coreruleset) | Core Rule Set | Apache-2.0 |
| [go-ftw](https://github.com/coreruleset/go-ftw) | WAF testing framework | Apache-2.0 |
| [crs-toolchain](https://github.com/coreruleset/crs-toolchain) | Regex assembly, fp-finder | Apache-2.0 |
| [crslang](https://github.com/coreruleset/crslang) | Seclang/CRSLang parser | Apache-2.0 |
| [Albedo](https://github.com/coreruleset/albedo) | HTTP reflector for go-ftw | Apache-2.0 |
| [PyYAML](https://github.com/yaml/pyyaml) | OpenAPI YAML parsing | MIT |
| [Docker](https://www.docker.com/) | Container runtime | Docker licensing terms apply |
| [Finch](https://runfinch.com/) | Container runtime (alternative) | Apache-2.0 |
| [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) | Browser automation MCP server | Apache-2.0 |
| [Context7 MCP](https://context7.com) | Live documentation MCP server | Upstash terms apply |

## License

MIT License. Copyright (c) 2025 Etienne Munnich. See [LICENSE](../../LICENSE) for details.
