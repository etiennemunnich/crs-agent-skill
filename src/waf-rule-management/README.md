# WAF Rule Management AgentSkill

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Developer-led security skill for ModSecurity v3, Coraza, and OWASP CRS. Rule writing, validation, testing, tuning, OpenAPI-to-WAF. Emphasizes **effective** (detection) and **performant** (no ReDoS, efficient operators) rules.

**Audience**: Developers, system admins, security teams. **SKILL.md** routes tasks; **references/** are on-demand deep dives, **scripts/** are helpers.

## Install

```bash
bash scripts/install_tools.sh
```

| Tool | Required | Install |
|------|----------|---------|
| Python 3.8+, PyYAML, Go | **Yes** | `pip install pyyaml` |
| go-ftw, crs-toolchain, crslang | **Yes** | `bash scripts/install_tools.sh` or `go install` + `git clone` crslang |
| Docker or Finch | **Yes** (local tests) | [Docker](https://docker.com) / [Finch](https://runfinch.com) |
| cdncheck, httpx, nuclei, vulnx | Optional (DAST) | `go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` etc. |

## Quick Start

> **Container**: `docker` and `finch` are interchangeable. Scripts auto-detect.

```bash
python scripts/validate_rule.py rule.conf
curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?file=/etc/passwd"
docker compose -f assets/docker/docker-compose.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
python scripts/openapi_to_rules.py openapi.yaml -o rules.conf
```

## Contents

| Scripts | Purpose |
|---------|---------|
| `validate_rule.py`, `lint_regex.py`, `lint_crs_rule.py` | Rule validation, ReDoS lint, CRS conventions |
| `analyze_log.py`, `detect_app_profile.py` | Log analysis, app fingerprinting |
| `generate_exclusion.py`, `validate_exclusion.py` | FP exclusion generation and safety checks |
| `openapi_to_rules.py`, `generate_ftw_test.py` | OpenAPI→rules, go-ftw test generation |
| `install_tools.sh`, `new_incident.sh`, `assemble_rules.sh` | Setup, incident scaffolding |

**References**: 27 docs in `references/` — routing index in `SKILL.md`. **Assets**: `assets/docker/` — ModSec/Coraza compose + go-ftw config.

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

## MCP Servers

[recommended-mcp-servers.md](references/recommended-mcp-servers.md) — Context7 (live docs), Chrome DevTools (Sandbox testing). Config template: `assets/mcp-servers.json`.

```json
{
  "mcpServers": {
    "chrome-devtools": { "command": "npx", "args": ["-y", "chrome-devtools-mcp@latest"] },
    "context7": { "command": "npx", "args": ["-y", "@upstash/context7-mcp@latest"] }
  }
}
```

## Install as Skill

| Agent | Path |
|-------|------|
| Cursor, Claude Code, Cline | `.cursor/skills/waf-rule-management/`, `.claude/skills/`, `.cline/skills/` |
| Aider, Plandex, AutoPR | `.agents/skills/` or `--read` / project context |

`npx ai-agent-skills install etiennemunnich/crs-agent-skill --agent <agent>` — supports cursor, claude-code, cline, goose, opencode, aider, etc.

**Multi-agent** (LangGraph, CrewAI, AutoGen, LlamaIndex, N8n, Strands, Semantic Kernel): inject via system prompts or tool context.

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
| [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) | Optional high-confidence app fingerprinting helper | MIT |
| [cdncheck](https://github.com/projectdiscovery/cdncheck) | Optional CDN/cloud/WAF ingress detection for DAST/discovery | MIT |
| [httpx](https://github.com/projectdiscovery/httpx) | Optional HTTP probing and technology discovery for DAST/discovery | MIT |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Optional active vulnerability scanner for DAST/discovery | MIT |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Optional nuclei template source for broad vulnerability coverage | MIT |
| [cvemap](https://github.com/projectdiscovery/cvemap) | Optional CVE intelligence CLI (`vulnx`) for vulnerability prioritization | MIT |
| [Docker](https://www.docker.com/) | Container runtime | Docker licensing terms apply |
| [Finch](https://runfinch.com/) | Container runtime (alternative) | Apache-2.0 |
| [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) | Browser automation MCP server | Apache-2.0 |
| [Context7 MCP](https://context7.com) | Live documentation MCP server | Upstash terms apply |
| [NVD CVE MCP Server](https://mcpservers.org/servers/socteam-ai/nvd-cve-mcp-server) | Optional MCP CVE lookup/search for analyst triage | MIT |

## License

MIT License. Copyright (c) 2025 Etienne Munnich. See [LICENSE](../../LICENSE) for details.
