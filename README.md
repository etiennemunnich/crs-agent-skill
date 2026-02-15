# CRS Agent Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/etiennemunnich/crs-agent-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/etiennemunnich/crs-agent-skill/actions/workflows/ci.yml)
[![Links](https://github.com/etiennemunnich/crs-agent-skill/actions/workflows/links.yml/badge.svg)](https://github.com/etiennemunnich/crs-agent-skill/actions/workflows/links.yml)
[![AgentSkill](https://img.shields.io/badge/Agent_Skill-v0.4-8A2BE2)](https://agentskills.io)

Agent skill for writing, validating, testing, and tuning **ModSecurity v3**, **Coraza**, and **OWASP Core Rule Set (CRS)** WAF rules using AI coding assistants.

> **What is an Agent Skill?** A portable instruction package that gives AI coding agents domain-specific knowledge, scripts, and workflows. Drop it into your IDE and the agent learns how to manage WAF rules, handle false positives, respond to incidents, and more.

> [!CAUTION]
> **Don't ship agent-generated rules straight to production.** A bad WAF rule can block legitimate traffic or miss real attacks. Always test in a lower environment first (dev, staging, or `DetectionOnly` / sampling mode), review the output yourself, and promote through your normal release process. This skill gives you validation scripts, linters, and regression tests to make that easy -- use them.

---

## Install

### One-Line Install (any supported agent)

```bash
npx ai-agent-skills install etiennemunnich/crs-agent-skill --agent <agent>
```

Replace `<agent>` with: `cursor`, `claude-code`, `cline`, `codex`, `copilot`, `gemini`, `kiro`, `roo-code`, `windsurf`, `vscode`, or `goose`.

### Per-Platform Manual Install

Clone into the global skill path for your agent, then install dependencies:

```bash
git clone https://github.com/etiennemunnich/crs-agent-skill.git \
  <SKILL_PATH> --depth 1
bash <SKILL_PATH>/src/waf-rule-management/scripts/install_tools.sh
```

| Platform | `<SKILL_PATH>` |
|----------|-----------------|
| [![Cursor](https://img.shields.io/badge/Cursor-black?logo=cursor&logoColor=white)](https://cursor.com/docs/context/skills) | `~/.cursor/skills/waf-rule-management` |
| [![Claude Code](https://img.shields.io/badge/Claude_Code-F97316?logo=anthropic&logoColor=white)](https://docs.anthropic.com/en/docs/claude-code/skills) | `~/.claude/skills/waf-rule-management` |
| [![OpenAI Codex](https://img.shields.io/badge/Codex-412991?logo=openai&logoColor=white)](https://developers.openai.com/codex/skills) | `~/.agents/skills/waf-rule-management` |
| [![GitHub Copilot](https://img.shields.io/badge/Copilot-000000?logo=github&logoColor=white)](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills) | `~/.copilot/skills/waf-rule-management` |
| [![Gemini CLI](https://img.shields.io/badge/Gemini-4285F4?logo=google&logoColor=white)](https://geminicli.com/docs/cli/skills/) | `~/.gemini/skills/waf-rule-management` |
| [![Kiro](https://img.shields.io/badge/Kiro-FF9900?logo=amazonaws&logoColor=white)](https://kiro.dev/docs/skills) | `~/.kiro/skills/waf-rule-management` |
| [![Cline](https://img.shields.io/badge/Cline-EC6E2C?logo=cline&logoColor=white)](https://docs.cline.bot/features/skills) | `~/.cline/skills/waf-rule-management` |
| [![Roo Code](https://img.shields.io/badge/Roo_Code-16A34A?logoColor=white)](https://docs.roocode.com/features/skills) | `~/.roo/skills/waf-rule-management` |
| [![Windsurf](https://img.shields.io/badge/Windsurf-06B6D4?logo=codeium&logoColor=white)](https://docs.windsurf.com/windsurf/cascade/skills) | `~/.codeium/windsurf/skills/waf-rule-management` |

> **Gemini CLI** also supports `gemini skills install https://github.com/etiennemunnich/crs-agent-skill.git`
>
> **Kiro** also supports importing via **Agent Steering & Skills > + > Import a skill** in the IDE.

### Included Scripts

All scripts live under `src/waf-rule-management/scripts/`.

| Script | Purpose |
|--------|---------|
| `install_tools.sh` | Install all required Go and Python tools (go-ftw, crs-toolchain, crslang, PyYAML) |
| `validate_rule.py` | SecRule syntax validation via crslang and legacy parser |
| `lint_regex.py` | ReDoS and regex performance linting |
| `lint_crs_rule.py` | CRS convention checker (ID ranges, phases, actions, metadata) |
| `analyze_log.py` | Audit log parser -- summaries, top triggered rules, per-rule detail |
| `openapi_to_rules.py` | Convert OpenAPI 3.x specs into positive-security WAF rules |
| `generate_ftw_test.py` | Generate go-ftw regression test YAML |
| `generate_exclusion.py` | Generate false-positive exclusion rules |
| `new_incident.sh` | Scaffold an incident response workspace |
| `assemble_rules.sh` | Assemble active incident rules into `custom-rules.conf` |

---

## What This Skill Does

When installed, your AI coding agent gains the ability to:

| Capability | Description |
|-----------|-------------|
| **Write WAF rules** | Author ModSec v3 / Coraza `SecRule` directives with proper ID ranges, phases, actions, and metadata |
| **Validate & lint** | Syntax validation (crslang + legacy parsers), CRS convention checking, ReDoS/regex performance lint |
| **Test rules** | Local Docker/Finch test environments (ModSecurity + Coraza), go-ftw regression tests, CRS Sandbox |
| **Handle false positives** | Analyze audit logs, classify FP vs TP, generate narrowest-scope exclusions |
| **OpenAPI to WAF** | Convert OpenAPI 3.x specs into positive-security allowlist rules evaluated before CRS |
| **Incident response** | Scaffold incident workspaces, write virtual patches for zero-day CVEs, per-incident regression tests |
| **Regex assembly** | Work with `.ra` regex assembly files, crs-toolchain, and fp-finder for CRS development |
| **CRSLang** | Support for the next-generation CRS rule format and parser validation |
| **CI/CD integration** | Pre-commit checks, GitHub Actions examples, deploy-with-sampling workflows |

### Progressive Loading

The skill uses **progressive context loading** -- only the routing index loads at startup. Full reference docs (27 files) load on-demand when your task needs them, keeping agent context lean and fast.

---

## Skills

| Skill | Path | Description |
|-------|------|-------------|
| [WAF Rule Management](src/waf-rule-management/) | `src/waf-rule-management/` | Write, validate, test, and tune ModSec v3 / Coraza rules with CRS. OpenAPI-to-WAF, log analysis, go-ftw, CRS Sandbox, incident response. |

---

## Project Structure

```text
src/waf-rule-management/
├── SKILL.md                    # Skill definition and routing index
├── README.md                   # Detailed skill documentation
├── scripts/                    # Executable helpers
│   ├── install_tools.sh        # Install all required tools
│   ├── validate_rule.py        # SecRule syntax validation
│   ├── lint_regex.py           # ReDoS and regex performance lint
│   ├── lint_crs_rule.py        # CRS convention checker
│   ├── analyze_log.py          # Audit log parser
│   ├── openapi_to_rules.py     # OpenAPI → WAF rules converter
│   ├── generate_ftw_test.py    # go-ftw test generator
│   ├── generate_exclusion.py   # FP exclusion generator
│   ├── new_incident.sh         # Incident workspace scaffolder
│   └── assemble_rules.sh       # Multi-incident rule assembly
├── references/                 # 27 on-demand reference docs
│   ├── actions-reference.md
│   ├── anomaly-scoring.md
│   ├── crs-rule-format.md
│   ├── go-ftw-reference.md
│   ├── ... and 23 more
│   └── variables-and-collections.md
└── assets/
    ├── mcp-servers.json        # MCP server config template
    └── docker/
        ├── docker-compose.yaml          # ModSecurity + CRS + Albedo
        ├── docker-compose.coraza.yaml   # Coraza + CRS + Albedo
        ├── .ftw.yaml                    # go-ftw configuration
        └── .env.example                 # Tunable environment variables
```

---

## Requirements

| Tool | Required | Purpose |
|------|----------|---------|
| Python 3.8+ | Yes | Run skill scripts |
| Go toolchain | Yes | Install go-ftw, crs-toolchain |
| Docker or Finch | Yes (for testing) | Local CRS test environments |
| [go-ftw](https://github.com/coreruleset/go-ftw) | Yes | WAF regression testing |
| [crs-toolchain](https://github.com/coreruleset/crs-toolchain) | Yes | Regex assembly, FP finder |
| [crslang](https://github.com/coreruleset/crslang) | Recommended | Parser-based rule validation |
| PyYAML | Yes | OpenAPI YAML parsing |

Quick setup:

```bash
bash src/waf-rule-management/scripts/install_tools.sh
```

---

## Quick Start

```bash
# Validate a rule file
python src/waf-rule-management/scripts/validate_rule.py rule.conf

# Lint regex for ReDoS
python src/waf-rule-management/scripts/lint_regex.py rule.conf -v

# Quick sandbox test (no setup needed)
curl -i -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd"

# Full local test — ModSecurity + CRS + Albedo
docker compose -f src/waf-rule-management/assets/docker/docker-compose.yaml up -d
go-ftw run --cloud --config src/waf-rule-management/assets/docker/.ftw.yaml -d tests/
docker compose -f src/waf-rule-management/assets/docker/docker-compose.yaml down

# Generate positive-security rules from OpenAPI
python src/waf-rule-management/scripts/openapi_to_rules.py openapi.yaml -o rules.conf
```

---

## MCP Server Integration

Two optional MCP servers enhance agent capabilities:

| Server | Purpose | Install |
|--------|---------|---------|
| [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) | Browser-based WAF testing, CRS Sandbox automation, screenshot evidence | `npx chrome-devtools-mcp@latest` |
| [Context7](https://context7.com) | Live upstream docs for ModSecurity, CRS, Coraza, go-ftw | `npx @upstash/context7-mcp@latest` |

A merge-ready config template is at [`src/waf-rule-management/assets/mcp-servers.json`](src/waf-rule-management/assets/mcp-servers.json).

---

## Who Is This For

- **Developers** writing custom WAF rules during feature delivery
- **System administrators** operating ModSecurity/Coraza + CRS in production
- **Security teams** monitoring attacks/false positives and improving WAF posture
- **DevSecOps engineers** integrating WAF validation into CI/CD pipelines

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- [Report a bug](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=bug-report.yml)
- [Request a feature](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=feature-request.yml)
- [Suggest a reference doc](https://github.com/etiennemunnich/crs-agent-skill/issues/new?template=reference-request.yml)

---

## Related Projects

| Project | Role |
|---------|------|
| [OWASP CRS](https://github.com/coreruleset/coreruleset) | The upstream rule set this skill helps manage |
| [ModSecurity v3](https://github.com/owasp-modsecurity/ModSecurity) | Primary WAF engine |
| [Coraza WAF](https://github.com/corazawaf/coraza) | Go-native WAF engine |
| [go-ftw](https://github.com/coreruleset/go-ftw) | WAF testing framework |
| [crs-toolchain](https://github.com/coreruleset/crs-toolchain) | Regex assembly and FP finder |
| [crslang](https://github.com/coreruleset/crslang) | CRS rule parser |

---

## License

MIT License. Copyright (c) 2025 Etienne Munnich. See [LICENSE](LICENSE).
