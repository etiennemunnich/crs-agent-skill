---
name: waf-rule-management
description: >
  Write, validate, tune, test, and improve ModSecurity 3.0 / Coraza WAF rules
  and OWASP Core Rule Set (CRS) configurations using a developer-led security
  approach and OODA loop methodology. Converts OpenAPI specifications into
  positive-security WAF rules for inclusion before CRS evaluation. Supports
  false positive analysis, rule exclusions, audit log analysis, go-ftw testing,
  CRS Sandbox testing, regex assembly with crs-toolchain, CRSLang (next-gen rule format), and CI/CD integration.
  Use when the user mentions ModSecurity, Coraza, CRS, SecRule, WAF rules,
  web application firewall, false positives, paranoia level, anomaly scoring,
  audit logs, go-ftw, rule tuning, OpenAPI to WAF, CRSLang, positive security model,
  JA4, JA3, TLS fingerprint, CDN (CloudFront, Akamai, Cloudflare, Fastly), or load balancer.
  Primary target is ModSecurity v3; supports migration from v2.
license: MIT
compatibility: >
  Requires Python 3.8+, Docker or Finch for test env. Run scripts/install_tools.sh
  to install go-ftw, crs-toolchain, PyYAML. Scripts must support --help.
metadata:
  author: owasp-crs-tooling
  version: "0.4"
---

# WAF Rule Management

A developer-led security skill for writing, testing, and maintaining ModSecurity v3
and Coraza WAF rules with OWASP Core Rule Set (CRS v4.x).

## Constraints (Always Follow)

- **NEVER deploy agent-generated rules straight to production.** Every rule change — new rules, exclusions, tuning, virtual patches — must be tested in a lower environment (dev, staging, or DetectionOnly/sampling) and reviewed by the user before going live. A bad rule can block real traffic or miss real attacks. When generating or modifying rules, remind the user to validate before promoting.
- **DO** use custom rule IDs 100000–199999 (never CRS range 900000–999999)
- **DO** validate every rule with `validate_rule.py` and lint regex with `lint_regex.py` before deploying
- **DO** generate and run go-ftw regression tests for every new or modified rule
- **DO NOT** modify CRS rule files directly — use exclusions in separate config files
- **DO NOT** write regex with nested quantifiers (`(a+)+`, `(a|b?)*`) — ReDoS risk
- **DO NOT** lower anomaly thresholds or jump paranoia levels without exclusion tuning first
- **DO NOT** enable blocking mode before tuning in DetectionOnly/sampling
- **Antipattern steering**: When the user proposes code/config matching an antipattern, recognize it, explain why it's wrong, redirect to the correct approach, and offer a fix. See [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) for the full catalog.
- **Always verify** against latest official documentation and GitHub repos for CRS, ModSecurity, and Coraza.

## Quick Start

**First time**: `bash scripts/install_tools.sh` (see [README](README.md)).

**Required**: Python 3.8+, PyYAML, Go toolchain, go-ftw, crs-toolchain, Docker or Finch.
**Optional (recommended)**: crslang, modsec-rules-check (parser validation).

> **Container runtime**: All `docker compose` / `docker logs` commands work identically with `finch compose` / `finch logs`. Replace `docker` with `finch` throughout if Docker is not installed. Scripts auto-detect the available runtime.

### SecRule One-Liner

```
SecRule VARIABLE "@OPERATOR pattern" "id:N,phase:N,ACTION,status:NNN,log,msg:'...',tag:'...',severity:'...'"
```

Phases: 1=Request Headers, 2=Request Body, 3=Response Headers, 4=Response Body, 5=Logging.
Custom rule IDs: **100000–199999** (avoids CRS conflicts).

### Essential Commands

```bash
python scripts/validate_rule.py rule.conf            # Validate syntax
python scripts/lint_regex.py rule.conf -v             # ReDoS/performance lint
python scripts/lint_crs_rule.py rule.conf             # CRS convention lint
python scripts/analyze_log.py audit.log --summary     # Log analysis
python scripts/openapi_to_rules.py spec.yaml -o r.conf  # OpenAPI → rules
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/  # Regression tests

# Test environment — choose your engine:
docker compose -f assets/docker/docker-compose.yaml up -d          # ModSecurity
docker compose -f assets/docker/docker-compose.coraza.yaml up -d   # Coraza

curl -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd" # Sandbox check
```

---

## Determine Your Task

Choose workflow by intent:
- New/custom detection: [Writing New Rules](#writing-new-rules)
- API allowlist model: [OpenAPI to WAF Rules](#openapi-to-waf-rules)
- False positives and exclusions: [Tuning and False Positives](#tuning-and-false-positives)
- Logs and incident triage: [Analyzing WAF Logs](#analyzing-waf-logs)
- Regression testing: [Testing Rules](#testing-rules)
- CRS development tooling: [Regex Assembly and Steering](#regex-assembly-and-steering)
- **Testing by engine** (ask the user which stack they run):
  - ModSecurity + CRS: [modsec-crs-testing-reference.md](references/modsec-crs-testing-reference.md)
  - Coraza + CRS: [coraza-testing-reference.md](references/coraza-testing-reference.md)
  - Both / cross-engine comparison: load both references + [go-ftw-reference.md](references/go-ftw-reference.md)
- First-response zero-day risk triage: [first-responder-risk-runbook.md](references/first-responder-risk-runbook.md) (covers both engines — ask which stack the user deploys)
  - Scaffold workspace: `bash scripts/new_incident.sh <INCIDENT_ID>` — creates `incidents/<INCIDENT_ID>/` with `rules.conf`, `REPORT.md`, and `tests/`. Populate files following conventions in the runbook.
  - Assemble and activate rules across incidents: `bash scripts/assemble_rules.sh`
  - Per-incident regression: `go-ftw run --cloud --config assets/docker/.ftw.yaml -d incidents/<INCIDENT_ID>/tests/`
- Rule conversion (v2→v3): [modsecurity-migration-checklist.md](references/modsecurity-migration-checklist.md)
- CRSLang (next-gen format): [crslang-reference.md](references/crslang-reference.md)
- Deployment & rollout: [best-practices-modsec-coraza-crs.md](references/best-practices-modsec-coraza-crs.md), [sampling-mode.md](references/sampling-mode.md), [paranoia-levels.md](references/paranoia-levels.md)

---

## Progressive Loading Index

Load only files matching the current task. Tags are short routing labels for agents.

| File | Tags | Load When |
|------|------|-----------|
| `references/actions-reference.md` | actions,seclang,rule-writing | Choosing disruptive/logging/flow actions or fixing action misuse |
| `references/anomaly-scoring.md` | scoring,thresholds,paranoia,tuning | Explaining score behavior, threshold tuning, and block policy |
| `references/antipatterns-and-troubleshooting.md` | anti-patterns,troubleshooting,steering | Diagnosing broken configs, bad exclusions, or poor tuning decisions |
| `references/best-practices-modsec-coraza-crs.md` | best-practices,operations,deployment | Need operational guidance, rollout checklist, or secure defaults |
| `references/coraza-testing-reference.md` | coraza,testing,cross-engine | Running Coraza tests or comparing ModSecurity vs Coraza behavior |
| `references/modsec-crs-testing-reference.md` | modsec,testing,docker,crs | ModSecurity + CRS local test environment, go-ftw workflow, troubleshooting |
| `references/crs-application-profiles.md` | app-profiles,exclusions,tuning | Tuning for known app stacks (WordPress/Drupal/etc.) |
| `references/crs-rule-format.md` | crs-contrib,rule-style,metadata | Writing rules for CRS contribution or CRS-style formatting |
| `references/crs-sandbox-reference.md` | sandbox,reproducibility,http | Building reproducible CRS Sandbox requests (method/headers/body/evidence) |
| `references/crs-toolchain-reference.md` | crs-toolchain,fp-finder,regex | Using `crs-toolchain` commands for regex and FP workflows |
| `references/crslang-reference.md` | crslang,conversion,validation | Converting Seclang/CRSLang or parser-based validation workflows |
| `references/developer-security-workflow.md` | dev-workflow,ci,ooda | Mapping security work into developer/CI lifecycle |
| `references/false-positives-and-tuning.md` | false-positives,exclusions,tuning | Handling FP reports and choosing safe exclusion strategy |
| `references/first-responder-risk-runbook.md` | incident,zero-day,triage,virtual-patch | New risk/CVE triage with virtual-patch authoring and per-incident regression testing |
| `references/go-ftw-reference.md` | go-ftw,regression,tests | Authoring/running regression tests and CI guardrails |
| `references/ja4-ja3-cdn-lb-steering.md` | ja3,ja4,cdn,lb,fingerprints | TLS/client-fingerprint logic behind CDN/load balancer paths |
| `references/log-analysis-steering.md` | logs,audit,error,top-talkers | Audit/error log analysis, top talkers, and CLI triage patterns |
| `references/modsec-directives.md` | directives,engine-config,seclang | Selecting/fixing ModSecurity directives and engine settings |
| `references/modsecurity-migration-checklist.md` | migration,v2-v3,validation-gates | Structured migration with unsupported items and sign-off gates |
| `references/ooda-loop-guide.md` | ooda,method,operations | Need OODA method framing for investigation/tuning loop |
| `references/openapi-to-waf.md` | openapi,positive-security,api | Generating/operating OpenAPI-derived allowlist rules |
| `references/operators-and-transforms.md` | operators,transforms,matching | Choosing `@rx/@pm/...` and transform order correctly |
| `references/paranoia-levels.md` | paranoia,pl,tuning | Planning PL rollout and interpreting PL-specific behavior |
| `references/regex-assembly.md` | regex,assembly,ra,crs-dev | Working with `.ra` regex assembly files in CRS development |
| `references/regex-steering-guide.md` | regex,redos,performance,lint | Hardening regex quality and preventing performance issues |
| `references/sampling-mode.md` | sampling,rollout,deployment | Progressive/percentage rollout patterns and rollback strategy |
| `references/variables-and-collections.md` | variables,collections,seclang | Picking the right variable targets (`ARGS`, headers, cookies, TX, etc.) |
| `references/recommended-mcp-servers.md` | mcp,context7,chrome-devtools,browser | Setting up or using MCP servers for live docs, browser testing, or sandbox automation |

Loading defaults:
- Start with **one** primary file from this index.
- Add at most one adjacent file for edge cases.
- Only load broad guides (`best-practices`, `antipatterns`) if needed for decision context.

---

## Writing New Rules

**Workflow**: Identify threat → choose variables → select operator → define actions → validate → lint regex → generate tests → run go-ftw → iterate.

| Step | Action | Reference |
|------|--------|-----------|
| Variables | `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, etc. | [variables-and-collections.md](references/variables-and-collections.md) |
| Operators | `@rx`, `@pm`, `@streq`, `@beginsWith`, etc. | [operators-and-transforms.md](references/operators-and-transforms.md) |
| Actions | `deny`, `pass`, `chain`, `setvar`, etc. | [actions-reference.md](references/actions-reference.md) |
| Rule template | CRS-style `id`, `phase`, `msg`, `tag`, `severity`, `ver` | [actions-reference.md](references/actions-reference.md), [crs-rule-format.md](references/crs-rule-format.md) |
| Chained rules | Multi-condition matching; only first rule carries `id`/disruptive action | [actions-reference.md](references/actions-reference.md) |
| Regex quality | ReDoS prevention, operator choice, transform order | [regex-steering-guide.md](references/regex-steering-guide.md) |
| OODA framing | Observe → Orient → Decide → Act loop | [ooda-loop-guide.md](references/ooda-loop-guide.md) |

```bash
python scripts/validate_rule.py rule.conf
python scripts/lint_regex.py rule.conf -v
python scripts/generate_ftw_test.py rule.conf -o tests/rule-test.yaml
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
```

---

## OpenAPI to WAF Rules

Generate **allowlist rules from OpenAPI specs** that validate requests BEFORE CRS. Your API contract defines what is allowed; CRS catches everything else.

```bash
python scripts/openapi_to_rules.py openapi.yaml -o before-crs-rules.conf
python scripts/validate_rule.py before-crs-rules.conf
```

Five rule categories: allowed paths+methods, required params, type/enum validation, content-type enforcement, auth header presence. Use `--skip-params`, `--skip-body`, `--skip-auth` to omit categories; `--mode detect` for log-only rollout.

For detailed steering (inclusion order, chaining patterns, tagging, anti-patterns, LLM guidance): [openapi-to-waf.md](references/openapi-to-waf.md).

Reference implementations: [openapi-sec](https://github.com/EP-Tribe/openapi-sec), [swagger2modsec](https://github.com/angeloxx/swagger2modsec).

---

## Tuning and False Positives

**Workflow**: Analyze logs → classify FP vs TP → choose narrowest exclusion → validate → regression test.

```bash
python scripts/analyze_log.py audit.log --rule-id 942100
python scripts/generate_exclusion.py --rule-id 942100 --uri /api/search --param ARGS:q
python scripts/validate_rule.py exclusion.conf
```

**Key principle**: Runtime exclusions (`ctl:*`) go BEFORE CRS include; configure-time exclusions (`SecRuleRemove*`, `SecRuleUpdateTarget*`) go AFTER CRS include.

For exclusion strategies, decision tree, patterns, and what to avoid: [false-positives-and-tuning.md](references/false-positives-and-tuning.md).
For app-specific exclusion packages (WordPress, Drupal, APIs): [crs-application-profiles.md](references/crs-application-profiles.md).
For antipatterns: [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md).

---

## Analyzing WAF Logs

```bash
python scripts/analyze_log.py audit.log --summary
python scripts/analyze_log.py audit.log --top-rules 20
python scripts/analyze_log.py audit.log --rule-id 942100 --detail
```

Classify triggers as TP or FP. For FPs → [Tuning workflow](#tuning-and-false-positives). For TPs → verify coverage.

For top-talker CLI patterns, error log analysis, and audit log format details: [log-analysis-steering.md](references/log-analysis-steering.md).

---

## Testing Rules

Use both **local (CRS + Albedo + go-ftw)** and **CRS Sandbox** in your process:

1. **Quick payload check** → Sandbox (no setup): [crs-sandbox-reference.md](references/crs-sandbox-reference.md)
2. **Full regression** → Local: start compose + run go-ftw: [go-ftw-reference.md](references/go-ftw-reference.md)
3. **Compare** → Same payload in both to verify consistency

**Choose your engine** (ask the user if unclear). Both share port 8080 — run one at a time.
Review tuning parameters before first use — see `assets/docker/.env.example`.

```bash
# Start test environment — pick your engine:
docker compose -f assets/docker/docker-compose.yaml up -d          # ModSecurity
docker compose -f assets/docker/docker-compose.coraza.yaml up -d   # Coraza

# Run regression tests (same command regardless of engine)
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

# Cross-engine swap (stop one, start the other):
docker compose -f assets/docker/docker-compose.yaml down
docker compose -f assets/docker/docker-compose.coraza.yaml up -d

# Sandbox quick check
curl -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?payload=attack_string"
```

For full ModSecurity testing workflow, Docker env, troubleshooting: [modsec-crs-testing-reference.md](references/modsec-crs-testing-reference.md).
For Coraza testing, env vars, paths, and cross-engine comparison: [coraza-testing-reference.md](references/coraza-testing-reference.md).
For go-ftw config, test file format, cloud mode, and templates: [go-ftw-reference.md](references/go-ftw-reference.md).
For Sandbox API headers, output formats, reproducible reporting: [crs-sandbox-reference.md](references/crs-sandbox-reference.md).
For CI/CD integration and dev workflow: [developer-security-workflow.md](references/developer-security-workflow.md).

---

## Regex Assembly and Steering

Ensure rules are **effective**, **performant** (no ReDoS), and **maintainable**.

```bash
python scripts/lint_regex.py rule.conf -v                 # ReDoS + performance lint
crs-toolchain regex generate 942170                       # Build from .ra file
crs-toolchain regex compare 942170                        # Compare generated vs current
crs-toolchain util fp-finder 942170                       # Check for false positives
```

For regex guidance (ReDoS patterns, operator selection, transforms): [regex-steering-guide.md](references/regex-steering-guide.md).
For `.ra` file format and processors: [regex-assembly.md](references/regex-assembly.md).
For crs-toolchain CLI: [crs-toolchain-reference.md](references/crs-toolchain-reference.md).

---

## CRS Contribution

Follow [crs-rule-format.md](references/crs-rule-format.md), lint with `python scripts/lint_crs_rule.py`, include regression tests (positive+negative), and run `crs-toolchain util fp-finder RULE_ID` from a CRS repo checkout before submission.

---

## OODA Loop

All workflows map to Observe → Orient → Decide → Act. See [ooda-loop-guide.md](references/ooda-loop-guide.md) and [developer-security-workflow.md](references/developer-security-workflow.md).

---

## Recommended MCP Servers

Two MCP servers enhance this skill when available. Configuration template: `assets/mcp-servers.json`.

### Context7 — Live Documentation

Retrieves **current upstream docs** for ModSecurity, CRS, Coraza, go-ftw, and crs-toolchain via `resolve-library-id` + `query-docs`.

Use Context7 when:
- A directive, operator, or variable is not covered in skill references
- You need to verify behavior for a specific version
- The user asks about recently-released features or API changes

Key library IDs: `/owasp-modsecurity/ModSecurity`, `/coreruleset/coreruleset`, `/corazawaf/coraza`, `/coreruleset/go-ftw`, `/coreruleset/crs-toolchain`.

### Chrome DevTools MCP — Browser Automation

Controls a live Chrome browser for WAF testing workflows:
- **CRS Sandbox testing**: navigate to `https://sandbox.coreruleset.org/` with payloads, inspect response headers and matched rules
- **WAF response verification**: submit requests and verify block pages, status codes, and WAF headers
- **Network inspection**: view full request/response pairs including WAF-injected headers via `list_network_requests`
- **Screenshot evidence**: capture block pages or application behavior for incident `REPORT.md`

For full details, configuration options, and example workflows: [recommended-mcp-servers.md](references/recommended-mcp-servers.md).
