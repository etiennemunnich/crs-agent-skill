---
name: waf-rule-management
description: >
  Write, validate, tune, test, and improve ModSecurity 3.0 / Coraza WAF rules
  and OWASP Core Rule Set (CRS) configurations — both effective (detection) and
  performant (no ReDoS, efficient operators). Developer-led security approach
  and OODA loop methodology. Converts OpenAPI specifications into positive-security
  WAF rules for inclusion before CRS evaluation. Supports false positive analysis,
  rule exclusions, audit log analysis, go-ftw testing, CRS Sandbox testing, regex
  assembly with crs-toolchain, CRSLang (next-gen rule format), and CI/CD integration.
  Use when the user mentions ModSecurity, Coraza, CRS, SecRule, WAF rules,
  web application firewall, false positives, paranoia level, anomaly scoring,
  audit logs, go-ftw, rule tuning, OpenAPI to WAF, CRSLang, positive security model,
  JA4, JA3, TLS fingerprint, CDN (CloudFront, Akamai, Cloudflare, Fastly, etc), or load balancer.
  Primary target is ModSecurity v3; supports migration from v2.
license: MIT
compatibility: >
  Requires Python 3.8+, Go, go-ftw, crs-toolchain, crslang, Docker or Finch.
  Run scripts/install_tools.sh. Scripts must support --help.
metadata:
  author: owasp-crs-tooling
  version: "0.9"
---

# WAF Rule Management

A developer-led security skill for writing, testing, and maintaining ModSecurity v3
and Coraza WAF rules with OWASP Core Rule Set (CRS v4.x). Rules must be **effective**
(detect attacks) and **performant** (no ReDoS, prefer @pm/@streq over @rx when possible).

## Constraints (Always Follow)

- **NEVER deploy agent-generated rules straight to production.** Every rule change — new rules, exclusions, tuning, virtual patches — must be tested in a lower environment (dev, staging, or DetectionOnly/sampling) and reviewed by the user before going live. A bad rule can block real traffic or miss real attacks. When generating or modifying rules, remind the user to validate before promoting.
- **DO** use custom rule IDs 100000–199999 (never CRS range 900000–999999)
- **DO** validate every rule with `validate_rule.py` and lint regex with `lint_regex.py` before deploying
- **DO** prefer non-regex operators (`@pm`, `@streq`, `@beginsWith`, `@contains`) when they suffice — faster and no ReDoS risk
- **DO** generate and run go-ftw regression tests for every new or modified rule
- **DO NOT** modify CRS rule files directly — use exclusions in separate config files
- **DO NOT** write regex with nested quantifiers (`(a+)+`, `(a|b?)*`) — ReDoS risk
- **DO NOT** lower anomaly thresholds or jump paranoia levels without exclusion tuning first
- **DO NOT** enable blocking mode before tuning in DetectionOnly/sampling
- **Antipattern steering**: When the user proposes code/config matching an antipattern, recognize it, explain why it's wrong, redirect to the correct approach, and offer a fix. See [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) for the full catalog.
- **Always verify** against latest official documentation and GitHub repos for CRS, ModSecurity, and Coraza.
- **Check latest official sources** before advising: news, releases, and issues for CRS ([coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)), ModSecurity ([owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)), Coraza ([corazawaf/coraza](https://github.com/corazawaf/coraza)), nuclei ([projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)), go-ftw ([coreruleset/go-ftw](https://github.com/coreruleset/go-ftw)), crs-toolchain. Docs: [coreruleset.org/docs](https://coreruleset.org/docs/), [modsecurity.org](https://modsecurity.org), [coraza.io/docs](https://coraza.io/docs/).
- **User-provided steering first**: When the user provides explicit TTPs, tiered approaches, methodology, or decision frameworks — use them **first**. Do not substitute with generic alternatives (e.g. CRS precedent patterns) unless the user asks or the provided steering is demonstrably incorrect. If in doubt, apply the user's model and note trade-offs.

## Quick Start

**First time**: `bash scripts/install_tools.sh` (see [README](README.md)).

**Required**: Python 3.8+, PyYAML, Go toolchain, go-ftw, crs-toolchain, crslang, Docker or Finch.
**Optional fallback**: modsec-rules-check (legacy parser; crslang is primary).
**Optional**: cdncheck (ingress discovery).

> **Container runtime**: All `docker compose` / `docker logs` commands work identically with `finch compose` / `finch logs`. Replace `docker` with `finch` throughout if Docker is not installed. Scripts auto-detect the available runtime.

### SecRule One-Liner

```
SecRule VARIABLE "@OPERATOR pattern" "id:N,phase:N,ACTION,status:NNN,log,msg:'...',tag:'...',severity:'...'"
```

Phases: 1=Request Headers, 2=Request Body, 3=Response Headers, 4=Response Body, 5=Logging.
Custom rule IDs: **100000–199999** (avoids CRS conflicts).

### Essential Commands

```bash
python scripts/validate_rule.py rule.conf            # Validate syntax (crslang first, then legacy)
python scripts/lint_regex.py rule.conf -v             # ReDoS/performance lint
python scripts/lint_crs_rule.py rule.conf             # CRS convention lint
python scripts/analyze_log.py audit.log --summary     # Log analysis
python scripts/analyze_log.py audit.log --explain     # Why rules triggered
python scripts/openapi_to_rules.py spec.yaml -o r.conf  # OpenAPI → rules
python scripts/validate_exclusion.py --input exclusion.conf --output text  # Exclusion safety checks
python scripts/detect_app_profile.py audit.log --output text  # App profile hints
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/  # Regression tests
bash scripts/new_incident.sh INC-001 "brief title"   # Create incident workspace
bash scripts/assemble_rules.sh rules/                # Assemble rule set from directory

# Optional ingress discovery (CDN/cloud/WAF front door)
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
cdncheck -i app.example.com -jsonl

# Test environment — choose your engine:
docker compose -f assets/docker/docker-compose.yaml up -d          # ModSecurity
docker compose -f assets/docker/docker-compose.coraza.yaml up -d   # Coraza

curl -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd" # Sandbox check
```

---

## Determine Your Task → Load Reference

**Load exactly one primary reference** for the task. Add adjacent refs only for edge cases. Full index below.

| User intent | Load reference |
|-------------|----------------|
| False positive / exclusion | [false-positives-and-tuning.md](references/false-positives-and-tuning.md) + [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) — includes Post-Upgrade / Regex-Change FP section |
| Attack not blocked / evasion | [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) §5 (Rule not matching) |
| New rule / custom detection | [variables-and-collections.md](references/variables-and-collections.md) → [actions-reference.md](references/actions-reference.md) → [crs-rule-format.md](references/crs-rule-format.md) + [regex-steering-guide.md](references/regex-steering-guide.md) (effective + performant) |
| Rule validation / Seclang syntax | [crslang-reference.md](references/crslang-reference.md) — crslang is primary; validate_rule.py uses it first |
| OpenAPI → WAF allowlist | [openapi-to-waf.md](references/openapi-to-waf.md) |
| Log analysis / triage | [log-analysis-steering.md](references/log-analysis-steering.md) |
| Anomaly scoring / threshold tuning | [anomaly-scoring.md](references/anomaly-scoring.md) — includes M2M/API scoring models |
| Sampling / DetectionOnly rollout | [sampling-mode.md](references/sampling-mode.md) |
| Regression testing | [go-ftw-reference.md](references/go-ftw-reference.md) |
| ModSecurity + CRS test env | [modsec-crs-testing-reference.md](references/modsec-crs-testing-reference.md) |
| Coraza + CRS / cross-engine | [coraza-testing-reference.md](references/coraza-testing-reference.md) |
| Incident / zero-day triage | [first-responder-risk-runbook.md](references/first-responder-risk-runbook.md) |
| CRS groups, phases, tuning | [crs-tune-rule-steering.md](references/crs-tune-rule-steering.md) |
| CRS contribution / PR | [crs-contribution-workflow.md](references/crs-contribution-workflow.md) |
| Deployment / rollout | [best-practices-modsec-coraza-crs.md](references/best-practices-modsec-coraza-crs.md) |
| Regex / ReDoS / crs-toolchain | [regex-steering-guide.md](references/regex-steering-guide.md) |
| v2→v3 migration | [modsecurity-migration-checklist.md](references/modsecurity-migration-checklist.md) |
| OODA loop / workflow methodology | [ooda-loop-guide.md](references/ooda-loop-guide.md) |
| Developer security lifecycle / CI | [developer-security-workflow.md](references/developer-security-workflow.md) |

---

## LRM Default Workflow (Concise)

For most false-positive and triage tasks, steer with this minimal sequence:

1. **Observe**: `analyze_log.py --summary --top-rules 20`
2. **Explain**: `analyze_log.py --explain-rule <ID> --detail`
3. **Profile check**: `detect_app_profile.py` (and app package/plugin match)
4. **Tune narrow**: `generate_exclusion.py` (URI + param scoped)
5. **Validate + test**: `validate_exclusion.py` + go-ftw regression

Use broader discovery tools (`httpx`, `cdncheck`, `nuclei`, `vulnx`) only when the core 5-step flow lacks enough evidence.

### FP handling steering

When the user reports a false positive or asks how to handle FPs:

1. **Capture context first** — Paranoia level, CRS version, engine, app/platform, triggering payload, rule ID + matched variable. Ask if missing.
2. **Post-upgrade FP?** — If user says "after upgrading to vX.Y.Z, rule N fires": follow [false-positives-and-tuning.md](references/false-positives-and-tuning.md) Post-Upgrade / Regex-Change FP section — trace to recent PR, extract Matched Data from logs, check variable-target (headers vs ARGS).
3. **Investigate** — `analyze_log.py --explain-rule <ID> --detail`; search [CRS issues](https://github.com/coreruleset/coreruleset/issues) for the rule ID; run `detect_app_profile.py` for app package match.
4. **Classify** — Use [false-positives-and-tuning.md](references/false-positives-and-tuning.md) FP category routing (natural language, GraphQL, SQL keyword in text, etc.) to choose approach.
5. **Apply narrowest exclusion** — Prefer `ctl:ruleRemoveTargetById` (URI + param scoped) over whole-rule removal. For dynamic variable keys, target exclusion may not work — use URI-scoped `ctl:ruleRemoveById`. Check engine source/docs for exclusion syntax limits.
6. **Validate + regression** — `validate_exclusion.py`; go-ftw with FP test (pass) and attack test (block).

**Process is paramount**: reproduce, investigate engine behavior, then apply fix. Do not hardcode issue-specific examples — keep steering generic.

### Evasion / false negative steering

When the user reports "attack not blocked" or "rule not working":

1. **Phase** — ARGS/body need phase 2. **Variable** — Is target populated? **Transform** — Encoding bypass? Add t:urlDecodeUni.
2. **Search CRS issues** for evasion/bypass reports on the rule ID.
3. **Content-type** — Test across form, JSON, multipart; content-type bypass is common.
4. If reporting upstream → [CRS false-negative template](https://github.com/coreruleset/coreruleset/issues/new?template=02_false-negative.md).

Full checklist: [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) §5 (Rule not matching).

### Context7

- **Context7**: Use Context7 (or documentation-lookup skill) **early** when the skill references it — for CVE lookup, CRS rule format, ModSecurity/Coraza docs, go-ftw. Do not wait for the user to ask.

---

## DAST/Discovery Tool Preference Order

Use these tools directly (not wrappers) based on the gap you need to fill:

| Priority | Tool | Use First When | Why |
|----------|------|----------------|-----|
| 1 | `httpx` | You need live target normalization + HTTP probing | Fast host/URL probing, tech detect, response metadata, CDN hints |
| 2 | `cdncheck` | You need ingress visibility (CDN/cloud/WAF masking) | Confirms front-door providers that may hide origin fingerprints |
| 3 | `nuclei` | You need active DAST checks for known classes/CVEs | High-performance scanner across HTTP/DNS/network/cloud |
| 4 | `nuclei-templates` | You need broad, current detection coverage | Community-curated template corpus used by `nuclei` |
| 5 | `cvemap` (`vulnx`) | You need vuln intelligence prioritization | Search/filter CVEs, KEV/PoC/template context for risk triage |
| 6 | `nvd-cve` MCP server | You need CVE fact lookup inside agent chat | Quick CVE detail/search in MCP-native workflow |

Practical steering sequence:
1. `httpx` enumerate reachable surfaces and technology clues.
2. `cdncheck` confirm ingress layers and adjust confidence for origin fingerprinting.
3. `nuclei` with curated template scope (start focused, then widen).
4. `cvemap` (`vulnx`) prioritize findings by severity, KEV, exploitability.
5. `nvd-cve` MCP for rapid CVE detail lookup during triage writeups.

Reference installs:
- `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
- `go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest`
- `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- `go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest`
- `nuclei -ut` (update templates)

---

## Reference Index (Load on Demand)

| File | Load When |
|------|-----------|
| [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md) | Broken config, bad exclusion, rule not working, CRS reporting |
| [false-positives-and-tuning.md](references/false-positives-and-tuning.md) | FP handling, exclusion decision tree, safe patterns |
| [crs-tune-rule-steering.md](references/crs-tune-rule-steering.md) | CRS groups, phases, request/response, version-aware tuning |
| [anomaly-scoring.md](references/anomaly-scoring.md) | Anomaly threshold tuning, M2M/API scoring models, inbound/outbound |
| [sampling-mode.md](references/sampling-mode.md) | DetectionOnly / sampling rollout strategy |
| [log-analysis-steering.md](references/log-analysis-steering.md) | Audit/error log analysis, top talkers |
| [go-ftw-reference.md](references/go-ftw-reference.md) | Regression tests, test format, cloud mode |
| [modsec-crs-testing-reference.md](references/modsec-crs-testing-reference.md) | ModSecurity + CRS local test env |
| [coraza-testing-reference.md](references/coraza-testing-reference.md) | Coraza / cross-engine testing |
| [crs-application-profiles.md](references/crs-application-profiles.md) | WordPress, Drupal, APIs — app-specific exclusions |
| [crs-rule-format.md](references/crs-rule-format.md) | CRS-style rule writing, metadata |
| [crslang-reference.md](references/crslang-reference.md) | Rule validation (primary), Seclang↔CRSLang conversion |
| [actions-reference.md](references/actions-reference.md) | Rule actions (deny, chain, setvar, ctl) |
| [variables-and-collections.md](references/variables-and-collections.md) | ARGS, headers, TX, etc. |
| [operators-and-transforms.md](references/operators-and-transforms.md) | @rx, @pm, transforms |
| [regex-steering-guide.md](references/regex-steering-guide.md) | Effective + performant rules, ReDoS, operator choice, transforms |
| [openapi-to-waf.md](references/openapi-to-waf.md) | OpenAPI → positive-security rules |
| [first-responder-risk-runbook.md](references/first-responder-risk-runbook.md) | Incident triage, virtual patches |
| [ooda-loop-guide.md](references/ooda-loop-guide.md) | OODA loop methodology mapped to WAF workflows |
| [developer-security-workflow.md](references/developer-security-workflow.md) | Branch-per-change strategy, developer-friendly CI lifecycle |
| [crs-contribution-workflow.md](references/crs-contribution-workflow.md) | CRS PR, go-ftw, nuclei |
| [best-practices-modsec-coraza-crs.md](references/best-practices-modsec-coraza-crs.md) | Deployment, rollout |
| [modsec-directives.md](references/modsec-directives.md) | Engine directives |
| [paranoia-levels.md](references/paranoia-levels.md) | PL rollout |
| [crs-sandbox-reference.md](references/crs-sandbox-reference.md) | Sandbox API, reproducible curl |
| [crs-toolchain-reference.md](references/crs-toolchain-reference.md) | crs-toolchain CLI |
| [regex-assembly.md](references/regex-assembly.md) | .ra files |
| [baseline-testing-tools.md](references/baseline-testing-tools.md) | go-test-waf, nuclei |
| [upgrade-and-testing.md](references/upgrade-and-testing.md) | CRS upgrade |
| [modsecurity-migration-checklist.md](references/modsecurity-migration-checklist.md) | v2→v3 migration |
| [ja4-ja3-cdn-lb-steering.md](references/ja4-ja3-cdn-lb-steering.md) | TLS fingerprints, CDN |
| [recommended-mcp-servers.md](references/recommended-mcp-servers.md) | Context7, Chrome DevTools MCP |

**Rule**: Load one primary ref. Add adjacent only for edge cases.

---

## Writing New Rules

**Effective + performant**: Use `@pm`/`@streq`/`@beginsWith` when regex not needed; avoid nested quantifiers; run `lint_regex.py`. See [regex-steering-guide.md](references/regex-steering-guide.md).

Variables → [variables-and-collections.md](references/variables-and-collections.md) | Operators → [operators-and-transforms.md](references/operators-and-transforms.md) | Actions → [actions-reference.md](references/actions-reference.md) | Format → [crs-rule-format.md](references/crs-rule-format.md)

```bash
python scripts/validate_rule.py rule.conf && python scripts/lint_regex.py rule.conf -v
python scripts/generate_ftw_test.py rule.conf -o tests/
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
```

---

## OpenAPI to WAF Rules

Allowlist rules from OpenAPI → validate before CRS. See [openapi-to-waf.md](references/openapi-to-waf.md).

```bash
python scripts/openapi_to_rules.py openapi.yaml -o before-crs-rules.conf
python scripts/validate_rule.py before-crs-rules.conf
```

---

## Tuning and False Positives

See [false-positives-and-tuning.md](references/false-positives-and-tuning.md) and [antipatterns-and-troubleshooting.md](references/antipatterns-and-troubleshooting.md). Exclusion placement: runtime (`ctl:*`) BEFORE CRS include; configure-time (`SecRuleRemove*`) AFTER.

```bash
python scripts/analyze_log.py audit.log --explain-rule 942100 --detail
python scripts/generate_exclusion.py --rule-id 942100 --uri /api/search --param ARGS:q
python scripts/validate_exclusion.py --input exclusion.conf
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
```

---

## Analyzing WAF Logs

See [log-analysis-steering.md](references/log-analysis-steering.md).

```bash
python scripts/analyze_log.py audit.log --summary --top-rules 20
python scripts/analyze_log.py audit.log --explain-rule 942100 --detail
python scripts/detect_app_profile.py audit.log --output text
```

---

## Testing Rules

Quick check → [crs-sandbox-reference.md](references/crs-sandbox-reference.md) | Local regression → [go-ftw-reference.md](references/go-ftw-reference.md) | ModSec env → [modsec-crs-testing-reference.md](references/modsec-crs-testing-reference.md) | Coraza → [coraza-testing-reference.md](references/coraza-testing-reference.md)

```bash
docker compose -f assets/docker/docker-compose.yaml up -d   # or docker-compose.coraza.yaml
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?file=/etc/passwd"
```

---

## Regex Assembly

[regex-steering-guide.md](references/regex-steering-guide.md) | [regex-assembly.md](references/regex-assembly.md) | [crs-toolchain-reference.md](references/crs-toolchain-reference.md)

```bash
python scripts/lint_regex.py rule.conf -v
crs-toolchain regex generate 942170
crs-toolchain util fp-finder 942170
```

---

## CRS Contribution

[crs-contribution-workflow.md](references/crs-contribution-workflow.md) | [crs-rule-format.md](references/crs-rule-format.md). Lint: `python scripts/lint_crs_rule.py`. Before submit: `crs-toolchain util fp-finder RULE_ID`.

---

## MCP Servers

[recommended-mcp-servers.md](references/recommended-mcp-servers.md) — Context7 (live docs), Chrome DevTools (Sandbox testing).
