# Coraza Testing Reference

Use this guide to run consistent testing workflows across **ModSecurity + CRS** and
**Coraza + CRS** with **Albedo** backend and `go-ftw`.

Primary upstream reference:

- <https://github.com/coreruleset/coraza-crs-docker>

Purpose:

- compare engines (ModSecurity vs Coraza)
- validate custom rules and exclusions
- run false-positive regression
- support first-response probing for recent/zero-day risk hypotheses

## Quick Start

Both engines share port 8080 — run one at a time. See [modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) for full quick start; Coraza uses `docker-compose.coraza.yaml` instead of `docker-compose.yaml`. `docker`/`finch` interchangeable.

```bash
docker compose -f assets/docker/docker-compose.coraza.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d path/to/tests/
# Cross-engine: bash scripts/engine_integration_compare.sh <INCIDENT_ID>
```

## Testing Workflow (Recommended)

Use the standardized incident workflow in `first-responder-risk-runbook.md` for
first-response risk triage and consolidated reporting.

1. **Baseline engine**: run tests on ModSecurity first.
2. **Cross-engine check**: rerun same tests on Coraza.
3. **Version check**: pin CRS version/env vars and rerun.
4. **False-positive loop**:
   - replay legitimate traffic patterns
   - capture rule IDs from logs
   - add narrow exclusions
   - rerun regression suite
5. **Recent/zero-day risk probing**:
   - use a focused payload runbook (hypothesis -> probes -> logs -> decision)
   - run locally on CRS+Albedo first, then compare with CRS Sandbox
   - only convert stable repro cases into go-ftw regression tests

## Test Matrix (What to Vary)

| Dimension | Typical Values | Why |
|---|---|---|
| Engine | ModSecurity, Coraza | Detect engine-specific behavior differences |
| Rule set | CRS only, CRS + custom rules | Validate custom rule interactions |
| Mode | DetectionOnly, On | Separate detection quality from blocking impact |
| PL | 1, 2, (3/4 if needed) | Tune false positives progressively |
| Thresholds | default 5/4, tuned | Verify anomaly policy impact |
| Input set | attack payloads + legitimate traffic | Prevent regressions and overblocking |

## Differences from ModSecurity

| Aspect | ModSecurity (default) | Coraza |
|--------|----------------------|--------|
| Image | `owasp/modsecurity-crs:nginx` | `ghcr.io/coreruleset/coraza-crs:caddy-alpine` |
| Custom rules mount | `/etc/modsecurity.d/custom-rules.conf` | `/opt/coraza/rules.d/custom-rules.conf` |
| Config dir | `/etc/modsecurity.d` | `/opt/coraza/config.d` |
| User rules dir | `/etc/modsecurity.d` | `/opt/coraza/rules.d` |

### Image Sources

- Primary examples in this skill use `owasp/modsecurity-crs` (Docker Hub) and
  `ghcr.io/coreruleset/coraza-crs` (GHCR).
- Alternate ModSecurity image catalog: <https://modsecurity.digitalwave.hu>
- Always pin image tags for reproducibility in incident and regression runs.

## Environment Variables (Coraza)

See [coraza-crs-docker README](https://github.com/coreruleset/coraza-crs-docker#env-variables) for full list.

**CRS-specific** (same as ModSecurity):

- `PARANOIA`, `BLOCKING_PARANOIA`, `ANOMALY_INBOUND`, `ANOMALY_OUTBOUND`

**Coraza-specific**:

- `CORAZA_RULE_ENGINE` — On, Off, DetectionOnly
- `CORAZA_REQ_BODY_ACCESS`, `CORAZA_RESP_BODY_ACCESS`
- `CORAZA_REQ_BODY_LIMIT`, `CORAZA_RESP_BODY_LIMIT`

Common defaults (from upstream image docs):

- `CORAZA_AUDIT_LOG_FORMAT=JSON`
- `CORAZA_AUDIT_LOG_PARTS=ABIJDEFHZ`
- `CORAZA_RULE_ENGINE=On`
- `CORAZA_REQ_BODY_ACCESS=On`
- `CORAZA_RESP_BODY_ACCESS=On`

## Container Paths (Coraza)

When debugging rule load/order issues, verify these paths in the container:

- `/opt/coraza/config/coraza.conf` (main config)
- `/opt/coraza/config.d/*.conf` (supplemental user config)
- `/opt/coraza/config/crs-setup.conf` (CRS setup)
- `/opt/coraza/owasp-crs/*.conf` (CRS rules)
- `/opt/coraza/rules.d/*.conf` (user rule sets)

Plugins:

- Mount plugin files under `/opt/coraza/plugins` to load CRS plugins at startup.
- Upstream plugin registry: <https://github.com/coreruleset/plugin-registry>

## Coraza Tuning Notes

CRS tuning on Coraza uses the **same exclusion syntax** as ModSecurity: `SecRuleRemoveById`, `ctl:ruleRemoveTargetById`, `SecRuleUpdateTargetById`, etc. Placement rules are identical (runtime before CRS, configure-time after).

**RE2 behavior**: Coraza uses Go's `regexp` (RE2-based) by default. PCRE-only features (lookahead, lookbehind, backreferences) are not supported. CRS v4 rules are RE2-compatible; custom rules intended for both engines should avoid PCRE-only patterns. See [regex-steering-guide.md](regex-steering-guide.md).

**Config paths**: Custom exclusions go in `/opt/coraza/rules.d/` (Coraza) vs `/etc/modsecurity.d/` (ModSecurity). Mount your exclusion file to the correct path for your engine.

## Custom Rules and False Positive Testing

- Custom rules are assembled from `incidents/*/rules.conf` into `assets/docker/custom-rules.conf` using `scripts/assemble_rules.sh`. Do not edit `custom-rules.conf` directly.
- Always include **positive + negative** tests for each custom rule.
- For false positives, prefer scoped exclusions (`ruleRemoveTargetById` + URI/param), not global disable.
- Use `references/log-analysis-steering.md` to identify top noisy rules/paths before tuning.

## CVE / New Vulnerability Testing

Important distinction:

- **go-ftw is baseline/regression tooling**, not a complete zero-day discovery workflow.
- For new/unknown risks, use first-responder probing with CRS+Albedo + logs + Sandbox comparison.
- When a probe becomes repeatable and useful, codify it into go-ftw so it stays covered in regression.

See `first-responder-risk-runbook.md` for the full procedure.

## When to Use Coraza

- Validate rules work on both ModSecurity and Coraza
- Coraza-specific behavior or edge cases
- Caddy-based deployments

## Best Practices

- Always test on **both** ModSecurity and Coraza before releasing custom rules — detect engine-specific behavior early.
- Pin container image tags for reproducibility in incident and regression runs.
- Include both **positive** (attack detected) and **negative** (legitimate traffic passes) tests for every custom rule.
- Use the **same `.ftw.yaml` config** and test files across both engines for fair comparison.
- Start baseline testing on ModSecurity first, then cross-validate on Coraza.
- Keep custom rules in a separate mounted file — do not modify CRS rule files in the container.

## What to Avoid

- Assuming ModSecurity and Coraza behave identically — subtle differences exist (e.g. directive support, regex engine).
- Testing only on one engine and deploying on the other without validation.
- Using `:latest` container tags in regression suites — results become non-reproducible.
- Mounting custom rules to incorrect paths (ModSecurity and Coraza have different rule directories).
- Running go-ftw without `--cloud` mode when testing against Docker containers.

## Related

[modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) | [go-ftw-reference.md](go-ftw-reference.md) | [first-responder-risk-runbook.md](first-responder-risk-runbook.md)
