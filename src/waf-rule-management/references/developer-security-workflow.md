# Developer Security Workflow

Map WAF rule changes into a developer-friendly lifecycle with OODA at each stage.

## Branch and Change Strategy

1. **Branch per change**: Create a branch for each rule change, tuning adjustment, or
   exclusion set. Name branches descriptively: `waf/fix-942100-search-fp`,
   `waf/add-api-positive-security`, `waf/tune-pl2-rollout`.

2. **Atomic commits**: One logical change per commit — a new rule, an exclusion, or a
   config tweak. Include the corresponding go-ftw test in the same commit.

3. **PR with impact notes**: Describe what changed, why (FP report, new endpoint, CVE),
   which rules/IDs are affected, and whether this is `enforce` or `detect` mode.

## OODA in the Developer Loop

| OODA Phase | Developer Action | Tooling |
|------------|-----------------|---------|
| **Observe** | Receive FP report, CVE advisory, or new API spec | Audit logs, monitoring alerts, OpenAPI spec diff, `cdncheck` ingress discovery |
| **Orient** | Identify triggering rules, classify FP vs TP, scope the change | `analyze_log.py`, CRS Sandbox, `crs-toolchain util fp-finder` |
| **Decide** | Choose fix: exclusion, new rule, tuning, or positive-security rule | `openapi-to-waf.md`, `false-positives-and-tuning.md`, `paranoia-levels.md` |
| **Act** | Write rule → validate → lint → test → PR → deploy | Scripts, go-ftw, CI pipeline |

### DAST/Discovery Ingress Check (recommended)

Before deep fingerprinting/tuning, map ingress providers that may mask the origin stack:

```bash
# Install latest cdncheck
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Detect CDN / cloud / WAF in front of target
cdncheck -i app.example.com -jsonl
cdncheck -i app.example.com -waf -resp
```

If CDN/WAF ingress is detected, treat origin fingerprinting confidence as lower and prefer:
1. log-based evidence from WAF telemetry,
2. app profile recommendations with explicit confidence,
3. staged validation before exclusion rollout.

### Tool Preference to Fill Discovery Gaps

Use these tools directly (in this order) when building discovery evidence:

1. `httpx` - normalize reachable targets, tech hints, HTTP metadata.
2. `cdncheck` - confirm CDN/cloud/WAF ingress masking.
3. `nuclei` + `nuclei-templates` - run focused active checks (then broaden).
4. `vulnx` (`cvemap`) - prioritize findings by severity/KEV/PoC/template availability.
5. `nvd-cve` MCP - quick CVE lookup inside analyst workflow.

## Pre-Commit Checks

Before pushing a branch, run locally:

> **Container runtime**: All `docker` commands below work with `finch` as a drop-in replacement.

```bash
# Validate syntax (crslang primary)
python scripts/validate_rule.py rules/*.conf

# Lint CRS conventions
python scripts/lint_crs_rule.py rules/*.conf

# Lint regex for ReDoS/performance
python scripts/lint_regex.py rules/*.conf -v --strict

# Run regression tests (or: finch compose ...)
docker compose -f assets/docker/docker-compose.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
docker compose -f assets/docker/docker-compose.yaml down
```

## CI/CD Pipeline Integration

### Validation Stage (every PR)

Run on every pull request. Fast, no containers needed:

```yaml
# Example CI step (GitHub Actions / GitLab CI / etc.)
- name: Validate rules
  run: python scripts/validate_rule.py rules/*.conf   # crslang primary

- name: Lint CRS conventions
  run: python scripts/lint_crs_rule.py rules/*.conf -o text

- name: Lint regex
  run: python scripts/lint_regex.py rules/*.conf -v --strict
```

### Regression Stage (every PR)

Requires Docker/Finch. Start CRS+Albedo, run go-ftw:

```yaml
- name: Start test environment
  run: docker compose -f assets/docker/docker-compose.yaml up -d

- name: Run regression tests
  run: go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

- name: Tear down
  run: docker compose -f assets/docker/docker-compose.yaml down
```

### Cross-Engine Stage (optional, pre-release)

Run the same suite on Coraza to catch engine-specific differences:

```yaml
- name: Start Coraza
  run: docker compose -f assets/docker/docker-compose.coraza.yaml up -d

- name: Run Coraza regression
  run: go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

- name: Tear down
  run: docker compose -f assets/docker/docker-compose.coraza.yaml down
```

## Test Coverage Requirements

Every rule change should include go-ftw tests:

| Change Type | Required Tests |
|------------|---------------|
| New detection rule | At least 1 trigger (attack blocked) + 1 benign (no FP) |
| New exclusion | At least 1 test proving the FP is resolved + 1 test proving the original attack is still caught |
| Positive-security rule | At least 1 valid request (allowed) + 1 invalid request (blocked) per rule |
| Tuning change (PL/threshold) | Replay existing suite; note any delta |

## Deploy Workflow

1. **Merge PR** after review and CI pass.
2. **Deploy to staging** with `SecRuleEngine DetectionOnly` or sampling mode.
3. **Monitor** audit logs for unexpected blocks or new FPs.
4. **Promote to production** — switch to `On` or increase sampling percentage.
5. **Iterate** — if new FPs appear, create a new branch and repeat.

For gradual rollout patterns, see `sampling-mode.md` and `paranoia-levels.md`.

## Operational Cadence

| Frequency | Activity |
|-----------|----------|
| Every PR | Validate + lint + regression |
| Weekly | Review top-triggered rules (`analyze_log.py --top-rules 20`) |
| Monthly | Check for CRS updates, regenerate positive-security rules if API spec changed |
| Per incident | First-responder runbook → stabilize → codify into regression tests |

## Best Practices

- One logical change per commit — a new rule, an exclusion, or a config tweak, with corresponding tests in the same commit.
- Every PR should include impact notes: what changed, why, which rule IDs are affected, and whether the change is detect or enforce mode.
- Run the full pre-commit check suite locally before pushing (validate + lint + regex lint + regression).
- Use branch naming that encodes intent: `waf/fix-942100-search-fp`, `waf/add-api-positive-security`.
- Deploy to staging with DetectionOnly or sampling before promoting to production.

## What to Avoid

- Skipping regression tests on a PR because "it's just an exclusion" — exclusions can have side effects.
- Merging without CI pass — even minor rule changes can break detection or introduce FPs.
- Deploying directly to production without a staging/sampling phase.
- Combining unrelated rule changes in a single commit — makes rollback and debugging harder.
- Ignoring weekly top-triggered rule reviews — silent regressions accumulate.

## External References

- [CRS GitHub Repository](https://github.com/coreruleset/coreruleset) — Upstream rule set and contribution guidelines
- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))
- [Coraza Documentation](https://coraza.io/docs/) — Engine-specific guidance
- [OWASP DevGuide: ModSecurity](https://devguide.owasp.org/en/09-operations/03-modsecurity/)

## Related

- `ooda-loop-guide.md` — OODA method framing
- `best-practices-modsec-coraza-crs.md` — Operations checklist
- `go-ftw-reference.md` — Test format and commands
- `sampling-mode.md` — Gradual rollout
- `paranoia-levels.md` — PL rollout strategy
- `first-responder-risk-runbook.md` — Incident triage
