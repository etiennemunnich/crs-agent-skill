# ModSecurity Migration Checklist (v2 -> v3)

Use this checklist when migrating Seclang rules from ModSecurity v2 environments
to ModSecurity v3 and/or Coraza.

## Goal

- Keep behavior equivalent where safe.
- Remove unsupported features explicitly (no silent fallbacks).
- Prove migration quality with validation and regression tests.

## 1) Unsupported/Changed Items Review

Check each custom rule file for directives/actions that differ in v3.

High-priority review items:

- `SecServerSignature` (not supported in v3).
- Deprecated or unsupported directives/actions noted in ModSecurity v3 docs.
- Exclusions by message (`*ByMsg`) should be avoided for operational tuning.
- Engine-specific assumptions (Apache-only behavior, connector-specific features).

Authoritative references:

- ModSecurity Rules Language Porting Specification:
  <https://github.com/owasp-modsecurity/ModSecurity/wiki/ModSecurity-Rules-Language-Porting-Specification>
- ModSecurity v3 Reference Manual:
  <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>
- Coraza Seclang Syntax:
  <https://coraza.io/docs/seclang/syntax/>

## 2) Validation Gates (Must Pass)

Run these gates for every migrated rule pack:

```bash
# validate_rule.py will use crslang first, then official legacy rules-check tools when installed
python scripts/validate_rule.py path/to/rules.conf
python scripts/lint_crs_rule.py path/to/rules.conf
python scripts/lint_regex.py path/to/rules.conf -v
```

Gate policy:

- No syntax errors.
- No critical lint issues left unreviewed.
- Regex warnings triaged (ReDoS/performance risks either fixed or documented).

## 3) Regression Requirements (Must Pass)

Minimum regression set:

- Positive tests: known malicious payloads still detected/blocked.
- Negative tests: known legitimate traffic no longer false-positives after tuning.
- Cross-engine check: same suite on ModSecurity and Coraza.
- Version pinning: record engine/CRS image tags used for results.

Suggested command flow (all `docker` commands work with `finch` as drop-in replacement):

```bash
# ModSecurity regression
docker compose -f assets/docker/docker-compose.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d path/to/tests/

# Swap to Coraza for cross-engine check (stop ModSec first — shared port 8080)
docker compose -f assets/docker/docker-compose.yaml down
docker compose -f assets/docker/docker-compose.coraza.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d path/to/tests/
```

## 4) Evidence and Sign-off

Before promoting migrated rules, capture:

- Rule diff summary (what changed and why).
- Validation outputs.
- Regression results (ModSecurity + Coraza).
- Known behavior deltas accepted by security owner.

Release only when all required gates pass.

## Best Practices

- Migrate one rule file at a time — easier to isolate issues.
- Run validation gates (`validate_rule.py`, `lint_crs_rule.py`, `lint_regex.py`) on every migrated file before testing.
- Keep a diff summary documenting what changed and why for each migrated file.
- Test on both ModSecurity v3 and Coraza to catch engine-specific issues early.
- Pin engine and CRS image tags used during migration testing for reproducibility.

## What to Avoid

- Migrating all rules at once without incremental validation — makes debugging nearly impossible.
- Assuming v2 behavior is identical in v3 — check the porting specification for each directive/action.
- Keeping `SecServerSignature` or other v2-only directives — they silently fail or cause errors in v3.
- Skipping cross-engine testing — Coraza may handle edge cases differently from ModSecurity v3.
- Using `*ByMsg` exclusions during migration — fragile and likely to break across versions.

## Related References

- [modsec-directives.md](modsec-directives.md) — Directive reference for v3
- [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) — Common migration mistakes
- [coraza-testing-reference.md](coraza-testing-reference.md) — Cross-engine testing
- [crslang-reference.md](crslang-reference.md) — Using crslang for validation during migration
