# CRS Upgrade and Regression Testing

Community practices for upgrading CRS and validating changes. Complements [go-ftw-reference.md](go-ftw-reference.md) and [crs-sandbox-reference.md](crs-sandbox-reference.md).

---

## Testing Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| **go-ftw** | Regression testing | Run CRS test suite before/after upgrade; quantitative testing support |
| **sandbox.coreruleset.org** | Public payload testing | Test against specific PL/version without touching production; `x-format-output: txt-matched-rules`, `x-crs-paranoia-level` |
| **msc_retest** (Digitalwave) | PCRE/regex behavior | Test regex across PCRE/PCRE2, JIT, limit settings; validate PCRE limit changes |
| **SecRuleEngine DetectionOnly** | Shadow mode | Run new rules alongside production; logs hits, zero impact |
| **CRS Docker images** | Isolated test env | `owasp/modsecurity-crs:apache-alpine` or nginx variant |
| **Netnea CRS Upgrading Plugin** | 3.x → 4.x transition | Bridges config differences |
| **renovatebot** | Automated update PRs | Auto-creates PRs when new CRS releases drop |

---

## Typical Upgrade Workflow

1. Run **go-ftw** regression suite against new version locally.
2. Deploy to **staging** with `SecRuleEngine DetectionOnly`.
3. Monitor logs for new rule triggers vs previous version.
4. Use **sandbox.coreruleset.org** to validate specific payload concerns.
5. Address new FPs with targeted exclusions before go-live.
6. Enable `SecRuleEngine On` in production.
7. Monitor 1–2 weeks before considering stable.

---

## Upgrade Approaches by Environment

| Approach | When Used | Risk |
|----------|------------|------|
| Detection-Only shadow | First step for any production upgrade | Very Low |
| Staging clone | Pre-production validation, real app traffic | Low |
| Paranoia Level stepping | New deployments or major version upgrades | Medium (deliberate) |
| Per-VHost PL override | Upgrade one app at a time | Low |
| Docker parallel instance | A/B traffic comparison | Low |
| Quantitative testing (go-ftw) | Compare detection rates between versions | None (offline) |

---

## Upgrade Gotchas

| Gotcha | Context | Lesson |
|-------|---------|--------|
| **Variable renames** | CRS 3 → 4 | `PARANOIA` → `BLOCKING_PARANOIA` in Docker images; check release notes |
| **Exclusion load order** | All versions | Exclusion loaded after rules = exclusion ignored. Re-validate post-upgrade |
| **Chain rule exclusion** | All versions | `ctl:ruleRemoveTargetById` with regex fails silently; test each exclusion with curl after upgrade |
| **New rules at PL1** | Any minor release | New rules can fire at PL1 that didn't exist before; always run DetectionOnly first |
| **Dev branch in production** | CRS 4.10.0+ | 932237 (UNIX) had known FPs; don't upgrade dev to production; wait for stable |
| **Per-VHost PL regression** | 4.10.0-dev | Per-VHost PL override stopped working; reported by community |

---

## Release Cadence

- **Monthly** releases (occasional security patches).
- Users on quarterly policy can skip intermediate releases.
- **renovatebot** can automate PR creation; human decision = approve/skip.
- **CRS 4 LTS** (Q1 2026): long-term stable for conservative environments; security fixes backported.

---

## Related

- [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) — Exclusion placement, phase ordering
- [go-ftw-reference.md](go-ftw-reference.md) — Test format, cloud mode
- [crs-sandbox-reference.md](crs-sandbox-reference.md) — Sandbox headers, reproducibility
- [sampling-mode.md](sampling-mode.md) — Gradual rollout patterns
