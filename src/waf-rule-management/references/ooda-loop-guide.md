# OODA Loop Guide for WAF Operations

The **Observe → Orient → Decide → Act** loop is the core methodology for all WAF rule management workflows. Each workflow in this skill maps to OODA phases.

---

## The Loop

```
┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│  OBSERVE  │────>│  ORIENT   │────>│  DECIDE   │────>│    ACT    │
│           │     │           │     │           │     │           │
│ Collect   │     │ Analyze   │     │ Choose    │     │ Implement │
│ evidence  │     │ context   │     │ action    │     │ and test  │
└───────────┘     └───────────┘     └───────────┘     └───────────┘
      ^                                                      │
      └──────────────────────────────────────────────────────┘
                        feedback loop
```

**Speed matters**: The loop is continuous. Shorter loops mean faster response to threats and fewer false positives in production.

---

## OODA Applied to WAF Workflows

### Rule Writing

| Phase | Actions | Tools |
|-------|---------|-------|
| **Observe** | Gather threat intel, CVE details, attack samples, PoC code | Web research, vendor advisories, NVD |
| **Orient** | Map threat to ModSec variables/operators; check existing CRS coverage | CRS docs, `crs-toolchain util fp-finder`, Sandbox |
| **Decide** | Choose strategy: single rule vs chain, PL placement, anomaly score, virtual-patch vs CRS contribution | [actions-reference.md](actions-reference.md), [anomaly-scoring.md](anomaly-scoring.md) |
| **Act** | Write → validate → lint → test → deploy | `validate_rule.py` (crslang), `lint_regex.py`, `go-ftw`, `docker compose` |

### False Positive Tuning

| Phase | Actions | Tools |
|-------|---------|-------|
| **Observe** | Collect audit logs, user reports, monitoring alerts | `analyze_log.py --summary`, `--top-rules` |
| **Orient** | Identify triggering rule, matched data, classify FP vs TP | `analyze_log.py --rule-id N --detail`, error log |
| **Decide** | Exclusion scope: runtime vs configure-time, by-rule vs by-tag vs by-variable | [false-positives-and-tuning.md](false-positives-and-tuning.md) |
| **Act** | Generate exclusion → validate → test regression → deploy | `generate_exclusion.py`, `validate_rule.py`, `go-ftw` |

### Incident Response (First Responder)

| Phase | Actions | Tools |
|-------|---------|-------|
| **Observe** | Advisory details, CVSS, attack vector, PoC, active exploitation | Scaffold workspace: `new_incident.sh`, document in REPORT.md |
| **Orient** | Probe payloads across content-types; analyze WAF response; compare with Sandbox | `probes.sh`, `analyze_log.py`, CRS Sandbox |
| **Decide** | Gaps found? Write virtual-patch rules. No gaps? Document and monitor. | [first-responder-risk-runbook.md](first-responder-risk-runbook.md) |
| **Act** | Write rules → validate → assemble → test → deploy → document | `assemble_rules.sh`, `go-ftw`, REPORT.md |

### Deployment & Rollout

| Phase | Actions | Tools |
|-------|---------|-------|
| **Observe** | Baseline metrics: current block rate, FP rate, top triggered rules | `analyze_log.py`, monitoring dashboards |
| **Orient** | Assess readiness: are exclusions tuned? Are tests passing? | `go-ftw` regression suite, [sampling-mode.md](sampling-mode.md) |
| **Decide** | Advance sampling percentage? Increase paranoia level? Promote to production? | [paranoia-levels.md](paranoia-levels.md) |
| **Act** | Deploy change → monitor → tune → advance or rollback | `docker compose`, CDN/LB config |

---

## Key Principles

- **Every workflow is a loop** — never "set and forget." Rules, exclusions, and thresholds need continuous review.
- **Observe before acting** — collect evidence (logs, probes, tests) before writing rules or exclusions.
- **Orient with context** — understand what CRS already covers before adding custom rules.
- **Decide with traceability** — document why you chose an approach (in REPORT.md, commit messages, comments).
- **Act with tests** — every change must have regression coverage (`go-ftw`).
- **Feedback is mandatory** — after acting, observe the results and start the next loop.

## What to Avoid

- **Skipping Observe**: Writing rules based on assumptions without evidence.
- **Skipping Orient**: Not checking existing CRS coverage before adding custom detection.
- **Acting without testing**: Deploying rules without `go-ftw` regression.
- **One-shot thinking**: Treating a rule change as "done" without monitoring its production impact.
- **Analysis paralysis**: Spending too long in Orient/Decide when a quick virtual-patch is needed.

---

## Operational Cadence

| Cadence | Activity |
|---------|----------|
| **Continuous** | Monitor audit logs, respond to alerts |
| **Daily** | Review top-triggered rules, check for new advisories |
| **Weekly** | Run full regression suite, review FP backlog |
| **Monthly** | Review PL/threshold settings, check for CRS updates |
| **Per-incident** | Full OODA loop per [first-responder-risk-runbook.md](first-responder-risk-runbook.md) |

---

## Best Practices

- Complete all four OODA phases for every change — skipping Orient or Decide leads to reactive, poorly scoped fixes.
- Log your observations and decisions explicitly (in `REPORT.md` for incidents, in PR descriptions for routine changes).
- Use OODA at multiple scales: per-incident (minutes/hours), per-tuning-cycle (days), and per-operational-review (monthly).
- Let the Observe phase drive tool selection — audit logs for detection issues, error logs for config issues, Sandbox for quick validation.

## External References

- [OODA Loop (Wikipedia)](https://en.wikipedia.org/wiki/OODA_loop) — Original concept by John Boyd
- [OWASP CRS Documentation](https://coreruleset.org/docs/) — Operations context for OODA application

## Related References

- [developer-security-workflow.md](developer-security-workflow.md) — CI/CD integration
- [first-responder-risk-runbook.md](first-responder-risk-runbook.md) — Incident OODA
- [best-practices-modsec-coraza-crs.md](best-practices-modsec-coraza-crs.md) — Operations checklist
- [log-analysis-steering.md](log-analysis-steering.md) — Observe phase tools
