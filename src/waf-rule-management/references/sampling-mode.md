# Sampling Mode (Gradual CRS Rollout)

Deploy CRS progressively by applying rules to a percentage of traffic, monitoring at each stage, and tuning before increasing coverage.

**Verified against**: CRS v4.23.0, ModSecurity v3.0.14 (Feb 2025).

---

## Why Sample

- **Reduce blast radius**: A misconfigured rule affects only a fraction of traffic.
- **Build tuning confidence**: Observe false positives at low percentages before committing.
- **Stakeholder buy-in**: Demonstrate safety at each stage before increasing.
- **Rollback is instant**: Set sampling to 0% or switch to `DetectionOnly`.

---

## Recommended Progression

```
DetectionOnly → 1% → 2% → 5% → 10% → 25% → 50% → 100%
```

At **each stage**:
1. Run for a meaningful traffic window (hours to days depending on volume).
2. Review audit logs: `python scripts/analyze_log.py audit.log --summary`.
3. Identify and fix false positives before advancing.
4. Record the stage, duration, FP count, and tuning actions in your change log.

---

## Implementation Approaches

### 1. CDN/Load Balancer Split (Recommended)

Route a percentage of traffic through the WAF-enabled path:

```
                ┌─── WAF path (CRS enabled) ─── backend
  LB / CDN ────┤
                └─── bypass path (no WAF) ───── backend
```

This is the safest approach — the WAF is a complete pass-through for the bypass path.

### 2. ModSecurity `DetectionOnly` + Threshold Tuning

Use `DetectionOnly` mode to log without blocking, then progressively lower the anomaly threshold:

```apache
# Stage 1: Log everything, block nothing
SecRuleEngine DetectionOnly

# Stage 2: Block only high-confidence attacks (threshold 25)
SecRuleEngine On
# In crs-setup.conf:
SecAction "id:900110,phase:1,pass,setvar:tx.inbound_anomaly_score_threshold=25"

# Stage 3: Lower threshold to 10
SecAction "id:900110,phase:1,pass,setvar:tx.inbound_anomaly_score_threshold=10"

# Stage 4: Default threshold (5)
SecAction "id:900110,phase:1,pass,setvar:tx.inbound_anomaly_score_threshold=5"
```

### 2b. Production Retrofit (Existing Traffic)

When adding CRS to **existing production** with mixed FP/TP traffic, start with a very high threshold so no legitimate users are blocked. Tune away FPs at each step, then lower:

```apache
# Start: no blocking (threshold 10000)
SecAction "id:900110,phase:1,pass,setvar:tx.inbound_anomaly_score_threshold=10000"

# After tuning highest-scoring FPs: 100 → 50 → 20 → 10 → 5
# Lower only when FPs at current level are addressed
```

Progression: **10,000 → 100 → 50 → 20 → 10 → 5**. At each stage, use `analyze_log.py --summary --top-rules` to identify and fix FPs before advancing. See [false-positives-and-tuning.md](false-positives-and-tuning.md).

### 3. IP/Header-Based Sampling

Apply CRS only to traffic matching a sampling condition:

```apache
# Skip CRS for 90% of traffic (simple hash-based sampling)
SecRule REMOTE_ADDR "@rx [0-8]$" \
    "id:100000,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

**Warning**: This is crude. Prefer CDN/LB-level splitting for production.

---

## Monitoring at Each Stage

| Metric | Tool | Command |
|--------|------|---------|
| Top triggered rules | analyze_log.py | `python scripts/analyze_log.py audit.log --top-rules 20` |
| False positive candidates | analyze_log.py | `python scripts/analyze_log.py audit.log --rule-id N --detail` |
| Block rate | CLI | `grep -c 'Access denied' error.log` |
| Top blocked paths | CLI | See [log-analysis-steering.md](log-analysis-steering.md) |
| Anomaly score distribution | jq | `jq '.transaction.messages[].details.data' audit.json` |

---

## Rollback

- **Instant**: Set `SecRuleEngine DetectionOnly` or `Off`.
- **CDN/LB**: Shift all traffic to the bypass path.
- **Threshold**: Raise `tx.inbound_anomaly_score_threshold` to a very high value (e.g., 999).

Always have a documented rollback procedure before advancing to the next stage.

---

## Best Practices

- **Never jump from 0% to 100%** — even well-tested rules can surprise in production.
- **Tune before advancing** — fix FPs at each stage, don't carry them forward.
- **Record everything** — stage, duration, traffic volume, FP count, rules tuned, actions taken.
- **Use `DetectionOnly` first** — observe the full rule set without blocking before any sampling.
- **Test with representative traffic** — staging environments may not reflect production patterns.
- **Coordinate with app teams** — they should know which stage you're at and how to report issues.

## What to Avoid

- **Skipping `DetectionOnly`** and going straight to blocking.
- **Staying at low percentages indefinitely** — set a timeline and stick to it.
- **Raising anomaly thresholds as a permanent fix** — address root causes (exclusions, rule tuning).
- **Sampling without monitoring** — logging must be active and reviewed at every stage.
- **Deploying sampling and PL changes simultaneously** — change one variable at a time.

---

## Related References

- [paranoia-levels.md](paranoia-levels.md) — PL rollout strategy
- [anomaly-scoring.md](anomaly-scoring.md) — Threshold tuning
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies
- [best-practices-modsec-coraza-crs.md](best-practices-modsec-coraza-crs.md) — Operations checklist
- [log-analysis-steering.md](log-analysis-steering.md) — Monitoring commands
- CRS Docs – Anomaly Scoring: https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
