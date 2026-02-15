# Paranoia Levels (PL1–PL4)

CRS paranoia levels control detection aggressiveness. Higher levels activate more rules, catching more attacks but generating more false positives.

**Verified against**: CRS v4.23.0, https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/.

---

## Overview

| Level | Detection | FP Risk | Use Case |
|-------|-----------|---------|----------|
| **PL1** | Baseline | Low | Default. Production environments with minimal tuning. |
| **PL2** | Enhanced | Moderate | Sensitive apps (finance, healthcare). Requires tuning. |
| **PL3** | Aggressive | High | High-security environments. Significant tuning effort. |
| **PL4** | Maximum | Very high | Research/audit. Not recommended for production without extensive tuning. |

---

## How It Works

- Each rule is assigned a paranoia level via `tag:'paranoia-level/N'`.
- CRS loads **all** rules but only scores at or below the configured level.
- Scoring is tracked per PL: `tx.inbound_anomaly_score_pl1`, `tx.inbound_anomaly_score_pl2`, etc.
- Blocking decision uses the configured PL's cumulative score.

### Configuration

In `crs-setup.conf` (rule 900000):

```apache
# Set paranoia level (1-4)
SecAction "id:900000,phase:1,pass,t:none,nolog,\
    setvar:tx.blocking_paranoia_level=1,\
    setvar:tx.detection_paranoia_level=1"
```

### Executing vs Blocking Paranoia Level

CRS supports **split PL** for safe testing of higher levels:

```apache
# Block at PL1, but detect (log-only) at PL2
SecAction "id:900000,phase:1,pass,t:none,nolog,\
    setvar:tx.blocking_paranoia_level=1,\
    setvar:tx.detection_paranoia_level=2"
```

This lets you **observe PL2 rule hits without blocking**, then tune exclusions before promoting.

---

## PL Rollout Strategy

### Step-by-step

1. **Start at PL1** with default thresholds (inbound=5, outbound=4).
2. **Tune PL1 false positives** until clean for your traffic.
3. **Enable PL2 in detection-only mode**: set `detection_paranoia_level=2`, `blocking_paranoia_level=1`.
4. **Monitor PL2 hits** in audit logs: look for rules tagged `paranoia-level/2`.
5. **Tune PL2 false positives** with exclusions.
6. **Promote PL2 to blocking**: set `blocking_paranoia_level=2`.
7. **Repeat** for PL3 if needed (rare in production).

### Monitoring PL-Specific Hits

```bash
# Find rules that fire at PL2+ (these are the new detections)
python scripts/analyze_log.py audit.log --summary | grep "pl2\|paranoia-level/2"

# Or from raw logs
grep 'paranoia-level/2' audit.log | grep -oE 'id "([0-9]+)"' | sort | uniq -c | sort -rn
```

---

## What Each PL Adds

| PL | Notable Additions | Common FP Triggers |
|----|-------------------|--------------------|
| **PL1** | SQLi, XSS, LFI, RFI, RCE basics, protocol enforcement | Rare with standard apps |
| **PL2** | Stricter SQL/XSS patterns, additional injection vectors, request body checks | Search queries, rich text editors, URL parameters with special chars |
| **PL3** | Very aggressive patterns, uncommon encoding, header anomalies | API traffic, JSON payloads, non-standard user agents |
| **PL4** | Catch-all patterns, very broad matching | Almost everything; requires extensive exclusions |

---

## Best Practices

- **Never start at PL3/PL4** in production without extensive tuning.
- **Use split PL** (detection vs blocking) to safely test higher levels.
- **Tune before promoting** — don't carry PL1 false positives into PL2.
- **Track PL-specific metrics** — know how many rules fire at each PL for your traffic.
- **Document your PL** — teams should know the current level and when it was last reviewed.
- **Consider per-application PL** — sensitive APIs may warrant PL2 while marketing pages stay at PL1.
- **Combine with sampling** — roll out PL changes gradually. See [sampling-mode.md](sampling-mode.md).

## What to Avoid

- **Jumping from PL1 to PL3** — always tune PL2 first.
- **Raising PL and anomaly threshold simultaneously** — change one variable at a time.
- **Using PL4 in production** without dedicated security engineering support.
- **Ignoring PL-specific log data** — the split PL feature exists to give you visibility.
- **Setting PL globally when apps have different sensitivity** — use per-virtual-host or per-location overrides.

---

## Related References

- [anomaly-scoring.md](anomaly-scoring.md) — Scoring thresholds and tuning
- [sampling-mode.md](sampling-mode.md) — Gradual rollout strategy
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies
- [modsec-directives.md](modsec-directives.md) — Engine configuration
- CRS Paranoia Levels docs: https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/
