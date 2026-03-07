# Anomaly Scoring

## Overview

CRS uses anomaly scoring: rules increment a running score; blocking occurs when the score exceeds a threshold. This reduces false positives from single noisy rules.

## Severity Scores (Default)

|Severity|Score|
|--------|-----|
|CRITICAL|5|
|ERROR|4|
|WARNING|3|
|NOTICE|2|

## Thresholds

- **Inbound**: 5 (default)
- **Outbound**: 4 (default)

Configure in `crs-setup.conf` (rule 900900).

Practical interpretation:

- Threshold `5` means one CRITICAL match can block.
- Higher thresholds tolerate more suspicious signals before blocking.
- Lower thresholds increase sensitivity but usually increase false positives.

## Per-PL Tracking

Scores are tracked per paranoia level: `tx.inbound_anomaly_score_pl1`, `pl2`, etc. Blocking uses the configured paranoia level's score.

## Early Blocking

Rule 949110 blocks when inbound threshold exceeded. Rule 959100 blocks outbound.

## Recommended Best Practices

- Start with **PL1 + default thresholds** in new environments.
- Tune exclusions before lowering thresholds or increasing paranoia level.
- Roll out changes gradually (sampled traffic or staged environments first).
- Track top contributing rules/paths from audit logs before changing score policy.
- Keep inbound/outbound tuning separate; outbound is often noisier and needs deliberate validation.
- Document every threshold change with reason, date, and rollback plan.

## What to Avoid

- Lowering thresholds globally as a first response to incidents.
- Raising thresholds to silence noise without investigating false-positive root causes.
- Changing thresholds and paranoia level at the same time (hard to attribute impact).
- Using anomaly scoring without sufficient logging/observability.
- Applying one threshold policy across all apps without app-specific validation.

## Related

[paranoia-levels.md](paranoia-levels.md) | [false-positives-and-tuning.md](false-positives-and-tuning.md) | [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md)

## Source

<https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/>
