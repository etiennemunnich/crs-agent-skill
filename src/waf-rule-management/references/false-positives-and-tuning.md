# False Positives and Tuning

Use this guide when legitimate traffic is blocked or heavily scored by CRS.
Goal: reduce false positives while preserving detection depth.

## Authoritative References

- CRS false-positive and exclusion guidance:
  <https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/#rule-exclusion-packages>
- Netnea large-scale tuning methodology (iterative, score-first triage):
  <https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/>
- ModSecurity v3 directive/action details:
  <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>

## Capture Configuration Context First

Before analyzing or writing any exclusion, collect the following. Without this context, exclusion recommendations are speculative — the same rule ID fires for entirely different reasons depending on platform and paranoia level.

| Field | What to capture |
|-------|----------------|
| **Paranoia level** | `blocking_paranoia_level` and `detection_paranoia_level` from `crs-setup.conf` |
| **Engine + version** | ModSecurity v2/v3 or Coraza; WAF host (Apache, Nginx, Caddy) |
| **CRS version** | e.g. `4.0.0`, `4.19.0` |
| **Application / platform** | WordPress, NextJS, PrestaShop, Payload CMS, custom API, etc. |
| **Triggering payload** | URI, HTTP method, relevant headers, body snippet, or cookie value that caused the match |
| **Rule ID + matched variable** | From the audit or error log (e.g. `id:933150`, matched on `REQUEST_COOKIES:session-token`) |

Ask the user for these details if they are not provided before proceeding.

## Standard Tuning Workflow

1. Reproduce with controlled test traffic (same path, params, headers, body).
2. Collect evidence from error log + audit log:
   - rule ID
   - matched variable (`ARGS`, `REQUEST_COOKIES`, etc.)
   - URI/method context
   - anomaly score impact
3. Classify event:
   - true positive
   - acceptable behavior to allow
   - unknown (needs app owner validation)
4. Apply the narrowest safe exclusion.
5. Re-test:
   - false-positive transaction passes
   - known attack payloads are still detected/blocked
6. Add regression coverage in `go-ftw` for the case.

## Exclusion Decision Tree

Prefer this order:

1. **Runtime target exclusion** (most precise)
2. **Configure-time target exclusion**
3. **Runtime remove by ID/tag** (URI/method scoped)
4. **Configure-time remove by ID/tag** (global last resort)

### Placement Rules (Critical)

- Runtime exclusions (`ctl:*`) go **before** CRS include.
- Configure-time exclusions (`SecRuleRemove*`, `SecRuleUpdateTarget*`) go
  **after** CRS include.

## Safe Exclusion Patterns

Runtime, URI-scoped, single target:

```apache
SecRule REQUEST_URI "@beginsWith /api/search" \
    "id:100100,\
    phase:1,\
    pass,\
    nolog,\
    t:none,\
    ctl:ruleRemoveTargetById=942100;ARGS:q"
```

Configure-time, single target:

```apache
SecRuleUpdateTargetById 941320 "!ARGS:wp_post"
```

Configure-time, full rule removal (last resort):

```apache
SecRuleRemoveById 920273
```

## What to Avoid

- Editing CRS rule files directly (creates an upgrade fork).
- Global `SecRuleRemoveByTag attack-*` without tight justification.
- Excluding by message (`ByMsg`) for core workflows; brittle and error-prone.
- Skipping regression after exclusions.
- Raising anomaly thresholds instead of fixing repeatable false positives.

## Rule Exclusion Packages

Before writing many custom exclusions, check if a CRS exclusion package fits the app
(for example WordPress, Drupal, Nextcloud, phpMyAdmin). Package guidance and limits:

<https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/#rule-exclusion-packages>

Enable packages narrowly by app location whenever possible.

## Testing Expectations After Every Tuning Change

- Replay the original false-positive request.
- Replay representative attack payloads for same endpoint family.
- Run local regression (`go-ftw`) on impacted rule families.
- Compare with CRS Sandbox only as reference signal, not production truth.

## Best Practices

- Always reproduce the false positive with controlled test traffic before writing an exclusion.
- Use the **narrowest exclusion possible** — specific URI + specific param + specific rule ID.
- Add both a false-positive regression test (verifying the FP is resolved) and an attack regression test (verifying the original attack is still caught).
- Document every exclusion with: rule ID, triggering URI/param, reason, and date added.
- Check existing CRS exclusion packages before writing custom exclusions — they may already cover your app.
- Re-run the full go-ftw suite after any exclusion change, not just the specific false-positive case.

## Related References

- [go-ftw-reference.md](go-ftw-reference.md) — Regression testing after tuning
- [first-responder-risk-runbook.md](first-responder-risk-runbook.md) — Incident-driven tuning
- [log-analysis-steering.md](log-analysis-steering.md) — Identifying false positives in logs
- [crs-application-profiles.md](crs-application-profiles.md) — Pre-built exclusion packages
- [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) — Exclusion antipatterns
