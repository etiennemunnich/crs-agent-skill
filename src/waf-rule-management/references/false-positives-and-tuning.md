# False Positives and Tuning

Use this guide when legitimate traffic is blocked or heavily scored by CRS.
Goal: reduce false positives while preserving detection depth.

**Steering scope**: This reference describes mechanisms, process, and decision frameworks — not issue-specific examples. For concrete cases (e.g. a given CRS issue), use the process here and check CRS issues / user-provided context.

**Verified against** (2026-02-15):
- https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/
- https://coreruleset.org/docs/4-about-plugins/4-1-plugins/

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

## FP Category Quick Routing

When no CRS issue match is found, classify by symptom and route to the right approach:

| Symptom | Likely category | Example rules | Reference |
|---------|-----------------|---------------|-----------|
| Non-ASCII (Cyrillic, Chinese, Bengali) in payload | Encoding / transform order | 941xxx, 942xxx | [operators-and-transforms.md](operators-and-transforms.md) — transform pitfalls |
| Natural language ("watch has been used", "time based", place names) | Natural language / regex overmatch | 932xxx, 933xxx | `crs-toolchain util fp-finder`; target exclusion on param |
| GraphQL query/body | GraphQL / structured query | 932xxx | URI-scoped `ctl:ruleRemoveById`; target exclusion may not work (phase ordering) |
| "select", punctuation (`"! N`), apostrophe, Punycode in benign text | SQL keyword/pattern in text | 942xxx | Target exclusion on param; search CRS issues for rule ID |
| Multipart with colons in header | Multipart / app-specific | 922xxx | JSF/form exclusion; URI-scoped |
| Response body text ("file size is") | Response body | 953xxx | URI-scoped rule removal |
| Different behavior across engines or CRS versions | Engine / platform | 932xxx | Engine-specific; check CRS version and release notes |
| **FP after CRS upgrade** (e.g. "after v4.24.0, rule N fires") | Post-upgrade / regex-change | 942xxx, 932xxx | See [Post-Upgrade / Regex-Change FP](#post-upgrade--regex-change-fp) below |

## Tiered FP Model (When Adding New Paths/Rules)

When adding new detection (e.g. paths to restricted-files, new rules), categorize by FP risk:

| Tier | FP risk | Action | Example |
|------|---------|--------|---------|
| **Tier 1** | Low | Block globally | Highly specific paths (e.g. `.claude/`, `.cursor/`) — rarely legitimate in URLs |
| **Tier 2** | Medium | Alert / increase anomaly score (no block) | Generic names (e.g. `mcp.json`, `AGENTS.md`) — may be legitimate elsewhere |
| **Tier 3** | High | Chained rules only — block only when path context matches | Generic config (e.g. `settings.local.json`) — block only inside known AI paths |

Use **chained rules** for Tier 3: match generic filename only when the path contains a known AI directory (e.g. `/.claude/settings.local.json` → block; `/api/config.toml` → allow).

---

## Production Rollout Strategy

When adding CRS to **existing production traffic**, start with a high anomaly threshold to avoid blocking legitimate users while you tune. Lower the threshold iteratively as you fix false positives:

```
10,000 → 100 → 50 → 20 → 10 → 5
```

At each step: deploy, observe, tune away FPs, then lower. A threshold of 5 (default) blocks on the first CRITICAL match; only reach it after FPs are under control. See [sampling-mode.md](sampling-mode.md) for the full production retrofit path.

## Standard Tuning Workflow

1. Reproduce with controlled test traffic (same path, params, headers, body).
2. **Prioritize by anomaly score** — when triaging many FPs, tackle highest-scoring requests first. They block the most traffic and often share common rule patterns.
3. Collect evidence from error log + audit log:
   - rule ID
   - matched variable (`ARGS`, `REQUEST_COOKIES`, etc.)
   - URI/method context
   - anomaly score impact
4. Classify event:
   - true positive
   - acceptable behavior to allow
   - unknown (needs app owner validation)
5. Use `python scripts/analyze_log.py audit.log --explain-rule <RULE_ID> --detail` to capture exact target/payload evidence.
6. **Search CRS issues** — Check [coreruleset/coreruleset Issues](https://github.com/coreruleset/coreruleset/issues) for the rule ID. Similar FPs often have documented exclusion patterns or upstream fixes. **Post-upgrade FP?** — If the FP appeared after a CRS upgrade, follow [Post-Upgrade / Regex-Change FP](#post-upgrade--regex-change-fp) below. If reporting upstream, use the [CRS false-positive template](https://github.com/coreruleset/coreruleset/issues/new?template=01_false-positive.md) — see [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md#8-reporting-to-crs-issue-template).
7. Run `python scripts/detect_app_profile.py audit.log` to check if an official CRS app profile/plugin applies first.
8. Apply the narrowest safe exclusion.
9. Validate exclusion safety: `python scripts/validate_exclusion.py --input exclusion.conf`.
10. Re-test:
    - false-positive transaction passes
    - known attack payloads are still detected/blocked
11. Add regression coverage in `go-ftw` for the case.

## Post-Upgrade / Regex-Change FP

When the user reports "after upgrading to vX.Y.Z, rule N fires" or "rule N started blocking after a recent update" — the FP may be a regression from a regex fix. Based on patterns from CRS issues (e.g. [#4502](https://github.com/coreruleset/coreruleset/issues/4502), [#4476](https://github.com/coreruleset/coreruleset/pull/4476)).

**Additional capture**: CRS version before/after; **Matched Data** from log `[data "Matched Data: ..."]` — the minimal substring that triggered the regex.

**Workflow**:
1. **Trace to recent change** — Search CRS issues for rule ID; check PRs that fix/modify the rule ("fix(942200)", etc.); check [release notes](https://github.com/coreruleset/coreruleset/releases).
2. **Analyze regex** — If CRS repo available: `git show v4.23.0:rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf | grep -A 5 "942200"` vs current; or `crs-toolchain regex compare 942200`, `crs-toolchain util fp-finder 942200`.
3. **Variable-target check** — Rules designed for ARGS/body may overmatch on headers. `REQUEST_HEADERS:User-Agent` has different FP semantics (browser UAs like ", like Gecko) Chrome") than `ARGS:param`. Consider whether target exclusion works or URI-scoped `ctl:ruleRemoveById` is needed.
4. **Immediate options** — **Downgrade** to the previous CRS version in production until upstream fixes (common when FPs are widespread, e.g. all Chrome UAs). Or **apply narrowest exclusion** — target exclusion if variable is static; otherwise URI-scoped `ctl:ruleRemoveById`. Document rule ID, URI, reason, CRS issue link.
5. **Report upstream** — If widespread (e.g. all Chrome UAs): use [CRS false-positive template](https://github.com/coreruleset/coreruleset/issues/new?template=01_false-positive.md); **reference the PR** that introduced the change (e.g. "Regression from #4476"); test on [sandbox.coreruleset.org](https://sandbox.coreruleset.org/) first.

## Exclusion Decision Tree

Prefer this order:

1. **Runtime target exclusion** (most precise)
2. **Configure-time target exclusion**
3. **Runtime remove by ID/tag** (URI/method scoped)
4. **Configure-time remove by ID/tag** (global last resort)

### Rule Group-Aware Tuning (General Guidance)

When selecting exclusions, consider the rule group semantics first:

| Group | Typical Meaning | Tuning Bias |
|------|------------------|-------------|
| 920/921xxx | Protocol sanity/evasion checks | Prefer narrow protocol-specific fixes; avoid broad group removal |
| 941xxx | XSS detectors | Usually content-field FPs; target exclusion on specific field+route |
| 942xxx | SQLi detectors | Usually search/filter FPs; param+URI scoped exclusions |
| 949/959xxx | Blocking evaluation | Treat as symptom; tune contributing rules/threshold policy |
| 95x outbound | Response leak/anomaly checks | Tune app error behavior and response patterns before exclusion |

Rule group details vary by CRS version; verify active files/rules in your running CRS release before writing broad exclusions. For full group mapping, phase order, and request/response flow: [crs-tune-rule-steering.md](crs-tune-rule-steering.md).

### Placement Rules (Critical)

Runtime (`ctl:*`) → BEFORE-CRS, **phase 1**. Configure-time (`SecRuleRemove*`, `SecRuleUpdateTarget*`) → AFTER-CRS. Full table: [antipatterns-and-troubleshooting.md#6-quick-reference-exclusion-placement](antipatterns-and-troubleshooting.md#6-quick-reference-exclusion-placement).

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

Configure-time, regex target (for dynamically named variables, e.g. session cookies):

```apache
# Exclude cookies matching pattern (enclose regex in /.../)
SecRuleUpdateTargetById 942440 "!REQUEST_COOKIES:/^uid_.*/"
```

**Note**: Target exclusions apply only to the **first rule** in a chained rule. For chained rules where the problematic target is in a later rule, you may need `SecRuleRemoveById` or `ctl:ruleRemoveById` instead.

**Dynamic variable keys** (e.g. array indices, generated param names): `ctl:ruleRemoveTargetById` does not support regex targets. `SecRuleUpdateTargetById` supports regex in the target but is configure-time and **global** — no URI scope. When the matched variable uses dynamic keys, prefer URI-scoped `ctl:ruleRemoveById` for the affected path.

Configure-time, full rule removal (last resort):

```apache
SecRuleRemoveById 920273
```

## What to Avoid

- Editing CRS rule files directly; global removal; excluding by msg; skipping regression; raising thresholds instead of fixing FPs.
- Rule ranges in `ctl:ruleRemoveById` — ModSecurity v3 does not support; use `SecRuleRemoveById` (configure-time) or exclude individually.
- Full antipattern catalog: [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md).

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

## Related

[antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) | [crs-tune-rule-steering.md](crs-tune-rule-steering.md) | [crs-application-profiles.md](crs-application-profiles.md) | [go-ftw-reference.md](go-ftw-reference.md)
