# ModSecurity Directives Reference

Key ModSecurity v3 directives for rule operations, engine configuration, and logging.

**Verified against**: ModSecurity v3.0.14, [Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).

---

## Engine Directives

| Directive | Values | Purpose |
|-----------|--------|---------|
| `SecRuleEngine` | `On`, `Off`, `DetectionOnly` | Master switch. `DetectionOnly` logs but does not block — use for initial rollout. |
| `SecRequestBodyAccess` | `On`, `Off` | Enable request body inspection (phase 2). Must be `On` for POST/PUT rule scanning. |
| `SecResponseBodyAccess` | `On`, `Off` | Enable response body inspection (phase 4). Performance cost; enable only if needed. |
| `SecRequestBodyLimit` | bytes | Max request body size. Requests exceeding this are rejected. Default: 13107200 (12.5 MB). |
| `SecResponseBodyLimit` | bytes | Max response body size for inspection. |
| `SecRequestBodyNoFilesLimit` | bytes | Max body size excluding file uploads. Default: 131072 (128 KB). |
| `SecTmpDir` | path | Temp directory for request body buffering. Must be writable by the web server. |
| `SecDataDir` | path | Persistent data directory for `initcol`/`setsid`. Must be writable. |

## Rule Directives

| Directive | Purpose | Example |
|-----------|---------|---------|
| `SecRule` | Define a rule with variable, operator, actions | `SecRule ARGS "@rx attack" "id:1,deny"` |
| `SecAction` | Unconditional action (no variable/operator) | `SecAction "id:900000,phase:1,pass,setvar:tx.crs_setup=1"` |
| `SecMarker` | Named label for `skipAfter` | `SecMarker END_CUSTOM_RULES` |
| `SecDefaultAction` | Default actions for subsequent rules | `SecDefaultAction "phase:2,log,auditlog,deny,status:403"` |
| `SecRuleRemoveById` | Remove rule by ID (configure-time, after CRS) | `SecRuleRemoveById 942100` |
| `SecRuleRemoveByTag` | Remove rules by tag | `SecRuleRemoveByTag "attack-sqli"` |
| `SecRuleUpdateTargetById` | Exclude variable from rule (configure-time) | `SecRuleUpdateTargetById 942100 "!ARGS:q"` |
| `SecRuleUpdateActionById` | Change a rule's actions | `SecRuleUpdateActionById 942100 "deny,status:403"` |

## Logging Directives

| Directive | Values | Purpose |
|-----------|--------|---------|
| `SecAuditEngine` | `On`, `Off`, `RelevantOnly` | Audit log master switch. `RelevantOnly` logs only transactions with rule matches or errors. |
| `SecAuditLogFormat` | `JSON`, `Native` | Output format. JSON recommended for automated analysis. |
| `SecAuditLog` | path | Audit log file path. Use `/dev/stderr` in containers. |
| `SecAuditLogParts` | section letters | Which sections to log: `ABCFHZ` is common. `K` is not implemented in v3. |
| `SecAuditLogRelevantStatus` | regex | Status codes to audit when `RelevantOnly`. Example: `"^(?:5\|4(?!04))"` |
| `SecDebugLog` | path | Debug log path (very verbose; use for troubleshooting only). |
| `SecDebugLogLevel` | 0–9 | Debug verbosity. 0=off, 3=warnings, 5=detailed, 9=everything. |

## PCRE Directives (v2 only)

| Directive | Default | Purpose |
|-----------|---------|---------|
| `SecPcreMatchLimit` | 1000 | Max PCRE match attempts. Prevents ReDoS. |
| `SecPcreMatchLimitRecursion` | 1000 | Max PCRE recursion depth. |

**Note**: These are v2-only. ModSecurity v3 uses compile-time PCRE limits. As of 2025, v3 is transitioning to PCRE2 as the default engine. See [regex-steering-guide.md](regex-steering-guide.md) for PCRE2 migration.

### PCRE Limit Tuning (v2)

`MSC_PCRE_LIMITS_EXCEEDED` (rule 200004) is the most frequently reported false positive class in ModSecurity v2 deployments. It is typically triggered by long query strings from social media tracking parameters (Facebook, Google Ads UTM chains) and complex ad-campaign URLs — not by malicious traffic.

Community-validated safe values:

| Profile | `SecPcreMatchLimit` | Notes |
|---------|---------------------|-------|
| Default (unchanged) | 1000 | Blocks some legitimate ad-campaign traffic |
| Most production sites | 1500–2000 | Handles social media tracking params; recommended starting point |
| Low-traffic sites | up to 10 000 | Acceptable when request volume is small |
| Vendor suggestion (avoid) | 250 000 | Community consensus: causes resource exhaustion under load |

Raise these limits **only** when audit logs confirm 200004 is triggering on legitimate traffic (tracking params, long query strings) and your regexes have been validated with `lint_regex.py`. Do not raise limits as a substitute for fixing ReDoS-prone patterns.

---

## Best Practices

- **Start with `DetectionOnly`** in new environments. Switch to `On` after tuning.
- **Enable `SecRequestBodyAccess On`** — without it, POST/PUT payloads are invisible to rules.
- **Use `JSON` audit log format** for automated analysis with `analyze_log.py` and `jq`.
- **Set `SecAuditEngine RelevantOnly`** in production to avoid logging clean traffic.
- **Keep `SecRequestBodyNoFilesLimit` reasonable** — 128 KB default is fine for most APIs.
- **Use `SecRuleUpdateTargetById`** for precise exclusions instead of removing entire rules.
- **Place configure-time exclusions after CRS include**, runtime exclusions (`ctl:`) before CRS.

## What to Avoid

- **`SecRuleEngine Off`** as a troubleshooting shortcut — use `DetectionOnly` instead.
- **`SecAuditLogParts ABCDEFGHIJKZ`** — logging everything is expensive. Section K is not implemented in v3.
- **`SecDebugLogLevel` above 3 in production** — massive log volume, performance impact.
- **Raising `SecPcreMatchLimit`** as a substitute for fixing ReDoS-prone regexes (v2) — raising is appropriate for the 200004 tracking-param FP class when regexes are sound.
- **Missing `SecTmpDir`/`SecDataDir`** — causes silent failures for body buffering and persistent collections.
- **Editing CRS rule files directly** — use exclusion directives instead.

---

## Related References

- [actions-reference.md](actions-reference.md) — Rule actions (`deny`, `chain`, `setvar`)
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies
- [regex-steering-guide.md](regex-steering-guide.md) — PCRE2 migration, ReDoS
- ModSecurity v3 Reference Manual: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
- ModSecurity v3 GitHub: https://github.com/owasp-modsecurity/ModSecurity
