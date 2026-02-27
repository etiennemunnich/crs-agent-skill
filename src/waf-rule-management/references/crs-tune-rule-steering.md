# CRS Tune and Rule Steering

**Purpose**: Agent steering for tuning and managing OWASP CRS for a given version. Use when the user needs to understand how CRS rules work, which groups inspect what, request vs response flow, phase order, and version-aware tuning. Covers rule structure, file layout, and practical triage shortcuts.

**Target**: CRS v4.x. Verified against CRS v4.23.0–4.24.0, https://coreruleset.org/docs/2-how-crs-works/.

---

## Steering for LRMs

When the user mentions CRS tuning, rule groups, request/response, phases, or version-specific behavior:

1. **Identify intent** — Tuning FPs, understanding a rule ID, planning exclusions, or upgrading CRS
2. **Map rule ID to group** — Use the group table below; confirm file in the running CRS version
3. **Check phase** — Request rules: phase 1 (headers) or 2 (body); response rules: phase 3 or 4
4. **Suggest tool** — `analyze_log.py --explain-rule`, `detect_app_profile.py`, `generate_exclusion.py`
5. **Version caveat** — Rule IDs and group membership can change between CRS releases; always verify against the installed version

---

## 1. How CRS Rules Work

### Anomaly Scoring (Default Mode)

CRS uses **collaborative detection** and **delayed blocking**:

1. **Detection rules** — Match and increment anomaly score; they do **not** block immediately
2. **Blocking evaluation** — Separate rules (949xxx inbound, 959xxx outbound) compare total score to threshold and block if exceeded

| Step | What Happens |
|------|--------------|
| Execute all **request** rules (phase 1 + 2) | Each match adds to `tx.inbound_anomaly_score_plN` |
| **Blocking decision** (REQUEST-949) | If inbound score ≥ threshold → deny request |
| Execute all **response** rules (phase 3 + 4) | Each match adds to `tx.outbound_anomaly_score_plN` |
| **Blocking decision** (RESPONSE-959) | If outbound score ≥ threshold → block response (request already served) |

### Severity → Score

| Severity | Default Score |
|----------|---------------|
| CRITICAL | 5 |
| ERROR | 4 |
| WARNING | 3 |
| NOTICE | 2 |

### Per-Paranoia-Level Tracking

Scores are tracked per PL: `tx.inbound_anomaly_score_pl1`, `pl2`, etc. Blocking uses the configured `tx.blocking_paranoia_level`. Rules tagged `paranoia-level/N` only contribute when N ≤ configured PL.

---

## 2. Processing Phases

| Phase | Data Available | CRS Use |
|-------|-----------------|---------|
| **1** | Request headers | Protocol checks, method enforcement, header anomalies |
| **2** | Request body, ARGS, cookies, XML/JSON | Injection detection (SQLi, XSS, LFI, RCE, etc.) |
| **3** | Response headers | Leakage detection in headers |
| **4** | Response body | Leakage detection (SQL errors, stack traces, etc.) |
| **5** | Logging | Post-request logging (rare in CRS) |

**Critical**: Body variables (`ARGS`, `REQUEST_BODY`, `XML`, `JSON`) are **empty in phase 1**. Rules that inspect body must use phase 2.

---

## 3. Rule Groups and File Layout

### Request Rule Files (Inbound)

| File | Rule ID Range | Purpose |
|------|---------------|---------|
| REQUEST-900-EXCLUSION-RULES-BEFORE-CRS | — | **Runtime exclusions** (ctl:ruleRemoveById, etc.); load before CRS |
| REQUEST-901-INITIALIZATION | 901xxx | TX defaults, thresholds, paranoia level |
| REQUEST-905-COMMON-EXCEPTIONS | 905xxx | Common CRS-wide exclusions |
| REQUEST-911-METHOD-ENFORCEMENT | 911xxx | HTTP method enforcement |
| REQUEST-913-SCANNER-DETECTION | 913xxx | Scanner/bot fingerprinting |
| REQUEST-920-PROTOCOL-ENFORCEMENT | 920xxx | Protocol and header validation |
| REQUEST-921-PROTOCOL-ATTACK | 921xxx | Protocol-level attacks |
| REQUEST-922-MULTIPART-ATTACK | 922xxx | Multipart/form-data abuse |
| REQUEST-930-APPLICATION-ATTACK-LFI | 930xxx | Local file inclusion |
| REQUEST-931-APPLICATION-ATTACK-RFI | 931xxx | Remote file inclusion |
| REQUEST-932-APPLICATION-ATTACK-RCE | 932xxx | Remote code execution |
| REQUEST-933-APPLICATION-ATTACK-PHP | 933xxx | PHP injection |
| REQUEST-934-APPLICATION-ATTACK-GENERIC | 934xxx | Generic injection (Node.js, etc.) |
| REQUEST-941-APPLICATION-ATTACK-XSS | 941xxx | Cross-site scripting |
| REQUEST-942-APPLICATION-ATTACK-SQLI | 942xxx | SQL injection |
| REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION | 943xxx | Session fixation |
| REQUEST-944-APPLICATION-ATTACK-JAVA | 944xxx | Java injection |
| REQUEST-949-BLOCKING-EVALUATION | 949xxx | **Inbound blocking decision** |
| REQUEST-999-COMMON-EXCEPTIONS-AFTER | 999xxx | Post-CRS exceptions |
| REQUEST-999-EXCLUSION-RULES-AFTER-CRS | — | **Configure-time exclusions** (SecRuleRemoveById, etc.) |

### Response Rule Files (Outbound)

| File | Rule ID Range | Purpose |
|------|---------------|---------|
| RESPONSE-950-DATA-LEAKAGES | 950xxx | Generic response leakage |
| RESPONSE-951-DATA-LEAKAGES-SQL | 951xxx | SQL error leakage |
| RESPONSE-952-DATA-LEAKAGES-JAVA | 952xxx | Java stack trace leakage |
| RESPONSE-953-DATA-LEAKAGES-PHP | 953xxx | PHP error leakage |
| RESPONSE-954-DATA-LEAKAGES-IIS | 954xxx | IIS error leakage |
| RESPONSE-955-WEB-SHELLS | 955xxx | Web shell detection |
| RESPONSE-956-DATA-LEAKAGES-RUBY | 956xxx | Ruby error leakage |
| RESPONSE-959-BLOCKING-EVALUATION | 959xxx | **Outbound blocking decision** |
| RESPONSE-980-CORRELATION | 980xxx | Request/response correlation |
| RESPONSE-999-EXCLUSION-RULES-AFTER-CRS | — | Configure-time exclusions for response rules |

### Inclusion Order (Critical)

```
1. modsecurity.conf
2. crs-setup.conf
3. REQUEST-900-EXCLUSION-RULES-BEFORE-CRS   ← runtime exclusions first
4. REQUEST-901 … REQUEST-949 (CRS request rules)
5. REQUEST-999-EXCLUSION-RULES-AFTER-CRS    ← configure-time exclusions after
6. RESPONSE-950 … RESPONSE-959 (CRS response rules)
7. RESPONSE-999-EXCLUSION-RULES-AFTER-CRS
```

---

## 4. Group-by-Group Steering for Tuning

| Group | Main Goal | Typical Surface | Frequent FP Pattern | Safer First Tuning |
|-------|-----------|------------------|---------------------|---------------------|
| 901xxx | TX defaults, thresholds | Setup | Misconfigured variables | Fix config; avoid excluding 901 rules |
| 910xxx | IP reputation | Client IP | Internal scanners, NAT | Source + path allowlist, not global disable |
| 911xxx | Method enforcement | REQUEST_METHOD | APIs with uncommon verbs | Per-endpoint method tuning |
| 912/913xxx | Scanner detection | Headers, URI | Monitoring/QA tools | Narrow exclusions on known probe paths |
| 920/921xxx | Protocol checks | Headers, URI, encoding | Legacy clients, proxy quirks | Tune specific check before group removal |
| 930/931xxx | LFI/RFI | URI, ARGS, BODY | Legit file-like params | URI + param scoped target exclusions |
| 932xxx | RCE | ARGS, BODY | Admin inputs with shell-like strings | Param-scoped exclusions only |
| 933xxx | PHP injection | ARGS, BODY | CMS/plugin internals | Prefer CRS app profile/plugin first |
| 934xxx | Generic injection | ARGS, BODY | Code snippets, docs | Endpoint + param scoped |
| 941xxx | XSS | ARGS, BODY, cookies | Rich text editors, CMS content | Target exclusion on content fields + route |
| 942xxx | SQLi | ARGS, BODY, cookies | Search/filter with SQL-like terms | Param + URI scoped; keep rule elsewhere |
| 943xxx | Session fixation | Cookies, args | Custom session formats | Exclude specific token variables only |
| 944xxx | Java attacks | ARGS, BODY | Code snippet workflows | Endpoint + param scoped |
| 949xxx | Inbound block | TX scores | Threshold mismatch | Tune contributing rules before threshold |
| 95x outbound | Response leakage | Response body/headers | Verbose debug/error responses | Fix app error behavior before relaxing WAF |

---

## 5. Triage Shortcuts by Group

- **941xxx** and **942xxx** — Common high-volume; always inspect matched variable + payload first
- **920/921xxx** — Often transport/proxy/client edge cases more than app bugs
- **949/959** — Decision rules, not root-cause; tune upstream contributing rules first
- **Outbound (95x)** — Keep inbound and outbound tuning separate; outbound often noisier

---

## 6. Request vs Response

| Aspect | Request (Inbound) | Response (Outbound) |
|--------|-------------------|---------------------|
| Phases | 1 (headers), 2 (body) | 3 (headers), 4 (body) |
| Blocking | Request denied before backend | Response blocked after backend served it |
| Threshold | `tx.inbound_anomaly_score_threshold` (default 5) | `tx.outbound_anomaly_score_threshold` (default 4) |
| Evaluation | REQUEST-949-BLOCKING-EVALUATION | RESPONSE-959-BLOCKING-EVALUATION |
| Body access | `SecRequestBodyAccess On` | `SecResponseBodyAccess On` (performance cost) |

**Note**: Response body inspection is disabled by default in many deployments. Enabling it increases CPU and memory use; enable only when needed.

---

## 7. Version-Aware Tuning

- **Rule IDs** — Generally stable; exact rule membership can change between releases
- **Group intent** — Stable across minor versions
- **New rules** — New IDs added; some logic may move into plugins
- **Before broad exclusions** — Confirm loaded files and rule IDs in the running CRS version

```bash
# Check installed CRS version (from container or config)
grep -r "ver:'OWASP_CRS" /path/to/crs/rules/ | head -1

# List rules in a group
grep -E "^\s*SecRule" REQUEST-942-APPLICATION-ATTACK-SQLI.conf | wc -l
```

---

## 8. Key Setup Variables (crs-setup.conf)

| Variable | Purpose | Default |
|----------|----------|---------|
| `tx.blocking_paranoia_level` | PL for blocking decisions | 1 |
| `tx.detection_paranoia_level` | PL for rule execution (can be higher for observe-only) | = blocking_paranoia_level |
| `tx.inbound_anomaly_score_threshold` | Inbound block threshold | 5 |
| `tx.outbound_anomaly_score_threshold` | Outbound block threshold | 4 |
| `tx.critical_anomaly_score` | Score for CRITICAL severity | 5 |
| `tx.blocking_early` | Enable early blocking (after phase 1/3) | 0 |

---

## 9. Agent Steering: When to Suggest What

| User Says | Suggest |
|-----------|---------|
| "What does rule 942100 do?" | Map to 942xxx group (SQLi); explain phase 2, ARGS/BODY; suggest `analyze_log.py --explain-rule 942100` |
| "Which group handles XSS?" | 941xxx (REQUEST-941-APPLICATION-ATTACK-XSS.conf) |
| "Request vs response rules?" | Phase 1/2 = request; phase 3/4 = response; 949 = inbound block; 959 = outbound block |
| "Upgrading CRS, what changes?" | Check CHANGES file; run `analyze_log.py` on old logs; compare rule IDs per group |
| "Tuning 942xxx FPs" | Param + URI scoped exclusion; use `generate_exclusion.py`; validate with `validate_exclusion.py` |
| "Outbound rules firing" | 95x families; often app error leakage; fix app before relaxing WAF |

---

## 10. Related References

- [crs-rule-format.md](crs-rule-format.md) — Rule style, ID ranges, chaining
- [anomaly-scoring.md](anomaly-scoring.md) — Thresholds, severity scores
- [paranoia-levels.md](paranoia-levels.md) — PL rollout, split PL
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies
- [crs-application-profiles.md](crs-application-profiles.md) — Built-in app packages
- [openapi-to-waf.md](openapi-to-waf.md) — Inclusion order, before-CRS rules

## 11. Official Sources

- CRS How It Works: https://coreruleset.org/docs/2-how-crs-works/
- Anomaly Scoring: https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
- Paranoia Levels: https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/
- CRS GitHub (rules): https://github.com/coreruleset/coreruleset/tree/main/rules
