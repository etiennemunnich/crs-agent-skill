# Antipatterns and Troubleshooting

**Purpose**: Equip LRMs (language models) and agents to recognize bad patterns, steer users toward correct solutions, and troubleshoot common WAF/CRS issues. When assisting, **flag antipatterns** and **suggest fixes** rather than implementing them silently.

---

## Steering for LRMs

When the user proposes or shows code/config that matches an antipattern below:

1. **Recognize** — Identify which antipattern applies
2. **Explain** — Briefly state why it's problematic
3. **Redirect** — Point to the correct approach or reference
4. **Offer fix** — Provide corrected example when appropriate

Do not silently accept antipatterns. Proactively steer toward best practices.

---

## 1. Rule Antipatterns

| Antipattern | Why It's Bad | Correct Approach |
|-------------|--------------|------------------|
| **Modifying CRS rule files directly** | Creates a fork; updates overwrite changes; maintenance burden | Use rule exclusions (SecRuleRemoveById, ctl:ruleRemoveTargetById) in separate config |
| **Using @rx for exact/fixed strings** | Slower, ReDoS risk, unnecessary | Use @streq, @pm, @beginsWith, @contains |
| **Nested quantifiers in regex** | ReDoS; CPU exhaustion; DoS | Use single quantifier, atomic groups, or @pm |
| **ARGS without t:urlDecodeUni** | Encoded payloads bypass detection | Add t:urlDecodeUni when matching ARGS with @rx |
| **Wrong phase for variable** | Variable not yet available → false negative | Phase 1: headers; Phase 2: body, ARGS, XML |
| **Over-broad variable (ARGS vs ARGS:param)** | More FPs, slower, inspects unrelated data | Use narrowest variable that detects the threat |
| **Capture groups when not needed** | Performance cost | Use `(?:...)` for non-capturing |
| **Rule ID in CRS range (900000–999999)** | Conflicts with CRS | Use 100000–199999 for custom rules |
| **Missing id action** | Hard to exclude, debug, or reference | Always include id:NNNNNN |
| **Lookahead/lookbehind in rules** | PCRE-only; breaks Coraza/RE2 | Use alternative pattern or chain |

---

## 2. Configuration Antipatterns

| Antipattern | Why It's Bad | Correct Approach |
|-------------|--------------|------------------|
| **SecRuleEngine Off** (in production) | No protection | Use On; use DetectionOnly only for initial tuning |
| **SecRequestBodyAccess Off** | Cannot inspect POST; major blind spot | Always On for WAF use |
| **Exclusion placed after CRS for runtime** | Runtime exclusions must run before rules | Put ctl:ruleRemove* in BEFORE-CRS config |
| **Exclusion placed before CRS for configure-time** | SecRuleRemove* must run after rules exist | Put SecRuleRemove* in AFTER-CRS config |
| **Global rule/tag removal** | Disables protection broadly | Narrow to URI, method, or specific variable |
| **Lowering anomaly threshold below 5/4** | Weakens blocking | Keep default; tune exclusions instead |
| **Public /tmp for SecTmpDir, SecDataDir** | Security risk | Use private, non-world-readable dirs |

---

## 3. Exclusion Antipatterns

| Antipattern | Why It's Bad | Correct Approach |
|-------------|--------------|------------------|
| **SecRuleRemoveByTag attack-sqli** (global) | Removes all SQLi rules everywhere | Use ctl:ruleRemoveTargetById for specific param at specific URI |
| **Excluding by msg** | Msg can change; fragile | Prefer SecRuleRemoveById or ByTag |
| **Excluding entire rule when only one param triggers** | Loses protection for other inputs | Use ctl:ruleRemoveTargetById=ID;ARGS:param |
| **No condition on exclusion** | Applies to all traffic | Add REQUEST_URI, REQUEST_METHOD, etc. |
| **Exclusion in wrong file** | Won't take effect | BEFORE-CRS for runtime; AFTER-CRS for configure-time |
| **Regex in `ctl:ruleRemoveTargetById`** | Silently fails — ModSec ignores regex target selectors; rule still fires | Use a literal name: `ctl:ruleRemoveTargetById=933150;REQUEST_COOKIES:session-token` |
| **`ctl:ruleRemoveTargetById` on a chained rule** | Target exclusion doesn't propagate through chain links; chain still matches | Use `ctl:ruleRemoveById=RULE_ID` scoped to the URI instead |
| **Duplicate custom rule IDs** | Second rule silently overwrites first; one exclusion never runs | Assign unique IDs — use a counter (100001, 100002, …) and keep a project ID registry |

---

## 4. Deployment and Tuning Antipatterns

| Antipattern | Why It's Bad | Correct Approach |
|-------------|--------------|------------------|
| **Enabling blocking before tuning** | Legitimate traffic blocked; user complaints | Start DetectionOnly or sampling; tune; then block |
| **Jumping to PL3/PL4 without exclusions** | High FP rate; alert fatigue | Start PL1; add exclusions; increase gradually |
| **Disabling CRS due to FPs** | Drops all protection | Tune exclusions; use rule exclusion packages |
| **Reporting PL2+ FPs to CRS** | Expected at higher PL; not a bug | Write exclusions; see CRS docs |
| **Ignoring REQBODY_ERROR, MULTIPART_STRICT_ERROR** | Impedance mismatch; evasion risk | Add rules to check these variables |

---

## 5. Troubleshooting Flow

When the user reports "rule not working", "blocking legitimate traffic", "WAF not blocking", or similar:

### Rule not matching (expected block, no block)

1. **Phase** — Is the rule in the right phase? ARGS/body need phase 2.
2. **Variable** — Is the target variable populated? (e.g. ARGS only after body parsed)
3. **Transform** — Is encoding bypassing? Add t:urlDecodeUni, t:htmlEntityDecode.
4. **Operator** — Case sensitivity? Add t:lowercase or (?i) in pattern.
5. **Anomaly score** — Single rule may not reach threshold; check crs-setup.conf.

### Legitimate traffic blocked (false positive)

1. **Identify rule** — Get rule ID from audit/error log.
2. **Scope** — Narrowest exclusion: specific URI + specific param/variable.
3. **Placement** — Runtime → BEFORE-CRS; Configure-time → AFTER-CRS.
4. **Test** — Validate exclusion with same request; check for regression.

### WAF not loading / config error

1. **Syntax** — Run `validate_rule.py` on custom rules.
2. **Include order** — Base config → crs-setup → rules → exclusions.
3. **Paths** — Include paths correct; files exist.
4. **Logs** — Check ModSecurity/Coraza error log for parse errors.

### Performance / timeouts

1. **ReDoS** — Run `lint_regex.py`; check for nested quantifiers.
2. **PCRE limits** — MSC_PCRE_LIMITS_EXCEEDED in logs.
3. **Body size** — SecRequestBodyLimit, SecResponseBodyLimit.
4. **Rule count** — Consider disabling unused rule files or tags.

---

## 6. Quick Reference: Exclusion Placement

| Exclusion Type | Directive/Action | Placement |
|----------------|-------------------|-----------|
| Remove rule globally | SecRuleRemoveById | **After** CRS include |
| Remove rule for URI | ctl:ruleRemoveById | **Before** CRS include |
| Exclude variable from rule | SecRuleUpdateTargetById | **After** CRS include |
| Exclude variable for URI | ctl:ruleRemoveTargetById | **Before** CRS include |

---

## 7. Best Practices (Positive Counterparts)

For every antipattern above, the correct approach is documented. When steering agents/users:

- Always offer the **correct approach** alongside identifying the antipattern — don't just say "wrong", show "right".
- Use the troubleshooting flow (Section 5) as a systematic checklist rather than guessing.
- Start with the most common cause first — wrong phase and missing transforms account for the majority of "rule not working" reports.
- Validate every fix with regression tests — the troubleshooting flow should always end with a go-ftw run.

## 8. Related References

- [best-practices-modsec-coraza-crs.md](best-practices-modsec-coraza-crs.md) — Positive best practices
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion decision tree
- [regex-steering-guide.md](regex-steering-guide.md) — Regex quality and ReDoS prevention
- [log-analysis-steering.md](log-analysis-steering.md) — Diagnosing issues from logs
- [CRS False Positives and Tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)
