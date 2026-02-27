# CRS Rule Format and Contribution Guide

Style and formatting requirements for writing CRS-compatible rules, whether for contribution upstream or for consistent custom rules.

**Verified against**: CRS v4.23.0, https://coreruleset.org/docs/development/.

---

## CRS-Style Rule Template

```apache
SecRule VARIABLE "@OPERATOR pattern" \
    "id:NNNNNN,\
    phase:N,\
    ACTION,\
    status:NNN,\
    log,\
    msg:'Clear description of what this detects',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'attack-TYPE',\
    tag:'OWASP_CRS',\
    tag:'capec/NNNN',\
    tag:'paranoia-level/N',\
    ver:'OWASP_CRS/4.x.x',\
    severity:'SEVERITY',\
    setvar:'tx.inbound_anomaly_score_plN=+%{tx.critical_anomaly_score}'"
```

---

## Required Metadata

| Field | Requirement | Notes |
|-------|-------------|-------|
| `id` | Mandatory, unique | CRS ranges: 9xxxxx. Custom: 100000–199999. |
| `phase` | Mandatory | 1 (headers) or 2 (body) for request rules. |
| `msg` | Mandatory | Human-readable, describes what was detected. |
| `severity` | Mandatory | `CRITICAL` (5), `ERROR` (4), `WARNING` (3), `NOTICE` (2). |
| `tag` | Required | At minimum: attack category + `OWASP_CRS` + `paranoia-level/N`. |
| `ver` | Required for CRS | Format: `OWASP_CRS/4.x.x`. For custom: `<project>/N.N`. |
| `logdata` | Recommended | Include `%{TX.0}`, `%{MATCHED_VAR_NAME}`, `%{MATCHED_VAR}`. |

---

## Rule ID Ranges

### CRS Ranges

| Range | Category |
|-------|----------|
| 901xxx | Initialization |
| 910xxx | IP reputation |
| 911xxx | Method enforcement |
| 912xxx | Scanner detection |
| 913xxx | Scanner fingerprinting |
| 920xxx | Protocol enforcement |
| 921xxx | Protocol attack |
| 930xxx | LFI (Local File Inclusion) |
| 931xxx | RFI (Remote File Inclusion) |
| 932xxx | RCE (Remote Code Execution) |
| 933xxx | PHP injection |
| 934xxx | Node.js/generic injection |
| 941xxx | XSS (Cross-Site Scripting) |
| 942xxx | SQLi (SQL Injection) |
| 943xxx | Session fixation |
| 944xxx | Java attack |
| 949xxx | Inbound blocking evaluation |
| 950xxx–959xxx | Outbound rules |

### Version Variance Notes

- Rule IDs and group intent are generally stable, but exact rule membership changes across CRS releases.
- Some logic may move into plugins or be refactored between minor/major versions.
- Before broad exclusions, confirm loaded files/rules in the running CRS version.

Verify against:
- https://github.com/coreruleset/coreruleset
- https://coreruleset.org/docs/

### CRS Rule Groups in Practice

Use this for steering during triage and tuning.

| Group | Main Goal | Typical Surface | Frequent FP Pattern | Safer First Tuning |
|------|-----------|-----------------|---------------------|--------------------|
| 901xxx Initialization | Configure TX defaults/thresholds | Setup phase | Misconfigured setup variables | Fix config; avoid excluding 901 rules |
| 910xxx IP reputation | Flag known risky source ranges | Client IP | Internal scanners/NAT testing traffic | Source + path allowlisting, not global disable |
| 911xxx Method enforcement | Enforce expected HTTP methods | Request method | API endpoints with uncommon verbs | Per-endpoint method tuning |
| 912/913xxx Scanner detection | Detect scanner behavior/signatures | Headers/URI | Monitoring/QA tooling | Narrow signal exclusions on known probe paths |
| 920/921xxx Protocol checks | Detect protocol violations/evasion | Headers/URI/encoding | Legacy clients/proxy quirks | Tune specific check before group-level removals |
| 930/931xxx File inclusion | LFI/RFI/path traversal detection | URI/ARGS/BODY | Legit file-like app parameters | URI+param scoped target exclusions |
| 932xxx RCE | Command-injection indicators | ARGS/BODY | Admin/dev inputs with shell-like strings | Param-scoped exclusions only |
| 933xxx PHP injection | PHP-specific abuse patterns | ARGS/BODY | CMS/plugin internals | Prefer CRS app profile/plugin before custom rules |
| 941xxx XSS | Script/HTML injection detection | ARGS/BODY/cookies | Rich text editors and CMS content fields | Target exclusion on content fields + route |
| 942xxx SQLi | SQL lexical/pattern detection | ARGS/BODY/cookies | Search/filter parameters with SQL-like terms | Param+URI scoped exclusion; keep rule elsewhere |
| 943xxx Session fixation | Session token misuse checks | Cookies/args | Custom session/token formats | Exclude specific token variables only |
| 944xxx Java attacks | Java-specific injection patterns | ARGS/BODY | Code snippet/docs workflows | Endpoint+parameter scoped exclusion |
| 949xxx Inbound evaluation | Inbound anomaly block decision | TX scores | Threshold-policy mismatch | Tune contributing rules before threshold changes |
| 95x outbound families | Leakage/outbound evaluation | Response body/headers/status | Verbose debug/error responses | Fix app error behavior before relaxing WAF |

### Triage Shortcuts by Group

- `941xxx` and `942xxx` are common high-volume groups; always inspect matched variable + payload evidence first.
- `920/921xxx` spikes often indicate transport/proxy/client edge cases more than direct app bugs.
- `949/959` are decision rules, not root-cause signatures; tune upstream contributing rules first.
- Keep inbound and outbound tuning separate to avoid masking real response leakage.

### Custom Rule Ranges

| Range | Use |
|-------|-----|
| 100000–199999 | Custom rules (per-incident, auto-allocated by `new_incident.sh`) |
| 200000–299999 | Custom rules (alternative range) |

---

## Chained Rules

For multi-condition matching, use `chain`. Only the **first rule** carries `id`, disruptive action, and metadata.

```apache
SecRule REQUEST_METHOD "@streq POST" \
    "id:100010,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'POST with script tag in body',\
    tag:'custom/xss-post',\
    severity:'CRITICAL',\
    chain"
    SecRule REQUEST_BODY "@rx <script" \
        "t:lowercase,\
        t:htmlEntityDecode"
```

### Chaining Rules

- **First rule**: `id`, phase, disruptive action (`deny`/`pass`), `msg`, `tag`, `severity`, `chain`.
- **Chained rules**: Only transforms and operators. No `id`, no disruptive action.
- **All conditions must match** for the action to fire.
- **Max chain depth**: Keep short (2–3 rules). Deep chains are hard to debug.

---

## Tagging Convention

```apache
tag:'attack-sqli',           # Attack category
tag:'OWASP_CRS',             # CRS identification
tag:'capec/1000/255/153/66', # CAPEC classification
tag:'paranoia-level/1',      # PL where this rule is active
tag:'PCI/6.5.2',             # PCI-DSS mapping (if applicable)
```

For custom/virtual-patch rules:

```apache
tag:'virtual-patch',
tag:'CVE-2025-55182',
tag:'custom/react-flight',
```

---

## Anomaly Scoring Convention

Rules should use `setvar` to increment the anomaly score for the appropriate paranoia level:

```apache
setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'   # PL1, CRITICAL
setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'    # PL2, WARNING
```

Score variables: `tx.critical_anomaly_score` (5), `tx.error_anomaly_score` (4), `tx.warning_anomaly_score` (3), `tx.notice_anomaly_score` (2).

For virtual-patch rules that must block immediately: use `deny,status:403` instead of anomaly scoring.

---

## Formatting Rules

- **Line continuation**: Use `\` at end of line for multi-line rules.
- **Indentation**: 4 spaces for continued actions.
- **One action per line** (for readability in CRS contributions).
- **Quote consistency**: Single quotes for action string values.
- **Operator explicit**: Always write `@rx`, never rely on implicit regex.

### Lint Check

```bash
python scripts/lint_crs_rule.py rule.conf      # CRS convention check
python scripts/validate_rule.py rule.conf       # Syntax validation
```

---

## CRS Contribution Workflow

1. Fork https://github.com/coreruleset/coreruleset.
2. Write rule following the template above.
3. Lint: `python scripts/lint_crs_rule.py your-rule.conf`.
4. If using `@rx` with complex patterns, create a `.ra` file and use `crs-toolchain regex generate`.
5. Run `crs-toolchain util fp-finder RULE_ID` from CRS repo root to check for false positive candidates.
6. Write regression tests (positive + negative cases) in go-ftw format.
7. Run full test suite: `go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/`.
8. Submit PR with rule + tests + `.ra` file (if applicable).

See https://coreruleset.org/docs/development/ for contribution guidelines.

---

## Best Practices

- **Always include `logdata`** — makes audit log analysis actionable.
- **Narrow your variable** — `ARGS:param` over `ARGS` when possible.
- **Prefer `@pm` over `@rx`** for fixed word lists — faster and no ReDoS risk.
- **Use non-capturing groups** `(?:...)` in regex — capturing groups cost performance.
- **Test both attack and benign** — every rule needs a non-trigger test case.
- **Keep `msg` meaningful** — it appears in logs and must explain the detection clearly.

## What to Avoid

- **Missing `id`** — rule won't load.
- **Missing `phase`** — defaults are unreliable.
- **Broad `ARGS` with no `logdata`** — impossible to debug which parameter triggered.
- **`@rx` for exact strings** — use `@streq`, `@pm`, `@beginsWith` instead.
- **Deep chains (>3)** — hard to debug, hard to test.
- **Implicit operator** — always write `@rx` explicitly.
- **Missing `tag`** — makes log analysis and exclusion by tag impossible.

---

## Related References

- [crs-tune-rule-steering.md](crs-tune-rule-steering.md) — How CRS rules work, groups, request/response, phases, version-aware tuning
- [actions-reference.md](actions-reference.md) — Detailed action guidance
- [regex-steering-guide.md](regex-steering-guide.md) — Regex quality and PCRE2
- [operators-and-transforms.md](operators-and-transforms.md) — Operator/transform tables
- [variables-and-collections.md](variables-and-collections.md) — Variable reference
- [crs-toolchain-reference.md](crs-toolchain-reference.md) — Regex assembly and fp-finder
- CRS Contribution Docs: https://coreruleset.org/docs/development/
- CRS GitHub: https://github.com/coreruleset/coreruleset
