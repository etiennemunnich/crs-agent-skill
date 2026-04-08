# ModSecurity Operators and Transforms

Complete reference for operators and transforms used in ModSecurity v3 and Coraza rules. **Performance**: Prefer `@pm`, `@streq`, `@beginsWith`, `@contains` over `@rx` when they suffice — faster and no ReDoS risk. See [regex-steering-guide.md](regex-steering-guide.md) for full guidance.

**Verified against**: ModSecurity v3.0.14, Coraza v3.3.3, [Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).

---

## Operators

### String/Pattern Operators

| Operator | Description | Example | Performance |
|----------|-------------|---------|-------------|
| `@rx` | Regex match (PCRE2 on ModSecurity; Go `regexp`/RE2 on Coraza) | `@rx /admin` | Slower than string operators; Coraza may use compile-time `coraza.rule.rx_prefilter` if your binary was built with that tag ([corazawaf/coraza#1534](https://github.com/corazawaf/coraza/pull/1534)) |
| `@pm` | Phrase match (word list, case-insensitive) | `@pm select union drop` | Fast; Aho-Corasick |
| `@pmFromFile` | Phrase match from file | `@pmFromFile wordlist.data` | Fast; file-based |
| `@streq` | Exact string match | `@streq POST` | Fastest |
| `@beginsWith` | Prefix match | `@beginsWith /api` | Fast |
| `@endsWith` | Suffix match | `@endsWith .php` | Fast |
| `@contains` | Substring match | `@contains <script` | Fast |
| `@within` | Value is within a list | `@within GET,POST,HEAD` | Fast |
| `@strmatch` | Glob-style pattern match | `@strmatch /admin/*` | Fast |

### Numeric Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `@eq` | Equals | `@eq 0` |
| `@gt` | Greater than | `@gt 100` |
| `@ge` | Greater than or equal | `@ge 5` |
| `@lt` | Less than | `@lt 1000` |
| `@le` | Less than or equal | `@le 10` |

### Network Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `@ipMatch` | IP address/CIDR match | `@ipMatch 192.168.0.0/24,10.0.0.0/8` |
| `@ipMatchFromFile` | IP match from file | `@ipMatchFromFile blocklist.txt` |

### Validation Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `@validateByteRange` | Check byte range | `@validateByteRange 1-255` |
| `@validateUrlEncoding` | Validate URL encoding | `@validateUrlEncoding` |
| `@validateUtf8Encoding` | Validate UTF-8 | `@validateUtf8Encoding` |
| `@detectSQLi` | libinjection SQLi detection | `@detectSQLi` |
| `@detectXSS` | libinjection XSS detection | `@detectXSS` |

### Selection Guide

| Need | Use | Not |
|------|-----|-----|
| Exact string | `@streq` | `@rx ^POST$` |
| Prefix | `@beginsWith` | `@rx ^/admin` |
| Word list (<50 words) | `@pm` | `@rx (?:select\|union\|drop)` |
| Large word list | `@pmFromFile` | Long `@pm` inline |
| Substring | `@contains` | `@rx <script` |
| Complex pattern | `@rx` | Over-complicated `@pm` chains |
| SQL injection | `@detectSQLi` | Complex `@rx` for SQLi |

**Always specify the operator explicitly** — never rely on implicit `@rx` (CRS convention).

---

## Transforms

### Common Transforms

| Transform | Description | When to Use |
|-----------|-------------|-------------|
| `t:none` | No transform | Explicit "no transform" (CRS convention) |
| `t:lowercase` | Convert to lowercase | Case-insensitive matching |
| `t:uppercase` | Convert to uppercase | Rarely needed; prefer `t:lowercase` |
| `t:urlDecodeUni` | URL decode (Unicode-aware) | URL-encoded input (ARGS, URI) |
| `t:urlDecode` | URL decode (basic) | Prefer `urlDecodeUni` for better coverage |
| `t:htmlEntityDecode` | Decode HTML entities | XSS detection in HTML context |
| `t:normalizePath` | Normalize path (`../`, `//`) | Path traversal detection |
| `t:normalizePathWin` | Windows path normalization | Windows-specific path traversal |
| `t:removeNulls` | Remove null bytes | Null byte injection |
| `t:compressWhitespace` | Collapse whitespace | Whitespace evasion |
| `t:removeWhitespace` | Remove all whitespace | Concatenated evasion payloads |
| `t:base64Decode` | Decode base64 | Base64-encoded payloads |
| `t:hexDecode` | Decode hex encoding | Hex-encoded payloads |
| `t:jsDecode` | Decode JavaScript escapes | JS evasion sequences |
| `t:cssDecode` | Decode CSS escapes | CSS injection patterns |
| `t:replaceComments` | Replace `/* */` with space | SQL comment evasion |
| `t:sha1` / `t:md5` | Hash value | Comparison with known hashes (rare) |
| `t:length` | Return string length | Size-based checks |
| `t:trim` | Strip leading/trailing whitespace | Clean comparison |

### Transform Order

Transforms apply **left to right**. Order matters:

```apache
# CORRECT: decode first, then lowercase
t:urlDecodeUni,t:lowercase

# WRONG: lowercase raw bytes, then decode — corrupts data
t:lowercase,t:urlDecodeUni
```

### Transform Order Pitfalls (Encoding FPs)

For rules 941xxx or 942xxx when payload contains non-ASCII (Cyrillic, Chinese, Bengali):

- **`t:utf8toUnicode` + `t:urlDecodeUni` on already-UTF-8 input** — Can corrupt data and produce false matches. Example: Cyrillic "имо" → `8<>` triggers XSS/SQLi patterns.
- **Inspect the rule's transform stack** — Use CRS rule file or `analyze_log.py --explain-rule <ID>`.
- **Exclusion** — `ctl:ruleRemoveTargetById` for the affected param, or URI-scoped `ctl:ruleRemoveById`.

### Recommended Transform Stacks

| Context | Transform Stack |
|---------|----------------|
| URL params/query strings | `t:none,t:urlDecodeUni,t:lowercase` |
| Request body (form) | `t:none,t:urlDecodeUni,t:lowercase` |
| HTML content (XSS) | `t:none,t:htmlEntityDecode,t:jsDecode,t:lowercase` |
| Path traversal | `t:none,t:urlDecodeUni,t:normalizePath` |
| SQL injection | `t:none,t:urlDecodeUni,t:replaceComments,t:lowercase` |
| Exact match (no evasion) | `t:none` |

---

## Best Practices

- **Prefer non-regex operators** when possible — `@pm`, `@streq`, `@beginsWith` are faster and have no ReDoS risk.
- **Use `t:none` explicitly** when no transform is needed.
- **Decode before matching** — `t:urlDecodeUni` before `t:lowercase` for URL params.
- **Don't stack unnecessary transforms** — each costs CPU.
- **Use `@detectSQLi` and `@detectXSS`** for libinjection-based detection (fast, low FP).
- **CRS convention**: use camelCase for operators (`@beginsWith` not `@beginswith`).

## What to Avoid

- **Implicit `@rx`** — always write the operator name explicitly.
- **`@rx` for exact strings** — use `@streq` instead.
- **Wrong transform order** — `t:lowercase` before `t:urlDecodeUni` corrupts data.
- **`t:utf8toUnicode` + `t:urlDecodeUni` on already-UTF-8 input** — corrupts non-ASCII and causes encoding FPs (e.g. Cyrillic "имо" → `8<>`).
- **Too many transforms** — start with the minimum needed; add only for specific evasion vectors.
- **`t:base64Decode` without checking** — can produce garbled output on non-base64 input.
- **PCRE-only features in portable rules** — lookahead/lookbehind don't work in Coraza RE2 mode.

---

## Cross-Engine Compatibility

| Feature | ModSecurity (PCRE) | Coraza (RE2 default) |
|---------|-------------------|---------------------|
| `@rx` with lookahead | Yes | **No** |
| `@rx` with backrefs | Yes | **No** |
| `@pm` / `@pmFromFile` | Yes | Yes |
| `@detectSQLi` / `@detectXSS` | Yes | Yes |
| All transforms | Yes | Yes (most) |

For portability, see [regex-steering-guide.md](regex-steering-guide.md) cross-engine table.

---

## Related References

- [regex-steering-guide.md](regex-steering-guide.md) — ReDoS prevention, PCRE2, operator selection detail
- [variables-and-collections.md](variables-and-collections.md) — Variable targets for operators
- [actions-reference.md](actions-reference.md) — Actions to pair with operators
- ModSecurity v3 Reference Manual: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
