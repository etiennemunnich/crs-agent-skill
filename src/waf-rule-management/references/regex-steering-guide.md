# Regex Steering Guide for WAF Rules

Ensures WAF rules are **effective** (detection), **performant** (no ReDoS), and **maintainable**. Use when writing, reviewing, or optimizing rules with `@rx`, transforms, or regex assembly.

**Verified against**: ModSecurity v3.0.14, Coraza v3.3.3, CRS v4.23.0 (Feb 2025).

---

## 1. PCRE2 Migration (Current)

### What Changed

As of February 2025, **PCRE2 is becoming the default regex engine** for both ModSecurity v3 (libmodsecurity3) and ModSecurity v2 (mod_security2). Previously both defaulted to PCRE1 (also called "PCRE3" in some contexts).

- **Announcement**: https://modsecurity.org/20250217/use-pcre2-as-default-2025-february/
- **Implementation PR**: https://github.com/owasp-modsecurity/ModSecurity/pull/3321
- **Compile flags**: `--with-pcre2` (opt-in now, will be default in next releases); `--with-pcre` (legacy fallback)

### Impact on Rule Writers

| Area | PCRE1 (legacy) | PCRE2 (current) | Action |
|------|----------------|-----------------|--------|
| Possessive quantifiers | `++`, `*+` supported | `++`, `*+` supported | No change |
| Atomic groups | `(?>...)` supported | `(?>...)` supported | No change |
| Named captures | `(?P<name>...)` | `(?P<name>...)` or `(?<name>...)` | Both work in PCRE2 |
| `\K` (keep) | Supported | Supported | No change |
| Unicode properties | Limited (`\p{L}`) | Full Unicode support (`\p{Script=...}`) | PCRE2 is more capable |
| JIT compilation | Available (`pcre_jit`) | Available (`pcre2_jit_compile`) | Different API, same concept |
| Match limits | `SecPcreMatchLimit` (v2 only) | PCRE2 has `pcre2_set_match_limit()` | v3 uses compile-time limits |
| Backtracking limits | `SecPcreMatchLimitRecursion` (v2) | `pcre2_set_depth_limit()` | PCRE2 separates depth from match |
| `\R` (line ending) | Supported | Supported | No change |
| Callouts | Rarely used | Different API | Avoid in WAF rules |

### Migration Steps

1. **Check your ModSecurity build**: `modsecurity -v` or check compile flags. If built with `--with-pcre2`, you're already on PCRE2.
2. **Test existing rules**: Run your full regression suite (`go-ftw`) against a PCRE2-compiled ModSecurity. Most rules work unchanged.
3. **Watch for edge cases**:
   - PCRE2 is stricter about some invalid patterns that PCRE1 silently accepted.
   - Unicode handling may differ for non-ASCII payloads.
   - JIT behavior differences may affect timing-sensitive ReDoS tests.
4. **Update ReDoS testing**: PCRE2's `pcre2_set_depth_limit()` and `pcre2_set_match_limit()` provide better backtracking control than PCRE1.
5. **Coraza note**: Coraza uses Go's `regexp` (RE2-based) by default, which does not support PCRE features like lookahead/lookbehind. Coraza also supports PCRE via cgo. Rules intended for both engines should avoid PCRE-only features.

### Legacy PCRE1 Context

If you or your users are still on PCRE1 (older ModSecurity builds):

- **ModSecurity 2.x**: `SecPcreMatchLimit` and `SecPcreMatchLimitRecursion` (default 1000) stop runaway matches. Increase only if needed; prefer fixing the regex.
- **ModSecurity 3.x (PCRE1 build)**: Limits are compile-time; no runtime config. ReDoS is a bigger risk — rules must be ReDoS-free.
- To continue using PCRE1, compile with `--with-pcre`. This remains supported.

---

## 2. ReDoS Prevention

### What is ReDoS?

**Regular Expression Denial of Service** occurs when crafted input causes catastrophic backtracking — the engine tries exponentially many paths before failing. Result: CPU exhaustion, timeouts, DoS.

CRS has had ReDoS CVEs: CVE-2019-11387 through CVE-2019-11391; CVE-2020-15598 in ModSecurity 3.0.0–3.0.4. ModSecurity v3.0.14 also fixed `htmlEntityDecode` processing (CVE-2025-27110).

### Patterns to Avoid

| Anti-pattern | Example | Why |
|--------------|---------|-----|
| **Nested quantifiers** | `(a+)+`, `(x+x+)+y` | Exponential backtracking |
| **Quantifier on quantifier** | `^(A+)*B` | Overlapping matches |
| **Optional inside repetition** | `(\w+\s?)*` | Ambiguity → many paths |
| **Non-mutually exclusive alternation** | `(a\|ab)+` | Overlapping alternatives |
| **Repeated optional** | `.*.*` | Double-greedy |

### Safer Alternatives

- **Possessive quantifiers** (`++`, `*+`) or **atomic groups** (`(?>...)`) — supported in both PCRE1 and PCRE2; prevents backtracking into the group.
- **Single quantifier** — Replace `(a+)+` with `a+` when equivalent.
- **Mutually exclusive alternation** — `(foo\|bar)` is fine; avoid `(a\|ab)`.
- **Anchors** — `^` and `$` can help limit backtracking scope.

### PCRE Limits by Engine

| Engine | Limit mechanism | Notes |
|--------|----------------|-------|
| ModSecurity 2.x | `SecPcreMatchLimit`, `SecPcreMatchLimitRecursion` | Runtime config, default 1000 |
| ModSecurity 3.x (PCRE1) | Compile-time only | No runtime config; rules must be ReDoS-free |
| ModSecurity 3.x (PCRE2) | `pcre2_set_match_limit()`, `pcre2_set_depth_limit()` | Better granularity than PCRE1 |
| Coraza (RE2) | Linear-time guarantee | No backtracking by design; no ReDoS risk |
| Coraza (PCRE via cgo) | Depends on PCRE version | Same risks as ModSecurity |

### Sources

- [CRS ReDoS blog](https://coreruleset.org/20190425/regular-expression-dos-weaknesses-in-crs/)
- [rexegg.com – Explosive Quantifiers](https://www.rexegg.com/regex-explosive-quantifiers.php)
- [regular-expressions.info – Catastrophic Backtracking](https://www.regular-expressions.info/catastrophic.html)
- [PCRE2 migration announcement](https://modsecurity.org/20250217/use-pcre2-as-default-2025-february/)

---

## 3. Operator Selection

### When to Use What

| Operator | Use When | Performance |
|----------|----------|-------------|
| **@pm** | Fixed phrases, small word list (< ~50) | Fast; Aho-Corasick-like |
| **@pmFromFile** | Large word list, shared across rules | Fast; file-based |
| **@rx** | Pattern matching, alternation, structure | Slower; PCRE/RE2 engine |
| **@streq** | Exact string (e.g. method) | Fastest |
| **@beginsWith** | Prefix (e.g. path) | Fast |
| **@contains** | Simple substring | Fast |

### Prefer Non-Regex When Possible

- **Exact match** → `@streq POST` not `@rx ^POST$`
- **Prefix** → `@beginsWith /admin` not `@rx ^/admin`
- **Word list** → `@pm select union drop` not `@rx (?:select|union|drop)`
- **Substring** → `@contains <script` not `@rx <script` (when no regex needed)

### @rx Only When Necessary

Use `@rx` when you need:
- Alternation of many options with structure
- Character classes, boundaries
- Lookahead/lookbehind (**PCRE-only**; avoid for Coraza RE2 portability)
- Structured patterns (e.g. JSON, paths with params)

### Cross-Engine Portability

If rules must work on both ModSecurity and Coraza (RE2):

| Feature | PCRE1/PCRE2 | RE2 (Coraza default) |
|---------|-------------|----------------------|
| Lookahead `(?=...)` | Yes | **No** |
| Lookbehind `(?<=...)` | Yes | **No** |
| Backreferences `\1` | Yes | **No** |
| Possessive `++` | Yes | **No** |
| Atomic `(?>...)` | Yes | **No** |
| Named groups `(?P<n>...)` | Yes | Yes |
| Non-capturing `(?:...)` | Yes | Yes |
| Character classes | Yes | Yes |
| Alternation | Yes | Yes |

**Rule of thumb**: If portability matters, write RE2-compatible patterns. If ModSecurity-only, use possessive quantifiers and atomic groups for performance.

---

## 4. Transforms: Order and Selection

### Transform Order Matters

Transforms apply **left to right**. Order affects both detection and performance.

| Order | Effect |
|-------|--------|
| `t:lowercase,t:urlDecodeUni` | Decode first, then lowercase — correct for case-insensitive URL params |
| `t:urlDecodeUni,t:lowercase` | Lowercase raw bytes then decode — can corrupt data |

### CRS Convention

- **t:none** when no transform is needed (explicit is better).
- **t:lowercase** before case-insensitive patterns.
- **t:urlDecodeUni** for URL params, query strings, paths — attackers encode payloads.
- **t:htmlEntityDecode** for HTML context (XSS, injection in HTML).
- **t:normalizePath** for path traversal — normalizes `./`, `../`, `//`.

### When to Use Each Transform

| Transform | When to Use |
|-----------|-------------|
| t:lowercase | Case-insensitive match |
| t:urlDecodeUni | URL-encoded input |
| t:htmlEntityDecode | HTML entities in input |
| t:normalizePath | Path variables |
| t:removeNulls | Binary/null byte injection |
| t:compressWhitespace | When whitespace variation matters |

**Add only what you need.** Each transform costs CPU. Avoid stacking transforms "just in case."

### Detection Effectiveness

- **Decode before match** — Attackers use `%3cscript%3e`, `&lt;script&gt;`. Apply `t:urlDecodeUni` and `t:htmlEntityDecode` when the attack vector uses encoding.
- **Normalize evasions** — `t:normalizePath` catches `....//`, `%2e%2e/`.
- **Chain rules** — If one transform + one rule is complex, use a chain: first rule decodes/sets TX, second rule matches.

---

## 5. Regex Assembly (.ra Files)

For CRS development, complex regexes are built from `.ra` (regex assembly) files. This enables:

- **Maintainability** — Human-readable components, processors
- **Optimization** — crs-toolchain generates optimized PCRE
- **Testing** — Compare generated vs current, run fp-finder

```bash
crs-toolchain regex generate 942170   # Build from .ra
crs-toolchain regex compare 942170    # Compare generated vs current
crs-toolchain regex update 942170     # Update rule file
crs-toolchain regex format 942170     # Format .ra file
```

See [crs-toolchain-reference.md](crs-toolchain-reference.md) for full CLI reference.
See [regex-assembly.md](regex-assembly.md) for `.ra` file format and processors.

### .ra Best Practices

- Use **processors** (cmdline, assemble, define, include) for structure.
- Avoid hand-written long regexes; prefer .ra for anything non-trivial.
- Run `regex compare` before merging to catch regressions.

---

## 6. Testing Regex Rules

### lint_regex.py

```bash
python scripts/lint_regex.py rule.conf -v
python scripts/lint_regex.py rule.conf -v --strict   # CRS strictness
```

### msc_retest

[msc_retest](https://github.com/digitalwave/msc_retest) mimics ModSecurity 2.x and 3.x regex behavior for performance testing:

```bash
echo "payload" | pcre4msc2 pattern.txt        # ModSec 2.x behavior
echo "payload" | pcre4msc3 pattern.txt        # ModSec 3.x behavior
echo "payload" | pcre4msc2 -n 10 -j pattern.txt  # n iterations, JIT
```

- **pcre4msc2** — ModSecurity 2.x behavior; `-j` for JIT.
- **pcre4msc3** — ModSecurity 3.x behavior; `-f` for broken CVE-2020-15598 mode (for testing).

### go-ftw + CRS Sandbox

```bash
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?payload"
```

### ReDoS Payload Testing

Craft inputs that exploit nested quantifiers, e.g. for `(a+)+` use `"a" * 30 + "X"`. If response time spikes, the pattern is vulnerable.

For PCRE2 builds, also test with `pcre2_set_match_limit()` to verify limits are effective.

---

## 7. Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Unnecessary capture groups | Use `(?:...)` for non-capturing; captures cost performance |
| Greedy `.*` at start | Prefer `[^x]*` or anchor `^` when possible |
| Redundant alternation | `(a|a)` → `a` |
| Missing `t:urlDecodeUni` on ARGS | Encoded payloads bypass |
| Over-broad variable | Use `ARGS:param` not `ARGS` when possible |
| Lookahead/lookbehind in portable rules | PCRE-only; avoid for Coraza/RE2 portability |
| Assuming PCRE1 is still default | Check your ModSec build; PCRE2 is now default |
| Not testing regex against PCRE2 | Run regression after upgrading ModSecurity |

---

## 8. Checklist for New Rules

- [ ] Use `@pm` / `@streq` / `@beginsWith` / `@contains` when regex not needed
- [ ] If `@rx`: no nested quantifiers, no explosive patterns
- [ ] Transforms: only those needed; correct order
- [ ] Narrow variable (e.g. `ARGS:id` not `ARGS`)
- [ ] Run `lint_regex.py` or equivalent
- [ ] Test with go-ftw; include adversarial payloads
- [ ] For CRS: use .ra + crs-toolchain for complex patterns
- [ ] If targeting both engines: verify RE2 compatibility (no lookahead/lookbehind)
- [ ] If upgrading to PCRE2: run full regression to catch edge cases

---

## Related References

- [operators-and-transforms.md](operators-and-transforms.md) — Full operator/transform tables
- [crs-toolchain-reference.md](crs-toolchain-reference.md) — crs-toolchain CLI
- [regex-assembly.md](regex-assembly.md) — `.ra` file format
- [modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) — Local testing setup
- [coraza-testing-reference.md](coraza-testing-reference.md) — Cross-engine testing
- ModSecurity v3 Reference Manual: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
- PCRE2 docs: https://www.pcre.org/current/doc/html/
