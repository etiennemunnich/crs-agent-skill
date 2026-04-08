# Regex Steering Guide for WAF Rules

Ensures WAF rules are **effective** (detect attacks), **performant** (no ReDoS, efficient operators), and **maintainable**. Use when writing, reviewing, or optimizing rules with `@rx`, transforms, or regex assembly.

**Core principle**: Prefer `@pm`/`@streq`/`@beginsWith`/`@contains` when they suffice — faster and no ReDoS risk. Use `@rx` only when pattern structure is needed.

**Verified against**: ModSecurity v3.0.14, Coraza v3.3.3, CRS v4.23.0 (Feb 2025).

---

## 1. PCRE2 (Current Default)

**PCRE2 is the default regex engine** for ModSecurity v2 and v3 ([announcement](https://modsecurity.org/20250217/use-pcre2-as-default-2025-february/)). ModSecurity v3 uses compile-time limits; no runtime PCRE directives. Rules must be ReDoS-free.

**Migrating from PCRE1?** See [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md#5-pcre1-to-pcre2-migration).

### Impact on Rule Writers

| Area | PCRE2 | Action |
|------|-------|--------|
| Possessive quantifiers, atomic groups | `++`, `*+`, `(?>...)` supported | No change |
| Named captures | `(?P<name>...)` or `(?<name>...)` | Both work |
| Unicode | Full `\p{Script=...}` support | PCRE2 is more capable |
| Match limits (v3) | Compile-time only | No runtime config; rules must be ReDoS-free |
| Coraza | RE2 by default; no lookahead/lookbehind | Avoid PCRE-only features for portability |

### PCRE Limits by Engine

| Engine | Limit mechanism |
|--------|-----------------|
| ModSecurity v3 (PCRE2) | Compile-time; no runtime config |
| ModSecurity v2 | `SecPcreMatchLimit`, `SecPcreMatchLimitRecursion` (v2-only directives) |
| Coraza (RE2) | Linear-time; no ReDoS risk |

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

- **Possessive quantifiers** (`++`, `*+`) or **atomic groups** (`(?>...)`) — supported in PCRE2; prevents backtracking into the group.
- **Single quantifier** — Replace `(a+)+` with `a+` when equivalent.
- **Mutually exclusive alternation** — `(foo\|bar)` is fine; avoid `(a\|ab)`.
- **Anchors** — `^` and `$` can help limit backtracking scope.

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
| **@rx** | Pattern matching, alternation, structure | Slower; PCRE2 (ModSecurity) / Go `regexp` RE2 (Coraza default) |
| **@streq** | Exact string (e.g. method) | Fastest |
| **@beginsWith** | Prefix (e.g. path) | Fast |
| **@contains** | Simple substring | Fast |

### Prefer Non-Regex When Possible

- **Exact match** → `@streq POST` not `@rx ^POST$`
- **Prefix** → `@beginsWith /admin` not `@rx ^/admin`
- **Word list** → `@pm select union drop` not `@rx (?:select|union|drop)`
- **Substring** → `@contains <script` not `@rx <script` (when no regex needed)

### Coraza: optional `@rx` prefilter (compile-time)

Some Coraza builds enable `coraza.rule.rx_prefilter` at compile time (`go build -tags coraza.rule.rx_prefilter`), adding cheap pre-checks before the full `@rx` match for many patterns—useful throughput on CRS-heavy configs, especially when traffic rarely matches each rule. **It is opt-in and not universal**; prebuilt images may omit it. Rule-writing guidance is unchanged: still prefer `@pm` / `@streq` / `@contains` when they express the check. Upstream: [corazawaf/coraza#1534](https://github.com/corazawaf/coraza/pull/1534) (merged 2026-03-31).

### @rx Only When Necessary

Use `@rx` when you need:
- Alternation of many options with structure
- Character classes, boundaries
- Lookahead/lookbehind (**PCRE-only**; avoid for Coraza RE2 portability)
- Structured patterns (e.g. JSON, paths with params)

### Cross-Engine Portability

If rules must work on both ModSecurity and Coraza (RE2):

| Feature | PCRE2 (ModSec) | RE2 (Coraza default) |
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

**Rule of thumb**: If portability matters, write RE2-compatible patterns. If ModSecurity-only (PCRE2), use possessive quantifiers and atomic groups for performance.

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

For CRS development, complex regexes are built from `.ra` (regex assembly) files via [crs-toolchain](crs-toolchain-reference.md). This enables:

- **Maintainability** — Human-readable components, processors ([regex-assembly.md](regex-assembly.md))
- **Optimization** — crs-toolchain generates optimized PCRE
- **Testing** — Compare generated vs current, run fp-finder

```bash
crs-toolchain regex generate 942170   # Build from .ra
crs-toolchain regex compare 942170    # Compare generated vs current
crs-toolchain regex update 942170     # Update rule file
crs-toolchain regex format 942170     # Format .ra file
```

See [crs-toolchain-reference.md](crs-toolchain-reference.md) for full CLI reference; [regex-assembly.md](regex-assembly.md) for `.ra` format, processors, and when to use.

### .ra Best Practices

- Use **processors** (cmdline, assemble, define, include) for structure.
- Avoid hand-written long regexes; prefer .ra for anything non-trivial.
- Run `regex compare` before merging to catch regressions.

---

## 6. Tooling and Iteration

### Tool Matrix

| Tool | Purpose | When |
|------|---------|------|
| `lint_regex.py` | ReDoS heuristics, operator hints | Every change; CI |
| `crs-toolchain regex compare` | Diff generated vs current | Before `regex update` |
| `crs-toolchain util fp-finder` | FP candidate words | After regex change |
| **msc_retest** | Match timing (ModSec-like) | ReDoS suspect; compare variants |
| `go-ftw run` | Regression | After any change |
| `go-ftw quantitative` | Throughput / detection rate | Rule/version comparison |

### Iteration Loop

1. Edit → `lint_regex.py -v --strict`
2. (CRS) `regex compare` → `fp-finder` → `regex update` if satisfied
3. `go-ftw run` regression
4. If performance concern: msc_retest with adversarial payload (e.g. `"a"*30+"X"` for `(a+)+`)

### Commands

```bash
python scripts/lint_regex.py rule.conf -v --strict
crs-toolchain regex compare 942170 && crs-toolchain util fp-finder 942170
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
go-ftw quantitative -C /path/to/coreruleset -s 10K -r 942100   # rule comparison
```

### msc_retest (Performance)

[msc_retest](https://github.com/digitalwave/msc_retest): `echo "payload" | pcre4msc3 pattern.txt`. Use `-n 1000 -j` for iterations + JIT. ReDoS test: long input that forces backtracking (e.g. 30×`a`+`X` for `(a+)+`).

### ReDoS Payload Testing

Craft inputs that exploit nested quantifiers. For `(a+)+` use `"a"*30+"X"`. If response time spikes, the pattern is vulnerable.

### Online Tools (Exploration Only)

regex101.com, regexr.com — use for structure/debug. PCRE flavor differs from PCRE2; not authoritative for ModSec.

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
| Assuming PCRE1 is still default | PCRE2 is default; see [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md#5-pcre1-to-pcre2-migration) |
| Not testing regex against PCRE2 | Run regression after upgrading ModSecurity |

---

## 8. Checklist for New Rules

- [ ] Use `@pm` / `@streq` / `@beginsWith` / `@contains` when regex not needed
- [ ] If `@rx`: no nested quantifiers, no explosive patterns
- [ ] Transforms: only those needed; correct order
- [ ] Narrow variable (e.g. `ARGS:id` not `ARGS`)
- [ ] Run `lint_regex.py`; (CRS) `regex compare` + `fp-finder`
- [ ] Test with go-ftw; include adversarial payloads
- [ ] For CRS: use .ra + crs-toolchain for complex patterns
- [ ] If targeting both engines: verify RE2 compatibility (no lookahead/lookbehind)
- [ ] If migrating from PCRE1: run full regression; see [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md#5-pcre1-to-pcre2-migration)

---

## Related References

- [operators-and-transforms.md](operators-and-transforms.md) — Full operator/transform tables
- [crs-toolchain-reference.md](crs-toolchain-reference.md) — crs-toolchain CLI (regex generate/compare/update, fp-finder)
- [regex-assembly.md](regex-assembly.md) — `.ra` file format, processors, when to use
- [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md) — PCRE1→PCRE2 migration
- [modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) — Local testing setup
- [coraza-testing-reference.md](coraza-testing-reference.md) — Cross-engine testing
- ModSecurity v3 Reference Manual: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
- PCRE2 docs: https://www.pcre.org/current/doc/html/
