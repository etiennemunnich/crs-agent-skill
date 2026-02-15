# Regex Assembly (.ra Files)

CRS uses `.ra` (regex assembly) files to build complex, maintainable regexes via `crs-toolchain`. This separates human-readable pattern components from the optimized PCRE output.

**Verified against**: crs-toolchain v2.7.0, CRS v4.23.0.

---

## Why Regex Assembly

- **Maintainability**: Complex patterns are broken into named, documented components.
- **Optimization**: `crs-toolchain` generates optimized PCRE with minimal alternation.
- **Testing**: `regex compare` detects regressions; `fp-finder` checks for false positive candidates.
- **Collaboration**: Multiple contributors can work on components independently.

---

## .ra File Format

```
##! This is a regex assembly file for rule 942170 (SQLi)
##! Comments start with ##!

##! Processor: cmdline
##! This runs the output through a command before assembly

##! Define reusable groups
##!> define sql-keywords
select
insert
update
delete
drop
##!<

##!> define sql-functions
concat
char
ascii
substring
##!<

##! Assemble the final pattern
##!> assemble
  ##!> include sql-keywords
  ##!> include sql-functions
  union\s+(?:all\s+)?select
  having\s+\d+\s*[>=<]
##!<
```

### Processors

| Processor | Syntax | Purpose |
|-----------|--------|---------|
| `define` | `##!> define NAME` ... `##!<` | Define a named group of patterns |
| `include` | `##!> include NAME` | Include a defined group |
| `assemble` | `##!> assemble` ... `##!<` | Combine patterns into final regex |
| `cmdline` | `##! Processor: cmdline` | Run output through external command |

### Pattern Lines

- One pattern per line (within an `assemble` or `define` block).
- Lines are combined as alternation by default (`|`).
- Empty lines and `##!` comment lines are ignored.
- Whitespace within a pattern is significant (it's regex).

---

## Workflow

```bash
# Generate optimized regex from .ra file
crs-toolchain regex generate 942170

# Compare generated regex with what's currently in the rule file
crs-toolchain regex compare 942170

# Update the rule file with the generated regex
crs-toolchain regex update 942170

# Format/sort the .ra file
crs-toolchain regex format 942170

# Generate from stdin
cat regex-assembly/942170.ra | crs-toolchain regex generate -
```

### Typical Development Cycle

1. Edit the `.ra` file (add/remove patterns, update definitions).
2. Run `crs-toolchain regex generate RULE_ID` to see the output.
3. Run `crs-toolchain regex compare RULE_ID` to verify against the current rule.
4. Run `crs-toolchain util fp-finder RULE_ID` to check for false positive candidates.
5. If satisfied: `crs-toolchain regex update RULE_ID` to update the rule file.
6. Run regression tests: `go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/`.
7. Commit both the `.ra` file and the updated rule file.

---

## File Layout in CRS

```
coreruleset/
  rules/
    REQUEST-942-APPLICATION-ATTACK-SQLI.conf      # Rule files
  regex-assembly/
    942170.ra                                      # Assembly source for rule 942170
    include/                                       # Shared includes
      sql-keywords.ra
```

---

## Best Practices

- **Use `.ra` for any non-trivial regex** — if a pattern has more than ~5 alternations, use assembly.
- **Use `define`/`include` for reuse** — shared patterns across rules avoid duplication.
- **Run `regex compare` before merging** — catches unintended changes.
- **Run `fp-finder` before submission** — identifies common English words that match.
- **Keep patterns sorted** — use `crs-toolchain regex format` for consistency.
- **Comment intent** — use `##!` comments to explain why a pattern exists.
- **Commit `.ra` alongside rule changes** — they must stay in sync.

## What to Avoid

- **Hand-editing the generated regex in the rule file** — it will be overwritten by `regex update`.
- **Skipping `regex compare`** — you may introduce regressions.
- **Overly broad patterns** in assembly — each line becomes an alternation; add only what's needed.
- **Forgetting `fp-finder`** — CRS contribution reviews will check for this.
- **Using `.ra` for simple patterns** — `@pm` or a short `@rx` is clearer for small word lists.

---

## Related References

- [crs-toolchain-reference.md](crs-toolchain-reference.md) — Full CLI reference for crs-toolchain
- [regex-steering-guide.md](regex-steering-guide.md) — ReDoS prevention, operator selection, transforms
- [crs-rule-format.md](crs-rule-format.md) — CRS contribution format
- CRS Regex Assembly docs: https://coreruleset.org/docs/development/regex_assembly/
- crs-toolchain: https://github.com/coreruleset/crs-toolchain
