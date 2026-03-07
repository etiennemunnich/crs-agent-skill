# CRS-Toolchain Reference

## Overview

[crs-toolchain](https://github.com/coreruleset/crs-toolchain) is a CLI for OWASP CRS development: regex assembly from `.ra` files, fp-finder (false positive candidate words), and rule formatting. Run from CRS repo root.

## Installation

```bash
go install github.com/coreruleset/crs-toolchain/v2@latest
```

## Regex Assembly

Complex regexes are built from `.ra` (regex assembly) files. See [regex-assembly.md](regex-assembly.md) for format and when to use; [regex-steering-guide.md](regex-steering-guide.md) for ReDoS prevention and operator choice. Commands:

```bash
# Generate optimized regex from .ra file
crs-toolchain regex generate 942170

# Compare generated vs current rule
crs-toolchain regex compare 942170

# Update rule file with generated regex
crs-toolchain regex update 942170

# Format .ra file
crs-toolchain regex format 942170

# From stdin
cat regex-assembly/942170.ra | crs-toolchain regex generate -
```

## False Positive Finder

Find candidate words that may cause false positives for a rule or regex:
For rule-id mode, run from a CRS checkout where the target rule/assembly files exist.

```bash
# By rule ID
crs-toolchain util fp-finder 942170

# By regex pattern
crs-toolchain util fp-finder 'union\s+select'

# Help
crs-toolchain util fp-finder --help
```

## Best Practices

- Always run from a **CRS repo checkout** — commands like `regex generate 942170` expect `.ra` files in `regex-assembly/`.
- **Iteration**: `regex compare` → `fp-finder` → (fix) → `regex update`. Never `regex update` without `regex compare` first.
- Run `fp-finder` on every new or modified regex before merging — catches common words that would trigger false positives.
- Pin `crs-toolchain` version in CI to avoid unexpected behavior from upstream changes.
- Use `regex format` to normalize `.ra` files before committing.

## What to Avoid

- Running `regex update` without reviewing the diff (`regex compare`) first — may silently change regex behavior.
- Using `fp-finder` with overly broad regex (e.g. `.*`) — returns too many false candidates to be useful.
- Editing generated `.conf` regex directly instead of the `.ra` source — changes will be overwritten on next `regex update`.
- Forgetting to `go install ... @latest` periodically — stale toolchain may lack bug fixes.

## Related References

- [regex-assembly.md](regex-assembly.md) — `.ra` file format, processors, when to use
- [regex-steering-guide.md](regex-steering-guide.md) — Effective + performant rules, ReDoS, operator choice
- [crs-rule-format.md](crs-rule-format.md) — CRS contribution conventions
- [go-ftw-reference.md](go-ftw-reference.md) — Testing after regex changes

## Source

- [CRS Toolchain docs](https://coreruleset.org/docs/6-development/6-2-crs-toolchain/)
- [Assembling Regular Expressions](https://coreruleset.org/docs/6-development/6-3-assembling-regular-expressions/)
- [crs-toolchain GitHub](https://github.com/coreruleset/crs-toolchain)
