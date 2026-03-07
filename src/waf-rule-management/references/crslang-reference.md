# CRSLang Reference

## Overview

[CRSLang](https://github.com/coreruleset/crslang) is the next-generation representation for OWASP CRS rules. It abstracts Seclang into a modern YAML format for better maintainability, tooling, and analysis. **crslang is the primary Seclang parser/validator** — use it ahead of modsec-rules-check and rules-check.

## Why CRSLang First?

- **Primary validation** — `validate_rule.py` uses crslang first; legacy tools are fallback only
- **Language independence** — Not tied to Seclang syntax
- **Bidirectional conversion** — Seclang ↔ CRSLang
- **Improved readability** — YAML structure with metadata, conditions, actions
- **Enhanced tooling** — Analysis and transformation support

## Installation

```bash
bash scripts/install_tools.sh   # Installs crslang as required
# Or manually:
git clone https://github.com/coreruleset/crslang
cd crslang
go build
# Binary: ./crslang or $(go env GOPATH)/bin/crslang
```

## Expected Workflows

| Workflow | Use crslang | Command |
|----------|-------------|---------|
| **Syntax validation** | Primary | `python scripts/validate_rule.py rule.conf` (uses crslang first) |
| **New rule** | After writing | `validate_rule.py` → `lint_regex.py` → `go-ftw` |
| **Migration** | First-pass parse | `validate_rule.py` on migrated rules; see [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md) |
| **CRS contribution** | Before PR | `validate_rule.py` + `lint_crs_rule.py`; see [crs-contribution-workflow.md](crs-contribution-workflow.md) |
| **Seclang → YAML** | Direct | `crslang -o output_name path/to/rules` |
| **YAML → Seclang** | Direct | `crslang -s input.yaml -o output_dir/` |
| **Programmatic analysis** | Convert first | `crslang -o rules path/to/crs` then inspect YAML |

## Usage

### Seclang → CRSLang

```bash
crslang -o output_name path/to/rules
# Output: output_name.yaml
```

### CRSLang → Seclang

```bash
crslang -s input.yaml -o output_dir/
# Output: .conf files in output_dir/
```

## CRSLang Rule Format (YAML)

```yaml
- kind: rule
  metadata:
    phase: "1"
    id: 920300
    message: Request Missing an Accept Header
    severity: NOTICE
    tags:
      - paranoia-level/3
      - OWASP_CRS
    version: OWASP_CRS/4.0.1-dev
  conditions:
    - collections:
        - name: REQUEST_HEADERS
          arguments: [Accept]
          count: true
      operator:
        eq: "0"
      transformations: [none]
  actions:
    disruptive: pass
    non-disruptive:
      - setvar:
          collection: TX
          operation: =+
          assignments:
            - inbound_anomaly_score_pl3: "%{tx.notice_anomaly_score}"
    flow: [chain]
```

## When to Use

- **Validation**: crslang parses Seclang — parse success implies valid syntax
- **Analysis**: Convert to YAML for programmatic rule inspection
- **Transformation**: Edit YAML, convert back to Seclang
- **Migration**: Work with rules in abstract form

## Best Practices

- **Always use crslang first** for syntax validation — `validate_rule.py` does this automatically.
- Convert rules to YAML for programmatic analysis (counting rules, checking tags, extracting IDs) rather than fragile regex parsing of `.conf` files.
- Keep the original Seclang as the source of truth; use CRSLang as a tool, not a replacement format (unless the CRS project officially migrates).
- Pin the crslang binary version in CI for reproducible results.
- Run `validate_rule.py` (which uses crslang) before `lint_regex.py` and `go-ftw` in every rule workflow.

## What to Avoid

- **Skipping crslang** — Use `validate_rule.py` (crslang first); do not rely on legacy modsec-rules-check alone.
- Editing CRSLang YAML and converting back without verifying equivalence — round-trip may not preserve comments or whitespace.
- Relying on crslang for features it doesn't support yet (check the [GitHub issues](https://github.com/coreruleset/crslang/issues) for known limitations).

## Related References

- [crs-rule-format.md](crs-rule-format.md) — CRS rule conventions
- [crs-toolchain-reference.md](crs-toolchain-reference.md) — Regex assembly and FP finding
- [modsecurity-migration-checklist.md](modsecurity-migration-checklist.md) — Using crslang for migration validation

## Source

- <https://github.com/coreruleset/crslang>
