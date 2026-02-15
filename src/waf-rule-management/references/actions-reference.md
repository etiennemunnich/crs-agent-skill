# ModSecurity Actions Reference (v3)

Practical action guidance for custom rules and CRS-style tuning.
This page focuses on what to use, when to use it, and what to avoid.

## Action Categories

- **Disruptive**: `deny`, `block`, `drop`, `allow`, `redirect`
- **Logging**: `log`, `nolog`, `auditlog`, `noauditlog`
- **Flow/control**: `chain`, `skip`, `skipAfter`, `ctl:*`
- **Metadata**: `id`, `msg`, `tag`, `severity`, `ver`
- **State/scoring**: `setvar`, `expirevar`, `initcol`

## Core Actions and Recommended Use

### Disruptive Actions

- **`deny`**: explicit and predictable; preferred for custom blocking rules.
- **`block`**: inherits behavior from default actions; use only if your defaults are well understood.
- **`drop`**: closes connection; use sparingly (operational impact, harder troubleshooting).
- **`allow`**: bypass behavior; use with strict scope (URI/method/IP) to prevent broad blind spots.
- **`redirect`**: niche use; ensure it cannot leak internal details.

### Logging Actions

- **`log`**: keep enabled on security-relevant rules unless volume is unacceptable.
- **`auditlog`**: force audit logging for important matches.
- **`nolog`/`noauditlog`**: use only for high-volume/noise suppression after validation.

### Flow and Control Actions

- **`chain`**: best for multi-condition logic without duplicating actions.
- **`ctl:ruleRemoveById` / `ctl:ruleRemoveTargetById`**: preferred runtime exclusion mechanisms.
- **`skip` / `skipAfter`**: advanced optimization/control; easy to misuse and create gaps.

### Metadata and Scoring

- **`id`**: mandatory and unique. Keep custom IDs in a dedicated range.
- **`msg`**: clear human-readable reason for match/block.
- **`tag`**: use consistent taxonomy (`attack-*`, app/team/domain tags).
- **`severity`**: align with your scoring and incident processes.
- **`setvar`**: update anomaly scores and per-transaction state intentionally.

## Best Practices

- **Prefer explicit behavior**: use `deny,status:403` over implicit behavior when possible.
- **Minimize side effects**: keep each rule's action set focused on one intent.
- **Log before you mute**: start with `log`, then reduce noise after observing production behavior.
- **Use scoped exclusions**: target specific variable + URI, not global `ruleRemoveById` unless required.
- **Keep chain semantics clean**: disruptive/meta actions on the first rule in a chain.
- **Make rules explainable**: always include meaningful `msg` and useful tags.
- **Version and ownership**: include `ver` and domain/team tags for maintainability.

## What to Avoid

- **Broad `allow` rules** without strict conditions (can disable WAF protection unintentionally).
- **Global disablement** (`SecRuleRemoveById` or `ctl:ruleRemoveById`) as first response to false positives.
- **Overuse of `nolog`/`noauditlog`** before tuning confidence is established.
- **Relying on `block` defaults blindly** when `SecDefaultAction` differs across environments.
- **Unbounded `skip/skipAfter` logic** that may bypass unrelated protections.
- **Missing `id`/`msg`/`tag`** on custom rules (hard to audit and maintain).
- **High-disruption actions (`drop`)** in early rollout phases.

## Safe Custom Rule Template (Action Set)

```conf
SecRule REQUEST_URI "@beginsWith /admin" \
    "id:100001,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Blocked unauthorized admin path access',\
    tag:'attack-surface/admin',\
    severity:'CRITICAL'"
```

## Safe Runtime Exclusion Template

```conf
SecRule REQUEST_URI "@beginsWith /api/search" \
    "id:100100,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveTargetById=942100;ARGS:q"
```

Use runtime exclusions before CRS include; configure-time exclusions after CRS include.

## References

- ModSecurity v3 Reference Manual: actions and directives
- `best-practices-modsec-coraza-crs.md`
- `antipatterns-and-troubleshooting.md`
- `false-positives-and-tuning.md`
