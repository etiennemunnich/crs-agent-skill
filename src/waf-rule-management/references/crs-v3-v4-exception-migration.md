# CRS v3 → v4 Exception / Exclusion Migration

Migrate OWASP CRS v3.3 custom exception and exclusion configuration files to **CRS v4 LTS** format: `ctl:ruleEngine=Off` handling, application exclusion packages → plugins, `ver:` metadata updates, rule ID validation, and correct file placement (`REQUEST-900` vs `RESPONSE-999`).

**When to load**: User is upgrading CRS major version, migrating exclusion files, replacing v3 `REQUEST-903.9xxx` packages, or fixing post-upgrade silent exclusions.

---

## Attribution and source

This reference integrates the **CRS v3 → v4 Exception Migration** workflow contributed by **[Felipe Zipitria](https://github.com/fzipi)** — **OWASP CRS and Coraza project co-leader** — as published in the upstream skill gist:

- Source gist: [CRS v3 → v4 Exception Migration (SKILL.md)](https://gist.githubusercontent.com/fzipi/0e674a93f61e8e577a7bee492d4a6912/raw/04ca50d9b0f2d8408824ad2982683f975cbaa2ea/SKILL.md)

Content is adapted for this skill’s reference style (paths, cross-links, and version notes). **CRS v4.25.0** is the first LTS release for CRS 4 (security fixes through Q3 2027). Always confirm the target CRS release string for `ver:` against the current LTS on the [Coreruleset releases page](https://github.com/coreruleset/coreruleset/releases) and the official [migration blog series](https://coreruleset.org/20260330/migrating-crs-3-to-4-part-1-overview/).

---

## Invocation (agent workflow)

Treat user requests like:

`/migrate-exceptions [file-or-directory]`

- **No argument**: look for `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` and `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` in the working directory.
- **File path**: migrate that single file.
- **Directory**: migrate all `*.conf` exception files found there.

---

## Migration workflow (ordered steps)

### Step 1 — Read and parse the input file(s)

For each target file, identify:

- All `SecRule` blocks (including multi-line rules with `\` continuation)
- `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`
- `SecRuleUpdateTargetById`, `SecRuleUpdateTargetByMsg`, `SecRuleUpdateTargetByTag`
- `SecRuleUpdateActionById`
- All `ctl:` actions inside `SecRule` action lists
- `Include` directives referencing v3 exclusion packages (see Transformation 3)

### Step 2 — Apply transformations

Apply each transformation below **in sequence**. After each automated change, add an inline comment on the changed line: `# MIGRATED: <reason>`. If a change needs human judgment, use `# REVIEW: <explanation>` instead.

---

## Transformation 1: `ctl:ruleEngine=Off` → `ctl:ruleRemoveByTag=OWASP_CRS`

**Why:** v3 used `ctl:ruleEngine=Off` to disable ModSecurity for matched requests. In v4 this is replaced with `ctl:ruleRemoveByTag=OWASP_CRS` so other rulesets (e.g. application plugins) can still run.

**Detection:** Any `ctl:ruleEngine=Off` inside a `SecRule` actions list.

**Transformation:**

```text
ctl:ruleEngine=Off  →  ctl:ruleRemoveByTag=OWASP_CRS
```

**Preserve** `ctl:auditEngine=Off` if it appears alongside `ctl:ruleEngine=Off` on the same rule — keep it unchanged on that rule.

**Example**

Before (v3):

```apache
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1,::1" \
    "id:905100,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    ver:'OWASP_CRS/3.3.9',\
    chain"
    SecRule REQUEST_HEADERS:User-Agent "@endsWith (internal dummy connection)" \
        "t:none,\
        ctl:ruleEngine=Off,\
        ctl:auditEngine=Off"
```

After (v4) — update `ver:` to your target CRS v4 release (see note below); inner rule uses `ctl:ruleRemoveByTag=OWASP_CRS`:

```apache
SecRule REMOTE_ADDR "@ipMatch 127.0.0.1,::1" \
    "id:905100,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    ver:'OWASP_CRS/4.25.0',\
    chain"
    SecRule REQUEST_HEADERS:User-Agent "@endsWith (internal dummy connection)" \
        "t:none,\
        ctl:ruleRemoveByTag=OWASP_CRS,\
        ctl:auditEngine=Off"
```

`# MIGRATED: ctl:ruleEngine=Off → ctl:ruleRemoveByTag=OWASP_CRS (v4 multi-ruleset model)` — place on the line above the inner `SecRule` or in your change log.

**Edge case — standalone (non-chained) `ctl:ruleEngine=Off`:**  
If `ctl:ruleEngine=Off` appears in a **non-chained** rule, replace it with `ctl:ruleRemoveByTag=OWASP_CRS` **and** add `# REVIEW:` — v4 cannot replicate “turn off the entire engine for this request” the same way; confirm intent with the operator.

---

## Transformation 2: Version string update

**Why:** Custom rules copied from v3 carry `ver:'OWASP_CRS/3.3.x'`, which is wrong after migration.

**Detection:** Any `ver:'OWASP_CRS/3.` in a `SecRule` actions list.

**Transformation:**

```text
ver:'OWASP_CRS/3.3.x'  →  ver:'OWASP_CRS/<YOUR_V4_LTS>'
```

The upstream gist used **`4.25.0`** as an example target. **Confirm** the correct string for your deployment from [Coreruleset releases](https://github.com/coreruleset/coreruleset/releases). Add `# MIGRATED: version updated`.

---

## Transformation 3: Application exclusion package detection

**Why:** CRS v3 shipped built-in exclusion packages (WordPress, Drupal, Nextcloud, etc.) as `REQUEST-903.9XXX-*-EXCLUSIONS.conf` files. These were **removed in v4** and replaced by the [plugin registry](https://github.com/coreruleset/plugin-registry).

**Detection:** `Include` directives or file names matching:

| Pattern | Application |
|---------|-------------|
| `REQUEST-903.9001` | WordPress |
| `REQUEST-903.9002` | Drupal |
| `REQUEST-903.9003` | NextCloud |
| `REQUEST-903.9004` | XenForo |
| `REQUEST-903.9005` | phpBB |
| `REQUEST-903.9006` | phpMyAdmin |
| `REQUEST-903.9007` | cPanel |
| `REQUEST-903.9008` | dokuwiki |
| `REQUEST-903.9009` | cPanel (alt) |
| `REQUEST-903.9010` | XenForo (alt) |

Also detect `SecRule` blocks with tags such as `tag:'platform-wordpress'`, `tag:'platform-drupal'` that originated from those packages.

**Action:**

1. Comment out the `Include` with `# REVIEW:` — must be replaced by the corresponding v4 plugin.
2. Append a summary block at the end of the migrated file listing required plugins and the registry URL (template):

```apache
# ============================================================
# MIGRATION NOTE: The following v3 exclusion packages were
# detected. Install the corresponding v4 plugins per:
# https://github.com/coreruleset/plugin-registry
#
# Required plugins (examples — verify names in registry):
#   - wordpress-rule-exclusions-plugin (replaces REQUEST-903.9001)
#   - drupal-rule-exclusions-plugin    (replaces REQUEST-903.9002)
# ============================================================
```

---

## Transformation 4: Rule ID validation

**Why:** Some v3 rule IDs were renumbered, split, or removed. Keeping stale IDs in `SecRuleRemoveById` / `ctl:ruleRemoveById` may **silently do nothing**.

**Detection:** All IDs in:

- `SecRuleRemoveById`
- `SecRuleUpdateTargetById`
- `SecRuleUpdateActionById`
- `ctl:ruleRemoveById`
- `ctl:ruleRemoveTargetById`

**Action:**

1. From the CRS v4 tree, collect defined rule IDs (`SecRule ... "id:NNNNN,` in `rules/REQUEST-*.conf` and `rules/RESPONSE-*.conf`).
2. For each ID referenced in the exception file, verify it exists in v4.
3. If **not** found: `# REVIEW: rule id NNNNN not found in v4 — removed, renumbered, or merged; verify before deploy.`
4. **Known:** Rules in the **903.9xxx** application-package range — removed; treat as plugin migration (Transformation 3).

---

## Transformation 5: Placement validation

**Why:** Startup-context vs transaction-context mix-ups cause silent failures.

**Rules:**

`REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` must contain **only** runtime `ctl:` removals/updates:

- `ctl:ruleEngine` (legacy v3 only — migrate per Transformation 1)
- `ctl:ruleRemoveById`
- `ctl:ruleRemoveByMsg`
- `ctl:ruleRemoveByTag`
- `ctl:ruleRemoveTargetById`
- `ctl:ruleRemoveTargetByMsg`
- `ctl:ruleRemoveTargetByTag`

`RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` must contain **only** configure-time directives:

- `SecRuleRemoveById`
- `SecRuleRemoveByMsg`
- `SecRuleRemoveByTag`
- `SecRuleUpdateActionById`
- `SecRuleUpdateTargetById`
- `SecRuleUpdateTargetByMsg`
- `SecRuleUpdateTargetByTag`

**Detection:** Wrong file → `# REVIEW: directive belongs in [correct file].`

---

## Transformation 6: `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf` awareness

**Why:** CRS v4 introduced `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf` for shared FPs (e.g. analytics cookies). v3 custom workarounds may now duplicate that.

**Detection:** `SecRuleUpdateTargetById` for tracking cookies (`_ga`, `_gid`, `_gat`, `_utm`, `__utm*`, `_pk_*`, `matomo_*`, `piwik_*`) or similar.

**Action:** Add:

```apache
# REVIEW: May duplicate CRS v4 REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf
# (analytics cookie exclusions). Compare with upstream and remove duplicates.
```

---

## Step 3 — Output

### Migrated file(s)

Write migrated content to **`<original-name>.v4.conf`** (do **not** overwrite the original unless the user explicitly requests it).

### Migration report (print to user)

Use this structure:

```text
## CRS v3 → v4 Exception Migration Report

### Files processed
- (list)

### Changes applied
- N × ctl:ruleEngine=Off → ctl:ruleRemoveByTag=OWASP_CRS
- N × version strings updated to OWASP_CRS/<v4>

### Manual review (# REVIEW:)
- Rule IDs not found in v4: ...
- Application packages → plugins: ...
- Directives in wrong file: ...
- Possible duplicate analytics exceptions: ...

### Plugins to install
- (from Transformation 3)

### Next steps
1. Resolve all # REVIEW: comments
2. Install plugins from https://github.com/coreruleset/plugin-registry
3. Test with go-ftw / staging / DetectionOnly before production
```

---

## Quick-reference table

| v3 directive/pattern | v4 equivalent | Notes |
|---------------------|---------------|--------|
| `ctl:ruleEngine=Off` | `ctl:ruleRemoveByTag=OWASP_CRS` | Keeps other rulesets active |
| `ver:'OWASP_CRS/3.3.x'` | `ver:'OWASP_CRS/<v4 LTS>'` | Confirm release |
| `REQUEST-903.9001-WORDPRESS-EXCLUSIONS.conf` | wordpress-rule-exclusions-plugin (registry) | Verify name in registry |
| `SecRuleRemoveById` | unchanged | Validate ID exists in v4 |
| `SecRuleUpdateTargetById` | unchanged | Validate ID exists in v4 |

---

## Related in this skill

- [false-positives-and-tuning.md](false-positives-and-tuning.md) — exclusion patterns and FP handling  
- [upgrade-and-testing.md](upgrade-and-testing.md) — upgrade workflow and regression testing  
- [validate_exclusion.py](../scripts/validate_exclusion.py) — validate exclusion safety after edits  
- [go-ftw-reference.md](go-ftw-reference.md) — regression tests  

---

## Upstream resources

- [CRS v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/) — first LTS for CRS 4; security fixes through Q3 2027
- [Migrating CRS 3.3 to 4.25 LTS — blog series](https://coreruleset.org/20260330/migrating-crs-3-to-4-part-1-overview/) — official multi-part guide (overview, configuration, plugins, scoring, rule changes, FP tuning, engine notes)
- [CRS v4 migration docs](https://coreruleset.org/docs/migration/migration_from_v3/)
- [CRS plugin registry](https://github.com/coreruleset/plugin-registry)
- [CRS CHANGES — v4.25.0](https://github.com/coreruleset/coreruleset/blob/v4.25.0/CHANGES.md)
- [ModSecurity v3 reference manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))
