# CRS Application Profiles and Exclusion Packages

Application-specific CRS tuning for common platforms. CRS ships pre-built exclusion packages; use them before writing custom exclusions.

**Verified against**: CRS v4.23.0, https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/.

---

## Built-In Exclusion Packages

CRS includes exclusion packages for common applications. Enable in `crs-setup.conf`:

| Application | CRS Package | Enable Variable |
|-------------|-------------|-----------------|
| WordPress | `REQUEST-903.9001-WORDPRESS-EXCLUSION-RULES` | `tx.crs_exclusions_wordpress=1` |
| Drupal | `REQUEST-903.9002-DRUPAL-EXCLUSION-RULES` | `tx.crs_exclusions_drupal=1` |
| Nextcloud | `REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES` | `tx.crs_exclusions_nextcloud=1` |
| phpMyAdmin | `REQUEST-903.9004-PHPMYADMIN-EXCLUSION-RULES` | `tx.crs_exclusions_phpmyadmin=1` |
| phpBB | `REQUEST-903.9005-PHPBB-EXCLUSION-RULES` | `tx.crs_exclusions_phpbb=1` |
| cPanel | `REQUEST-903.9006-CPANEL-EXCLUSION-RULES` | `tx.crs_exclusions_cpanel=1` |
| DokuWiki | `REQUEST-903.9007-DOKUWIKI-EXCLUSION-RULES` | `tx.crs_exclusions_dokuwiki=1` |
| XenForo | `REQUEST-903.9008-XENFORO-EXCLUSION-RULES` | `tx.crs_exclusions_xenforo=1` |

### Enabling a Package

```apache
# In crs-setup.conf or before CRS include:
SecAction "id:900130,phase:1,pass,t:none,nolog,\
    setvar:tx.crs_exclusions_wordpress=1"
```

### Scoping Packages by Location

For multi-app servers, enable packages only for the relevant path:

```apache
# WordPress at /blog/
SecRule REQUEST_URI "@beginsWith /blog/" \
    "id:100200,phase:1,pass,nolog,\
    setvar:tx.crs_exclusions_wordpress=1"
```

---

## Common Application Patterns

### WordPress

| FP Trigger | Typical Rules | Exclusion Approach |
|-----------|---------------|-------------------|
| Post editor (HTML in body) | 941xxx (XSS) | Enable WordPress package; or `ctl:ruleRemoveTargetById=941xxx;ARGS:content` for `/wp-admin/post.php` |
| Plugin/theme upload | 920xxx (file upload) | Scoped by URI: `/wp-admin/update.php` |
| REST API (`/wp-json/`) | 942xxx (SQLi) | Enable WordPress package; covers common REST parameters |
| Customizer AJAX | Multiple | WordPress package handles most cases |

### JSON/REST APIs

| FP Trigger | Typical Rules | Exclusion Approach |
|-----------|---------------|-------------------|
| JSON body with SQL-like keys | 942xxx | `ctl:ruleRemoveTargetById=942xxx;ARGS:filter` for specific endpoints |
| GraphQL queries | 942xxx, 941xxx | Scope by URI: `/graphql`; consider `ctl:ruleRemoveById` for 942100 at that path |
| Bearer token in Authorization | 920xxx | Usually not triggered; if needed, exclude `REQUEST_HEADERS:Authorization` |
| Base64 in body | 941xxx, 942xxx | Scope by endpoint and parameter |
| Large JSON bodies | 920xxx (body size) | Adjust `SecRequestBodyNoFilesLimit` for API paths |

### Single-Page Applications (SPAs)

| FP Trigger | Typical Rules | Exclusion Approach |
|-----------|---------------|-------------------|
| Framework-specific headers (e.g., `Next-Action`) | 920xxx | `ctl:ruleRemoveTargetByTag=920;REQUEST_HEADERS:Next-Action` scoped to SPA paths |
| Encoded state in URL | 942xxx | Scope by path; decode before matching |
| Preflight (OPTIONS) | 911xxx | Usually allowed; verify method enforcement rules |

### Legacy/Custom Applications

| Pattern | Approach |
|---------|----------|
| Non-standard parameter names (dots, brackets) | Exclusion by `ARGS_NAMES` pattern |
| Binary/file uploads | Adjust body limits; exclude upload paths |
| SOAP/XML bodies | Ensure `SecRequestBodyAccess On`; check XML body processor |

---

## Workflow for Application Tuning

1. **Check if a CRS package exists** for your application. Enable it first.
2. **Run representative traffic** through the WAF (or replay production logs).
3. **Analyze false positives**: `python scripts/analyze_log.py audit.log --top-rules 20`.
4. **Apply narrowest exclusion** — prefer `ctl:ruleRemoveTargetById` scoped by URI over global removal.
5. **Test regression**: `go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/`.
6. **Document exclusions** with reason, date, and owning team.

---

## Best Practices

- **Enable built-in packages first** — they're tested and maintained by CRS contributors.
- **Scope narrowly** — by URI, method, and specific parameter. Never exclude globally without justification.
- **Test with attack payloads** after applying exclusions — ensure they don't create security gaps.
- **Review exclusions periodically** — app updates may change parameter names or endpoints.
- **Keep exclusions in separate files** — one file per application for maintainability.

## What to Avoid

- **Enabling all exclusion packages** "just in case" — each package loosens detection.
- **Global `SecRuleRemoveById`** for application tuning — scope by URI/method.
- **Disabling entire rule categories** (e.g., all 942xxx) for one noisy endpoint.
- **Not testing after exclusions** — an exclusion can silently disable detection for real attacks.
- **Editing CRS rule files directly** — use exclusion mechanisms instead.

---

## Related References

- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies and decision tree
- [actions-reference.md](actions-reference.md) — `ctl:ruleRemoveTargetById` and exclusion actions
- [modsec-directives.md](modsec-directives.md) — `SecRuleRemoveById`, `SecRuleUpdateTargetById`
- CRS Exclusion Packages: https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/#rule-exclusion-packages
- CRS Plugins: https://github.com/coreruleset/plugin-registry
