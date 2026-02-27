# CRS Application Profiles and Exclusion Packages

Application-specific CRS tuning for common platforms. CRS ships pre-built exclusion packages; use them before writing custom exclusions.

**Verified against** (2026-02-15):
- CRS docs: https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/
- CRS plugins docs: https://coreruleset.org/docs/4-about-plugins/4-1-plugins/
- CRS plugin registry: https://github.com/coreruleset/plugin-registry

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

### NextJS + Coraza (Caddy)

No built-in CRS exclusion package. Write targeted exclusions for session token cookies.

| FP Trigger | Typical Rules | Exclusion Approach |
|-----------|---------------|-------------------|
| `__Secure-next-auth.session-token` cookie with base64-encoded PHP-like substrings (`fputs`, `fclose`) | 933150 | `ctl:ruleRemoveTargetById=933150;REQUEST_COOKIES:__Secure-next-auth.session-token` — use **literal** cookie name, not regex |
| Same session token containing `.env` substring | 930120 | `ctl:ruleRemoveTargetById=930120;REQUEST_COOKIES:__Secure-next-auth.session-token` |
| `Next-Action` or other framework-specific headers | 920xxx | `ctl:ruleRemoveTargetByTag=920;REQUEST_HEADERS:Next-Action` scoped to SPA paths |

> **Warning**: Regex patterns in `ctl:ruleRemoveTargetById` silently fail. Always use the exact, literal cookie or parameter name.

```apache
# Example: NextJS session token exclusions (place BEFORE CRS include)
SecRule REQUEST_URI "@beginsWith /" \
    "id:100010,phase:1,pass,nolog,t:none,\
    ctl:ruleRemoveTargetById=933150;REQUEST_COOKIES:__Secure-next-auth.session-token"

SecRule REQUEST_URI "@beginsWith /" \
    "id:100011,phase:1,pass,nolog,t:none,\
    ctl:ruleRemoveTargetById=930120;REQUEST_COOKIES:__Secure-next-auth.session-token"
```

### Payload CMS (REST API)

No built-in CRS exclusion package. Rule 932370 fires at PL1 on any JSON body containing URL fields.

| FP Trigger | Typical Rules | Exclusion Approach |
|-----------|---------------|-------------------|
| `POST /admin/collections/*` JSON body with `{"url": "..."}` | 932370 (PL1) | `ctl:ruleRemoveById=932370` scoped to `/admin/collections` — **must use `ctl:ruleRemoveById`**, not `ctl:ruleRemoveTargetById` (chain rule) |
| `POST /api/pages/*` or other REST endpoints with URL fields in JSON | 932370 (PL1) | `ctl:ruleRemoveById=932370` scoped to `/api/` |

> **Note**: Rule 932370 is a chained rule. `ctl:ruleRemoveTargetById` does not propagate through chain links and will silently fail. Use `ctl:ruleRemoveById` scoped narrowly by URI.

```apache
# Example: Payload CMS REST API exclusions (place BEFORE CRS include)
SecRule REQUEST_URI "@beginsWith /admin/collections" \
    "id:100020,phase:1,pass,nolog,t:none,\
    ctl:ruleRemoveById=932370"

SecRule REQUEST_URI "@beginsWith /api/" \
    "id:100021,phase:1,pass,nolog,t:none,\
    ctl:ruleRemoveById=932370"
```

### Legacy/Custom Applications

| Pattern | Approach |
|---------|----------|
| Non-standard parameter names (dots, brackets) | Exclusion by `ARGS_NAMES` pattern |
| Binary/file uploads | Adjust body limits; exclude upload paths |
| SOAP/XML bodies | Ensure `SecRequestBodyAccess On`; check XML body processor |

---

## Workflow for Application Tuning

1. **Run representative traffic** through the WAF (or replay production logs).
2. **Detect likely profile**: `python scripts/detect_app_profile.py audit.log --output text`.
3. **Check if a CRS package/plugin exists** for the detected application and enable that first.
4. **Analyze false positives**: `python scripts/analyze_log.py audit.log --explain`.
5. **Apply narrowest exclusion** — prefer `ctl:ruleRemoveTargetById` scoped by URI over global removal.
6. **Validate exclusion trade-offs**: `python scripts/validate_exclusion.py --input exclusion.conf`.
7. **Test regression**: `go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/`.
8. **Document exclusions** with reason, date, and owning team.

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
