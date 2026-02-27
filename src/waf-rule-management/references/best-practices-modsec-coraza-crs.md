# Best Practices: ModSecurity, Coraza, and CRS

Recommended practices for deploying, configuring, and operating ModSecurity, Coraza WAF, and OWASP Core Rule Set (CRS). Use this reference when advising on configuration, tuning, or rule development.

---

## 1. ModSecurity Best Practices

### Rule Engine and Deployment

| Practice | Recommendation |
|----------|----------------|
| **Initial deployment** | Start with `SecRuleEngine DetectionOnly` to minimize post-installation disruption. Switch to `On` only after tuning and validation. |
| **Request body access** | Always enable `SecRequestBodyAccess On`. Without it, ModSecurity cannot inspect POST parameters—a major security gap. |
| **Response body access** | Enable `SecResponseBodyAccess On` to detect data leakage and errors. Be aware it increases memory and latency. |

### Request/Response Body Handling

| Directive | Recommended | Notes |
|-----------|--------------|-------|
| `SecRequestBodyLimit` | 13107200 (12.5 MB) | Adjust for max file upload size |
| `SecRequestBodyNoFilesLimit` | 131072 (128 KB) | Keep low for non-file args |
| `SecRequestBodyLimitAction` | Reject | Use ProcessPartial only in DetectionOnly |
| `SecRequestBodyJsonDepthLimit` | 512 | Lower if possible |
| `SecArgumentsLimit` | 1000 | Match rule 200007 |
| `SecResponseBodyMimeType` | text/plain text/html text/xml | Avoid buffering images/archives |
| `SecResponseBodyLimit` | 524288 (512 KB) | Balance coverage vs memory |
| `SecResponseBodyLimitAction` | ProcessPartial | Avoid breaking large responses |

### Parsing and Limits

- **XML/JSON parsers**: Enable via `ctl:requestBodyProcessor=XML` or `JSON` for appropriate Content-Types.
- **Multipart**: Keep strict multipart validation; do not remove rule 200003/200004. Use permissive mode only if PEM/header-like content is required.
- **PCRE limits**: Set `SecPcreMatchLimit` and `SecPcreMatchLimitRecursion` (e.g. 1000) to mitigate ReDoS.

### Audit and Logging

| Directive | Recommended |
|-----------|-------------|
| `SecAuditEngine` | RelevantOnly |
| `SecAuditLogRelevantStatus` | `^(?:5\|4(?!04))` (5xx and 4xx except 404) |
| `SecAuditLogParts` | ABIJDEFHZ |
| `SecAuditLogType` | Serial (or Concurrent with storage dir) |

### Filesystem and Security

- Use a **private** `SecTmpDir` and `SecDataDir` (not world-readable `/tmp`).
- Use a **private** `SecUploadDir` for intercepted uploads.
- Set `SecCookieFormat 0` (most apps use version 0).
- Set `SecUnicodeMapFile` for correct `t:urlDecodeUni` behavior and fewer FPs.

### Sources

- [modsecurity.conf-recommended](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/modsecurity.conf-recommended)
- [OWASP ModSecurity DevGuide](https://devguide.owasp.org/en/09-operations/03-modsecurity/)

---

## 2. Coraza Best Practices

### Configuration Order

Load directives in this order:

1. `coraza.conf` (or coraza.conf-recommended) — base Coraza config
2. `crs-setup.conf.example` (or your tuned `crs-setup.conf`) — CRS variables and thresholds
3. `coreruleset/rules/*.conf` — CRS rules
4. User rules (e.g. `/opt/coraza/rules.d/*.conf`)

### Transaction Processing

- Process phases in order: ProcessConnection → ProcessURI → AddRequestHeader → ProcessRequestHeaders → RequestBodyBuffer → ProcessRequestBody.
- Use `ProcessRequest()` helper when available for phases 1 and 2.
- Check `tx.Interruption()` after processing to determine deny/allow.

### Rule Implementation

- Use Seclang syntax; add rules via `WithDirectives()` or equivalent.
- Apply disruptive actions (`deny(403)`) or logging as appropriate.
- Coraza supports most ModSecurity v3 directives; check [Coraza docs](https://coraza.io/docs/) for unsupported features.

### Deployment Options

- Library (embed in app), reverse proxy, or container (e.g. [coraza-crs-docker](https://github.com/coreruleset/coraza-crs-docker)).
- Integrations: Caddy, Envoy/Istio, HAProxy (SPOA), Nginx.

### Sources

- [Coraza CRS Tutorial](https://coraza.io/docs/tutorials/coreruleset/)
- [Coraza Quick Start](https://coraza.io/docs/tutorials/quick-start/)
- [OWASP Coraza DevGuide](https://devguide.owasp.org/en/09-operations/02-coraza/)

---

## 3. CRS Best Practices

### Paranoia Levels

| Level | Use Case | False Positives |
|-------|----------|-----------------|
| **PL1** | Default; beginners, multi-site, standard security | Minimal; report FPs to GitHub |
| **PL2** | Experienced users; elevated security | Some; write exclusions |
| **PL3** | High security; obfuscation coverage | Regular; expect exclusions |
| **PL4** | Very high security; experienced only | High; extensive tuning |

**Best practice**: Start at PL1 in production. Increase only after building exclusion rules for legitimate traffic. At PL2+, false positives are expected—write exclusions rather than reporting.

### Anomaly Scoring

- Default thresholds: **inbound 5**, **outbound 4** (rule 900900).
- Severity scores: CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2.
- Tune thresholds per application; avoid lowering below 5/4 without justification.

### Tuning and Exclusions

| Practice | Recommendation |
|----------|----------------|
| **Exclusion placement** | Prefer `SecRuleRemoveById` / `SecRuleRemoveByTag` in before-CRS config. Use `ctl:ruleRemoveById` for request-specific exclusions. |
| **Scope** | Narrow exclusions to specific URIs, methods, or variables. Avoid global disables. |
| **Application profiles** | Use [CRS plugins](https://github.com/coreruleset/plugin-registry) (e.g. WordPress, Drupal) for known apps. |
| **DAST/discovery ingress mapping** | Run `cdncheck` first to detect CDN/cloud/WAF front doors that may mask origin behavior during profiling and assessment. |
| **Sampling mode** | Use for gradual rollout; start with low percentage, increase after validation. |

### Deployment Workflow

1. Deploy in **DetectionOnly** (or sampling) first.
2. Monitor logs; identify false positives.
3. Add exclusions for legitimate traffic.
4. Validate with go-ftw or similar.
5. Enable blocking; continue monitoring.

For discovery-first assessments, add:
- `go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest`
- `cdncheck -i app.example.com -jsonl`

### Sources

- [CRS False Positives and Tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/) — Rule exclusions, placement, examples
- [CRS Paranoia Levels](https://coreruleset.org/faq/what-are-the-paranoia-levels)
- [CRS Documentation](https://coreruleset.org/docs/)
- [CRS Known Issues](https://coreruleset.org/docs/operation/known_issues/)

---

## 4. Rule Development Best Practices

### Writing New Rules

- Use the **narrowest variable** that detects the threat (e.g. `ARGS:password` vs `ARGS`).
- Prefer **positive matching** (match attack pattern) over broad negative patterns.
- Add **transformations** (e.g. `t:lowercase`, `t:urlDecodeUni`) only when needed.
- Set **severity** and **tag** for anomaly scoring and filtering.
- **Chain** rules when multiple conditions must match.

### CRS Conventions

- Follow [crs-rule-format.md](crs-rule-format.md) for CRS contributions.
- Use CRS rule ID ranges for custom rules (e.g. 100000+).
- Tag custom rules for easy exclusion.

### Testing

- Validate syntax: `python scripts/validate_rule.py rule.conf`
- Lint CRS style: `python scripts/lint_crs_rule.py rule.conf`
- **Regex rules**: Lint for ReDoS/performance: `python scripts/lint_regex.py rule.conf -v` — see [regex-steering-guide.md](regex-steering-guide.md)
- Test with go-ftw before deployment.
- Use CRS Sandbox for quick payload checks.
- Run the same regression suite on both ModSecurity and Coraza before release.
- Keep dedicated test sets for `custom`, `false-positives`, and `cve` payloads.
- For tuning changes, replay legitimate traffic tests first, then attack payload tests.

---

## 5. Operations Checklist

- [ ] Start with DetectionOnly or sampling
- [ ] Enable request and (if needed) response body access
- [ ] Set appropriate body limits and JSON depth
- [ ] Configure audit logging and retention
- [ ] Use private tmp/data/upload directories
- [ ] Start CRS at PL1; increase only with exclusions
- [ ] Add application-specific exclusions (plugins or custom)
- [ ] Test with go-ftw before blocking
- [ ] Monitor logs; iterate on exclusions
- [ ] Document custom rules and exclusions

---

## What to Avoid

- Deploying in blocking mode before tuning in DetectionOnly — causes immediate legitimate traffic disruption.
- Setting `SecRequestBodyAccess Off` — creates a critical blind spot for POST parameters.
- Using public `/tmp` for `SecTmpDir`, `SecDataDir`, or `SecUploadDir` — security risk.
- Lowering anomaly thresholds below 5/4 as a first response to incidents — address root causes with exclusions instead.
- Applying one configuration across all apps without validation — each app has unique traffic patterns.
- Disabling CRS entirely due to false positives — use exclusion packages and targeted tuning.
- Skipping cross-engine testing before release — ModSecurity and Coraza may differ.

---

## Related References

- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Exclusion strategies and decision tree
- [paranoia-levels.md](paranoia-levels.md) — PL rollout strategy
- [sampling-mode.md](sampling-mode.md) — Gradual rollout patterns
- [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) — Common configuration mistakes
- [developer-security-workflow.md](developer-security-workflow.md) — CI/CD integration
- [modsec-directives.md](modsec-directives.md) — Directive reference
