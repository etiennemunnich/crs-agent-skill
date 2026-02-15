# ModSecurity Variables and Collections

Complete reference for variables used in ModSecurity v3 and Coraza rules.

**Verified against**: ModSecurity v3.0.14, [Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).

---

## Request Variables

| Variable | Description | Phase | Common Use |
|----------|-------------|-------|------------|
| `REQUEST_URI` | Full request URI (path + query string) | 1 | Path-based rules, URL patterns |
| `REQUEST_URI_RAW` | Raw (undecoded) URI | 1 | Encoding evasion detection |
| `REQUEST_FILENAME` | URI path only (no query string) | 1 | File extension checks |
| `REQUEST_BASENAME` | Filename portion of path | 1 | File upload checks |
| `REQUEST_METHOD` | HTTP method (GET, POST, etc.) | 1 | Method enforcement |
| `REQUEST_PROTOCOL` | Protocol (HTTP/1.1, etc.) | 1 | Protocol validation |
| `REQUEST_LINE` | Full request line | 1 | Protocol anomaly detection |
| `REQUEST_HEADERS` | All request headers | 1 | Header-based rules |
| `REQUEST_HEADERS:Name` | Specific header | 1 | `REQUEST_HEADERS:Content-Type` |
| `REQUEST_HEADERS_NAMES` | Header names only | 1 | Unusual header detection |
| `REQUEST_BODY` | Raw request body | 2 | Body content scanning |
| `REQUEST_BODY_LENGTH` | Body size in bytes | 2 | Size-based rules |
| `ARGS` | All arguments (query + body) | 1–2 | General injection detection |
| `ARGS:name` | Specific argument | 1–2 | Targeted parameter check |
| `ARGS_NAMES` | Argument names only | 1–2 | Parameter name validation |
| `ARGS_GET` | Query string arguments only | 1 | GET-specific rules |
| `ARGS_GET:name` | Specific query parameter | 1 | Targeted query check |
| `ARGS_POST` | POST body arguments only | 2 | POST-specific rules |
| `ARGS_POST:name` | Specific POST parameter | 2 | Targeted body check |
| `ARGS_COMBINED_SIZE` | Total size of all arguments | 1–2 | Size limits |
| `REQUEST_COOKIES` | Cookie values | 1 | Cookie-based rules |
| `REQUEST_COOKIES:name` | Specific cookie | 1 | Targeted cookie check |
| `REQUEST_COOKIES_NAMES` | Cookie names only | 1 | Unusual cookie detection |
| `FILES` | Uploaded file content | 2 | File upload scanning |
| `FILES_NAMES` | Uploaded file field names | 2 | Upload field validation |
| `FILES_COMBINED_SIZE` | Total uploaded file size | 2 | Upload size limits |
| `FILES_TMPNAMES` | Temporary file paths | 2 | Internal use |
| `MULTIPART_STRICT_ERROR` | Multipart parse error flag | 2 | Malformed multipart detection |

## Response Variables

| Variable | Description | Phase |
|----------|-------------|-------|
| `RESPONSE_STATUS` | HTTP response status code | 3 |
| `RESPONSE_HEADERS` | All response headers | 3 |
| `RESPONSE_HEADERS:Name` | Specific response header | 3 |
| `RESPONSE_BODY` | Response body content | 4 |
| `RESPONSE_CONTENT_TYPE` | Response Content-Type | 3 |
| `RESPONSE_CONTENT_LENGTH` | Response body size | 3 |

## Connection Variables

| Variable | Description |
|----------|-------------|
| `REMOTE_ADDR` | Client IP address |
| `REMOTE_PORT` | Client port |
| `REMOTE_HOST` | Client hostname (if resolved) |
| `SERVER_ADDR` | Server IP |
| `SERVER_PORT` | Server port |
| `SERVER_NAME` | Server hostname |

## Transaction Variables

| Variable | Description | Scope |
|----------|-------------|-------|
| `TX` | Transaction collection (per-request) | Current request |
| `TX:name` | Specific transaction variable | Current request |
| `TX.0` / `TX.1` | Regex capture groups from last match | Current rule |
| `IP` | IP-based persistent collection | Cross-request (requires `initcol`) |
| `SESSION` | Session-based persistent collection | Cross-request (requires `initcol`) |
| `MATCHED_VAR` | Value that triggered the match | Current rule |
| `MATCHED_VAR_NAME` | Full name of variable that triggered | Current rule |
| `MATCHED_VARS` | All matched values (multi-match) | Current rule |
| `MATCHED_VARS_NAMES` | All matched variable names | Current rule |

### CRS Transaction Variables

| Variable | Purpose |
|----------|---------|
| `tx.inbound_anomaly_score_pl1` | PL1 inbound anomaly score |
| `tx.inbound_anomaly_score_pl2` | PL2 inbound anomaly score |
| `tx.inbound_anomaly_score_pl3` | PL3 inbound anomaly score |
| `tx.outbound_anomaly_score_pl1` | PL1 outbound anomaly score |
| `tx.critical_anomaly_score` | Score value for CRITICAL (5) |
| `tx.error_anomaly_score` | Score value for ERROR (4) |
| `tx.warning_anomaly_score` | Score value for WARNING (3) |
| `tx.notice_anomaly_score` | Score value for NOTICE (2) |
| `tx.blocking_paranoia_level` | Current blocking PL |
| `tx.detection_paranoia_level` | Current detection PL |
| `tx.inbound_anomaly_score_threshold` | Blocking threshold |

## Special Variables

| Variable | Description |
|----------|-------------|
| `DURATION` | Time elapsed since request start (microseconds) |
| `TIME` | Current time |
| `TIME_EPOCH` | Unix timestamp |
| `UNIQUE_ID` | Unique request identifier |
| `RULE` | Current rule metadata |
| `ENV` | Environment variables |
| `WEBSERVER_ERROR_LOG` | Last web server error message |

---

## Collection Count Operator

Use `&` prefix to count occurrences:

```apache
# True if ARGS:name has zero occurrences (parameter not set)
SecRule &ARGS:name "@eq 0" "id:100001,phase:2,deny,msg:'Missing required param'"

# True if there are more than 10 arguments
SecRule &ARGS "@gt 10" "id:100002,phase:2,deny,msg:'Too many parameters'"
```

---

## Variable Selection Guide

| Detecting | Use Variable | Phase |
|-----------|-------------|-------|
| Path-based attacks | `REQUEST_URI`, `REQUEST_FILENAME` | 1 |
| Query string injection | `ARGS_GET`, `ARGS_GET:param` | 1 |
| POST body injection | `ARGS_POST`, `ARGS_POST:param` | 2 |
| Any injection (query+body) | `ARGS`, `ARGS:param` | 1–2 |
| Header manipulation | `REQUEST_HEADERS:Name` | 1 |
| Cookie attacks | `REQUEST_COOKIES:name` | 1 |
| File uploads | `FILES`, `FILES_NAMES` | 2 |
| Method enforcement | `REQUEST_METHOD` | 1 |
| IP blocking | `REMOTE_ADDR` | 1 |
| Response data leakage | `RESPONSE_BODY` | 4 |

---

## Best Practices

- **Use specific variables** — `ARGS:param` over `ARGS` when you know the parameter name.
- **Use `ARGS_GET` / `ARGS_POST`** when the attack only applies to query or body.
- **Include `logdata` with `%{MATCHED_VAR_NAME}`** — shows which variable triggered the match.
- **Check with `&` count** for parameter presence/absence before matching.
- **Use phase 1 when possible** — avoids body buffering overhead.
- **Use `REQUEST_HEADERS:Content-Type`** for content-type enforcement (not `REQUEST_HEADERS`).

## What to Avoid

- **Scanning `ARGS` when only `ARGS_GET` is relevant** — increases FP surface.
- **Using `REQUEST_BODY` for structured data** — `ARGS_POST` is already parsed; `REQUEST_BODY` is raw.
- **Forgetting phase 2 for body rules** — body variables are empty in phase 1.
- **`RESPONSE_BODY` without `SecResponseBodyAccess On`** — variable will be empty.
- **Over-relying on `REMOTE_ADDR`** — may be CDN/proxy IP; check `X-Forwarded-For` handling.

---

## Related References

- [operators-and-transforms.md](operators-and-transforms.md) — Operators to apply to variables
- [actions-reference.md](actions-reference.md) — Actions for matched variables
- [crs-rule-format.md](crs-rule-format.md) — CRS template showing variable usage
- [anomaly-scoring.md](anomaly-scoring.md) — TX score variables
- ModSecurity v3 Reference Manual: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
