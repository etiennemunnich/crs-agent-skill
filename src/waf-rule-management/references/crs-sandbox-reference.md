# CRS Sandbox API Reference

## Overview

The CRS Sandbox at https://sandbox.coreruleset.org/ lets you test payloads against OWASP CRS without local setup. Send requests with optional HTTP headers to control backend, version, and output format.

## Quick Start

```bash
curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?file=/etc/passwd"
```

Returns matched rule IDs and descriptions. Without `x-format-output`, the full WAF audit log (JSON) is returned.

## HTTP Headers

| Header | Values | Default |
|--------|--------|---------|
| `x-backend` | `apache`, `nginx`, `coraza-caddy` | apache |
| `x-crs-paranoia-level` | 1–4 | 1 |
| `x-crs-version` | e.g. 4.20.0, or omit for latest | latest |
| `x-format-output` | `txt-matched-rules`, `json-matched-rules`, `csv-matched-rules`, `txt-matched-rules-extended` | full audit log |

Header names are case-insensitive.

## Output Formats

- **txt-matched-rules**: Human-readable, one rule per line (recommended for quick checks)
- **json-matched-rules**: JSON array of rule matches for automation
- **csv-matched-rules**: CSV format
- **txt-matched-rules-extended**: Same as txt with explanatory preamble for publications

## Examples

```bash
# Basic payload test
curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?file=/etc/passwd"

# Nginx + ModSec 3, paranoia level 2
curl -H "x-backend: nginx" \
     -H "x-crs-paranoia-level: 2" \
     -H "x-format-output: txt-matched-rules" \
     "https://sandbox.coreruleset.org/?file=/etc/passwd"

# JSON output for scripting
curl -H "x-format-output: json-matched-rules" \
     "https://sandbox.coreruleset.org/?file=/etc/passwd" | jq .

# Specific CRS version
curl -H "x-crs-version: 4.20.0" \
     -H "x-format-output: txt-matched-rules" \
     "https://sandbox.coreruleset.org/PAYLOAD"
```

## Reproducible Requests for CRS Tickets

For false-positive or rule-improvement tickets, do not rely on wrappers. Use raw `curl`
with explicit method, headers, and body, then save request/response artifacts.

**CRS issue templates** require a reproducible curl call. Use the appropriate template when filing:
- [False positive](https://github.com/coreruleset/coreruleset/issues/new?template=01_false-positive.md) — legitimate traffic blocked
- [False negative](https://github.com/coreruleset/coreruleset/issues/new?template=02_false-negative.md) — attack not blocked (evasion/bypass)

CRS asks that you **test your curl against the Sandbox** before submitting. See [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md#8-reporting-to-crs-issue-template) for full template requirements.

### GET with explicit controls

```bash
curl --request GET --include --silent --show-error \
  -H "x-backend: nginx" \
  -H "x-crs-paranoia-level: 2" \
  -H "x-crs-version: 4.20.0" \
  -H "x-format-output: json-matched-rules" \
  "https://sandbox.coreruleset.org/?q=<script>alert(1)</script>" \
  -o sandbox-get.out
```

### POST JSON payload

```bash
curl --request POST --include --silent --show-error \
  -H "Content-Type: application/json" \
  -H "x-backend: coraza-caddy" \
  -H "x-crs-paranoia-level: 1" \
  -H "x-format-output: json-matched-rules" \
  --data-binary '{"username":"admin","payload":"<script>alert(1)</script>"}' \
  "https://sandbox.coreruleset.org/api/login" \
  -o sandbox-post-json.out
```

### POST form payload

```bash
curl --request POST --include --silent --show-error \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "x-backend: apache" \
  -H "x-crs-paranoia-level: 2" \
  -H "x-format-output: txt-matched-rules" \
  --data-binary "user=test&comment=<h1>Hello</h1>" \
  "https://sandbox.coreruleset.org/submit" \
  -o sandbox-post-form.out
```

### Capture full exchange for attachment

```bash
curl --request POST --include --silent --show-error \
  -H "Content-Type: application/json" \
  -H "x-format-output: json-matched-rules" \
  --data-binary @payload.json \
  "https://sandbox.coreruleset.org/api/test" \
  --dump-header sandbox.headers \
  --output sandbox.body \
  --write-out "http_code=%{http_code}\n" \
  > sandbox.meta
```

Recommended ticket attachments:
- Exact `curl` command used (including method + headers + body source).
- `sandbox.headers`, `sandbox.body`, `sandbox.meta`.
- Any local ModSecurity/Coraza replay output for comparison.
- Expected vs actual behavior and why it is a false positive or missed detection.

## Response

- HTTP 200 regardless of detection (attack detected or not)
- `X-Unique-ID` header in response: unique value for referencing the request

## Limits

- Max 10 requests per second

## Known Issues

- **ReDoS**: Payloads causing catastrophic backtracking may timeout (502)
- **Malformed HTTP**: Frontend or backend may reject with 400 before CRS scans

## Best Practices

- Use `json-matched-rules` output for automation and scripting; `txt-matched-rules` for human review.
- Always include explicit `--request METHOD` and all relevant headers in reproducible requests — do not rely on curl defaults.
- Pin `x-crs-version` when filing bug reports or comparing behavior over time.
- Save both request command and response artifacts (`--dump-header`, `--output`, `--write-out`) for ticket attachments.
- Use Sandbox as a **quick reference signal**, not as production truth — your local CRS+Albedo environment is authoritative.
- Test the same payload locally and on Sandbox to verify consistency before reporting discrepancies.

## What to Avoid

- Exceeding the 10 requests/second rate limit — causes 429 errors.
- Sending intentionally ReDoS payloads without understanding they may timeout (502).
- Relying solely on Sandbox results without local reproduction — Sandbox config may differ from your setup.
- Omitting `x-backend` when results differ between engines — default is Apache, which may not match your deployment.
- Using wrapper scripts that hide the actual curl command — makes tickets hard to reproduce.

## Related

[go-ftw-reference.md](go-ftw-reference.md) | [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) | [CRS Sandbox docs](https://coreruleset.org/docs/6-development/6-4-using-the-crs-sandbox/)
