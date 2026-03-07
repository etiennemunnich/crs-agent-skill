# go-ftw Reference (v2)

go-ftw is the primary regression test runner for CRS-style WAF testing.
Verified against: **go-ftw v2.0.0** (Jan 2026).

- GitHub: <https://github.com/coreruleset/go-ftw>
- Baseline tools: [baseline-testing-tools.md](baseline-testing-tools.md) — go-test-waf, nuclei
- Test schema: <https://github.com/coreruleset/ftw-tests-schema>

## Install

```bash
# Go module path requires /v2 suffix
go install github.com/coreruleset/go-ftw/v2@latest

# Or download a binary from releases:
# https://github.com/coreruleset/go-ftw/releases
```

## Configuration (.ftw.yaml)

go-ftw looks for `.ftw.yaml` in the current directory, then `$HOME`. Override with `--config`.

```yaml
# Minimal cloud-mode config (no log file needed)
mode: "cloud"
testoverride:
  input:
    dest_addr: "localhost"
    port: 8080
    protocol: "http"
```

A ready-to-use config is provided in `assets/docker/.ftw.yaml`.

### Full config options

| Key | Description | Default |
|-----|-------------|---------|
| `logfile` | Path to WAF alert log (required for default mode, not needed in cloud mode) | — |
| `mode` | `"default"` (log-based) or `"cloud"` (HTTP status only) | `"default"` |
| `logmarkerheadername` | HTTP header for log markers (default mode) | `X-CRS-TEST` |
| `maxmarkerretries` | Max retries for log marker search | `20` |
| `maxmarkerloglines` | Max lines to search for marker | `500` |
| `testoverride` | Override test inputs, ignore/force tests (see below) | — |

### Test overrides

```yaml
testoverride:
  input:
    dest_addr: "192.168.1.100"
    port: 8080
    protocol: "http"
    override_empty_host_header: true   # replace empty Host with dest_addr
  ignore:
    '941190-3$': 'known MSC bug - PR #2023'
    '^920': 'skip all 920xxx tests'
  forcepass:
    '123456-02$': 'this test always passes'
  forcefail:
    '123456-01$': 'this test always fails'
```

Override lists use **Go regular expressions** matched against test IDs (`<rule_id>-<test_id>`).

## Test File Format

Schema: [ftw-tests-schema v2](https://github.com/coreruleset/ftw-tests-schema)

### Structure

```yaml
---
meta:
  author: "your-name"
  description: "Test description"
  name: "942100.yaml"
  tags:                         # optional, for filtering with -T
    - "sqli"
rule_id: 942100                 # REQUIRED — the rule being tested
tests:
  - test_title: "942100-1"      # optional (recommended for readability)
    test_id: 1                  # optional (inferred from position if omitted)
    desc: "SQL injection via UNION SELECT"  # optional
    tags: ["union"]             # optional, per-test tags
    stages:
      - input:
          method: "GET"
          uri: "/?id=1' UNION SELECT NULL--"
          headers:
            Host: "localhost"
            User-Agent: "go-ftw/test"
        output:
          status: 403
```

**Key requirements**:
- `rule_id` at top level — **required** by go-ftw v2
- `Host` header in all inputs — nginx returns 400 without it
- One file per rule ID (convention: `<RULE_ID>.yaml`)

### Input fields

| Field | Description |
|-------|-------------|
| `dest_addr` | Destination IP/hostname (overridden by `.ftw.yaml` in practice) |
| `port` | Port number |
| `protocol` | `http` or `https` |
| `method` | HTTP method (`GET`, `POST`, etc.) |
| `uri` | Request URI including query string |
| `version` | HTTP version (e.g. `"HTTP/1.1"`) |
| `headers` | Map of HTTP headers |
| `data` | Request body as plain string |
| `encoded_data` | Request body as base64 (for binary/invisible characters) |
| `encoded_request` | Base64 encoded full HTTP request (overrides all above) |
| `follow_redirect` | Follow redirect from previous stage (ignores address/URI) |
| `save_cookie` | Save cookies from response for subsequent stages |
| `autocomplete_headers` | Auto-add `Connection`, `Content-Length`, `Content-Type`. Default: `true` |

### Output fields

| Field | Description | Mode |
|-------|-------------|------|
| `status` | Expected HTTP status code (e.g. `403`) | cloud + default |
| `response_contains` | String expected in response body | both |
| `log_contains` | String expected in WAF log | default only |
| `no_log_contains` | String that must NOT be in log | default only |
| `log.expect_ids` | Array of rule IDs expected to trigger (e.g. `[942100]`) | default only |
| `log.no_expect_ids` | Rule IDs that must NOT trigger | default only |
| `log.match_regex` | Regex expected to match log content | default only |
| `log.no_match_regex` | Regex that must NOT match log | default only |
| `expect_error` | `true` if no response expected (WAF drops connection) | both |
| `retry_once` | Retry test once on failure (useful for phase 5 races) | both |
| `isolated` | Test should trigger ONLY the rule in `expect_ids` | default only |

### Cloud mode vs default mode

| | Cloud mode (`--cloud`) | Default mode |
|-|------------------------|--------------|
| Assertion | HTTP `status` code only | `status` + log analysis |
| Log file | Not needed | Required (`logfile` in config) |
| Setup | Simpler — recommended for most use cases | Needs log volume mount |
| Works with | ModSecurity, Coraza, any WAF | ModSecurity, Coraza with log access |

**Recommendation**: Use `--cloud` for incident response and custom rule testing. Use default mode for full CRS regression suites where log-level assertions matter.

## Templates in test data

go-ftw supports Go [text/template](https://golang.org/pkg/text/template/) and [Sprig functions](https://masterminds.github.io/sprig/) in `data:` fields:

```yaml
# Repeated characters
data: 'foo=%3d{{ "+" | repeat 34 }}'

# Environment variable
data: 'username={{ env "USERNAME" }}'

# Random data
data: 'token={{ randAlphaNum 32 }}'
```

## Commands

```bash
# Run all tests in cloud mode
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

# Run subset of tests
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/risk-regression/

# Include only specific rules (Go regex on test IDs)
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ -i "^942"

# Exclude specific tests
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ -e "^920"

# Include tests by tag
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ -T "^sqli$"

# Fail on first failure
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ --fail-fast

# Show only failures (CI-friendly)
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ --show-failures-only

# Debug output
go-ftw run --cloud --debug --config assets/docker/.ftw.yaml -d tests/

# JSON output (for CI automation)
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ -o json

# Check test files for syntax errors (no WAF needed)
go-ftw check -d tests/

# Wait for WAF to be ready before running
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/ \
  --wait-for-host http://localhost:8080 \
  --wait-for-expect-status-code 200

# Show version
go-ftw version
```

### Output formats

`-o` flag: `normal` (default, emoji), `plain` (no emoji), `quiet`, `github` (GHA annotations), `json` (machine-parseable).

## Quantitative testing (v2 feature)

Measure false-positive rates using text corpora (e.g., Leipzig news corpus):

```bash
# Run against CRS with default corpus (10K payloads)
go-ftw quantitative -C /path/to/coreruleset -s 10K

# Filter to specific rule
go-ftw quantitative -C /path/to/coreruleset -s 10K -r 942100

# Different paranoia level
go-ftw quantitative -C /path/to/coreruleset -s 10K -P 2

# Debug: show payloads causing FPs
go-ftw quantitative -C /path/to/coreruleset -s 10K --debug
```

## Suggested test layout

```text
tests/
  custom/              # rule behavior tests
  false-positives/     # legitimate traffic regression
  risk-regression/     # stabilized payloads from incident triage
```

## Best practices

- Keep every rule change paired with tests (attack + benign control).
- Pin test inputs for reproducibility — avoid ad-hoc payload drift.
- Run the same suite across both ModSecurity and Coraza before promotion.
- Use `--cloud` for incident response; default mode for full CRS regression.
- Use `go-ftw check -d tests/` before running to catch YAML syntax errors.
- Use `-o json` in CI for machine-parseable results.
- Use `--show-failures-only` in CI for shorter output.
- Use `--wait-for-host` in CI to avoid race conditions with container startup.
- Always include `Host` header in test inputs (nginx returns 400 without it).

## What to avoid

- Do not put non-test YAML files (`.ftw.yaml`, templates) in directories scanned by go-ftw.
- Do not rely on `log_contains` in cloud mode — it is ignored.
- Do not use deprecated fields (`stop_magic`, `raw_request`) — use `encoded_request` instead.
- Do not omit `rule_id` — tests will fail to load.

## Related

[modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) | [coraza-testing-reference.md](coraza-testing-reference.md) | [crs-sandbox-reference.md](crs-sandbox-reference.md)
