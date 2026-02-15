# ModSecurity + CRS Testing Reference

Primary testing reference for ModSecurity v3 with OWASP Core Rule Set. For Coraza cross-engine testing, see [coraza-testing-reference.md](coraza-testing-reference.md).

**Verified against**: ModSecurity v3.0.14, CRS v4.23.0, go-ftw v2.0.0 (Feb 2025).

## Official Sources

- ModSecurity v3: https://github.com/owasp-modsecurity/ModSecurity
- CRS: https://github.com/coreruleset/coreruleset — https://coreruleset.org/docs/
- ModSecurity CRS Docker: https://github.com/coreruleset/modsecurity-crs-docker
- go-ftw: https://github.com/coreruleset/go-ftw
- CRS Sandbox: https://coreruleset.org/docs/development/sandbox/

---

## Quick Start

> **Container runtime**: All `docker` commands in this file work with `finch` as a drop-in replacement.

```bash
# 1. Start test environment (CRS + Albedo backend)
docker compose -f assets/docker/docker-compose.yaml up -d  # or: finch compose ...

# 2. Verify WAF is running
curl -i -H "Host: localhost" "http://localhost:8080/"

# 3. Run regression tests
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

# 4. Quick payload check via Sandbox (no setup)
curl -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd"
```

---

## Test Environment Architecture

```
┌──────────┐     ┌──────────────────┐     ┌────────┐
│  go-ftw  │────>│  ModSecurity+CRS │────>│ Albedo │
│  / curl  │<────│  (nginx reverse  │<────│ (HTTP  │
│          │     │   proxy + WAF)   │     │ reflector)
└──────────┘     └──────────────────┘     └────────┘
   :8080              :8080                  :8888
```

- **ModSecurity+CRS**: WAF engine + OWASP CRS rules, runs as nginx reverse proxy.
- **[Albedo](https://github.com/coreruleset/albedo)**: HTTP reflector backend. Required for go-ftw response-body tests — it echoes back request data in the response for assertion.

### Docker Images

| Image | Source | Notes |
|-------|--------|-------|
| `owasp/modsecurity-crs:nginx` | [Docker Hub](https://hub.docker.com/r/owasp/modsecurity-crs) / [GitHub](https://github.com/coreruleset/modsecurity-crs-docker) | Primary; nginx+ModSec v3+CRS |
| `ghcr.io/coreruleset/modsecurity-crs` | GitHub Container Registry | Same image, alternate registry |
| Alternate catalog | https://modsecurity.digitalwave.hu | Community builds, various base images |

**Always pin image tags** for reproducible testing. Use `docker pull` with explicit tag.

### Compose Files

- **ModSecurity**: `assets/docker/docker-compose.yaml` (default)
- **Coraza**: `assets/docker/docker-compose.coraza.yaml` (see [coraza-testing-reference.md](coraza-testing-reference.md))

```bash
# Start (or: finch compose ...)
docker compose -f assets/docker/docker-compose.yaml up -d

# Check status
docker compose -f assets/docker/docker-compose.yaml ps

# View logs (audit entries are JSON on stderr)
docker logs crs-waf 2>/dev/null | grep '^{'   # or: finch logs crs-waf ...

# Restart after rule changes
docker compose -f assets/docker/docker-compose.yaml down && \
docker compose -f assets/docker/docker-compose.yaml up -d

# Stop
docker compose -f assets/docker/docker-compose.yaml down
```

### Environment Variables

Configure via `.env` file (copy from `assets/docker/.env.example`) or override in `docker-compose.yaml`.
**Review tuning values before first use** — see `.env.example` for guidance.

| Variable | Default | Purpose |
|----------|---------|---------|
| `PARANOIA` | 1 | CRS paranoia level (1–4) |
| `BLOCKING_PARANOIA` | (=PARANOIA) | Blocking threshold PL |
| `ANOMALY_INBOUND` | 5 | Inbound anomaly score threshold |
| `ANOMALY_OUTBOUND` | 4 | Outbound anomaly score threshold |
| `MODSEC_RULE_ENGINE` | On | `On`, `Off`, `DetectionOnly` |
| `MODSEC_AUDIT_LOG` | /dev/stderr | Audit log destination |
| `MODSEC_AUDIT_LOG_FORMAT` | JSON | `JSON` or `Native` |

### Custom Rules Mount

Custom rules are mounted into the CRS rules directory so they are included by the CRS wildcard:

```yaml
volumes:
  - ./custom-rules.conf:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-CUSTOM-RULES.conf:ro
```

Use `scripts/assemble_rules.sh` to compose rules from incident workspaces into `custom-rules.conf`.

---

## Testing Workflow

### 1. Validate rule syntax

```bash
python scripts/validate_rule.py rule.conf
python scripts/lint_regex.py rule.conf -v          # if rule uses @rx
python scripts/lint_crs_rule.py rule.conf          # CRS convention check
```

### 2. Test locally with go-ftw

go-ftw is the official CRS test framework. See [go-ftw-reference.md](go-ftw-reference.md) for test file format, configuration, and advanced usage.

```bash
# Run all tests
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/

# Run specific directory
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/custom/

# Debug mode (verbose output)
go-ftw run --cloud --debug --config assets/docker/.ftw.yaml -d tests/
```

### 3. Compare with CRS Sandbox

Test the same payload against the public Sandbox to verify consistency with upstream CRS:

```bash
curl -H "x-format-output: txt-matched-rules" \
  "https://sandbox.coreruleset.org/?file=/etc/passwd"
```

See [crs-sandbox-reference.md](crs-sandbox-reference.md) for full API headers and reproducible request patterns.

### 4. Verify via audit logs

```bash
# Extract JSON audit entries from container logs
docker logs crs-waf 2>/dev/null | grep '^{' > audit.log

# Analyze
python scripts/analyze_log.py audit.log --summary
python scripts/analyze_log.py audit.log --top-rules 20
```

See [log-analysis-steering.md](log-analysis-steering.md) for CLI patterns and error log analysis.

### 5. Cross-engine comparison (optional)

Run the same test suite against Coraza to catch engine-specific differences.
Stop ModSecurity first — both engines share port 8080.

```bash
docker compose -f assets/docker/docker-compose.yaml down
docker compose -f assets/docker/docker-compose.coraza.yaml up -d
go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/
```

See [coraza-testing-reference.md](coraza-testing-reference.md) for Coraza-specific env vars and paths.

---

## Test Matrix

| Dimension | Values | Why |
|-----------|--------|-----|
| Engine | ModSecurity v3, Coraza | Catch engine-specific behavior |
| CRS version | Latest, previous | Detect regression across CRS releases |
| Mode | `On`, `DetectionOnly` | Separate detection quality from blocking |
| Paranoia level | PL1, PL2, (PL3/PL4 if needed) | Tune false positives progressively |
| Thresholds | Default 5/4, tuned | Verify anomaly policy impact |
| Input set | Attack payloads + benign traffic | Prevent regressions and overblocking |
| Content-Type | JSON, multipart, urlencoded | CRS handles body types differently |

---

## Best Practices

- **Record exact versions**: `go-ftw version`, `docker inspect` for image tags, CRS version header.
- **Pin image tags** for reproducible testing. Use `:nginx-YYYYMM` or specific digest.
- **Use direct commands**: `docker compose`, `go-ftw`, `curl` — not local wrappers.
- **Include benign controls**: Every test suite must have non-trigger cases to detect overblocking.
- **Test across content-types**: Same payload in JSON, multipart, and urlencoded — CRS body processors differ.
- **Capture artifacts**: `--dump-header`, body output, status codes for issue attachments.
- **Use `--cloud` mode**: Simplest go-ftw mode, relies on HTTP status only, works with any WAF container.
- **Keep tests alongside rules**: `tests/` directory next to `rules.conf` for traceability.

## What to Avoid

- **Testing only happy-path attacks**: Always include benign/legitimate traffic regression.
- **Relying solely on Sandbox**: Sandbox is a reference signal, not production truth. Always test locally.
- **Skipping log verification**: Confirm rules fire by checking audit logs, not just HTTP status.
- **Testing one content-type only**: Content-type bypass is a common WAF evasion.
- **Running tests without `.ftw.yaml`**: go-ftw defaults to port 80; CRS Docker uses 8080.
- **Editing the mounted `custom-rules.conf` directly**: Use `assemble_rules.sh` for composability.
- **Testing without a Host header**: nginx returns 400 without one; include `Host: localhost` in test inputs.
- **Ignoring DetectionOnly mode**: Use it for initial rollout to observe without blocking.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `connection refused` on port 8080 | Container not running | `docker compose up -d` and check `docker compose ps` |
| `400 Bad Request` | Missing `Host` header | Add `Host: localhost` to test inputs |
| go-ftw `no tests found` | Missing `rule_id` field | Add top-level `rule_id` to test YAML |
| Rules not loading | Wrong mount path | Mount to `/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-CUSTOM-RULES.conf` |
| Rule fires in Sandbox but not locally | Different CRS version or PL | Check `PARANOIA` env var and image tag |
| `PCRE limit exceeded` in error log | ReDoS-prone regex | Fix regex pattern; see [regex-steering-guide.md](regex-steering-guide.md) |
| Audit log empty | `MODSEC_AUDIT_LOG_FORMAT` not set | Ensure env var is `JSON` in compose file |

---

## Related References

- [go-ftw-reference.md](go-ftw-reference.md) — Test file format, config, cloud mode
- [crs-sandbox-reference.md](crs-sandbox-reference.md) — Sandbox API, headers, reproducible requests
- [coraza-testing-reference.md](coraza-testing-reference.md) — Coraza cross-engine testing
- [log-analysis-steering.md](log-analysis-steering.md) — Audit/error log analysis
- [first-responder-risk-runbook.md](first-responder-risk-runbook.md) — Incident-driven testing workflow
- [developer-security-workflow.md](developer-security-workflow.md) — CI/CD integration
