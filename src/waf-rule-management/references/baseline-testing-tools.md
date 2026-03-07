# Baseline Steering — Testing Tools

Use when establishing a baseline before rule changes or validating WAF effectiveness.

---

## Baseline Workflow

1. **Observe** — analyze logs, detect app profile, identify FPs
2. **Validate** — rules, exclusions, regex
3. **Test** — go-ftw, go-test-waf, nuclei
4. **Compare** — cross-engine (ModSec vs Coraza) if needed

---

## External Tools

| Tool | Purpose | Baseline use |
|------|---------|--------------|
| **go-ftw** | CRS rule regression | `go-ftw run --cloud --config assets/docker/.ftw.yaml -d tests/` |
| **go-test-waf** | WAF evaluation (OWASP payloads, bypass detection) | `docker run wallarm/gotestwaf --url=http://localhost:8080 --noEmailReport` |
| **nuclei** | App vuln scanning (CVE, KEV) | `nuclei -u https://target -tags cve` or `-tags kev` |
| **crs-toolchain** | Regex assembly, fp-finder | `crs-toolchain regex compare`, `util fp-finder` |
| **CRS Sandbox** | Quick payload check (no setup) | `curl -H "x-format-output: txt-matched-rules" "https://sandbox.coreruleset.org/?payload"` |
| **httpx** | Probe HTTP surfaces, tech detection | Discovery before tuning |
| **cdncheck** | Detect CDN/WAF ingress | Ingress visibility |
| **vulnx** | CVE intelligence, KEV filtering | Triage prioritization |

---

## go-test-waf (Quick Reference)

WAF evaluation — attack simulation, blocked vs bypassed.

```bash
docker run --rm --network="host" -v ${PWD}/reports:/app/reports \
  wallarm/gotestwaf --url=http://127.0.0.1:8080 --noEmailReport
```

---

## nuclei (Quick Reference)

App-level vuln scanning; WAF in front.

```bash
nuclei -ut
nuclei -u https://target.example.com -tags cve
nuclei -u https://target.example.com -tags kev
```

---

## Relation to go-ftw

| go-ftw | go-test-waf | nuclei |
|--------|--------------|--------|
| Rule-specific regression | Broad attack coverage | App vuln discovery |
| CRS-aligned | OWASP payloads | CVE/KEV templates |
| Per-rule pass/fail | Blocked % | Vuln detection |

**CRS contribution**: When adding new CRS rules, go-ftw tests are required. Consider submitting a corresponding [nuclei template](https://github.com/projectdiscovery/nuclei-templates) for the same attack surface — see [crs-contribution-workflow.md](crs-contribution-workflow.md).

---

## Related

[go-ftw-reference.md](go-ftw-reference.md) | [modsec-crs-testing-reference.md](modsec-crs-testing-reference.md) | [crs-contribution-workflow.md](crs-contribution-workflow.md)
