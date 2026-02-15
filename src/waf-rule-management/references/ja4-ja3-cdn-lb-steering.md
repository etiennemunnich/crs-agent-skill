# JA4/JA3 Steering: CDN and Load Balancer Architecture

**Purpose**: Agent steering for TLS fingerprint (JA3/JA4) integration when traffic flows through upstream CDN and load balancers before reaching ModSecurity/Coraza/CRS. Use when customers deploy **Viewer → CDN → LB → Compute** and need rules or log analysis that account for CDN-injected headers.

---

## Architecture: Viewer → CDN → LB → Compute

```
┌─────────┐     HTTPS      ┌─────────┐     Origin     ┌─────────┐     HTTP(S)    ┌─────────────────────────────┐
│ Viewer │ ─────────────► │   CDN   │ ─────────────► │   LB    │ ─────────────► │ Compute (ModSec/CRS/Coraza) │
└─────────┘               └─────────┘               └─────────┘               └─────────────────────────────┘
   TLS                        TLS                      TLS or HTTP                  HTTP (TLS may terminate
   Client Hello               JA3/JA4 computed         Headers forwarded             at LB or compute)
```

**Key points**:
- **TLS terminates at CDN** — CDN sees the Client Hello and computes JA3/JA4.
- **CDN → Origin** — CDN adds JA3/JA4 and X-Forwarded-* headers to origin requests.
- **LB** — May append/preserve/strip headers; may terminate TLS (second handshake).
- **Compute** — WAF sees HTTP headers only; JA4 must arrive via CDN-injected header.

---

## CDN-Specific JA3/JA4 Header Mapping

| CDN | JA3 Header | JA4 Header | Notes |
|-----|------------|------------|-------|
| **CloudFront** | `CloudFront-Viewer-JA3-Fingerprint` | `CloudFront-Viewer-JA4-Fingerprint` | Origin request policy; HTTPS only. [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) |
| **Cloudflare** | `cf-ja3-hash` | `cf-ja4` | Managed Transform "Add bot protection headers"; Bot Management (Enterprise). [Cloudflare docs](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) |
| **Akamai** | Configurable | Configurable | `headerNames` from AppSec API; Beta for WAP/Kona. [Akamai docs](https://techdocs.akamai.com/application-security/reference/get-ja4-fingerprint-settings) |
| **Fastly** | VCL `tls.client.ja3_md5` | VCL `tls.client.ja4` | Must set custom header in VCL; not auto-forwarded. [JA4](https://www.fastly.com/documentation/reference/vcl/variables/client-connection/tls-client-ja4/) \| [JA3](https://www.fastly.com/documentation/reference/vcl/variables/client-connection/tls-client-ja3-md5/) |

### Header Availability

| CDN | When JA3/JA4 Present |
|-----|----------------------|
| CloudFront | HTTPS requests; add via origin request policy |
| Cloudflare | HTTPS; Bot Management enabled; not for Workers internal routing |
| Akamai | When JA4 fingerprint feature enabled; header name configurable |
| Fastly | Must add `req.http.X-JA4 = tls.client.ja4` in VCL `recv` |

### Fastly VCL Example (must explicitly forward)

```vcl
# In recv
set req.http.X-JA4-Fingerprint = tls.client.ja4;
set req.http.X-JA3-Fingerprint = tls.client.ja3_md5;
```

---

## X-Forwarded Header Chain

When traffic passes through CDN and LB, headers chain:

| Header | Purpose | Chain Format |
|--------|---------|--------------|
| `X-Forwarded-For` | Client IP | `client, proxy1, proxy2` — leftmost = viewer |
| `X-Forwarded-Proto` | Original protocol (http/https) | Single value from first proxy |
| `X-Forwarded-Host` | Original Host | From first proxy |
| `X-Real-IP` | Client IP (non-standard) | Some LBs use this instead of XFF |

**LB behavior** (varies by vendor):
- **Append**: LB adds its client IP to X-Forwarded-For (common for ALB)
- **Preserve**: LB leaves headers unchanged
- **Remove**: LB strips headers (WAF loses client context)
- **Overwrite**: LB replaces with its view of client (can lose CDN chain)

**Steering**: Confirm LB configuration. If LB strips CDN headers, JA4 will not reach compute.

---

## Load Balancer Considerations

| Scenario | JA4 Available? | Action |
|----------|----------------|--------|
| CDN adds JA4 header, LB preserves | Yes | Use `REQUEST_HEADERS` in rules |
| CDN adds JA4, LB strips custom headers | No | Configure LB to preserve or use LB-native JA4 (e.g. ALB + AWS WAF) |
| TLS terminates at LB (CDN→LB is HTTP) | Depends | CDN still has viewer TLS; CDN must forward JA4 |
| TLS terminates at LB (CDN→LB is HTTPS) | Depends | LB sees CDN's Client Hello, not viewer's — JA4 from CDN is correct |

**Critical**: JA4 reflects the **viewer-to-CDN** TLS handshake. If CDN forwards it, the value is correct regardless of LB TLS.

---

## Steering: Creating Rules to Evaluate JA3/JA4 Values

**When to use**: User wants to create ModSecurity/Coraza rules that evaluate TLS fingerprint headers (JA3 or JA4) for blocking, allowlisting, or anomaly scoring.

### Use-Case-Specific Steering

**Choose strategy based on deployment type.** APIs and websites have different security postures; JA3/JA4 rules must align.

| Use Case | JA3/JA4 Strategy | Rationale |
|----------|------------------|------------|
| **API only** | **Allowlist (positive security)** | Default deny. Only allow known client fingerprints (mobile app, SDK, trusted services). Blocklist is effectively a bypass — unknown clients get through. |
| **Website only** | Blocklist or anomaly scoring | Paths, query strings, and browser fingerprints change often; positive security is rarely feasible. Block known malware; allow unknown (browsers). |
| **Website + API** | **Mixed** — allowlist for `/api/*`, blocklist for `/*` | Apply allowlist only to API paths; blocklist or anomaly for website paths. Use `REQUEST_URI` or `REQUEST_FILENAME` to scope rules. |
| **GraphQL** | Allowlist (API-like) | Single endpoint, predictable clients. Treat as API. |
| **WebSocket** | Allowlist for control plane | Initial HTTP upgrade is API-like; allowlist for known clients. |

**API rule template = positive security model (default deny).** Blocklists are not recommended for APIs — they allow everything except a small known-bad set and effectively bypass strict client validation.

### Website-Specific: What to Know Before Writing Rules

Websites operate differently; positive security is not always possible. Before creating rules, document:

| Aspect | What to Know |
|--------|---------------|
| **Methods per path** | Allow POST/PUT/DELETE/PATCH **only where required**: login forms (`/login`), search forms (`/search`), contact forms (`/contact`), API paths (`/api/*`). GET/HEAD/OPTIONS for general browsing. Do not allow write methods globally. |
| **Allowed query strings** | Which params are valid per path? (e.g. `/search?q=`, `/product?id=`) |
| **Authorization requirements** | Which paths require `Authorization` or `Cookie`? |
| **Forms and write endpoints** | Map each form/action to its path and required method (e.g. `/login` POST, `/search` GET or POST, `/api/users` POST/PUT/DELETE). |
| **Content-Type** | Where is JSON, form-urlencoded, or multipart expected? |

Use this to scope JA4 rules (e.g. only enforce allowlist on `/api/*` where methods and params are known) and to avoid blocking legitimate browser traffic.

**Method enforcement**: Create rules that allow POST/PUT/DELETE/PATCH only on paths that have forms or API actions (login, search, contact, `/api/*`). Deny write methods on paths that only serve content (e.g. `/`, `/about`, `/product/*`).

**For APIs**: JA4 allowlist complements OpenAPI-derived positive security rules (methods, paths, params, content-type). Use `openapi_to_rules.py` for method/param allowlisting; see SKILL.md § OpenAPI to WAF Rules.

### Steering for LRMs

1. **Identify use case** — API, website, website+API, GraphQL, WebSocket (see [Use-Case-Specific Steering](#use-case-specific-steering))
2. **Identify CDN** — Which header name will the WAF see? (See [CDN-Specific JA3/JA4 Header Mapping](#cdn-specific-ja3ja4-header-mapping))
3. **Choose evaluation strategy** — Allowlist for API; blocklist or anomaly for website; mixed for hybrid
4. **Select operator** — `@pmFromFile` for lists; `@rx` for patterns; `@streq` for single value
5. **Validate format** — JA4: 36 chars (`t13d1516h2_8daaf6152771_02713d6af862`); JA3: 32 hex chars
6. **Test** — Use `validate_rule.py`, then go-ftw or curl with known fingerprints

### Rule Creation Workflow (OODA)

| Phase | Action |
|-------|--------|
| **Observe** | Confirm header present in logs; collect known-good (API clients) and known-bad (malware) fingerprints; document use case |
| **Orient** | Map to variable (`REQUEST_HEADERS:X` or `TX.ja4`); choose allowlist (API) vs blocklist (website) per use case |
| **Decide** | Rule ID range (100000–199999); phase 1; scope by REQUEST_URI for mixed deployments |
| **Act** | Write rule → validate → test → deploy (DetectionOnly first) |

### Evaluation Strategies

| Strategy | Use Case | Operator | Example |
|----------|----------|----------|---------|
| **Allowlist** | **API, GraphQL, WebSocket** — positive security, default deny | `!@pmFromFile` | Deny if JA4 not in `good-ja4.txt` |
| **Blocklist** | Website only — block known malware/bots | `@pmFromFile` | Deny if JA4 in `bad-ja4.txt` |
| **Anomaly scoring** | Website — add to CRS score without immediate block | `@pmFromFile` + `setvar` | `setvar:tx.inbound_anomaly_score_pl1=+3` |
| **Partial match** | Match JA4 segment (e.g. `_a` only) | `@rx` | `@rx ^t13d` for TLS version + transport |
| **Presence check** | Log when fingerprint absent (HTTP or stripped) | `@eq ""` or `!@rx` | Audit requests without JA4 |

**Do not use blocklist for API** — it allows all unknown clients and is effectively a bypass of strict client validation.

### Fingerprint Format Reference

| Type | Format | Example |
|------|--------|---------|
| **JA4** | `t|q` + version + `d|i` + `h` + `_` + 12 hex + `_` + 12 hex | `t13d1516h2_8daaf6152771_02713d6af862` |
| **JA3** | 32 hex characters (MD5 of JA3 string) | `771,4865-4866-4867-49195-49199...` → hash |

**JA4 regex** (for format validation): `^[tq][0-9a-f]{2}[di][0-9a-f]+h[0-9]_[a-f0-9]{12}_[a-f0-9]{12}$`

### Data File Format

For `@pmFromFile`, one fingerprint per line. Comments with `#` (ModSec v3) — check engine support.

```
# bad-ja4.txt - known malware fingerprints
t13d201100_2b729b4bf6f3_9e7b989ebec8
t13d190900_9dc949149365_97f8aa674fd9
# From ja4db.com / threat intel
```

### Rule Templates

**API — Allowlist (positive security, default deny)** — recommended for API, GraphQL, WebSocket:
```seclang
# API: deny when JA4 present but not in allowlist
SecRule REQUEST_URI "@beginsWith /api" \
    "id:100002,phase:1,deny,status:403,log,chain,\
    msg:'API: JA4 fingerprint not in allowlist',\
    tag:'custom/ja4-allowlist'"
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!^$" chain
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!@pmFromFile /path/to/api-good-ja4.txt"
```

**Website — Blocklist (deny known bad)**:
```seclang
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100001,phase:1,deny,status:403,log,\
    msg:'Blocked known malicious JA4 fingerprint',\
    logdata:'JA4: %{MATCHED_VAR}',\
    tag:'custom/ja4-blocklist',\
    severity:'CRITICAL'"
```

**Website + API — Mixed (allowlist for API, blocklist for website)**:
```seclang
# API paths: allowlist (positive security)
SecRule REQUEST_URI "@beginsWith /api" \
    "id:100010,phase:1,deny,status:403,log,chain,\
    msg:'API: JA4 not in allowlist'"
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!^$" chain
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!@pmFromFile /path/to/api-good-ja4.txt"

# Non-API paths: blocklist only
SecRule REQUEST_URI "!@beginsWith /api" \
    "id:100011,phase:1,deny,status:403,log,chain,\
    msg:'Blocked known malicious JA4'"
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "@pmFromFile /path/to/bad-ja4.txt"
```

**Anomaly scoring (CRS-compatible)**:
```seclang
SecRule TX:ja4 "@pmFromFile /path/to/suspicious-ja4.txt" \
    "id:100003,phase:1,pass,log,\
    setvar:tx.inbound_anomaly_score_pl1=+3,\
    setvar:tx.anomaly_score_pl1=+3,\
    msg:'Suspicious JA4 fingerprint',\
    tag:'custom/ja4-suspicious'"
```

**Partial match (JA4 segment)**:
```seclang
# Match JA4 "a" segment only (TLS version + transport + SNI + extensions count)
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "@rx ^t13d1516h2_" \
    "id:100004,phase:1,pass,log,\
    msg:'Chrome-like JA4 segment detected'"
```

### Antipatterns to Avoid

| Antipattern | Why | Correct Approach |
|-------------|-----|------------------|
| **Blocklist for API** | Allows all unknown clients; effectively a bypass | Use allowlist (positive security) for API, GraphQL, WebSocket |
| Blocking when header absent | HTTP or CDN bypass has no JA4; blocks legitimate HTTP | Only evaluate when header present; use `chain` to require non-empty |
| Allowlist for general website | Browsers change JA4 frequently; blocks legitimate users | Use blocklist or anomaly scoring for website; allowlist only for API |
| Hardcoding fingerprints in rule | Unmaintainable | Use `@pmFromFile` |
| Wrong phase | JA4 is in headers | Phase 1 only |
| Case-sensitive mismatch | JA4 is lowercase hex | Use `t:lowercase` if needed; JA4 is typically already lowercase |
| Same strategy for API and website | Different use cases need different postures | Scope by REQUEST_URI; allowlist for /api/*, blocklist for /* |

### Testing JA3/JA4 Rules

Tool capability boundaries:

- `go-ftw` can validate **rule matching behavior** by replaying request headers.
- `go-ftw` does **not** generate JA3/JA4 from TLS handshakes.
- Real JA3/JA4 generation must be validated at CDN/LB layer with real HTTPS client traffic.

Recommended flow:

1. **Validate syntax**: `python scripts/validate_rule.py ja4-rules.conf`
2. **Replay matching logic** with `go-ftw` using explicit JA4 header values
3. **Validate real generation path** end-to-end through CDN/LB using real HTTPS traffic
4. **Verify header reachability at origin**: `curl -H "CloudFront-Viewer-JA4-Fingerprint: t13d1516h2_8daaf6152771_02713d6af862" http://localhost:8080/`

### go-ftw Header Replay Example (Matching Only)

```yaml
# tests/ja4-blocklist.yaml
meta:
  author: custom
  enabled: true
  name: JA4 blocklist replay test
tests:
  - test_title: Block known bad JA4 (replayed header)
    stages:
      - stage:
          input:
            dest_addr: 127.0.0.1
            port: 8080
            headers:
              CloudFront-Viewer-JA4-Fingerprint: "t13d201100_2b729b4bf6f3_9e7b989ebec8"
            method: GET
            uri: /
          output:
            status: [403]
            log_contains: "Blocked known malicious JA4"
```

---

## Rule Construction: Multi-Header Normalization

CDNs use different header names. Use a **normalized variable** approach:

### Option 1: Normalize to TX.ja4 (First-Present Wins)

Set `TX.ja4` from whichever CDN header is present. Use `skipAfter` so only the first matching CDN sets it. Place **before** JA4 rules.

```seclang
# Normalize JA4 - try CloudFront first, then Cloudflare, then custom
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!^$" \
    "id:100010,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint},skipAfter:100019"
SecRule REQUEST_HEADERS:cf-ja4 "!^$" \
    "id:100011,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:cf-ja4},skipAfter:100019"
SecRule REQUEST_HEADERS:X-JA4-Fingerprint "!^$" \
    "id:100012,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:X-JA4-Fingerprint},skipAfter:100019"
SecMarker 100019
```

**Note**: In single-CDN deployments, only one header exists; order does not matter. For multi-tenant or CDN failover, first-present wins.

### Option 2: Multiple Rules with Same Logic

```seclang
# Block known-bad JA4 from CloudFront
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100001,phase:1,deny,status:403,log,msg:'Blocked JA4 (CloudFront)'"

# Block known-bad JA4 from Cloudflare
SecRule REQUEST_HEADERS:cf-ja4 "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100002,phase:1,deny,status:403,log,msg:'Blocked JA4 (Cloudflare)'"

# Block known-bad JA4 from custom (Fastly/Akamai/nginx)
SecRule REQUEST_HEADERS:X-JA4-Fingerprint "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100003,phase:1,deny,status:403,log,msg:'Blocked JA4 (custom)'"
```

### Option 3: Macro or Include for Header List

Define a list of header names and use `@within` or multiple `SecRule` with `|` (OR) — ModSec does not support OR across variables natively; use separate rules or `ctl:ruleRemoveById` for unused CDN.

### Recommended: CDN-Aware Config Snippet

```seclang
# JA4 normalization - set TX.ja4 from first non-empty CDN header
# Order: CloudFront, Cloudflare, Akamai/custom
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "!^$" \
    "id:100010,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint}"
SecRule REQUEST_HEADERS:cf-ja4 "!^$" \
    "id:100011,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:cf-ja4}"
SecRule REQUEST_HEADERS:X-JA4-Fingerprint "!^$" \
    "id:100012,phase:1,nolog,pass,setvar:tx.ja4=%{REQUEST_HEADERS:X-JA4-Fingerprint}"

# Then use TX.ja4 in blocking rules (only if set)
SecRule TX:ja4 "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100020,phase:1,deny,status:403,log,msg:'Blocked known malicious JA4'"
```

**Caveat**: `setvar` in separate rules will overwrite. Use **skipAfter** or **chain** so only the first matching CDN header sets `tx.ja4`. A cleaner approach: one rule per CDN that both sets and checks, or use `ctl:ruleEngine` to skip later rules when `tx.ja4` is set.

### Simplified: Single Rule Per CDN (Customer-Specific)

For a **known CDN**, configure only that header:

```seclang
# CloudFront-only customer
SecRule REQUEST_HEADERS:CloudFront-Viewer-JA4-Fingerprint "@pmFromFile /path/to/bad-ja4.txt" \
    "id:100001,phase:1,deny,status:403,log,msg:'Blocked JA4'"
```

---

## Client IP: X-Forwarded-For vs Direct

| Variable | When to Use |
|----------|-------------|
| `REMOTE_ADDR` | Direct client (LB IP when behind LB) |
| `REQUEST_HEADERS:X-Forwarded-For` | Client IP from CDN/LB chain; leftmost = viewer |
| `REQUEST_HEADERS:X-Real-IP` | Some LBs set this |

**CRS 920120** and similar may use `REMOTE_ADDR`. If behind LB, configure the connector (nginx, Apache) to set `REMOTE_ADDR` from `X-Forwarded-For` for correct logging and rate limiting.

---

## Log Analysis Steering

### JA4 in Audit Logs

- **Section B** (request headers) contains CDN-injected JA4 if present.
- **JSON format**: `audit_data.request_headers` or equivalent.

### Extracting JA4 for Analysis

```bash
# Native format - Section B contains headers
# Look for CDN-specific header names
grep -E 'CloudFront-Viewer-JA4-Fingerprint|cf-ja4|X-JA4-Fingerprint' audit.log

# Extract JA4 value (adjust pattern for your CDN)
awk '/CloudFront-Viewer-JA4-Fingerprint:/ {for(i=2;i<=NF;i++) print $i}' audit.log | sort | uniq -c | sort -rn
```

### Correlating JA4 with Rule Triggers

Extend `analyze_log.py` or use ad-hoc:

1. Parse Section A (IP), Section B (headers), Section H/K (rules).
2. Extract JA4 from B for each transaction.
3. Group by JA4: count transactions, unique IPs, triggered rules.
4. Output: "JA4 `t13d...` → 50 requests, 3 IPs, rules 942100, 941100".

### OODA Report Integration

When generating OODA reports, include:
- **Observe**: Which CDN headers are present in logs? Is JA4 populated?
- **Orient**: Map JA4 to known-good (e.g. browser) vs unknown/suspicious.
- **Decide**: Allowlist, blocklist, or anomaly scoring for JA4.
- **Act**: Deploy rules, tune LB header preservation, update CDN config.

---

## Checklist for Customers

| Step | Action |
|------|--------|
| 1 | Identify CDN (CloudFront, Cloudflare, Akamai, Fastly) |
| 2 | Enable JA4 forwarding in CDN (origin request policy, Managed Transform, VCL, or AppSec config) |
| 3 | Verify LB preserves CDN headers (no strip/overwrite of JA4 header) |
| 4 | Confirm header name in logs (`analyze_log` or `grep`) |
| 5 | Add normalization rules (set `TX.ja4`) or CDN-specific rules |
| 6 | Test replay with header injection (`curl`/go-ftw), then validate real JA4 generation via CDN/LB HTTPS path |
| 7 | Build allowlist/blocklist from threat intel (e.g. ja4db.com) |

---

## References

### AWS (CloudFront)

- [Add CloudFront request headers](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) — JA3 (`CloudFront-Viewer-JA3-Fingerprint`), JA4 (`CloudFront-Viewer-JA4-Fingerprint`), TLS-related headers; origin request policy

### Akamai

- [Get JA4 client TLS fingerprint settings](https://techdocs.akamai.com/application-security/reference/get-ja4-fingerprint-settings) — AppSec API, configurable header names
- [JA4 fingerprint (Terraform)](https://techdocs.akamai.com/terraform/docs/as-ds-ja4-fingerprint) — Terraform configuration

### Cloudflare

- [JA3/JA4 fingerprint](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) — `cf-ja3-hash`, `cf-ja4`; Bot Management (Enterprise); Managed Transform "Add bot protection headers"
- [cf.bot_management.ja4](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja4) — Ruleset Engine field reference
- [cf.bot_management.ja3_hash](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja3_hash) — Ruleset Engine field reference

### Fastly

- [tls.client.ja4](https://www.fastly.com/documentation/reference/vcl/variables/client-connection/tls-client-ja4/) — JA4 fingerprint VCL variable
- [tls.client.ja3_md5](https://www.fastly.com/documentation/reference/vcl/variables/client-connection/tls-client-ja3-md5/) — JA3 fingerprint VCL variable

### General

- [JA4+ suite](https://github.com/FoxIO-LLC/ja4)
- [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)

## Best Practices

- Validate that your CDN/LB actually populates the fingerprint header before writing rules that depend on it.
- Use allowlist logic (match known-good fingerprints) rather than blocklist (match known-bad) — fingerprint space is too large for effective blocklists.
- Combine JA3/JA4 with other signals (IP reputation, request rate, User-Agent) for defense in depth — fingerprints alone are spoofable.
- Always use `t:lowercase` when comparing fingerprint hashes — case normalization prevents false negatives.
- Document which CDN/LB tier is required for each fingerprint feature (e.g. Cloudflare requires Enterprise for JA4).
