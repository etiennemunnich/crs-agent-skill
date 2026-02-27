# Log Analysis Steering

**Purpose**: Agent steering for audit log and error log analysis. Use Linux CLI tools and `analyze_log.py` to produce top-talker metrics, identify attacks, and troubleshoot. When the user asks about logs, blocked traffic, or WAF behavior, guide them through this workflow.

**Target**: ModSecurity v3 (libModSecurity). Native and JSON formats; v3 does not implement Section K (matched rules list)—use Section H for rule IDs.

---

## Steering for LRMs

When the user mentions logs, blocked requests, attacks, or troubleshooting:

1. **Identify log type** — Audit log (transactions) vs error log (ModSecurity/nginx/Apache messages)
2. **Choose metric** — Top IPs, top rules, top paths, blocking vs allow, payload sizes
3. **Suggest tool** — `analyze_log.py` for rule-centric; CLI for top-talker and ad-hoc
4. **Provide examples** — Give concrete `grep`/`awk`/`jq` commands they can run

---

## 1. Audit Log Format

### Native (Sectioned) Format

Sections separated by `--boundary-X--` (e.g. `--c7036611-A--`). Key sections:

| Section | Content | Use For |
|---------|---------|---------|
| A | `[timestamp] unique_id src_ip src_port dst_ip dst_port` | Top IPs, timestamps |
| B | Request line + headers (`GET /path HTTP/1.1`) | Top paths, methods |
| C | Request body | Payload size, content |
| H | Rule matches, actions, messages | Top rules, block/allow (v3: K not implemented) |

**Section A example**: `[02/Aug/2016:09:57:47 +0300] V6BEawUs8J4AACcbno4AAAAE 177.80.183.159 43077 5.44.240.158 80`

### JSON Format

One JSON object per line (or array). Fields: `transaction`, `audit_data`, `messages`, `client_ip`, `uri`, `request_method`, etc.

### Payload Visibility (What You Usually Get)

Rule-match context is typically available by default; full request payload visibility depends on log parts and body-access settings.

| Engine/Profile | Typical default | Usually includes matched snippet (`[data ...]`) | Usually includes full body |
|---|---|---|---|
| ModSecurity v3 + CRS Docker profile | JSON audit logs with relevant parts | Yes (when rule logs `data`/`logdata`) | Depends on `SecAuditLogParts` and body-access settings |
| Coraza + CRS Docker profile | JSON audit logs with relevant parts | Yes (rule message/data) | Depends on `SecAuditLogParts` and `SecRequestBodyAccess` |

Practical default for LRMs:
- Expect reliable **rule id + message + matched variable/data snippet**.
- Do **not** assume full request body is present in every environment.
- If full payload is missing, guide user to verify audit log parts/body settings before deep forensics.

---

## 2. Top Talker: Audit Log (Native)

### Top 10/20/50 Source IPs

```bash
# Section A: [dd/Mon/yyyy:HH:MM:SS +tz] unique_id src_ip src_port dst_ip dst_port
# IP is 3rd field
grep -E '^\[[0-9]{2}/[A-Za-z]{3}/' audit.log | awk '{print $3}' | sort | uniq -c | sort -rn | head -20

# Top 50
grep -E '^\[[0-9]{2}/[A-Za-z]{3}/' audit.log | awk '{print $3}' | sort | uniq -c | sort -rn | head -50
```

### Top Blocked IPs (Section H contains "Access denied" or "block")

```bash
# Section A precedes H in each entry; extract IP from A lines near "Access denied"
awk '/^\[[0-9]{2}\/[A-Za-z]{3}\//{ip=$3} /Access denied|deny|block/{print ip}' audit.log | sort | uniq -c | sort -rn | head -20
```

### Top Paths / URIs

```bash
# Extract request line from Section B (GET /path HTTP/1.1)
awk '/^GET |^POST |^PUT |^DELETE / {print $2}' audit.log | sort | uniq -c | sort -rn | head -20

# Alternative: Section B contains request line
grep -E '^(GET|POST|PUT|DELETE|PATCH|HEAD) ' audit.log | awk '{print $2}' | sort | uniq -c | sort -rn | head -50
```

### Top Rule IDs

```bash
# From Section H (v3: K not implemented)
grep -oE 'id "([0-9]+)"' audit.log | sed 's/id "//;s/"//' | sort | uniq -c | sort -rn | head -20

# Or use analyze_log.py
python scripts/analyze_log.py audit.log --top-rules 50
```

### Blocking vs Allow Actions

```bash
# Count blocked transactions
grep -c 'Access denied\|deny\|block' audit.log

# Count allowed (pass) transactions that triggered rules
grep -c 'pass' audit.log
```

### Payload / Request Body Sizes

```bash
# Native: Section C is request body; boundaries are --boundary-X-- (ModSecurity format)
awk '
  /^--[a-zA-Z0-9]+-C--/ { in_c=1; len=0; next }
  in_c && /^--[a-zA-Z0-9]+-[A-Z]--/ { in_c=0; if (len>0) print len; next }
  in_c { len += length($0)+1 }
' audit.log | sort -n | tail -20

# JSON: use jq (see §3)
```

### Combined: Top IPs with Block Count

```bash
# Section A has IP; Section H has action; correlate within same entry
awk '
  /^\[[0-9]{2}\/[A-Za-z]{3}\// { ip=$3; total[ip]++ }
  /Access denied|deny|block/    { blocked[ip]++ }
  END { for (i in total) print total[i], blocked[i]+0, i }
' audit.log | sort -rn -k1 | head -20
```

---

## 3. Top Talker: Audit Log (JSON)

```bash
# Top 10 IPs
jq -r '.client_ip // .transaction.client_ip // empty' audit.json 2>/dev/null | sort | uniq -c | sort -rn | head -10

# Top 20 paths
jq -r '.uri // .transaction.uri // "\(.request_uri)" // empty' audit.json 2>/dev/null | sort | uniq -c | sort -rn | head -20

# Top 50 rule IDs
jq -r '.audit_data.messages[]? | select(.id?) | .id' audit.json 2>/dev/null | sort | uniq -c | sort -rn | head -50

# Blocked requests only
jq -r 'select(.audit_data.messages[]? | select(.message? | test("Access denied|deny|block"))) | .client_ip' audit.json 2>/dev/null | sort | uniq -c | sort -rn | head -20

# Payload size (request body length)
jq -r '.request_body_length // .request_body | length // 0' audit.json 2>/dev/null | sort -n | tail -20
```

---

## 4. Error Log Analysis

ModSecurity/nginx/Apache error logs contain rule match messages.

### Typical Error Log Line

```
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Rx' with parameter ..." at ARGS:id. [file "..."] [line "123"] [id "942100"] [msg "SQL Injection"] ...
```

### Top Rule IDs from Error Log

```bash
grep -oE '\[id "([0-9]+)"\]' error.log | sed 's/\[id "//;s/"\]//' | sort | uniq -c | sort -rn | head -20
```

### Top IPs from Error Log

```bash
grep -oE '\[client [0-9.]+:[0-9]+\]' error.log | sed 's/\[client //;s/\]//' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Apache format
awk '/\[client / {gsub(/\[client |:.*\]/,""); print $NF}' error.log | sort | uniq -c | sort -rn | head -20
```

### Top Paths / URIs from Error Log

```bash
grep -oE '\[uri "[^"]+"\]' error.log | sed 's/\[uri "//;s/"\]//' | sort | uniq -c | sort -rn | head -20
```

### PCRE Limit Exceeded (ReDoS)

```bash
grep -i 'pcre\|MSC_PCRE\|limit exceeded' error.log
```

### Blocked vs Logged

```bash
grep -c 'Access denied' error.log
grep -c 'ModSecurity:' error.log
```

### Recent Errors (last 100)

```bash
tail -100 error.log
# Or with context
tail -500 error.log | grep -E 'ModSecurity|denied|block'
```

---

## 5. Combined Workflow

| Goal | Tool | Example |
|------|------|---------|
| Top rules | analyze_log.py | `python scripts/analyze_log.py audit.log --top-rules 20` |
| Rule detail | analyze_log.py | `python scripts/analyze_log.py audit.log --rule-id 942100 --detail` |
| Why rule triggered | analyze_log.py | `python scripts/analyze_log.py audit.log --explain-rule 942100 --detail` |
| App profile hint | detect_app_profile.py | `python scripts/detect_app_profile.py audit.log --output text` |
| Top IPs | CLI | `grep ... \| awk ... \| sort \| uniq -c \| sort -rn \| head -20` |
| Top paths | CLI | `grep -E '^(GET|POST) ' audit.log \| awk '{print $2}' \| sort \| uniq -c \| sort -rn \| head -20` |
| Top rules (CLI) | grep/sed | `grep -oE 'id "([0-9]+)"' audit.log \| sed ... \| sort \| uniq -c \| sort -rn \| head -20` |
| Error log rules | grep | `grep -oE '\[id "([0-9]+)"\]' error.log \| sed ... \| sort \| uniq -c \| sort -rn` |
| JSON audit | jq | `jq -r '.client_ip' audit.json \| sort \| uniq -c \| sort -rn \| head -20` |

---

## 6. Agent Steering: When to Suggest What

| User Says | Suggest |
|-----------|---------|
| "Top IPs hitting the WAF" | CLI: Section A IP extraction or jq for JSON |
| "Which rules fire most?" | `analyze_log.py --top-rules 20` or grep rule IDs |
| "Why is X blocked?" | `analyze_log.py --explain-rule N --detail` then `--rule-id N --detail` for raw samples |
| "Error log analysis" | grep for id, client, uri; check PCRE limits |
| "Top blocked paths" | Filter for blocked + extract path from Section B |
| "Payload sizes" | Section C length or jq request_body length |
| "No Python/scripts" | Pure CLI: grep, awk, sed, sort, uniq, cut |

---

## 7. Common Log Paths

| Platform | Audit Log | Error Log |
|----------|-----------|-----------|
| ModSecurity (Apache) | SecAuditLog path (e.g. `/var/log/apache2/modsec_audit.log`) | Apache error log |
| ModSecurity (nginx) | Config-defined | nginx error log |
| Coraza | Config-defined | Application/Caddy log |

---

## 8. Best Practices

- Start every investigation with `--summary` to get a high-level view before drilling into specific rules.
- Use `--top-rules` to identify the noisiest rules — these are your highest-impact tuning targets.
- Use `--explain` or `--explain-rule` before tuning to capture variable/payload evidence, not just hit counts.
- Run `detect_app_profile.py` once per dataset to check if official CRS app exclusions/plugins are a better first fix than custom rules.
- Assume partial evidence first (id/msg/data snippet); verify body logging config before requiring full payload reconstruction.
- Always correlate audit log findings with error log entries — some events appear in one but not the other.
- When analyzing CRS Docker JSON logs, pipe through `jq` for structured filtering rather than raw `grep`.
- Archive raw logs before analysis — processed summaries cannot replace raw evidence.
- Pair log analysis with CRS Sandbox verification — replay suspicious payloads to confirm behavior.

## 9. What to Avoid

- Analyzing only the error log and ignoring the audit log — error logs lack request/response detail.
- Grepping for rule IDs in JSON logs without accounting for nested structures.
- Deleting or rotating logs before analysis is complete during an incident.
- Drawing conclusions from a single log entry — always check frequency and pattern.
- Ignoring PCRE limit exceeded warnings (`MSC_PCRE_LIMITS_EXCEEDED`) — these indicate ReDoS risk.

## 10. Related

- [analyze_log.py](../scripts/analyze_log.py) — Rule-centric audit log parsing
- [antipatterns-and-troubleshooting.md](antipatterns-and-troubleshooting.md) — Troubleshooting flow
- [false-positives-and-tuning.md](false-positives-and-tuning.md) — Acting on log analysis findings
- [first-responder-risk-runbook.md](first-responder-risk-runbook.md) — Incident-driven log analysis
- [ModSecurity Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)) — SecAuditLogFormat, SecAuditLogParts; [Legacy v2 Data Formats](https://github.com/owasp-modsecurity/ModSecurity/wiki/ModSecurity-2-Data-Formats) for Native boundary details
