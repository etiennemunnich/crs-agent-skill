# Known Version-Specific Issues

Issues, fixes and behaviour changes that are tied to a specific release. This file does **not** say what the latest release is — see *Versions and Freshness* in SKILL.md for where to look that up. Compare each row against the version the user actually runs. Items marked *verify* were not confirmed from a primary source.

## CRS: bypasses and their fixes

| ID | Rule(s) | Issue | Fixed in | Interim workaround |
|----|---------|-------|----------|--------------------|
| CVE-2026-21876 | 922110 | Chained rule checked only the last multipart part's charset; earlier parts bypass | 4.22.0 / 3.3.8 | Upgrade |
| GHSA-6jp8-c2w2-x7wr | ~159 rules in 921, 930–934, 941–943 | `XML:/*` matches element text only, **not attribute values**; 944 (Java) already had `XML://@*` | 4.28.0 (unconditional); 4.25.1 and 3.3.10 behind `tx.crs_xml_attr_inspect` (default on) | Upgrade. See "XML attribute gate" below for the opt-out |
| GHSA-f5qm-3h4p-8qhg | 932220/230/231/232/235/236/238/239/250/260/340/350 | ReDoS in shared `unix-shell-evasion-prefix.ra`. PCRE2 hits its limit, `@rx` **errors instead of matching**, so the payload is not inspected and CPU burns. Coraza (RE2) not affected | 4.28.0 / 4.25.1 / 3.3.10 | No full workaround: run on Coraza, or tighten `SecRequestBodyLimit` / argument length |
| GHSA-575j-qr6p-9763 | 932125–932390 | RCE rules did not target `REQUEST_FILENAME`; a payload in the URL path bypassed all of 932 even at PL4. Only matters if a path segment reaches a shell | 4.30.0 / 4.25.2. **CRS 3.x will not get a fix** | `SecRuleUpdateTargetById <id> "REQUEST_FILENAME"` for 932130, 932235, 932236, 932240, 932260, 932281, 932340, 932350, 932380 (config-time, **after** the CRS include). 932200 intentionally does not inspect the path |
| GHSA-89h9-2j8h-9gp2 | 920480 | Anchor matched lowercase `charset` only; `CHARSET=utf-7` skipped the allow-list (UTF-7 XSS). CRS 3.3.x not affected | 4.30.0 / 4.25.2 | `SecRuleUpdateActionById 920480 "t:lowercase"` |
| GHSA-qmx4-jfcv-fgww | 922100 | Only one `_charset_` value checked; a second allowed value shadowed a disallowed one (v2 expands to the first value, v3 to the last) | 4.30.0 / 4.25.2 | Upgrade |
| (no ID) | 933110, 944140 | `shell.php/` (trailing slash) not blocked by the upload extension check | 4.30.0 / 4.25.2 | Upgrade |
| (no ID) | 942390 | Length bound in the SQL (X)OR rule bypassable with long quoted/unary literals | 4.29.0 / 4.25.2 | Upgrade |
| *verify* CVE-2026-33691 | 933111 | Whitespace padding bypass of the PHP double-extension upload check (PR #4547). CVE number not confirmed from a primary source | 4.25.0 | Upgrade |

### XML attribute gate (4.25.1 and 3.3.10 only)

Opt-out: `SecAction "id:<local-id>,phase:1,nolog,pass,setvar:tx.crs_xml_attr_inspect=0"`.

- The upstream post shows `id:900130`. That ID is also the `tx.enable_default_collections` rule in `crs-setup.conf.example`; a duplicate ID aborts config load. Use an unused local ID.
- On **ModSecurity v2 before 2.9.14** the gate has no effect (`ctl:ruleRemoveTargetByTag` did not remove XML attribute targets). Upgrade the engine, or use the config-time form after the CRS include, one line per tag: `SecRuleUpdateTargetByTag "attack-xss" "!XML://@*"` (attack-protocol, -lfi, -rfi, -rce, -php, -generic, -xss, -sqli, -fixation).
- 4.28.0 and later have no gate.

## CRS: releases that change existing configuration

| Version | Change | What to do |
|---------|--------|-----------|
| 4.30.0 (not 4.25.x) | Per-file compression checks 950010, 951010, 952010, 953010, 954010, 955010, 956010 **replaced by 950020** | Update exclusions that reference the removed IDs. The 4.25 LTS line keeps the per-file rules |
| 4.30.0 / 4.25.2 | New rule 950022: `tx.crs_skip_response_analysis` (900500) now skips phase 4 bodies too; before, only phase 3 headers | Re-check response-rule exclusions |
| 4.30.0 / 4.25.2 | `application/*+json` (901370) and AWS `application/x-amz-json-1.0/1.1` (901360) allowed by default and parsed as JSON | Requests previously blocked by 920420 are now inspected; expect new matches on those bodies |
| 4.28.0 | `crs_validate_utf8_encoding` enabled by default; default actions for phases 3–5 added to `crs-setup.conf` | Expect UTF-8 validation hits from non-UTF-8 clients |
| 4.26.0 | HTTP/0.9 `GET` dropped from request-line validation (920100); 933100 checks all headers | — |
| 4.0 (from 3.x) | `SecCollectionTimeout` removed from `crs-setup.conf`; plugins need three Includes (`*-config.conf`, `*-before.conf`, `*-after.conf`); most exclusion packages became plugins | See [crs-v3-v4-exception-migration.md](crs-v3-v4-exception-migration.md) |

## ModSecurity: version-specific fixes and removals

| Fixed / changed in | Issue |
|--------------------|-------|
| v3 3.0.17 | Response body inspection bypass with mixed-case `Content-Type` (GHSA-vmg8-j66p-vgvw); XML body processor uninitialized pointer (GHSA-jx3r-phvx-2jmj); nullptr on invalid `@rx` pattern (GHSA-5m93-4h75-3p2w) |
| v3 3.0.17 / v2 2.9.15 | `t:htmlEntityDecode` missed named entities (GHSA-cxqf-vgrr-xxrv); `t:removeComments` adjacent comments (GHSA-qrch-pjfr-9g47); `t:base64DecodeExt` URL-safe alphabet (GHSA-4j47-8qcr-jf59); multipart `filename*` / duplicated `filename` (GHSA-5pww-8rfg-9crf); insecure host verification for remote rules (GHSA-2vqc-36qp-ccmw). Adds `MULTIPART_DUPLICATE_PART_HEADER`, `MULTIPART_FILENAME_CHARSET`, `MULTIPART_FILENAME_LANGUAGE` |
| v3 3.0.16 | CVE-2026-52747: multipart parser mishandles `\r`/`\n` in non-file fields, so `ARGS`/`ARGS_POST` rules miss the payload (parser differential). Also CVE-2026-52761 (`utf8toUnicode` on i386) and a lexer fix for `@` in `ctl:ruleRemoveTarget` |
| v2 2.9.14 | `ctl:ruleRemoveTargetByTag` now removes XML attribute targets. Deprecated `REQBODY_PROCESSOR_ERROR` / `_MSG` **removed** — use `REQBODY_ERROR` / `REQBODY_ERROR_MSG` |
| v2 2.9.13 | NGINX support removed from ModSecurity v2 |

## Support facts tied to a release line

- **CRS 4.25.x** is the CRS 4 LTS line: security fixes until Q3 2027; only security, regression, critical PL1 false-positive and engine-compatibility fixes are backported (no new rules, features or PL changes). Docker tags `4.25-lts` (floating) and `4.25.N-lts`.
- **CRS 3.3.x**: end of support Q3 2026 (upstream announcement). It does not receive fixes that are not explicitly listed above for 3.3.x.
- **CRS 4 engine matrix**: ModSecurity v2 + Apache, ModSecurity v3 + Nginx, Coraza. **Not supported**: Nginx + ModSecurity v2, Apache + ModSecurity v3. Coraza does not implement `SecWebAppID` (use a `Host` header match for per-vhost scoping). Lua plugins (fake-bot, antivirus) need Lua compiled into the engine.
- **go-ftw**: see the version notes at the top of [go-ftw-reference.md](go-ftw-reference.md).

## Parser-differential evasion class

The engine and the backend disagree on how a body is parsed (multipart line breaks, charset, duplicate `filename`, XML attributes, duplicate parameters, mixed-case headers). Signature rules cannot fix this. Order of response:

1. Upgrade the engine and ruleset past the fixed version.
2. Reject ambiguous or malformed bodies (`MULTIPART_STRICT_ERROR`, `REQBODY_ERROR`, `MULTIPART_UNMATCHED_BOUNDARY`, and `MULTIPART_DUPLICATE_PART_HEADER` where the engine has it).
3. Add go-ftw regression tests that send the differential request.

A ReDoS in a security rule is also a bypass: when PCRE2 exceeds its limit the rule does not evaluate (see rule 200004 / `MSC_PCRE_LIMITS_EXCEEDED`).

## Sources

- CRS `CHANGES.md` and security advisories: <https://github.com/coreruleset/coreruleset>
- <https://coreruleset.org/20261002/crs-versions-4.30.0-and-4.25.2-lts-released/>
- <https://coreruleset.org/20260702/crs-versions-4.28.0-4.25.1-lts-and-3.3.10-released/>
- <https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/>
- <https://coreruleset.org/20260321/announcing-crs-v4-25-lts/>
- <https://coreruleset.org/20260511/migrating-crs-3-to-4-part-7-engines/>
- ModSecurity `CHANGES` (v3/master and v2/master): <https://github.com/owasp-modsecurity/ModSecurity>
