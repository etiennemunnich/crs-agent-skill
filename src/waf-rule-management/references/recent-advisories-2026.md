# Recent Advisories and Releases (2026)

Snapshot for triage. **As of 2026-11.** Verified against primary sources: the CRS `CHANGES.md` and release posts on coreruleset.org, and the ModSecurity v2/v3 `CHANGES` files. Items marked *verify* were not confirmed from a primary source — check the GitHub advisory before quoting. CVE identifiers are often assigned after the advisory; when a post says "CVE requested", use the GHSA ID.

## CRS advisories

| ID | Rule(s) | Issue | Fixed in | Interim workaround | Eval |
|----|---------|-------|----------|--------------------|------|
| CVE-2026-21876 (CVSS 9.3) | 922110 | Chained rule checked only the last multipart part's charset; earlier parts bypass | 4.22.0 / 3.3.8 | Upgrade | 17 |
| GHSA-6jp8-c2w2-x7wr (HIGH 7.2) | ~159 rules in 921, 930–934, 941–943 | `XML:/*` matches element text only, **not attribute values**; 944 (Java) already had `XML://@*` | 4.28.0 (no gate); 4.25.1 and 3.3.10 behind `tx.crs_xml_attr_inspect` (default on) | Upgrade. LTS opt-out only: `SecAction "id:<local-id>,phase:1,nolog,pass,setvar:tx.crs_xml_attr_inspect=0"` (the upstream post uses `id:900130`, but 900130 is also the `tx.enable_default_collections` rule in `crs-setup.conf.example` — a duplicate ID aborts config load, so pick an unused local ID) | 12 |
| GHSA-f5qm-3h4p-8qhg (HIGH) | 932220/230/231/232/235/236/238/239/250/260/340/350 | ReDoS in shared `unix-shell-evasion-prefix.ra`; PCRE2 hits its limit, `@rx` **errors instead of matching**, so the payload is not inspected (bypass) and CPU burns. **Coraza (RE2) is not affected** | 4.28.0 / 4.25.1 / 3.3.10 | No full workaround: run on Coraza, tighten `SecRequestBodyLimit` / argument length | 15 |
| GHSA-575j-qr6p-9763 (MEDIUM 5.4) | 932125–932390 | RCE rules did not target `REQUEST_FILENAME`; payload in the URL path bypassed all of 932 even at PL4. Only matters if a path segment reaches a shell | 4.30.0 / 4.25.2 (not 3.x) | `SecRuleUpdateTargetById <id> "REQUEST_FILENAME"` for 932130, 932235, 932236, 932240, 932260, 932281, 932340, 932350, 932380 (config-time, **after** the CRS include). 932200 intentionally does not inspect the path | 13 |
| GHSA-89h9-2j8h-9gp2 (HIGH 7.2) | 920480 | Anchor matched lowercase `charset` only; `CHARSET=utf-7` skipped the allow-list (UTF-7 XSS). CRS 3.3.x not affected | 4.30.0 / 4.25.2 | `SecRuleUpdateActionById 920480 "t:lowercase"` | 17 |
| GHSA-qmx4-jfcv-fgww (MEDIUM 5.8) | 922100 | Only one `_charset_` value checked; a second allowed value shadowed a disallowed one. v2 expands to the first value, v3 to the last | 4.30.0 / 4.25.2 | Upgrade | 11 |
| (no ID) | 933110 (PHP), 944140 (Java) | `shell.php/` (trailing slash) not blocked by upload extension check | 4.30.0 / 4.25.2 | Upgrade | — |
| *verify* CVE-2026-33691 | 933111 | Whitespace padding bypass of PHP double-extension upload check; the fix (PR #4547) is in **4.25.0**. CVE number not confirmed from a primary source | 4.25.0 | Upgrade | — |
| (no ID) | 942390 | Length bound in SQL (X)OR rule bypassable with long quoted/unary literals | 4.29.0 / 4.25.2 | Upgrade | — |

## ModSecurity advisories

| Version | Date | Notable fixes |
|---------|------|---------------|
| v3 **3.0.17** | 2026-09-29 | Eight GHSAs: `t:htmlEntityDecode` missed named entities (GHSA-cxqf-vgrr-xxrv), insecure host verification for remote rules download (GHSA-2vqc-36qp-ccmw), XML body processor uninitialized pointer (GHSA-jx3r-phvx-2jmj), **response body inspection bypass with mixed-case Content-Type** (GHSA-vmg8-j66p-vgvw), invalid `@rx` pattern nullptr (GHSA-5m93-4h75-3p2w), `t:removeComments` adjacent comments (GHSA-qrch-pjfr-9g47), `t:base64DecodeExt` URL-safe alphabet (GHSA-4j47-8qcr-jf59), multipart `filename*` / duplicated `filename` (GHSA-5pww-8rfg-9crf) |
| v3 3.0.16 | 2026-06-29 | CVE-2026-52747 multipart parser mishandles `\r`/`\n` (parser differential); CVE-2026-52761 `utf8toUnicode` on i386; `@` in `ctl:ruleRemoveTarget` lexer fix |
| v2 **2.9.15** | 2026-09-29 | Same transform/multipart/XML/remote-rules fixes as 3.0.17 |
| v2 2.9.14 | 2026-07-02 | `ctl:ruleRemoveTargetByTag` now removes XML attribute targets (needed for the `tx.crs_xml_attr_inspect` gate); deprecated `REQBODY_PROCESSOR_ERROR` / `_MSG` **removed** — use `REQBODY_ERROR` / `REQBODY_ERROR_MSG` |

New multipart variables (3.0.17 / 2.9.15): `MULTIPART_DUPLICATE_PART_HEADER`, `MULTIPART_FILENAME_CHARSET`, `MULTIPART_FILENAME_LANGUAGE`. NGINX support was removed from ModSecurity v2 (2.9.13); v3 is the Nginx engine.

If a CRS advisory workaround uses `ctl:ruleRemoveTargetByTag` on ModSecurity v2 older than 2.9.14 it silently does nothing; use the config-time `SecRuleUpdateTargetByTag "attack-xss" "!XML://@*"` form (one line per tag: attack-protocol, -lfi, -rfi, -rce, -php, -generic, -xss, -sqli, -fixation).

## Release tracks

- **CRS current**: 4.30.0 (2026-10-02); 4.29.0 (2026-08-17), 4.28.0 (2026-07-01).
- **CRS LTS**: 4.25.x. 4.25.0 (2026-03-28) is the first CRS 4 LTS; 4.25.1 (2026-07-02), **4.25.2** (2026-10-02). Security fixes until **Q3 2027**; quarterly point releases; only security, regression, critical PL1 FP and engine-compat fixes are backported (no new rules/features/PL changes). Docker tags `4.25-lts` (floating) and `4.25.N-lts`.
- **CRS 3.3.x**: last release 3.3.10 (2026-07-02). **End of support Q3 2026** (upstream announcement, 2025-12-14) — migrate to 4.25 LTS. 3.x does not get the 4.30 REQUEST_FILENAME fix.
- **ModSecurity**: v3 3.0.17, v2 2.9.15 (both 2026-09-29). PCRE2 is the default regex engine.
- **Coraza**: 3.8.1 (2026-10-02) per secondary sources *verify*. Coraza does not implement `SecWebAppID`; use a `Host` header match for per-vhost plugin scoping.
- **go-ftw**: v2.6.2 (2026-10-26). 2.6.0 added `--threshold` and multi-`--rule` for quantitative runs; 2.6.1 rejects raw CR/LF in header values and fails (not skips) on unparseable test files — fix test YAML that used to be silently ignored.
- **Engine support matrix (CRS 4)**: ModSecurity v2 + Apache, ModSecurity v3 + Nginx, Coraza. **Not supported**: Nginx + ModSecurity v2, Apache + ModSecurity v3. Upstream now recommends Coraza for new deployments. CRS 4 needs ModSecurity ≥ 2.9; CRS 4 is RE2-compatible so rules behave the same on either Coraza regex build.

## CRS changes that break or alter existing configuration

- **4.30.0 response rules**: per-file compression checks 950010, 951010, 952010, 953010, 954010, 955010, 956010 are **replaced by 950020** (jumps to the new `BEGIN-RESPONSE-959-BLOCKING-EVALUATION` marker). Exclusions that reference the old IDs must be updated. New rule **950022** makes `tx.crs_skip_response_analysis` (900500) skip phase 4 bodies too; before, only phase 3 headers were skipped. Not in 4.25.2 (LTS keeps the per-file rules, but gets 950022).
- **4.30.0 / 4.25.2 JSON content types**: `application/*+json` (rule 901370) and AWS `application/x-amz-json-1.0/1.1` (901360) are now allowed by default and parsed as JSON. Requests previously blocked by 920420 are now inspected — a behaviour change on the LTS line.
- **4.28.0**: `crs_validate_utf8_encoding` enabled by default (expect new 920250 hits on non-UTF-8 clients); default actions for phases 3–5 added to `crs-setup.conf`.
- **4.26.0**: HTTP/0.9 `GET` dropped from request-line validation (920100); 933100 now checks all headers.
- **New detections**: 4.26 SSTI (934200); 4.28 ORM lookup operator injection (934) and quote evasion; 4.29 backslash-prefix and quote-evasion shell commands, `stat` at PL2+; 4.30 Velocity/FreeMarker directives, Active Directory tools (932380), SELinux commands, `.claude` restricted files, `Mozilla/6.0` scanner UA.
- The upstream engine-migration advice: `SecCollectionTimeout` was removed from `crs-setup.conf` in CRS 4 (keep it in global `modsecurity.conf`); CRS 4 plugins need three Includes (`*-config.conf`, `*-before.conf`, `*-after.conf`); Lua plugins (fake-bot, antivirus) need Lua compiled into the engine.

## Tooling and ecosystem news

- **CRSLang** (YAML rule language) is announced upstream as the format that **will replace SecLang in the next major CRS release**; today SecLang remains the source of truth. **seclang_parser** (ANTLR grammar with Go and Python parsers) is the shared SecLang parser.
- **Traffic observation plugin** (CRS performance): logs per-request statistics (header counts, sizes, content types — no URLs, values or bodies) and ships an analysis script; run it on your own traffic and share the summary upstream.
- **Mirror traffic CRS3→CRS4** (2026-09-12): nginx `mirror` in front of `owasp/modsecurity-crs:3.3-apache-lts` (primary) and `4.25-apache-lts` (shadow), then diff audit logs. Use it before cutover.

## Parser-differential evasion class
The engine and the backend disagree on how a body is parsed (multipart line breaks, charset, duplicate `filename`, XML attributes, duplicate parameters/parameter pollution, mixed-case headers). Signature rules cannot fix this. Order of response: (1) upgrade the engine and ruleset, (2) reject ambiguous or malformed bodies (`MULTIPART_STRICT_ERROR`, `REQBODY_ERROR`, `MULTIPART_UNMATCHED_BOUNDARY`, `MULTIPART_DUPLICATE_PART_HEADER`), (3) add go-ftw regression tests that send the differential request. Research reference: WAFFLED (arXiv 2503.10846, figures *verify*).

## Sources
- https://github.com/coreruleset/coreruleset/blob/main/CHANGES.md and /security/advisories
- https://coreruleset.org/20261002/crs-versions-4.30.0-and-4.25.2-lts-released/
- https://coreruleset.org/20260702/crs-versions-4.28.0-4.25.1-lts-and-3.3.10-released/
- https://coreruleset.org/20260321/announcing-crs-v4-25-lts/ and /20251214/announcing-crs-4-lts-release-timeline-moving-forward-despite-sponsorship-challenges/
- https://coreruleset.org/20260511/migrating-crs-3-to-4-part-7-engines/ and /20260912/mirror-traffic-crs3-to-crs4-migration/
- https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/
- https://github.com/owasp-modsecurity/ModSecurity (v3 `CHANGES`, v2 `CHANGES`)
- https://github.com/coreruleset/go-ftw/blob/main/CHANGELOG.md
