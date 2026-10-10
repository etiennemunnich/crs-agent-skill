# Recent Advisories and Releases (2026)

Snapshot for triage. **As of 2026-10.** Items marked *verify* came from secondary sources; confirm on the primary advisory before acting or quoting.

| ID | Component | Issue | Fixed in | Response | Eval |
|----|-----------|-------|----------|----------|------|
| CVE-2026-52747 (GHSA-rcw9-2f5r-7p88) | ModSecurity v3 | Multipart parser strips line breaks in non-file fields, so ARGS/ARGS_POST rules miss payloads (parser differential) | 3.0.16 | Upgrade; reject malformed multipart; add regression test | 11 |
| CVE-2026-21876 | CRS rule 922110 | Multipart charset bypass | CRS 4.22.0 / 3.3.8 | Upgrade | 17 |
| GHSA-575j-qr6p-9763 *verify* | CRS RCE rules (932xxx) | Path-based command injection (e.g. `/usr/bin/id`, globbed paths) | 4.30.0 / 4.25.2 LTS | Upgrade; interim custom rule with `t:urlDecodeUni,t:lowercase,t:normalizePath` | 13 |
| GHSA-89h9-2j8h-9gp2 *verify* | CRS charset allow-list | Case-sensitivity bug left allow-list ineffective | 4.30.0 / 4.25.2 | Upgrade | 17 |
| GHSA-qmx4-jfcv-fgww *verify* | CRS multipart | Charset shadowing bypasses encoding checks | 4.30.0 / 4.25.2 | Upgrade | 11 |
| GHSA-6jp8-c2w2-x7wr *verify* | CRS XML | Payloads in XML attribute values not inspected | 4.28.0 line | Upgrade; check XML targets | 12 |
| CVE-2026-33691 *verify* | CRS upload rules | Whitespace padding bypass of PHP double-extension upload detection | 4.30.0 (maybe backported) | Upgrade | — |

## Release tracks

- **CRS**: current 4.30.0 (2026-10-02); **LTS 4.25.x** (4.25.2 current). CRS 3.3.x is near or past end of support (*verify* date) — migrate; see [crs-v3-v4-exception-migration.md](crs-v3-v4-exception-migration.md).
- **ModSecurity v3**: 3.0.16 or newer. PCRE2 is the default regex engine.
- **Coraza**: 3.8.1 (2026-10-02, security/crash fix). Coraza does not implement `SecWebAppID`.
- **go-ftw**: v2.6.0 (adds `--threshold`, multi-`--rule`). **crs-toolchain**: latest version unverified.

## New detection coverage in CRS 4.30 (*verify*)
Active Directory `ds*` tools, Velocity/FreeMarker SSTI, SELinux commands.

## Parser-differential evasion class
The engine and the backend disagree on how a body is parsed (multipart line breaks and charset, XML attributes, duplicate parameters/parameter pollution, JSON edge cases). Signature rules cannot fix this. Order of response: (1) upgrade the engine/ruleset, (2) reject ambiguous or malformed bodies (`MULTIPART_STRICT_ERROR`, `REQBODY_ERROR`, `MULTIPART_UNMATCHED_BOUNDARY`), (3) add go-ftw regression tests that send the differential request. Research reference: WAFFLED (arXiv 2503.10846, *verify* figures).

## Sources
- https://github.com/coreruleset/coreruleset/releases and /security/advisories
- https://github.com/owasp-modsecurity/ModSecurity/releases
- https://github.com/corazawaf/coraza/releases
- https://github.com/coreruleset/go-ftw/releases
