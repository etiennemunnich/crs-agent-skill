# CRS Issue / Contribution Workflow

**Purpose**: Holistic steering for developers and maintainers contributing to CRS — rules, go-ftw regression tests, and optionally nuclei-templates. Use when adding/changing CRS rules or proposing new detection.

---

## When to Use

- User provides a CRS GitHub issue URL or a folder path for the issue
- User wants to create a patch, tests, or proposal for a CRS issue
- User wants to validate against CRS conventions before opening a PR
- User asks about the submission process for CRS changes

---

## Holistic Submission: CRS + go-ftw + nuclei-templates

| Deliverable | Purpose | Audience |
|-------------|---------|----------|
| **CRS rule/data change** | WAF detection at the edge | CRS maintainers, WAF deployers |
| **go-ftw tests** | Regression coverage; required for CRS PR | CRS CI, maintainers |
| **nuclei template** | DAST detection for scanners; optional but recommended for new attack surface | Security researchers, pentesters |

When adding or changing CRS rules, consider all three. go-ftw is **required** for CRS. nuclei-templates provides complementary coverage for the same attack surface.

---

## Workflow

1. **Understand the issue** — Read the issue, identify what change is needed (data file, rule, both).
2. **Check nuclei-templates** — Search [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) for existing coverage. Avoid duplicating. If none exists, plan a nuclei template for the same attack surface.
3. **Create structure** — If the user has an issue folder, use or create:
   - `ISSUE-NNNN.md` — Summary, context, implementation notes
   - `patch/` — Diffs against CRS master
   - `tests/` — go-ftw YAML files (for CRS PR)
   - `nuclei/` — Optional nuclei template(s) for community submission
   - `research/` — TTPs, CVEs, vendor docs
   - `examples/` — Exclusion examples, validation reports
4. **Apply CRS conventions** — See [CRS PR requirements](#crs-pr-requirements) below.
5. **Validate** — `validate_rule.py` (crslang primary), `lint_regex.py`, `lint_crs_rule.py`, CRS Sandbox. See [crslang-reference.md](crslang-reference.md).
6. **Run go-ftw** — Against CRS `tests/regression/tests/` or local test dir. Use `docker` or `finch`. Sandbox fallback when containers unavailable.
7. **Submit nuclei template** — If new attack surface, submit to [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) per their CONTRIBUTING.md and TEMPLATE-CREATION-GUIDE.md.

---

## CRS PR Requirements

From [CRS contribution guidelines](https://coreruleset.org/docs/6-development/6-1-contribution-guidelines/):

| Requirement | Description |
|-------------|-------------|
| **Issue first** | Open a [GitHub issue](https://github.com/coreruleset/coreruleset/issues) (or reference existing) before PR. Bonus: submit tests with the issue. Specify CRS version if reporting a bug. |
| **Fork + branch** | Fork the repo; create a topic branch per contribution. Base on latest `main`. |
| **One fix per PR** | Fix only one problem at a time; use separate branches for unrelated changes. |
| **PR title** | [Conventional Commits](https://www.conventionalcommits.org/) format, e.g. `fix(rce): Fix FP in rule 932345 with keyword 'time'` |
| **Rule ID in title** | If PR affects a single rule, include the rule ID |
| **go-ftw tests** | Add positive and negative tests; CRS runs tests in CI. Each rule file → directory; each rule → YAML (e.g. `REQUEST-911-METHOD-ENFORCEMENT/911100.yaml`). |
| **Test location** | CRS repo: `tests/regression/tests/` — tests named by rule ID (e.g. `930130.yaml`). Schema: [ftw-tests-schema](https://github.com/coreruleset/ftw-tests-schema/blob/main/spec). |
| **Test headers** | Include `Host`, `User-Agent`, `Accept` in every test — CRS has rules that fire on missing/empty headers. |
| **Formatting** | 4 spaces, 80-char line limit, American English, explicit operators (`@rx`). Signed commits preferred. |

---

## go-ftw (CRS Regression)

- **Required** for CRS contributions. Tests prove the rule works and prevent regressions.
- **Schema**: [ftw-tests-schema](https://github.com/coreruleset/ftw-tests-schema/blob/main/spec) — full YAML format and options.
- **Backend**: CRS uses [Albedo](https://github.com/coreruleset/albedo) — endpoints `/capabilities`, `/reflect`; other URIs get `200 OK` with empty body.
- **Run**: `go-ftw run --config .ftw.yaml -d tests/regression/tests/` (from CRS repo) or bind-mount patched rules into [modsecurity-crs-docker](https://github.com/coreruleset/modsecurity-crs-docker)
- **CRS CI**: [test.yml](https://github.com/coreruleset/coreruleset/blob/main/.github/workflows/test.yml) runs go-ftw against Apache + ModSecurity
- See [go-ftw-reference.md](go-ftw-reference.md) for test format, `rule_id`, `Host` header, cloud mode

---

## nuclei-templates (Optional, Recommended for New Detection)

When adding new attack surface (e.g. new paths to restricted-files, new rule for a CVE):

| Step | Action |
|------|--------|
| **Check first** | Search nuclei-templates for existing coverage; avoid duplicates |
| **Directory** | Place in `http/exposures/files/`, `cves/YYYY/`, or `misconfiguration/` as appropriate |
| **Validate** | `nuclei -validate -t template.yaml` |
| **Test** | `nuclei -t template.yaml -target http://vulnerable-test-host -debug` |
| **Submit** | PR to [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates); follow [CONTRIBUTING.md](https://github.com/projectdiscovery/nuclei-templates/blob/main/CONTRIBUTING.md) and [TEMPLATE-CREATION-GUIDE.md](https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-CREATION-GUIDE.md) |

nuclei templates use different semantics (HTTP probes, matchers) than CRS rules; they complement WAF coverage for DAST and external scanning.

---

## User-Provided Steering

When the user provides explicit TTPs, tiered approaches, or methodology (e.g. Tier 1 block, Tier 2 alert, Tier 3 chained only) — **use them first**. Do not substitute with generic CRS precedent unless the user asks. See [false-positives-and-tuning.md](false-positives-and-tuning.md) for tiered FP model guidance.

---

## Testing

- **go-ftw**: `rule_id` at top level, `Host` in every input, `output.status` for cloud mode.
- **Container runtime**: Try `docker` first, then `finch`. Use `--project-directory` when running from a different workspace.
- **Sandbox fallback**: When Docker/Finch unavailable, run against `sandbox.coreruleset.org` — caveat: no custom rules, so tests for new rules will fail (expected).

---

## Related

[crs-rule-format.md](crs-rule-format.md) | [crslang-reference.md](crslang-reference.md) | [go-ftw-reference.md](go-ftw-reference.md) | [CRS contribution guidelines](https://coreruleset.org/docs/6-development/6-1-contribution-guidelines/)
- [nuclei-templates CONTRIBUTING](https://github.com/projectdiscovery/nuclei-templates/blob/main/CONTRIBUTING.md)
- [nuclei TEMPLATE-CREATION-GUIDE](https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-CREATION-GUIDE.md)
