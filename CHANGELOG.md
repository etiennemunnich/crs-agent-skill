# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Release checklist**: Bump `metadata.version` in `src/waf-rule-management/SKILL.md` → update CHANGELOG (Unreleased → dated) → update README badge if present → `git tag vX.Y` → push tag.

---

## [Unreleased]

---

## [1.2] — 2026-04-09

### Added

- **crs-v3-v4-exception-migration.md** — v3.3 → v4.25.0 LTS exception/exclusion migration; attribution to Felipe Zipitria ([gist](https://gist.github.com/fzipi/0e674a93f61e8e577a7bee492d4a6912))
- **Eval 10** — CRS v3→v4 exception migration eval (evals suite v2.2)
- **Evals README** — how to run and grade evals
- **REPORT-template.md** — incident report template; `new_incident.sh` uses it
- **Coraza `@rx` prefilter note** — optional compile-time `coraza.rule.rx_prefilter` ([corazawaf/coraza#1534](https://github.com/corazawaf/coraza/pull/1534))

### Changed

- **engine_integration_compare.sh** moved from `scripts/` to `src/waf-rule-management/scripts/` (ships with skill)
- **Removed** `src/waf-rule-management/README.md` — redundant with SKILL.md per Agent Skills spec
- **.gitignore** — added `evals/results/`, `engine-compare/`, eval runtime artifacts; removed stale `custom-rules.conf` entry
- **SKILL.md** — routing for v3→v4 migration, engine compare in Essential Commands, removed dead README link
- **upgrade-and-testing.md** — exception file migration gotcha
- **References** — Coraza prefilter notes in `best-practices`, `coraza-testing-reference`, `operators-and-transforms`, `regex-steering-guide`

---

## [0.9] — 2026-03-13

### Added

- **anomaly-scoring.md** — Routed into task table and reference index; covers anomaly threshold tuning, M2M/API scoring models, inbound/outbound scoring
- **sampling-mode.md** — Routed into task table and reference index; DetectionOnly / sampling rollout strategy
- **ooda-loop-guide.md** — Routed into reference index; OODA loop methodology mapped to WAF workflows
- **developer-security-workflow.md** — Routed into reference index; branch-per-change strategy and developer-friendly CI lifecycle

### Changed

- **SKILL.md** — Bump to v0.9; four previously orphaned reference files now wired into routing table and reference index
- **SKILL.md** — `new_incident.sh` and `assemble_rules.sh` added to Essential Commands
- **.gitignore** — Added `.pytest_cache/`

### Benchmark (iteration-5, 2026-03-13) — A/B: without_skill vs with_skill_v09

| Config | Score | % |
|--------|-------|---|
| without_skill (baseline) | 44/45 | 97.8% |
| with_skill_v09 | 43/45 | 95.6% |

Both configs ≥ 95%. The 1-point differential is environment noise: eval 7 EDEADLK (filesystem deadlock on mounted volume) blocked `assemble_rules.sh` in both configs; `new_incident.sh` succeeded in without_skill run (incident directory created on disk) but not in with_skill run. All 8 remaining evals passed 5/5 in both configs. No skill regression.

**Eval design note:** Eval prompts are directive (explicitly name scripts to run), so agents score high regardless of skill presence. A v2 eval suite with open-ended prompts is needed to measure skill routing/discovery uplift. Filed as known limitation.

---

## [0.8] — 2026-03-07

### Added

- **evals/evals.json** — 9-eval tiered benchmark suite (easy → medium → hard → expert) replacing the previous 3-eval suite
- **evals/files/payment-api.yaml** — OpenAPI 3.0 sample spec for the OpenAPI-to-WAF pipeline eval
- **CHANGELOG.md** — Project changelog
- **crs-contribution-workflow.md** — Holistic CRS submission: rules + go-ftw + nuclei-templates
- **baseline-testing-tools.md** — go-ftw, go-test-waf, nuclei baseline workflow
- **upgrade-and-testing.md** — CRS upgrade workflow, tools, gotchas

### Changed

- **SKILL.md** — Bump to v0.8; added M2M/API-specific anomaly scoring and threshold tuning guidance for enterprise SaaS deployments
- **SKILL.md** — Check latest official sources (news, releases, issues) for CRS, ModSecurity, Coraza, nuclei, go-ftw, crs-toolchain before advising
- **SKILL.md** — Removed cross-workspace / container runtime guidance from steering
- **crs-tune-rule-steering.md** — Removed CRS data file conventions (930xxx); steering focuses on tuning, not implementation details
- **antipatterns-and-troubleshooting.md** — Reframed `ctl:ruleRemoveTargetById` antipattern: point to engine source/docs for limitations; emphasize FP/evasion investigation process
- **crs-contribution-workflow.md** — Aligned with [CRS contribution guidelines](https://coreruleset.org/docs/6-development/6-1-contribution-guidelines/): fork+branch, one fix per PR, test headers (Host/User-Agent/Accept), Albedo backend, ftw-tests-schema link

### Eval Suite (iteration 3 — 9 evals, 45 assertions)

| Tier | Evals | v0.8 | v0.7 |
|------|-------|------|------|
| Easy | paranoia-level-recommendation, block-bad-cidr | 10/10 | 9/10 |
| Medium | path-traversal, fp-scope-out, graphql-fp, log-triage | 20/20 | 20/20 |
| Hard | CVE-2025-29927 virtual patch, evasion bypass | 10/10 | 10/10 |
| Expert | openapi-to-waf pipeline | 5/5 | 5/5 |
| **Total** | | **45/45 (100%)** | **44/45 (97.8%)** |

*v0.8 gain: M2M anomaly scoring guidance closes the lone gap on the paranoia-level eval.*

---

## [0.6] — 2026-02-27

### Added

- **crs-tune-rule-steering.md** — Agent steering for CRS tuning: groups, phases, request/response flow, version-aware tuning
- **engine_integration_compare.sh** — Cross-engine ModSecurity vs Coraza probe + log integration test
- **detect_app_profile.py** — App profile hints from audit logs (WordPress, Drupal, etc.)
- **validate_exclusion.py** — Exclusion safety checks, runtime vs configure-time validation
- **recommended-mcp-servers.md** — Context7, Chrome DevTools MCP setup
- **labels.yml** — GitHub issue labels

### Changed

- **SKILL.md** — Expanded constraints, Context7 guidance, CRS contribution workflow link
- **analyze_log.py** — Major rewrite: `--explain`, `--explain-rule`, `--summary`, `--top-rules`
- **generate_exclusion.py** — Improved exclusion generation
- **crs-application-profiles.md** — NextAuth, Strapi, WordPress exclusions
- **false-positives-and-tuning.md** — Tiered FP model, dynamic variable keys note
- **antipatterns-and-troubleshooting.md** — Additional antipatterns
- **best-practices-modsec-coraza-crs.md**, **coraza-testing-reference.md**, **modsec-crs-testing-reference.md** — Updates
- **log-analysis-steering.md**, **developer-security-workflow.md**, **sampling-mode.md** — Steering improvements
- **crs-rule-format.md** — Stricter siblings, version variance notes
- **first-responder-risk-runbook.md** — Incident scaffolding

### Fixed

- Various reference fixes and consistency updates

---

## [0.5] — 2026-02-26

### Changed

- **antipatterns-and-troubleshooting.md** — Additional antipatterns
- **crs-application-profiles.md** — Community pain-point exclusions (NextAuth, Strapi, etc.)
- **false-positives-and-tuning.md** — FP handling guidance
- **modsec-directives.md** — Directive updates

*Addresses top CRS pain points from community Slack analysis*

---

## [0.4] — 2026-02-15

### Added

- **skill-validate.yml** — Agent Skill validation via skills-ref
- **lint.sh** — Repo-wide linting

### Changed

- **README.md** — Skill validation badge

---

## [0.3] — 2026-02-15

### Added

- Initial CRS agent skill for WAF rule management
- Scripts: `validate_rule.py`, `lint_regex.py`, `analyze_log.py`, `openapi_to_rules.py`, `generate_ftw_test.py`, `generate_exclusion.py`, `new_incident.sh`, `assemble_rules.sh`
- References: rule format, operators, variables, antipatterns, false positives, testing, deployment

---

[Unreleased]: https://github.com/etiennemunnich/crs-agent-skill/compare/v1.2...HEAD
[1.2]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.9...v1.2
[0.9]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.8...v0.9
[0.8]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.6...v0.8
[0.6]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.5...v0.6
[0.5]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.4...v0.5
[0.4]: https://github.com/etiennemunnich/crs-agent-skill/compare/v0.3...v0.4
[0.3]: https://github.com/etiennemunnich/crs-agent-skill/releases/tag/v0.3
