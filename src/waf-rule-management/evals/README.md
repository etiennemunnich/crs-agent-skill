# Evals

Benchmark suite for the `waf-rule-management` skill. Run these to verify your agent handles WAF tasks correctly, or to measure the impact of skill changes before submitting a PR.

## Structure

```
evals/
  evals.json          # Eval definitions — 9 prompts across 4 tiers
  files/
    payment-api.yaml  # OpenAPI 3.0 fixture used by the openapi-to-waf-pipeline eval
```

## Running evals

Use the [skill-creator](https://github.com/anthropics/agent-skills) eval runner:

```bash
# Run all 9 evals against the current SKILL.md
skill-creator eval run --skill src/waf-rule-management --evals evals/evals.json

# Run a single eval by ID
skill-creator eval run --skill src/waf-rule-management --evals evals/evals.json --id 7
```

Or run a specific eval manually: copy the `prompt` from `evals.json`, point your agent at `SKILL.md`, and check the output against the `expectations`.

## Eval tiers

| Tier | IDs | What it tests |
|------|-----|---------------|
| **Easy** | 1–2 | Conceptual knowledge — paranoia level selection, CIDR blocking |
| **Medium** | 3–6 | Multi-script workflows — path traversal rules, FP exclusions, log triage |
| **Hard** | 7–8 | Script-only solvable — CVE virtual patch (`new_incident.sh`), evasion bypass analysis |
| **Expert** | 9 | Full pipeline — OpenAPI spec → WAF rules → validation → regression tests |

Hard and Expert evals **cannot be completed without running the actual scripts**. They assert that `new_incident.sh`, `assemble_rules.sh`, and `openapi_to_rules.py` were invoked, not reimplemented.

## Benchmark (v0.8)

| Config | Passed | Total | Pass rate |
|--------|--------|-------|-----------|
| v0.8 (with skill) | 45 | 45 | 100% |
| v0.7 (without M2M guidance) | 44 | 45 | 97.8% |

The single v0.7 miss was eval #1, assertion 2 — M2M/API-specific anomaly scoring guidance added in v0.8.

## Adding evals

Follow the format in `evals.json`. Each eval needs:
- `id`, `tier`, `name` — unique identifier and difficulty bucket
- `prompt` — the task exactly as given to the agent
- `expectations` — 5 assertions checked against the agent's output and any files it creates
- `script_required` — list any scripts that *must* be invoked (not just mentioned) for a passing answer
