# CRS Agent Skill Evals

This folder holds the **evaluation suite** for the WAF Rule Management skill. Evals measure how well an AI agent follows the skill when solving real WAF problems.

## What are evals?

Evals are test prompts. We send each prompt to an AI model (with or without the skill loaded) and check if the answer is correct. That tells us whether the skill actually helps.

**Example:** "We're under a brute-force attack from 185.220.101.0/24. Block only POST /auth/login from that range." We grade whether the model writes a correct ModSecurity rule and uses the right tools. The suite (`evals_v2.json` v2.2) includes **10** evals, including CRS v3→v4 exception migration routing.

## How to run

```bash
# With skill loaded (simulates agent having SKILL.md)
python evals/run_evals.py --config with_skill --iteration 6

# Without skill (baseline)
python evals/run_evals.py --config without_skill --iteration 6

# Grade existing results
python evals/run_evals.py --grade-only --results-dir evals/results/iteration-6/with_skill/
```

Requires: `pip install anthropic`

## Files

| File | Purpose |
|------|---------|
| `evals_v2.json` | Eval definitions (prompts, grading rules) |
| `run_evals.py` | Runs evals via Anthropic API, saves responses |
| `grader.py` | Grades responses (string match + LLM rubric) |
| `files/` | OpenAPI specs and other inputs for evals |

## Learn more

- **[Agent Skills](https://agentskills.io/what-are-skills)** — What skills are and how they work
- **[Agent Skills spec](https://agentskills.io/specification)** — SKILL.md format
- **[Claude agent skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)** — Best practices for writing skills
- **[OpenAI evals](https://platform.openai.com/docs/guides/evals)** — OpenAI's eval framework (similar idea)
- **[OpenAI evals (GitHub)](https://github.com/openai/evals)** — Open-source eval registry and tools
