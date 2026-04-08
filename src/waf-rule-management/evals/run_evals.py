#!/usr/bin/env python3
"""
run_evals.py — Orchestrate WAF skill eval runs and grade results.

Calls the Anthropic API for each eval in evals_v2.json, saves responses, grades them
with grader.py, and produces a benchmark.json. Supports OODA diagnosis.

Usage:
  # A/B comparison (the core loop):
  python evals/run_evals.py --config with_skill --iteration 6
  python evals/run_evals.py --config without_skill --iteration 6

  # Single eval:
  python evals/run_evals.py --config with_skill --eval-id 2

  # Grade existing responses + OODA diagnosis:
  python evals/run_evals.py --grade-only --results-dir evals/results/iteration-6/with_skill/ --diagnose

  # Dry-run:
  python evals/run_evals.py --config with_skill --dry-run

Configs:
  with_skill      → SKILL.md loaded as system prompt context
  without_skill   → No skill context; model uses base knowledge only

OODA loop:
  --diagnose      → Observe failures → Orient to SKILL.md routing gaps → Decide fixes → print suggestions
"""

import json
import os
import sys
import time
import argparse
from pathlib import Path
from datetime import date

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("WARNING: anthropic package not installed. API calls will fail.")
    print("Install with: pip install anthropic --break-system-packages")

# Paths
SKILL_ROOT = Path(__file__).parent.parent
EVALS_PATH = Path(__file__).parent / "evals_v2.json"
RESULTS_ROOT = SKILL_ROOT / "evals" / "results"

# Import grader
sys.path.insert(0, str(Path(__file__).parent))
from grader import grade_response, print_summary, diagnose, print_diagnosis


# ---------------------------------------------------------------------------
# Skill loading
# ---------------------------------------------------------------------------

def load_skill_context(skill_file: str | None) -> str | None:
    """Load SKILL.md as system context (simulates agent having the skill loaded)."""
    if not skill_file:
        return None
    path = Path(skill_file)
    if not path.exists():
        path = SKILL_ROOT / skill_file
    if path.exists():
        return path.read_text()
    raise FileNotFoundError(f"Skill file not found: {skill_file}")


def build_system_prompt(skill_context: str | None, config: str) -> str:
    """
    Build the system prompt for the model being evaluated.

    IMPORTANT for A/B validity: the without_skill prompt does NOT list script
    names. The with_skill prompt loads SKILL.md which contains the routing
    table and Essential Commands. This is the controlled variable.
    """
    if skill_context:
        return (
            "You are an expert WAF security engineer with deep knowledge of OWASP CRS v4, "
            "ModSecurity v3, and Coraza WAF. You are working in the directory: "
            f"{SKILL_ROOT}\n\n"
            "You have access to scripts in scripts/ and reference documentation in references/.\n"
            "When you run a script, show the command and its output.\n"
            "Be precise, technical, and complete.\n\n"
            "=== SKILL CONTEXT (loaded) ===\n"
            f"{skill_context}\n"
            "=== END SKILL CONTEXT ==="
        )
    else:
        # without_skill: NO script names, NO routing hints
        # The agent must rely on base knowledge only
        return (
            "You are an expert WAF security engineer with deep knowledge of OWASP CRS v4, "
            "ModSecurity v3, and Coraza WAF. You are working in the directory: "
            f"{SKILL_ROOT}\n\n"
            "You have access to scripts in scripts/ and reference documentation in references/.\n"
            "When you run a script, show the command and its output.\n"
            "Be precise, technical, and complete."
        )


# ---------------------------------------------------------------------------
# Eval runner
# ---------------------------------------------------------------------------

def run_eval(
    eval_spec: dict,
    system_prompt: str,
    client,
    delay_s: float = 1.0,
) -> str:
    """Call the API with the eval prompt and return the response text."""
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": eval_spec["prompt"]}]
    )
    time.sleep(delay_s)
    return msg.content[0].text


def run_config(
    config: str,
    skill_file: str | None,
    eval_id_filter: int | None,
    results_dir: Path,
    dry_run: bool = False,
) -> list[dict]:
    """Run all matching evals and grade them."""

    with open(EVALS_PATH) as f:
        evals_data = json.load(f)

    skill_context = load_skill_context(skill_file) if config == "with_skill" else None
    system_prompt = build_system_prompt(skill_context, config)

    if not ANTHROPIC_AVAILABLE:
        raise RuntimeError("anthropic package required for running evals")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key and not dry_run:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key) if (api_key and not dry_run) else None

    results_dir.mkdir(parents=True, exist_ok=True)
    all_results = []
    count = 0

    for ev in evals_data["evals"]:
        if eval_id_filter and ev["id"] != eval_id_filter:
            continue

        count += 1
        response_file = results_dir / f"{ev['id']}.txt"

        print(f"\n[{count}] Eval {ev['id']} ({ev['tier']}): {ev['name']}")
        print(f"  Measures: {ev['measures']}")

        if dry_run:
            print("  [DRY RUN — skipping API call]")
            continue

        # Run or load cached response
        if response_file.exists():
            print(f"  Loading cached: {response_file.name}")
            response_text = response_file.read_text()
        else:
            print(f"  Calling API (claude-sonnet-4-6)...")
            try:
                response_text = run_eval(ev, system_prompt, client)
                response_file.write_text(response_text)
                print(f"  Saved: {response_file.name}")
            except Exception as e:
                print(f"  ERROR: {e}")
                continue

        # Grade
        print(f"  Grading...")
        result = grade_response(response_text, ev["id"])
        result["config"] = config
        result["source_file"] = str(response_file)
        all_results.append(result)

        score_str = f"{result['score']}/{result['total']} ({result['pct']}%)"
        fails = [a["assertion_id"] for a in result["assertions"] if not a["passed"]]
        print(f"  Score: {score_str}" + (f" | FAIL: {fails}" if fails else " ✓"))

    return all_results


# ---------------------------------------------------------------------------
# Benchmark builder
# ---------------------------------------------------------------------------

def build_benchmark(results: list[dict], config: str, iteration: int, diag: dict = None) -> dict:
    """Build a benchmark.json from graded results."""
    tiers = {"easy": [], "medium": [], "hard": [], "expert": []}
    for r in results:
        tiers.get(r.get("tier", "medium"), tiers["medium"]).append(r)

    def summarise(items):
        if not items:
            return {"score": 0, "total": 0, "pct": 0.0}
        s = sum(i["score"] for i in items)
        t = sum(i["total"] for i in items)
        return {"score": s, "total": t, "pct": round(s / t * 100, 1) if t else 0.0}

    total_score = sum(r["score"] for r in results)
    total_possible = sum(r["total"] for r in results)

    benchmark = {
        "iteration": iteration,
        "config": config,
        "date": str(date.today()),
        "eval_suite_version": "2.2",
        "eval_count": len(results),
        "summary": {
            "score": total_score,
            "total": total_possible,
            "pct": round(total_score / total_possible * 100, 1) if total_possible else 0.0,
        },
        "by_tier": {
            "easy": summarise(tiers["easy"]),
            "medium": summarise(tiers["medium"]),
            "hard": summarise(tiers["hard"]),
            "expert": summarise(tiers["expert"]),
        },
        "results": results,
    }
    if diag:
        benchmark["diagnosis"] = diag
    return benchmark


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run and grade WAF skill evals")
    parser.add_argument("--config", choices=["with_skill", "without_skill"], default="with_skill",
                        help="with_skill loads SKILL.md; without_skill uses base knowledge only")
    parser.add_argument("--skill-file", default="SKILL.md",
                        help="Path to SKILL.md (relative to skill root, or absolute)")
    parser.add_argument("--eval-id", type=int, help="Run only this eval ID (see evals_v2.json)")
    parser.add_argument("--iteration", type=int, default=6, help="Benchmark iteration number")
    parser.add_argument("--results-dir", help="Override default results directory")
    parser.add_argument("--grade-only", action="store_true",
                        help="Skip API calls, grade existing response files only")
    parser.add_argument("--diagnose", action="store_true",
                        help="Run OODA diagnosis: map failures → SKILL.md routing gaps → suggest fixes")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would run without calling API")
    parser.add_argument("--output", help="Write benchmark JSON to this file")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore cached responses, re-run all API calls")
    args = parser.parse_args()

    # Set up results directory
    if args.results_dir:
        results_dir = Path(args.results_dir)
    else:
        results_dir = RESULTS_ROOT / f"iteration-{args.iteration}" / args.config

    skill_file = None if args.config == "without_skill" else args.skill_file

    if args.grade_only:
        from grader import grade_directory
        print(f"Grading existing responses in {results_dir}...")
        results = grade_directory(str(results_dir))
        for r in results:
            r["config"] = args.config
    else:
        # Optionally clear cache
        if args.fresh and results_dir.exists():
            for f in results_dir.glob("*.txt"):
                f.unlink()
            print(f"Cleared cached responses in {results_dir}")

        results = run_config(
            config=args.config,
            skill_file=skill_file,
            eval_id_filter=args.eval_id,
            results_dir=results_dir,
            dry_run=args.dry_run,
        )

    if args.dry_run:
        return

    if not results:
        print("No results to report.")
        return

    print_summary(results)

    diag = None
    if args.diagnose:
        diag = diagnose(results)
        print_diagnosis(diag)

    benchmark = build_benchmark(results, args.config, args.iteration, diag)
    out_path = Path(args.output) if args.output else results_dir / "benchmark.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(benchmark, indent=2))
    print(f"Benchmark written to {out_path}")


if __name__ == "__main__":
    main()
