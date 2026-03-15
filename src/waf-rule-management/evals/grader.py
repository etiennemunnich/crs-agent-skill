#!/usr/bin/env python3
"""
grader.py — Automated eval grader for waf-rule-management skill.

Implements Anthropic eval best practices:
  - Code-based grading first (fastest, most reliable): string_match, regex_match, file checks
  - LLM-based grading for complex judgements: separate haiku grader with detailed rubrics
  - Grader uses claude-haiku (different model from claude-sonnet being evaluated)
  - Grader encouraged to reason in <thinking> before scoring (improves accuracy)
  - Outputs structured JSON for automated tracking

Usage:
  python evals/grader.py --response-file responses/2.txt --eval-id 2
  python evals/grader.py --response "..." --eval-id 7
  python evals/grader.py --grade-all results/iteration-6/with_skill/
  python evals/grader.py --grade-all results/iteration-6/with_skill/ --diagnose

Grading methods (evals_v2.json):
  "code"   → string_match, regex_match, file_or_string, string_match_all, string_match_all_groups
  "llm"    → LLM grader with rubric, outputs correct/incorrect + reasoning
"""

import json
import re
import sys
import os
import argparse
from pathlib import Path

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


EVALS_PATH = Path(__file__).parent / "evals_v2.json"
SKILL_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Code-based graders (fastest, most reliable — use first)
# ---------------------------------------------------------------------------

def grade_string_match(response: str, assertion: dict) -> tuple[bool, str]:
    """At least min_matches of the patterns must appear in the response (case-insensitive)."""
    patterns = assertion.get("patterns", [])
    min_matches = assertion.get("min_matches", 1)
    found = [p for p in patterns if p.lower() in response.lower()]
    passed = len(found) >= min_matches
    detail = f"Found {len(found)}/{min_matches} required: {found}"
    return passed, detail


def grade_string_match_all(response: str, assertion: dict) -> tuple[bool, str]:
    """ALL patterns must appear in the response."""
    patterns = assertion.get("patterns", [])
    missing = [p for p in patterns if p.lower() not in response.lower()]
    passed = len(missing) == 0
    detail = f"Missing: {missing}" if missing else "All patterns found"
    return passed, detail


def grade_string_match_all_groups(response: str, assertion: dict) -> tuple[bool, str]:
    """Each group must have at least one matching pattern."""
    groups = assertion.get("groups", [])
    results = []
    all_passed = True
    for group in groups:
        label = group.get("label", "?")
        patterns = group.get("patterns", [])
        found = [p for p in patterns if p.lower() in response.lower()]
        group_passed = len(found) > 0
        results.append(f"{label}: {'PASS' if group_passed else 'FAIL'} ({found})")
        if not group_passed:
            all_passed = False
    return all_passed, " | ".join(results)


def grade_regex_match(response: str, assertion: dict) -> tuple[bool, str]:
    """Regex pattern must match somewhere in the response."""
    pattern = assertion.get("pattern", "")
    match = re.search(pattern, response, re.IGNORECASE)
    passed = match is not None
    detail = f"Regex '{pattern}': {'matched' if passed else 'no match'}"
    return passed, detail


def grade_file_or_string(response: str, assertion: dict) -> tuple[bool, str]:
    """Check filesystem first (strongest evidence of script execution), fall back to string match."""
    file_check = assertion.get("file_check", "")
    string_patterns = assertion.get("string_patterns", [])

    if file_check:
        target = SKILL_ROOT / file_check
        if target.exists():
            return True, f"File exists: {target}"

    found = [p for p in string_patterns if p.lower() in response.lower()]
    passed = len(found) > 0
    detail = f"File '{file_check}' not found; string fallback: {found}"
    return passed, detail


CODE_GRADERS = {
    "string_match": grade_string_match,
    "string_match_all": grade_string_match_all,
    "string_match_all_groups": grade_string_match_all_groups,
    "regex_match": grade_regex_match,
    "file_or_string": grade_file_or_string,
}


# ---------------------------------------------------------------------------
# LLM-based grader (for complex quality judgements)
# Anthropic best practice: use a DIFFERENT model from the one being evaluated.
# Uses claude-haiku for speed + cost; encourages reasoning before scoring.
# ---------------------------------------------------------------------------

LLM_GRADER_SYSTEM = """You are an expert evaluator for WAF security engineering tasks.
Your job is to grade whether an AI assistant's response satisfies a specific assertion.
Be precise, strict, and technical. Do not give credit for vague or partially correct answers."""


def build_llm_grader_prompt(response: str, assertion: dict, eval_prompt: str) -> str:
    rubric = assertion.get("rubric", "No rubric provided.")
    return f"""Grade whether this assistant response satisfies the evaluation criterion below.

<eval_prompt>
{eval_prompt}
</eval_prompt>

<assistant_response>
{response[:6000]}
</assistant_response>

<grading_criterion>
{rubric}
</grading_criterion>

Think through your reasoning carefully in <thinking> tags.
Then output your verdict in <result> tags: either 'correct' or 'incorrect'.
Output nothing else after the </result> tag."""


def grade_llm(response: str, assertion: dict, eval_prompt: str = "") -> tuple[bool, str]:
    """LLM-based grading using claude-haiku as a separate grader model."""
    if not ANTHROPIC_AVAILABLE:
        return False, "ERROR: anthropic not installed (pip install anthropic --break-system-packages)"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return False, "ERROR: ANTHROPIC_API_KEY not set"

    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_llm_grader_prompt(response, assertion, eval_prompt)

    try:
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=LLM_GRADER_SYSTEM,
            messages=[{"role": "user", "content": prompt}]
        )
        full_response = msg.content[0].text

        thinking_match = re.search(r"<thinking>(.*?)</thinking>", full_response, re.DOTALL)
        result_match = re.search(r"<result>(.*?)</result>", full_response, re.DOTALL | re.IGNORECASE)

        reasoning = thinking_match.group(1).strip() if thinking_match else "(no reasoning)"
        verdict_text = result_match.group(1).strip().lower() if result_match else ""

        passed = "correct" in verdict_text and "incorrect" not in verdict_text
        detail = f"Grader: {reasoning[:300]}"
        return passed, detail

    except Exception as e:
        return False, f"LLM grader error: {e}"


# ---------------------------------------------------------------------------
# Main grading orchestrator
# ---------------------------------------------------------------------------

def load_evals() -> dict:
    with open(EVALS_PATH) as f:
        return json.load(f)


def find_eval(evals_data: dict, eval_id: int) -> dict:
    """Return the eval spec for the given eval_id."""
    for ev in evals_data["evals"]:
        if ev["id"] == eval_id:
            return ev
    raise ValueError(f"Eval {eval_id} not found in {EVALS_PATH}")


def grade_assertion(response: str, assertion: dict, eval_prompt: str = "") -> dict:
    """Grade a single assertion. Returns a result dict."""
    method = assertion.get("grading_method", "code")
    check_type = assertion.get("check", "string_match")

    if method == "llm":
        passed, detail = grade_llm(response, assertion, eval_prompt)
    elif method == "code":
        grader_fn = CODE_GRADERS.get(check_type)
        if grader_fn is None:
            passed, detail = False, f"Unknown check type: {check_type}"
        else:
            passed, detail = grader_fn(response, assertion)
    else:
        passed, detail = False, f"Unknown grading_method: {method}"

    return {
        "assertion_id": assertion["id"],
        "description": assertion["description"],
        "grading_method": method,
        "check_type": check_type if method == "code" else "llm",
        "passed": passed,
        "detail": detail,
    }


def grade_response(response: str, eval_id: int) -> dict:
    """Grade a response against all assertions for the given eval_id."""
    evals_data = load_evals()
    eval_spec = find_eval(evals_data, eval_id)

    results = []
    for assertion in eval_spec["assertions"]:
        result = grade_assertion(response, assertion, eval_spec["prompt"])
        results.append(result)

    score = sum(1 for r in results if r["passed"])
    total = len(results)

    return {
        "eval_id": eval_id,
        "name": eval_spec["name"],
        "tier": eval_spec["tier"],
        "measures": eval_spec["measures"],
        "score": score,
        "total": total,
        "pct": round(score / total * 100, 1) if total > 0 else 0,
        "assertions": results,
    }


def grade_directory(results_dir: str) -> list[dict]:
    """
    Grade all response files in a directory.
    Filename convention: <eval_id>.txt, e.g., 2.txt
    """
    results_path = Path(results_dir)
    all_results = []

    for f in sorted(results_path.glob("*.txt")):
        try:
            eval_id = int(f.stem)
        except ValueError:
            print(f"  Skipping {f.name} — filename must be <eval_id>.txt")
            continue
        try:
            response = f.read_text()
            result = grade_response(response, eval_id)
            result["source_file"] = str(f)
            all_results.append(result)
            status = "✓" if result["score"] == result["total"] else f"{result['score']}/{result['total']}"
            print(f"  {f.name}: {status}")
        except Exception as e:
            print(f"  ERROR grading {f.name}: {e}")

    return all_results


# ---------------------------------------------------------------------------
# OODA Diagnosis — maps assertion failures to SKILL.md routing gaps
# ---------------------------------------------------------------------------

# Which skill routing entries / Essential Commands each assertion tests
ASSERTION_ROUTING_MAP = {
    # eval_id -> assertion_id -> what SKILL.md entry enables it
    # Only maps [Tool discovery] and [Config] assertions — WAF logic/evasion/FP reasoning
    # failures indicate knowledge gaps, not routing gaps.
    1: {
        "A2": {"references": ["anomaly-scoring.md"], "routing": "Anomaly scoring / threshold tuning"},
        "A3": {"references": ["sampling-mode.md"], "routing": "Sampling / DetectionOnly rollout"},
        "A4": {"references": ["anomaly-scoring.md"], "routing": "Audit logging setup guidance"},
    },
    2: {
        "A4": {"commands": ["validate_rule.py"], "routing": "Essential Commands → validate_rule.py"},
    },
    3: {
        "A2": {"commands": ["lint_regex.py"], "routing": "Essential Commands → lint_regex.py"},
        "A3": {"commands": ["validate_rule.py"], "routing": "Essential Commands → validate_rule.py"},
        "A4": {"commands": ["generate_ftw_test.py"], "routing": "Essential Commands → generate_ftw_test.py"},
    },
    4: {
        "A1": {"commands": ["generate_exclusion.py"], "routing": "Essential Commands → generate_exclusion.py"},
    },
    5: {
        "A1": {"commands": ["generate_exclusion.py"], "routing": "Essential Commands → generate_exclusion.py"},
        "A4": {"commands": ["validate_rule.py"], "routing": "Essential Commands → validate_rule.py"},
    },
    6: {
        "A2": {"commands": ["analyze_log.py"], "routing": "Essential Commands → analyze_log.py"},
        "A4": {"commands": ["generate_exclusion.py"], "routing": "Essential Commands → generate_exclusion.py"},
        "A5": {"references": ["baseline-testing-tools.md"], "routing": "CRS Sandbox reference"},
    },
    7: {
        "A1": {"commands": ["new_incident.sh"], "routing": "Essential Commands → new_incident.sh"},
        "A5": {"commands": ["validate_rule.py", "generate_ftw_test.py"], "routing": "Essential Commands → validate + test"},
    },
    8: {
        "A4": {"commands": ["lint_regex.py"], "routing": "Essential Commands → lint_regex.py"},
        "A5": {"commands": ["validate_rule.py"], "routing": "Essential Commands → validate_rule.py"},
    },
    9: {
        "A1": {"commands": ["openapi_to_rules.py"], "routing": "Essential Commands → openapi_to_rules.py"},
        "A2": {"commands": ["validate_rule.py"], "routing": "Essential Commands → validate_rule.py"},
    },
}


def diagnose(results: list[dict]) -> dict:
    """
    OODA Orient+Decide: analyse failures and map them to SKILL.md improvements.
    Returns a diagnosis dict with gap analysis and suggested fixes.
    """
    failures = []
    tool_discovery_failures = []
    waf_logic_failures = []

    for r in results:
        for a in r["assertions"]:
            if a["passed"]:
                continue

            failure = {
                "eval_id": r["eval_id"],
                "eval_name": r["name"],
                "assertion_id": a["assertion_id"],
                "description": a["description"],
                "detail": a["detail"],
                "grading_method": a["grading_method"],
            }

            # Classify: tool discovery vs WAF logic/reasoning
            desc_lower = a["description"].lower()
            if "[tool discovery]" in desc_lower:
                tool_discovery_failures.append(failure)
                # Look up routing map
                routing_info = ASSERTION_ROUTING_MAP.get(r["eval_id"], {}).get(a["assertion_id"])
                if routing_info:
                    failure["skill_gap"] = routing_info
            elif any(tag in desc_lower for tag in ["[fp", "[evasion", "[regex", "[modsec", "[rule logic", "[triage"]):
                waf_logic_failures.append(failure)
            else:
                waf_logic_failures.append(failure)

            failures.append(failure)

    # Build suggestions
    suggestions = []
    missing_commands = set()
    missing_references = set()

    for f in tool_discovery_failures:
        gap = f.get("skill_gap", {})
        for cmd in gap.get("commands", []):
            missing_commands.add(cmd)
        for ref in gap.get("references", []):
            missing_references.add(ref)

    if missing_commands:
        suggestions.append({
            "type": "routing_gap",
            "action": "Add missing tools to SKILL.md Essential Commands and ensure routing table points to them",
            "tools": sorted(missing_commands),
        })
    if missing_references:
        suggestions.append({
            "type": "reference_gap",
            "action": "Ensure these references are in SKILL.md reference index with clear routing",
            "references": sorted(missing_references),
        })
    if waf_logic_failures:
        suggestions.append({
            "type": "waf_knowledge_gap",
            "action": "Review reference docs for gaps in: evasion transforms, FP scoping, rule logic",
            "failures": [f"{f['eval_name']}/{f['assertion_id']}: {f['description']}" for f in waf_logic_failures],
        })

    return {
        "total_failures": len(failures),
        "tool_discovery_failures": len(tool_discovery_failures),
        "waf_logic_failures": len(waf_logic_failures),
        "suggestions": suggestions,
        "all_failures": failures,
    }


def print_summary(results: list[dict]) -> None:
    """Print a summary table by tier."""
    if not results:
        print("No results.")
        return

    tiers = {"easy": [], "medium": [], "hard": [], "expert": []}
    for r in results:
        tiers.get(r.get("tier", "medium"), tiers["medium"]).append(r)

    total_score = sum(r["score"] for r in results)
    total_possible = sum(r["total"] for r in results)

    print("\n" + "=" * 60)
    print(f"OVERALL: {total_score}/{total_possible} = {round(total_score/total_possible*100,1)}%")
    print("=" * 60)

    for tier_name, tier_results in tiers.items():
        if not tier_results:
            continue
        s = sum(r["score"] for r in tier_results)
        t = sum(r["total"] for r in tier_results)
        print(f"\n  {tier_name.upper()}: {s}/{t} = {round(s/t*100,1) if t else 0}%")
        for r in tier_results:
            fails = [a["assertion_id"] for a in r["assertions"] if not a["passed"]]
            fail_str = f"  FAIL: {fails}" if fails else ""
            print(f"    [{r['eval_id']}] {r['name']}: {r['score']}/{r['total']}{fail_str}")

    print()


def print_diagnosis(diag: dict) -> None:
    """Print OODA diagnosis to console."""
    print("\n" + "=" * 60)
    print("DIAGNOSIS (OODA: Orient → Decide)")
    print("=" * 60)
    print(f"  Total failures: {diag['total_failures']}")
    print(f"  Tool discovery: {diag['tool_discovery_failures']}")
    print(f"  WAF logic/reasoning: {diag['waf_logic_failures']}")

    if diag["suggestions"]:
        print("\n  SUGGESTED ACTIONS:")
        for i, s in enumerate(diag["suggestions"], 1):
            print(f"\n  {i}. [{s['type']}] {s['action']}")
            if "tools" in s:
                print(f"     Tools: {', '.join(s['tools'])}")
            if "references" in s:
                print(f"     References: {', '.join(s['references'])}")
            if "failures" in s:
                for f in s["failures"][:5]:
                    print(f"     - {f}")
    else:
        print("\n  No failures — no SKILL.md changes needed.")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Grade WAF skill eval responses")
    parser.add_argument("--response", help="Response text (inline)")
    parser.add_argument("--response-file", help="Path to file containing response text")
    parser.add_argument("--eval-id", type=int, help="Eval ID (1-9)")
    parser.add_argument("--grade-all", help="Directory containing response .txt files to grade")
    parser.add_argument("--diagnose", action="store_true", help="Run OODA diagnosis on failures")
    parser.add_argument("--output", help="Write JSON results to this file")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-assertion detail")
    args = parser.parse_args()

    if args.grade_all:
        print(f"Grading all responses in {args.grade_all}...")
        results = grade_directory(args.grade_all)
        print_summary(results)
        if args.diagnose:
            diag = diagnose(results)
            print_diagnosis(diag)
        if args.output:
            out = {"results": results}
            if args.diagnose:
                out["diagnosis"] = diag
            Path(args.output).write_text(json.dumps(out, indent=2))
            print(f"Results written to {args.output}")
        return

    if not args.eval_id:
        parser.error("--eval-id required unless using --grade-all")

    if args.response_file:
        response = Path(args.response_file).read_text()
    elif args.response:
        response = args.response
    else:
        print("Reading response from stdin...")
        response = sys.stdin.read()

    result = grade_response(response, args.eval_id)

    print(f"\nEval {args.eval_id} — {result['name']} ({result['tier']})")
    print(f"Score: {result['score']}/{result['total']} = {result['pct']}%")
    print(f"Measures: {result['measures']}\n")

    for a in result["assertions"]:
        status = "✓" if a["passed"] else "✗"
        print(f"  {status} [{a['grading_method']}] {a['assertion_id']}: {a['description']}")
        if not args.quiet or not a["passed"]:
            print(f"      → {a['detail']}")

    if args.diagnose:
        diag = diagnose([result])
        if diag["total_failures"] > 0:
            print_diagnosis(diag)

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(f"\nResult written to {args.output}")


if __name__ == "__main__":
    main()
