#!/usr/bin/env python3
"""
Lint @rx patterns in ModSecurity rules for ReDoS risks, performance, and effectiveness.
Outputs warnings and suggestions. Use alongside validate_rule.py and lint_crs_rule.py.
"""
import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple


# ReDoS-prone patterns (simplified heuristics; not exhaustive)
REDOS_PATTERNS = [
    (r"\(\w+\+\)\+", "Nested quantifier: (x+)+ can cause catastrophic backtracking"),
    (r"\(\w+\*\)\+", "Nested quantifier: (x*)+ can cause catastrophic backtracking"),
    (r"\(\w+\+\)\*", "Nested quantifier: (x+)* can cause catastrophic backtracking"),
    (r"\(\?\w*\)[\+\*]", "Quantifier on group (e.g. (?:a)+) - verify no nested overlap"),
    (r"\.\*\.\*", "Double greedy .* - consider anchoring or narrowing"),
    (r"\(\[\^[^\]]+\]\+\?\)\+", "Repeated optional character class - potential ReDoS"),
    (r"\(\w+\|\w+\+\)", "Alternation with quantifier overlap (e.g. (a|ab))"),
]

# Performance hints
PERF_HINTS = [
    (r"@rx\s+[\"']\^?(?:[a-zA-Z0-9_-]+\|)+[a-zA-Z0-9_-]+[\"']", "Consider @pm for word list"),
    (r"@rx\s+[\"']\^[^$*+?{\[]+\$[\"']", "Exact match? Consider @streq"),
    (r"@rx\s+[\"']\^/[^$*+?{\[]+[\"']", "Path prefix? Consider @beginsWith"),
]

# Unnecessary capture groups (use (?:...) instead)
CAPTURE_HINT = re.compile(r"@rx\s+[\"']([^\"']*?)\((?!\?)[^)]+\)([^\"']*)[\"']")


def extract_rx_patterns(content: str, path: Path) -> List[Tuple[int, str, str]]:
    """Extract @rx patterns with line numbers. Returns [(line_no, full_match, pattern), ...]"""
    results = []
    # SecRule VAR "@rx /pattern/" or "@rx pattern" "actions"
    # 1) Slash-delimited: @rx /pattern/
    slash_re = re.compile(r"@rx\s+/([^/]+)/", re.MULTILINE)
    for m in slash_re.finditer(content):
        pattern = m.group(1).replace("\\/", "/")
        line_no = content[: m.start()].count("\n") + 1
        results.append((line_no, m.group(0), pattern))
    # 2) Quote-delimited: @rx "pattern" or @rx 'pattern'
    quote_re = re.compile(
        r'@rx\s+(["\'])((?:(?!\1).|\\.)*)\1',
        re.MULTILINE | re.DOTALL,
    )
    for m in quote_re.finditer(content):
        pattern = m.group(2).replace("\\'", "'").replace('\\"', '"')
        line_no = content[: m.start()].count("\n") + 1
        full = m.group(0)
        # Avoid double-counting if slash pattern was already found
        if not any(r[1] == full for r in results):
            results.append((line_no, full, pattern))
    return results


def check_redos(pattern: str) -> List[str]:
    """Check for ReDoS-prone patterns. Returns list of warning messages."""
    warnings = []
    for pat, msg in REDOS_PATTERNS:
        if re.search(pat, pattern):
            warnings.append(msg)
    return warnings


def check_perf(pattern: str, full_match: str) -> List[str]:
    """Check for performance improvement opportunities."""
    hints = []
    for pat, msg in PERF_HINTS:
        if re.search(pat, full_match):
            hints.append(msg)
    if CAPTURE_HINT.search(full_match):
        hints.append("Unnecessary capture group? Use (?:...) for non-capturing")
    return hints


def check_transforms(rule_block: str) -> List[str]:
    """Check transform usage in rule. Returns hints."""
    hints = []
    # Only suggest t:urlDecodeUni when rule targets ARGS (variable list after SecRule)
    var_match = re.search(r"SecRule\s+([\w|:.]+)\s+", rule_block)
    targets_args = var_match and "ARGS" in var_match.group(1)
    if targets_args and "t:urlDecodeUni" not in rule_block and "@rx" in rule_block:
        hints.append("ARGS with @rx: consider t:urlDecodeUni (attackers encode payloads)")
    if "t:lowercase" not in rule_block and "(?i)" in rule_block:
        hints.append("Case-insensitive @rx: consider t:lowercase instead of (?i)")
    return hints


def lint_file(path: Path, verbose: bool) -> dict:
    """Lint a rule file. Returns report dict."""
    content = path.read_text(errors="replace")
    patterns = extract_rx_patterns(content, path)
    report = {
        "file": str(path),
        "rx_count": len(patterns),
        "warnings": [],
        "hints": [],
    }
    lines = content.splitlines()
    for line_no, full_match, pattern in patterns:
        prefix = f"{path}:{line_no}: "
        for w in check_redos(pattern):
            report["warnings"].append(f"{prefix}ReDoS risk: {w}")
        for h in check_perf(pattern, full_match):
            report["hints"].append(f"{prefix}Performance: {h}")
        # Get rule block: from rule start (SecRule) to end of actions
        start = line_no - 1
        while start > 0 and not lines[start - 1].strip().startswith("SecRule"):
            start -= 1
        end = line_no
        while end < len(lines) and (lines[end - 1].strip().endswith("\\") or "SecRule" not in lines[end - 1]):
            end += 1
            if end > line_no + 5:
                break
        block = "\n".join(lines[max(0, start) : min(len(lines), end)])
        for h in check_transforms(block):
            report["hints"].append(f"{path}:{line_no}: Transform: {h}")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Lint @rx patterns for ReDoS risks, performance, and effectiveness."
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Path(s) to .conf rule file(s)",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show hints (performance suggestions) in addition to warnings",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any warnings (ReDoS risks) found",
    )
    args = parser.parse_args()

    all_reports = []
    for f in args.files:
        if not f.exists():
            print(f"Error: {f} not found", file=sys.stderr)
            sys.exit(1)
        all_reports.append(lint_file(f, args.verbose))

    has_warnings = any(r["warnings"] for r in all_reports)

    if args.output == "json":
        import json
        out = {
            "reports": all_reports,
            "summary": {
                "files": len(all_reports),
                "warnings": sum(len(r["warnings"]) for r in all_reports),
                "hints": sum(len(r["hints"]) for r in all_reports),
            },
        }
        print(json.dumps(out, indent=2))
    else:
        for r in all_reports:
            if r["warnings"] or (args.verbose and r["hints"]):
                print(f"\n{r['file']} ({r['rx_count']} @rx pattern(s))")
            for w in r["warnings"]:
                print(f"  WARN: {w}")
            if args.verbose:
                for h in r["hints"]:
                    print(f"  HINT: {h}")
        if all_reports and (has_warnings or (args.verbose and any(r["hints"] for r in all_reports))):
            print()

    if args.strict and has_warnings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
