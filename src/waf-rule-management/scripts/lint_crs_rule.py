#!/usr/bin/env python3
"""
Lint ModSecurity rules for CRS convention compliance.
For custom rules (100000-199999). For full CRS repo, use crs-linter.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Tuple


def parse_args():
    parser = argparse.ArgumentParser(
        description="Lint ModSecurity rules for CRS conventions. Use crs-linter for full CRS repo."
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
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--custom-range",
        default="100000-199999",
        help="Expected rule ID range for custom rules (default: 100000-199999)",
    )
    return parser.parse_args()


CRS_RESERVED_RANGES = [
    (920000, 920999),
    (921000, 921999),
    (930000, 930999),
    (931000, 931999),
    (932000, 932999),
    (933000, 933999),
    (934000, 934999),
    (941000, 941999),
    (942000, 942999),
    (943000, 943999),
    (944000, 944999),
]


def parse_custom_range(s: str) -> Tuple[int, int]:
    lo, hi = s.split("-")
    return int(lo), int(hi)


def lint_file(path: Path, custom_lo: int, custom_hi: int) -> dict:
    """Lint a rule file for CRS conventions."""
    report = {"file": str(path), "violations": []}

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        report["violations"].append({
            "line": 0,
            "rule": "file_read",
            "message": str(e),
        })
        return report

    # Extract rule IDs
    id_re = re.compile(r"id\s*:\s*(\d+)", re.IGNORECASE)
    # Check for required tags in CRS-style rules
    tag_re = re.compile(r"tag\s*:\s*['\"]?([^'\"\\]+)['\"]?", re.IGNORECASE)
    ver_re = re.compile(r"ver\s*:\s*['\"]?([^'\"\\]+)['\"]?", re.IGNORECASE)

    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Rule ID range check
        for m in id_re.finditer(line):
            rid = int(m.group(1))
            if rid < 100000 or rid > 999999:
                report["violations"].append({
                    "line": i,
                    "rule": "id_range",
                    "message": f"Rule ID {rid} outside valid range (100000-999999)",
                })
            elif any(lo <= rid <= hi for lo, hi in CRS_RESERVED_RANGES):
                report["violations"].append({
                    "line": i,
                    "rule": "id_reserved",
                    "message": f"Rule ID {rid} is in CRS reserved range. Use {custom_lo}-{custom_hi} for custom rules.",
                })
            elif rid < custom_lo or rid > custom_hi:
                report["violations"].append({
                    "line": i,
                    "rule": "id_custom_range",
                    "message": f"Custom rule ID {rid} outside recommended range {custom_lo}-{custom_hi}",
                })

        # Operator case (CRS requires @beginsWith not @beginswith)
        if "@beginswith" in line.lower() and "@beginsWith" not in line:
            report["violations"].append({
                "line": i,
                "rule": "operator_case",
                "message": "Use @beginsWith (camelCase) not @beginswith",
            })

        # Severity when setting anomaly score
        if "setvar:" in line and "inbound_anomaly" in line and "severity:" not in line:
            report["violations"].append({
                "line": i,
                "rule": "severity_required",
                "message": "Rules setting anomaly score should include severity: action",
            })

    return report


def main():
    args = parse_args()
    custom_lo, custom_hi = parse_custom_range(args.custom_range)

    results = []
    for f in args.files:
        if not f.exists():
            print(f"Error: File not found: {f}", file=sys.stderr)
            sys.exit(1)
        results.append(lint_file(f, custom_lo, custom_hi))

    output = {
        "passed": all(len(r["violations"]) == 0 for r in results),
        "results": results,
    }

    if args.output == "json":
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            print(f"\n{r['file']}: {len(r['violations'])} violation(s)")
            for v in r["violations"]:
                print(f"  L{v.get('line', '?')} [{v.get('rule', '')}]: {v.get('message', '')}")

    sys.exit(0 if output["passed"] else 1)


if __name__ == "__main__":
    main()
