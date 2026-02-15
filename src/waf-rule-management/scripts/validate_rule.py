#!/usr/bin/env python3
"""
Validate ModSecurity SecRule/SecAction syntax.
Uses crslang (https://github.com/coreruleset/crslang) when available for accurate parsing.
Uses official legacy ModSecurity rules-check tools when available.
Falls back to regex-based validation only when parser tools are unavailable.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate ModSecurity SecRule/SecAction syntax. Outputs JSON report."
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
        "--no-crslang",
        action="store_true",
        help="Skip crslang validation",
    )
    parser.add_argument(
        "--no-legacy",
        action="store_true",
        help="Skip legacy ModSecurity rules-check validation",
    )
    return parser.parse_args()


def validate_with_crslang(path: Path) -> tuple:
    # Returns (valid|None, errors). None = crslang not available
    """Use crslang for validation when available. Returns (valid, errors). None = not available."""
    crslang = shutil.which("crslang")
    if not crslang:
        return None, []

    try:
        with tempfile.TemporaryDirectory(prefix="crslang_validate_") as tmpdir:
            result = subprocess.run(
                [crslang, "-o", tmpdir, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        if result.returncode == 0:
            return True, []
        return False, [{"line": 0, "severity": "error", "message": result.stderr.strip() or "crslang parse failed"}]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, []


def get_legacy_validator() -> str:
    """
    Return an installed official legacy validator executable name/path.
    Common names:
      - modsec-rules-check (packaged libmodsecurity tool)
      - rules-check (tool from ModSecurity source tree)
    """
    for name in ("modsec-rules-check", "rules-check"):
        exe = shutil.which(name)
        if exe:
            return exe
    return ""


def validate_with_legacy_tool(path: Path) -> tuple:
    # Returns (valid|None, errors, validator_name). None = tool not available
    validator = get_legacy_validator()
    if not validator:
        return None, [], ""

    try:
        result = subprocess.run(
            [validator, str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, [], Path(validator).name
        message = (result.stderr or result.stdout or "").strip()
        if not message:
            message = f"{Path(validator).name} validation failed"
        return (
            False,
            [{"line": 0, "severity": "error", "message": message}],
            Path(validator).name,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, [], ""


# SecRule: SecRule VARIABLE "OPERATOR pattern" "ACTIONS"
# SecAction: SecAction "ACTIONS"
# SecRuleUpdateTargetById: SecRuleUpdateTargetById ID "!VAR"
SECRULE_RE = re.compile(
    r"^\s*SecRule\s+"
    r"([^\s\"']+)\s+"  # variable
    r"([\"'])([^\"']*)\2\s+"  # operator + pattern (quoted)
    r"([\"'])(.*)\4\s*$",  # actions (quoted, may span continuation)
    re.MULTILINE | re.DOTALL,
)
SECACTION_RE = re.compile(
    r"^\s*SecAction\s+"
    r"([\"'])(.*)\1\s*$",
    re.MULTILINE | re.DOTALL,
)
SECRULEUPDATE_RE = re.compile(
    r"^\s*SecRuleUpdateTargetById\s+(\d+)\s+([\"'])([^\"']+)\2\s*$",
    re.MULTILINE,
)


def validate_rule_line(line: str, line_num: int) -> List[Dict]:
    """Validate a single rule line, return list of issues."""
    issues = []
    stripped = line.strip()

    # Skip comments and empty
    if not stripped or stripped.startswith("#"):
        return issues

    # SecRule
    if stripped.startswith("SecRule "):
        m = SECRULE_RE.match(stripped)
        if not m:
            # Check for line continuation (backslash at end)
            if stripped.rstrip().endswith("\\"):
                return issues  # Multi-line, skip simple check
            issues.append({
                "line": line_num,
                "severity": "error",
                "message": "Invalid SecRule syntax. Expected: SecRule VARIABLE \"@OPERATOR pattern\" \"ACTIONS\"",
            })
        else:
            var, op_pattern, actions = m.group(1), m.group(3), m.group(5)
            if not op_pattern.strip().startswith("@"):
                issues.append({
                    "line": line_num,
                    "severity": "warning",
                    "message": "Operator should start with @ (e.g. @rx, @pm)",
                })
            # Check for id in actions
            if "id:" not in actions and "id:" not in line:
                issues.append({
                    "line": line_num,
                    "severity": "warning",
                    "message": "SecRule should include id: action",
                })

    # SecAction
    elif stripped.startswith("SecAction "):
        if not SECACTION_RE.match(stripped):
            issues.append({
                "line": line_num,
                "severity": "error",
                "message": "Invalid SecAction syntax. Expected: SecAction \"ACTIONS\"",
            })

    # SecRuleUpdateTargetById
    elif stripped.startswith("SecRuleUpdateTargetById "):
        if not SECRULEUPDATE_RE.match(stripped):
            issues.append({
                "line": line_num,
                "severity": "error",
                "message": "Invalid SecRuleUpdateTargetById syntax",
            })

    return issues


def validate_file(path: Path, use_crslang: bool = True, use_legacy: bool = True) -> dict:
    """Validate a rule file, return report dict."""
    report = {"file": str(path), "valid": True, "errors": [], "warnings": [], "validator": "regex"}

    # Prefer parser-based validation:
    # 1) crslang
    # 2) official legacy ModSecurity rules-check
    # If neither available, fall back to regex heuristics.
    parser_validators_used = []

    if use_crslang:
        crslang_result, crslang_errors = validate_with_crslang(path)
        if crslang_result is not None:
            parser_validators_used.append("crslang")
            if not crslang_result:
                report["errors"].extend(crslang_errors)
                report["validator"] = "crslang"
                report["valid"] = False
                return report
        else:
            report["warnings"].append({
                "line": 0,
                "severity": "warning",
                "message": "crslang not found; continuing with other validators",
            })

    if use_legacy:
        legacy_result, legacy_errors, legacy_name = validate_with_legacy_tool(path)
        if legacy_result is not None:
            parser_validators_used.append(legacy_name)
            if not legacy_result:
                report["errors"].extend(legacy_errors)
                report["validator"] = "+".join(parser_validators_used) if parser_validators_used else legacy_name
                report["valid"] = False
                return report
        else:
            report["warnings"].append({
                "line": 0,
                "severity": "warning",
                "message": "legacy ModSecurity rules-check tool not found; continuing",
            })

    # If at least one parser validator passed, accept parser result.
    if parser_validators_used:
        report["validator"] = "+".join(parser_validators_used)
        report["valid"] = True
        return report

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        report["valid"] = False
        report["errors"].append({"line": 0, "message": f"Could not read file: {e}"})
        return report

    # Handle line continuations
    lines = []
    current = []
    for line in content.split("\n"):
        if current:
            current.append(line)
            if not line.rstrip().endswith("\\"):
                lines.append("\n".join(current))
                current = []
        else:
            if line.rstrip().endswith("\\"):
                current = [line]
            else:
                lines.append(line)

    if current:
        lines.append("\n".join(current))

    for i, line in enumerate(lines, 1):
        for issue in validate_rule_line(line, i):
            if issue["severity"] == "error":
                report["errors"].append(issue)
            else:
                report["warnings"].append(issue)

    report["valid"] = len(report["errors"]) == 0
    return report


def main():
    args = parse_args()
    results = []

    for f in args.files:
        if not f.exists():
            print(f"Error: File not found: {f}", file=sys.stderr)
            sys.exit(1)
        results.append(
            validate_file(
                f,
                use_crslang=not args.no_crslang,
                use_legacy=not args.no_legacy,
            )
        )

    output = {
        "valid": all(r["valid"] for r in results),
        "results": results,
    }

    if args.output == "json":
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            print(f"\n{r['file']}: {'VALID' if r['valid'] else 'INVALID'}")
            for e in r["errors"]:
                print(f"  ERROR L{e.get('line', '?')}: {e.get('message', '')}")
            for w in r["warnings"]:
                print(f"  WARN  L{w.get('line', '?')}: {w.get('message', '')}")

    sys.exit(0 if output["valid"] else 1)


if __name__ == "__main__":
    main()
