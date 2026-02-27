#!/usr/bin/env python3
"""
Validate ModSecurity/CRS exclusions against tuning best practices.

The validator supports:
- Direct validation from CLI flags
- Validation from an exclusion config file
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate exclusion safety and CRS tuning best practices."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional exclusion file to validate.",
    )
    parser.add_argument(
        "--rule-id",
        default="",
        help="Rule ID being excluded (used when --input is not provided).",
    )
    parser.add_argument(
        "--uri",
        default="/",
        help="URI scope (default: /).",
    )
    parser.add_argument(
        "--param",
        default="",
        help="Variable target (example: ARGS:q). Empty means full rule exclusion.",
    )
    parser.add_argument(
        "--type",
        choices=["runtime", "configure"],
        default="runtime",
        help="Exclusion type.",
    )
    parser.add_argument(
        "--exclude-by",
        choices=["id", "tag"],
        default="id",
        help="Whether exclusion is done by rule id or tag.",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    return parser.parse_args()


def make_finding(severity: str, code: str, message: str, recommendation: str) -> Dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "recommendation": recommendation,
    }


def validate_exclusion(
    exclusion_type: str, exclude_by: str, uri: str, param: str, scope: str
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    uri = uri.strip() or "/"
    param = param.strip()

    if param and ":" not in param:
        findings.append(
            make_finding(
                "error",
                "invalid-param-format",
                "Parameter scope must include variable collection and key (example: ARGS:q).",
                "Use explicit scope such as ARGS:name or REQUEST_HEADERS:User-Agent.",
            )
        )

    if scope == "rule" and uri == "/":
        findings.append(
            make_finding(
                "error",
                "global-rule-removal",
                "Whole-rule exclusion is globally scoped.",
                "Narrow by URI and/or use target exclusion before removing entire rules.",
            )
        )
    elif scope == "rule":
        findings.append(
            make_finding(
                "warning",
                "whole-rule-removal",
                "Whole-rule exclusion removes protection for a route segment.",
                "Prefer target exclusion where feasible to preserve detection coverage.",
            )
        )

    if exclude_by == "tag":
        findings.append(
            make_finding(
                "warning",
                "tag-exclusion-broadness",
                "Tag-based exclusion can disable many related rules.",
                "Prefer exclude-by id unless you intentionally need category-wide tuning.",
            )
        )

    if exclusion_type == "configure":
        findings.append(
            make_finding(
                "info",
                "placement-configure",
                "Configure-time exclusions must be loaded after CRS includes.",
                "Place SecRuleRemove*/SecRuleUpdateTarget* after CRS rule include directives.",
            )
        )
    else:
        findings.append(
            make_finding(
                "info",
                "placement-runtime",
                "Runtime exclusions must be loaded before CRS includes.",
                "Place ctl:* exclusion rules before CRS rule include directives.",
            )
        )

    if param and uri == "/":
        findings.append(
            make_finding(
                "warning",
                "global-target-scope",
                "Target exclusion is still global because URI scope is '/'.",
                "Add URI scoping when possible to reduce blast radius.",
            )
        )

    if scope == "target" and param:
        findings.append(
            make_finding(
                "info",
                "target-exclusion-good",
                "Target-level exclusion follows the narrowest-scope tuning strategy.",
                "Retest with FP and attack payloads to confirm behavior.",
            )
        )

    return findings


def parse_exclusions_from_file(path: Path) -> List[Dict[str, str]]:
    exclusions: List[Dict[str, str]] = []
    content = path.read_text(encoding="utf-8", errors="replace")
    current_uri = "/"

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        uri_match = re.search(r"@beginsWith\s+(\S+)", stripped)
        if uri_match:
            current_uri = uri_match.group(1)

        # Runtime exclusions
        m_runtime_id = re.search(r"ctl:ruleRemoveById=([0-9\-]+)", stripped)
        if m_runtime_id:
            exclusions.append(
                {
                    "type": "runtime",
                    "exclude_by": "id",
                    "scope": "rule",
                    "rule_id": m_runtime_id.group(1),
                    "uri": current_uri,
                    "param": "",
                }
            )
            continue

        m_runtime_tag = re.search(r"ctl:ruleRemoveByTag=([^,\"]+)", stripped)
        if m_runtime_tag:
            exclusions.append(
                {
                    "type": "runtime",
                    "exclude_by": "tag",
                    "scope": "rule",
                    "rule_id": "",
                    "uri": current_uri,
                    "param": "",
                }
            )
            continue

        m_runtime_target_id = re.search(r"ctl:ruleRemoveTargetById=([0-9\-]+);([^,\"]+)", stripped)
        if m_runtime_target_id:
            exclusions.append(
                {
                    "type": "runtime",
                    "exclude_by": "id",
                    "scope": "target",
                    "rule_id": m_runtime_target_id.group(1),
                    "uri": current_uri,
                    "param": m_runtime_target_id.group(2),
                }
            )
            continue

        m_runtime_target_tag = re.search(r"ctl:ruleRemoveTargetByTag=([^;]+);([^,\"]+)", stripped)
        if m_runtime_target_tag:
            exclusions.append(
                {
                    "type": "runtime",
                    "exclude_by": "tag",
                    "scope": "target",
                    "rule_id": "",
                    "uri": current_uri,
                    "param": m_runtime_target_tag.group(2),
                }
            )
            continue

        # Configure-time exclusions
        m_remove_id = re.search(r"SecRuleRemoveById\s+([0-9\-]+)", stripped)
        if m_remove_id:
            exclusions.append(
                {
                    "type": "configure",
                    "exclude_by": "id",
                    "scope": "rule",
                    "rule_id": m_remove_id.group(1),
                    "uri": "/",
                    "param": "",
                }
            )
            continue

        m_remove_tag = re.search(r"SecRuleRemoveByTag\s+(.+)$", stripped)
        if m_remove_tag:
            exclusions.append(
                {
                    "type": "configure",
                    "exclude_by": "tag",
                    "scope": "rule",
                    "rule_id": "",
                    "uri": "/",
                    "param": "",
                }
            )
            continue

        m_update_target_id = re.search(r"SecRuleUpdateTargetById\s+([0-9\-]+)\s+\"?!([^\"\s]+)\"?", stripped)
        if m_update_target_id:
            target = m_update_target_id.group(2)
            if target.startswith("!"):
                target = target[1:]
            exclusions.append(
                {
                    "type": "configure",
                    "exclude_by": "id",
                    "scope": "target",
                    "rule_id": m_update_target_id.group(1),
                    "uri": "/",
                    "param": target,
                }
            )
            continue

        m_update_target_tag = re.search(r"SecRuleUpdateTargetByTag\s+([^\s]+)\s+\"?!([^\"\s]+)\"?", stripped)
        if m_update_target_tag:
            target = m_update_target_tag.group(2)
            if target.startswith("!"):
                target = target[1:]
            exclusions.append(
                {
                    "type": "configure",
                    "exclude_by": "tag",
                    "scope": "target",
                    "rule_id": "",
                    "uri": "/",
                    "param": target,
                }
            )
            continue

    return exclusions


def format_text(report: Dict[str, object]) -> str:
    lines = []
    lines.append(f"Validated exclusions: {report['summary']['checked']}")
    lines.append(f"Errors: {report['summary']['errors']}, Warnings: {report['summary']['warnings']}")
    lines.append("")

    for item in report["results"]:
        hdr = (
            f"- [{item['index']}] type={item['exclusion']['type']}, "
            f"scope={item['exclusion']['scope']}, by={item['exclusion']['exclude_by']}, "
            f"rule={item['exclusion']['rule_id'] or 'n/a'}, "
            f"uri={item['exclusion']['uri']}, param={item['exclusion']['param'] or 'n/a'}"
        )
        lines.append(hdr)
        for finding in item["findings"]:
            lines.append(
                f"  - {finding['severity'].upper()} {finding['code']}: "
                f"{finding['message']} -> {finding['recommendation']}"
            )
    return "\n".join(lines)


def main():
    args = parse_args()
    if args.input and not args.input.exists():
        print(f"Error: exclusion file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if args.input:
        exclusions = parse_exclusions_from_file(args.input)
    else:
        scope = "target" if args.param.strip() else "rule"
        exclusions = [
            {
                "type": args.type,
                "exclude_by": args.exclude_by,
                "scope": scope,
                "rule_id": args.rule_id,
                "uri": args.uri,
                "param": args.param,
            }
        ]

    results = []
    errors = 0
    warnings = 0
    for idx, exclusion in enumerate(exclusions, start=1):
        findings = validate_exclusion(
            exclusion["type"],
            exclusion["exclude_by"],
            exclusion["uri"],
            exclusion["param"],
            exclusion["scope"],
        )
        errors += sum(1 for finding in findings if finding["severity"] == "error")
        warnings += sum(1 for finding in findings if finding["severity"] == "warning")
        results.append({"index": idx, "exclusion": exclusion, "findings": findings})

    report: Dict[str, object] = {
        "ok": errors == 0,
        "summary": {
            "checked": len(exclusions),
            "errors": errors,
            "warnings": warnings,
        },
        "results": results,
    }

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_text(report))

    if errors > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
