#!/usr/bin/env python3
"""
Generate rule exclusion from false positive pattern.
Outputs runtime (before CRS) or configure-time (after CRS) exclusion.
"""
import argparse
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ModSec rule exclusion for false positive tuning."
    )
    parser.add_argument(
        "--rule-id",
        required=True,
        help="CRS rule ID to exclude (e.g. 942100)",
    )
    parser.add_argument(
        "--uri",
        default="",
        help="URI prefix to scope exclusion (e.g. /api/search). Empty = global.",
    )
    parser.add_argument(
        "--param",
        default="",
        help="Variable to remove from rule target (e.g. ARGS:q). Empty = entire rule.",
    )
    parser.add_argument(
        "--type",
        choices=["runtime", "configure"],
        default="runtime",
        help="runtime=before CRS (ctl), configure=after CRS (SecRuleUpdateTargetById)",
    )
    parser.add_argument(
        "--id",
        type=int,
        default=0,
        help="Rule ID for the exclusion rule itself (e.g. 100100). "
             "Must be unique per exclusion. 0 = auto-generate placeholder.",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file (default: stdout)",
    )
    return parser.parse_args()


def generate_runtime_exclusion(rule_id: str, uri: str, param: str, excl_id: int) -> str:
    """Generate runtime exclusion (goes BEFORE CRS include)."""
    id_str = str(excl_id) if excl_id else "CHANGE_ME"
    id_note = "" if excl_id else "  # ← assign a unique ID in your custom range"
    if param:
        # Remove specific variable from rule
        return f'''# Runtime exclusion: remove {param} from rule {rule_id}
SecRule REQUEST_URI "@beginsWith {uri or '/'}" \\
    "id:{id_str},\\{id_note}
    phase:1,\\
    pass,\\
    nolog,\\
    ctl:ruleRemoveTargetById={rule_id};{param}"
'''
    else:
        # Remove entire rule
        return f'''# Runtime exclusion: disable rule {rule_id}
SecRule REQUEST_URI "@beginsWith {uri or '/'}" \\
    "id:{id_str},\\{id_note}
    phase:1,\\
    pass,\\
    nolog,\\
    ctl:ruleRemoveById={rule_id}"
'''


def generate_configure_exclusion(rule_id: str, param: str) -> str:
    """Generate configure-time exclusion (goes AFTER CRS include)."""
    if param:
        return f'''# Configure-time exclusion: remove {param} from rule {rule_id}
SecRuleUpdateTargetById {rule_id} "!{param}"
'''
    else:
        return f'''# Configure-time exclusion: disable rule {rule_id} globally
SecRuleRemoveById {rule_id}
'''


def main():
    args = parse_args()
    uri = args.uri.strip() or "/"
    param = args.param.strip()
    if param and ":" not in param:
        print("Error: --param must include variable scope (example: ARGS:q, REQUEST_HEADERS:User-Agent)", file=sys.stderr)
        sys.exit(1)

    if args.type == "runtime":
        output = generate_runtime_exclusion(args.rule_id, uri, param, args.id)
    else:
        if uri != "/" and not param:
            print("Warning: --uri is ignored for configure-time full rule exclusion", file=sys.stderr)
        output = generate_configure_exclusion(args.rule_id, param)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
