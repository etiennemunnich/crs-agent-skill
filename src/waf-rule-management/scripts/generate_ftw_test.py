#!/usr/bin/env python3
"""
Generate go-ftw test YAML skeleton from a SecRule .conf file.
Extracts rule IDs and creates pass/fail test stubs compatible with go-ftw v2.x.

Output format follows go-ftw requirements:
  - Top-level `rule_id` field (required)
  - `test_title` for each test (not test_id)
  - `Host` header in all inputs (nginx requires it)
  - `output.status` for cloud-mode assertion (no log-based checks)
  - One file per rule ID (generated separately)
"""
import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate go-ftw test YAML from SecRule .conf file (go-ftw v2 format)."
    )
    parser.add_argument(
        "rulefile",
        type=Path,
        help="Path to .conf rule file",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output YAML file or directory. If directory, creates one file per rule ID. "
             "If file, creates a single file for the first rule ID. (default: stdout)",
    )
    parser.add_argument(
        "-i", "--rule-ids",
        type=str,
        default="",
        help="Comma-separated rule IDs to test (default: extract from file)",
    )
    parser.add_argument(
        "--block-status",
        type=int,
        default=403,
        help="Expected HTTP status for blocked requests (default: 403)",
    )
    parser.add_argument(
        "--pass-status",
        type=int,
        default=200,
        help="Expected HTTP status for passed requests (default: 200)",
    )
    return parser.parse_args()


def extract_rule_ids(content: str) -> List[str]:
    """Extract rule IDs from .conf content."""
    ids = re.findall(r"id\s*:\s*(\d+)", content, re.IGNORECASE)
    return sorted(set(ids), key=int)


def generate_test_yaml(rule_id: str, block_status: int, pass_status: int) -> str:
    """Generate go-ftw v2 test YAML for a single rule."""
    return f"""meta:
  author: "generated"
  enabled: true
  name: "{rule_id}.yaml"
  description: "Tests for rule {rule_id}"
rule_id: {rule_id}
tests:
  - test_title: "{rule_id}-1-attack"
    stages:
      - input:
          method: "GET"
          uri: "/?payload=TODO_REPLACE_WITH_ATTACK"
          headers:
            Host: "localhost"
            User-Agent: "go-ftw/test"
        output:
          status: {block_status}

  - test_title: "{rule_id}-2-benign"
    stages:
      - input:
          method: "GET"
          uri: "/?normal=value"
          headers:
            Host: "localhost"
            User-Agent: "go-ftw/test"
        output:
          status: {pass_status}
"""


def main():
    args = parse_args()
    if not args.rulefile.exists():
        print(f"Error: File not found: {args.rulefile}", file=sys.stderr)
        sys.exit(1)

    content = args.rulefile.read_text(encoding="utf-8", errors="replace")
    rule_ids = extract_rule_ids(content)

    if args.rule_ids:
        rule_ids = [r.strip() for r in args.rule_ids.split(",") if r.strip()]

    if not rule_ids:
        print("Error: No rule IDs found. Use -i to specify IDs.", file=sys.stderr)
        sys.exit(1)

    if args.output and args.output.is_dir():
        # Directory mode: one file per rule ID
        for rid in rule_ids:
            yaml_content = generate_test_yaml(rid, args.block_status, args.pass_status)
            out_path = args.output / f"{rid}.yaml"
            out_path.write_text(yaml_content, encoding="utf-8")
            print(f"Wrote {out_path}", file=sys.stderr)
    elif args.output:
        # Single file mode: first rule ID
        rid = rule_ids[0]
        yaml_content = generate_test_yaml(rid, args.block_status, args.pass_status)
        args.output.write_text(yaml_content, encoding="utf-8")
        print(f"Wrote {args.output} (rule {rid})", file=sys.stderr)
        if len(rule_ids) > 1:
            print(f"Note: {len(rule_ids) - 1} additional rule(s) skipped. "
                  f"Use -o <directory> to generate one file per rule.", file=sys.stderr)
    else:
        # stdout mode: all rules, separated by ---
        for i, rid in enumerate(rule_ids):
            if i > 0:
                print("---")
            print(generate_test_yaml(rid, args.block_status, args.pass_status))


if __name__ == "__main__":
    main()
