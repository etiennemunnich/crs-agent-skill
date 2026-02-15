#!/usr/bin/env python3
"""
Parse ModSecurity audit log and extract rule triggers, patterns, FP candidates.
Supports JSON and Native (sectioned) audit log formats.
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse ModSecurity audit log, extract rule triggers and patterns."
    )
    parser.add_argument(
        "logfile",
        type=Path,
        help="Audit log file (JSON or Native format)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary: total transactions, unique rules, top rules",
    )
    parser.add_argument(
        "--top-rules",
        type=int,
        default=0,
        metavar="N",
        help="Print top N most triggered rules",
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        default="",
        help="Filter by rule ID (e.g. 942100)",
    )
    parser.add_argument(
        "--detail",
        action="store_true",
        help="Show detailed matches for --rule-id",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["json", "text"],
        default="text",
        help="Output format",
    )
    return parser.parse_args()


def parse_json_log(path: Path) -> List[Dict]:
    """Parse JSON audit log. May be one JSON object per line or array."""
    entries = []
    content = path.read_text(encoding="utf-8", errors="replace")

    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            entries.append(obj)
        except json.JSONDecodeError:
            pass
    return entries


def parse_native_log(path: Path) -> List[Dict]:
    """Parse Native (sectioned) audit log format.

    Native format uses section boundaries like:
      --xxxxxxxx-A--   (start of transaction, section A)
      --xxxxxxxx-B--   (section B: request headers)
      --xxxxxxxx-H--   (section H: audit log trailer / rule matches)
      --xxxxxxxx-Z--   (end of transaction)

    Each transaction spans from the A-section marker to the Z-section marker.
    We accumulate all sections into a single dict per transaction.
    """
    entries = []  # type: List[Dict]
    content = path.read_text(encoding="utf-8", errors="replace")
    current = {}  # type: Dict
    current_section = ""  # single-letter section ID (A, B, C, ...)

    # Section boundary pattern: --<hex>-<LETTER>--
    section_re = re.compile(r"^--[0-9a-fA-F]+-([A-Z])--$")

    for line in content.split("\n"):
        m = section_re.match(line.strip())
        if m:
            section_letter = m.group(1)
            if section_letter == "A":
                # Start of new transaction — save previous if non-empty
                if current:
                    entries.append(current)
                current = {}
            elif section_letter == "Z":
                # End of transaction
                if current:
                    entries.append(current)
                current = {}
                current_section = ""
                continue
            current_section = section_letter
            continue

        # Accumulate content into current section
        if current_section:
            existing = current.get(current_section, "")
            if existing:
                current[current_section] = existing + "\n" + line.rstrip()
            else:
                current[current_section] = line.rstrip()

    # Catch any trailing entry without Z marker
    if current:
        entries.append(current)
    return entries


def extract_rules_from_json(entry: dict) -> List[Tuple[str, str]]:
    """Extract (rule_id, message) from JSON audit entry.

    Supports multiple JSON audit log formats:
    - CRS Docker (SecAuditLogFormat JSON): {"transaction": {"messages": [{"message": ..., "details": {"ruleId": ...}}]}}
    - Generic: {"audit_data": {"messages": [...]}} or flat {"messages": [...]}
    - String messages: "Rule 942100: SQL Injection ..." or "[id \"942100\"]"
    """
    rules = []

    # CRS Docker JSON format: entry["transaction"]["messages"]
    txn = entry.get("transaction", {})
    if txn and isinstance(txn.get("messages"), list):
        msgs = txn["messages"]
    else:
        # Fallback: audit_data or flat entry
        ad = entry.get("audit_data", entry)
        msgs = ad.get("messages", [])

    for m in msgs:
        if isinstance(m, str):
            # "Rule 942100: SQL Injection ..." or "[id \"942100\"]"
            r = re.search(r"\[id \"(\d+)\"\]", m)
            if not r:
                r = re.search(r"Rule (\d+):", m, re.I)
            if r:
                rules.append((r.group(1), m))
        elif isinstance(m, dict):
            # CRS Docker format: {"message": "...", "details": {"ruleId": "934130", ...}}
            details = m.get("details", {})
            rid = (
                details.get("ruleId")
                or m.get("id")
                or m.get("rule_id")
            )
            msg_text = m.get("message", "")
            # Enrich with matched data if available
            matched_data = details.get("data", "")
            if matched_data and msg_text:
                msg_text = f"{msg_text} | {matched_data}"
            elif not msg_text:
                msg_text = str(m)
            if rid:
                rules.append((str(rid), msg_text))
    return rules


def extract_rules_from_native(entry: dict) -> List[Tuple[str, str]]:
    """Extract rules from Native format sections H or K."""
    rules = []
    for sec in ("H", "K"):
        text = entry.get(sec, "")
        for m in re.finditer(r"id \"(\d+)\"[^\]]*\]\s*(.*)", text):
            rules.append((m.group(1), m.group(2).strip()))
    return rules


def analyze(path: Path, args) -> dict:
    """Analyze log file and return report."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    is_json = raw.strip().startswith("{") or raw.strip().startswith("[")

    if is_json:
        entries = parse_json_log(path)
        extract_rules = extract_rules_from_json
    else:
        entries = parse_native_log(path)
        extract_rules = extract_rules_from_native

    rule_counts = Counter()
    rule_messages = {}
    rule_matches = defaultdict(list)

    entry_details = []  # (uri, method, http_code, rule_ids)
    for entry in entries:
        matched_rules = extract_rules(entry)
        # Extract request context (CRS Docker JSON format)
        txn = entry.get("transaction", {})
        req = txn.get("request", {})
        resp = txn.get("response", {})
        uri = req.get("uri", "?")
        method = req.get("method", "?")
        http_code = resp.get("http_code", "?")
        entry_rids = []
        for rid, msg in matched_rules:
            rule_counts[rid] += 1
            rule_messages[rid] = msg
            entry_rids.append(rid)
            if args.rule_id and rid == args.rule_id and args.detail:
                rule_matches[rid].append(msg[:200])
        entry_details.append({
            "method": method,
            "uri": uri,
            "http_code": http_code,
            "rules": entry_rids,
        })

    report = {
        "file": str(path),
        "format": "json" if is_json else "native",
        "total_entries": len(entries),
        "unique_rules": len(rule_counts),
        "rule_counts": dict(rule_counts.most_common()),
        "top_rules": [{"id": r, "count": c, "message": rule_messages.get(r, "")}
                      for r, c in rule_counts.most_common(args.top_rules or 10)],
        "entries": entry_details,
    }

    if args.rule_id:
        report["filtered_rule"] = {
            "id": args.rule_id,
            "count": rule_counts.get(args.rule_id, 0),
            "message": rule_messages.get(args.rule_id, ""),
            "samples": rule_matches.get(args.rule_id, [])[:20],
        }

    return report


def main():
    args = parse_args()
    if not args.logfile.exists():
        print(f"Error: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    report = analyze(args.logfile, args)

    if args.output == "json":
        print(json.dumps(report, indent=2))
        return

    # Text output
    print(f"File: {report['file']} ({report['format']})")
    print(f"Entries: {report['total_entries']}, Unique rules: {report['unique_rules']}")
    print()

    if args.summary or (not args.rule_id and not args.top_rules):
        print("Top triggered rules:")
        for r in report["top_rules"]:
            print(f"  {r['id']}: {r['count']}x — {r['message'][:80]}...")
        print()
        print("Per-request breakdown:")
        for i, e in enumerate(report.get("entries", [])):
            rules_str = ", ".join(e["rules"]) if e["rules"] else "(none)"
            print(f"  [{i+1}] {e['method']} {e['uri']} -> {e['http_code']}  rules: {rules_str}")
    elif args.top_rules:
        for r in report["top_rules"]:
            print(f"  {r['id']}: {r['count']}x — {r['message'][:80]}")

    if args.rule_id:
        fr = report.get("filtered_rule", {})
        print(f"\nRule {args.rule_id}: {fr.get('count', 0)} triggers")
        print(f"  {fr.get('message', '')}")
        if args.detail and fr.get("samples"):
            print("  Sample matches:")
            for s in fr["samples"][:10]:
                print(f"    {s[:80]}...")


if __name__ == "__main__":
    main()
