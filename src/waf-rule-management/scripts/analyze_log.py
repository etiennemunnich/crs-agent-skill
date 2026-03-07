#!/usr/bin/env python3
"""
Parse ModSecurity/Coraza audit logs and explain why rules trigger.

Supports:
- ModSecurity JSON audit logs (line-delimited objects or object arrays)
- Coraza/Caddy JSON logs (level/msg structured lines with bracketed fields)
- Native sectioned logs (--boundary-A-- ... --boundary-Z--)
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from audit_log_parser import parse_json_log, parse_native_log

RULE_FAMILY_MAP = {
    "920": "protocol-enforcement",
    "921": "protocol-anomaly",
    "930": "lfi-rfi",
    "931": "rce",
    "932": "rce",
    "933": "php-injection",
    "934": "nodejs-injection",
    "941": "xss",
    "942": "sqli",
    "943": "session-fixation",
    "944": "java-injection",
    "949": "inbound-anomaly-evaluation",
    "959": "outbound-anomaly-evaluation",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse audit logs and explain triggered WAF rules."
    )
    parser.add_argument("logfile", type=Path, help="Audit log file (JSON or Native)")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary with top rules and request breakdown",
    )
    parser.add_argument(
        "--top-rules",
        type=int,
        default=0,
        metavar="N",
        help="Print top N triggered rules",
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        default="",
        help="Filter by rule ID (example: 942100)",
    )
    parser.add_argument(
        "--detail",
        action="store_true",
        help="Show detailed samples for --rule-id",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show explanation summary for top triggered rules",
    )
    parser.add_argument(
        "--explain-rule",
        type=str,
        default="",
        help="Explain a specific rule ID in depth",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["json", "text"],
        default="text",
        help="Output format",
    )
    return parser.parse_args()


def parse_message_field(text: str, field_name: str) -> str:
    m = re.search(rf'\[{re.escape(field_name)}\s+"([^"]*)"\]', text)
    return m.group(1) if m else ""


def parse_message_tags(text: str) -> List[str]:
    return re.findall(r'\[tag\s+"([^"]*)"\]', text)


def parse_target_from_message(message: str) -> str:
    m = re.search(r" at ([A-Z_]+(?::[^\s\]]+)?)", message)
    return m.group(1) if m else ""


def parse_payload_from_data(data_text: str) -> str:
    if not data_text:
        return ""
    m = re.search(r"Matched Data:\s*(.*?)\s*found within", data_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return data_text[:120]


def detect_coraza_json(entries: List[Dict]) -> bool:
    """Return True if entries look like Coraza/Caddy structured JSON logs."""
    for entry in entries[:10]:
        # Coraza/Caddy logs have 'logger' or 'level' keys, and a 'msg' string
        # containing bracketed fields like [id "..."].  ModSecurity JSON has a
        # 'transaction' key instead.
        if "transaction" in entry:
            return False
        msg = entry.get("msg", "")
        if isinstance(msg, str) and "[id " in msg:
            return True
        # Caddy info lines (no rule match) have 'level':'info'
        if entry.get("logger") == "http.handlers.waf":
            return True
    return False


def parse_coraza_json(entries: List[Dict]) -> List[Dict]:
    """Group Coraza/Caddy JSON lines by unique_id into transaction dicts.

    Each returned dict has keys: 'client_ip', 'uri', 'messages' (list of raw
    msg strings that contain rule matches), and 'unique_id'.
    """
    from collections import OrderedDict

    txns: Dict[str, Dict] = OrderedDict()

    for entry in entries:
        msg = entry.get("msg", "")
        if not isinstance(msg, str) or "[id " not in msg:
            continue  # skip info/startup lines

        uid = parse_message_field(msg, "unique_id") or "unknown"
        if uid not in txns:
            # Extract request context from the first line of a transaction
            client_match = re.search(r'\[client\s+"([^"]+)"\]', msg)
            uri_val = parse_message_field(msg, "uri") or "?"
            txns[uid] = {
                "client_ip": client_match.group(1) if client_match else "?",
                "uri": uri_val,
                "messages": [],
                "unique_id": uid,
            }
        txns[uid]["messages"].append(msg)

    return list(txns.values())


def extract_context_coraza(entry: dict) -> Dict[str, str]:
    """Extract request context from a grouped Coraza transaction dict."""
    return {
        "method": "?",  # Coraza error logs don't include method
        "uri": entry.get("uri", "?"),
        "http_code": "403",  # Coraza only logs blocked requests here
        "client_ip": entry.get("client_ip", "?"),
    }


def extract_rules_from_coraza(entry: dict) -> List[Dict[str, object]]:
    """Extract normalized rule matches from Coraza grouped transaction."""
    rules: List[Dict[str, object]] = []
    for msg in entry.get("messages", []):
        rule_id = parse_message_field(msg, "id")
        if not rule_id:
            continue
        msg_text = parse_message_field(msg, "msg") or msg[:120]
        data_text = parse_message_field(msg, "data")
        target = parse_target_from_message(msg)
        rules.append(
            {
                "id": str(rule_id),
                "message": msg_text,
                "data": data_text,
                "target": target,
                "tags": parse_message_tags(msg),
                "raw": msg.strip(),
            }
        )
    return rules


def extract_context_json(entry: dict) -> Dict[str, str]:
    txn = entry.get("transaction", {})
    req = txn.get("request", {})
    resp = txn.get("response", {})
    return {
        "method": str(req.get("method", entry.get("request_method", "?"))),
        "uri": str(req.get("uri", entry.get("uri", entry.get("request_uri", "?")))),
        "http_code": str(resp.get("http_code", entry.get("status", "?"))),
        "client_ip": str(txn.get("client_ip", entry.get("client_ip", "?"))),
    }


def extract_context_native(entry: dict) -> Dict[str, str]:
    method = "?"
    uri = "?"
    http_code = "?"
    client_ip = "?"

    a_section = entry.get("A", "")
    a_parts = a_section.split()
    if len(a_parts) >= 3:
        client_ip = a_parts[2]

    b_section = entry.get("B", "")
    first_request_line = b_section.splitlines()[0] if b_section.splitlines() else ""
    m_req = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/\d\.\d", first_request_line)
    if m_req:
        method, uri = m_req.group(1), m_req.group(2)

    f_section = entry.get("F", "")
    first_response_line = f_section.splitlines()[0] if f_section.splitlines() else ""
    m_resp = re.match(r"HTTP/\d\.\d\s+(\d+)", first_response_line)
    if m_resp:
        http_code = m_resp.group(1)

    return {
        "method": method,
        "uri": uri,
        "http_code": http_code,
        "client_ip": client_ip,
    }


def normalize_rule_family(rule_id: str) -> str:
    return RULE_FAMILY_MAP.get(rule_id[:3], "other")


def extract_rules_from_json(entry: dict) -> List[Dict[str, object]]:
    """Extract normalized rule matches from JSON entries."""
    rules: List[Dict[str, object]] = []
    txn = entry.get("transaction", {})
    if txn and isinstance(txn.get("messages"), list):
        messages = txn["messages"]
    else:
        ad = entry.get("audit_data", entry)
        messages = ad.get("messages", []) if isinstance(ad, dict) else []

    for message in messages:
        if isinstance(message, str):
            rule_id = parse_message_field(message, "id")
            if not rule_id:
                m = re.search(r"Rule (\d+):", message, re.IGNORECASE)
                rule_id = m.group(1) if m else ""
            if not rule_id:
                continue
            msg_text = parse_message_field(message, "msg") or message
            data_text = parse_message_field(message, "data")
            target = parse_target_from_message(message)
            rules.append(
                {
                    "id": str(rule_id),
                    "message": msg_text,
                    "data": data_text,
                    "target": target,
                    "tags": parse_message_tags(message),
                    "raw": message,
                }
            )
            continue

        if isinstance(message, dict):
            details = message.get("details", {})
            rule_id = str(
                details.get("ruleId") or message.get("id") or message.get("rule_id") or ""
            )
            if not rule_id:
                continue
            msg_text = str(message.get("message", ""))
            data_text = str(details.get("data", message.get("data", "")))
            target = str(details.get("match", "")) or parse_target_from_message(msg_text)
            tags = message.get("tags", [])
            if not isinstance(tags, list):
                tags = []
            rules.append(
                {
                    "id": rule_id,
                    "message": msg_text or f"Rule {rule_id}",
                    "data": data_text,
                    "target": target,
                    "tags": tags,
                    "raw": message,
                }
            )
    return rules


def extract_rules_from_native(entry: dict) -> List[Dict[str, object]]:
    """Extract normalized rule matches from native H/K sections."""
    rules: List[Dict[str, object]] = []
    for section in ("H", "K"):
        text = entry.get(section, "")
        if not text:
            continue
        for line in text.splitlines():
            if 'id "' not in line:
                continue
            rule_id = parse_message_field(line, "id")
            if not rule_id:
                continue
            msg_text = parse_message_field(line, "msg") or line.strip()
            data_text = parse_message_field(line, "data")
            target = parse_target_from_message(line)
            rules.append(
                {
                    "id": str(rule_id),
                    "message": msg_text,
                    "data": data_text,
                    "target": target,
                    "tags": parse_message_tags(line),
                    "raw": line.strip(),
                }
            )
    return rules


def explain_rule(rule_id: str, matches: List[Dict[str, object]]) -> Dict[str, object]:
    target_counts = Counter()
    payload_counts = Counter()
    tags = Counter()

    for match in matches:
        target = str(match.get("target", "")).strip()
        if target:
            target_counts[target] += 1
        payload = parse_payload_from_data(str(match.get("data", ""))).strip()
        if payload:
            payload_counts[payload] += 1
        for tag in match.get("tags", []):
            if isinstance(tag, str):
                tags[tag] += 1

    top_target = target_counts.most_common(1)[0][0] if target_counts else ""
    top_payload = payload_counts.most_common(1)[0][0] if payload_counts else ""
    confidence = "low"
    if top_target and top_payload:
        confidence = "high"
    elif top_target or top_payload:
        confidence = "medium"

    reason_bits = []
    if top_target:
        reason_bits.append(f"match location {top_target}")
    if top_payload:
        reason_bits.append(f"payload fragment '{top_payload[:60]}'")
    reason_text = ", ".join(reason_bits) if reason_bits else "message-only evidence"

    return {
        "id": rule_id,
        "family": normalize_rule_family(rule_id),
        "confidence": confidence,
        "likely_trigger": reason_text,
        "top_targets": [{"target": t, "count": c} for t, c in target_counts.most_common(5)],
        "top_payload_fragments": [
            {"fragment": f, "count": c} for f, c in payload_counts.most_common(5)
        ],
        "top_tags": [{"tag": t, "count": c} for t, c in tags.most_common(5)],
    }


def explain_rules(
    rule_matches: Dict[str, List[Dict[str, object]]], only_rule: Optional[str] = None
) -> List[Dict[str, object]]:
    if only_rule:
        selected = {only_rule: rule_matches.get(only_rule, [])}
    else:
        selected = rule_matches
    explanations = []
    for rule_id, matches in selected.items():
        if not matches:
            continue
        explanations.append(explain_rule(rule_id, matches))
    return sorted(explanations, key=lambda item: item["id"])


def analyze(path: Path, args) -> dict:
    raw = path.read_text(encoding="utf-8", errors="replace")
    is_json = raw.strip().startswith("{") or raw.strip().startswith("[")
    if is_json:
        raw_entries = parse_json_log(path)
        # Detect Coraza/Caddy JSON vs ModSecurity JSON
        if detect_coraza_json(raw_entries):
            entries = parse_coraza_json(raw_entries)
            extract_rules = extract_rules_from_coraza
            extract_context = extract_context_coraza
            is_json = True  # still JSON, just Coraza flavour
        else:
            entries = raw_entries
            extract_rules = extract_rules_from_json
            extract_context = extract_context_json
    else:
        entries = parse_native_log(path)
        extract_rules = extract_rules_from_native
        extract_context = extract_context_native

    rule_counts = Counter()
    rule_messages: Dict[str, str] = {}
    rule_samples = defaultdict(list)
    rule_matches: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    entry_details = []

    for entry in entries:
        context = extract_context(entry)
        matched_rules = extract_rules(entry)
        entry_rule_ids: List[str] = []

        for match in matched_rules:
            rule_id = str(match["id"])
            rule_counts[rule_id] += 1
            rule_messages[rule_id] = str(match.get("message", ""))
            rule_matches[rule_id].append(match)
            entry_rule_ids.append(rule_id)
            if args.detail and (args.rule_id == rule_id or args.explain_rule == rule_id):
                rule_samples[rule_id].append(str(match.get("raw", match.get("message", "")))[:240])

        entry_details.append(
            {
                "method": context["method"],
                "uri": context["uri"],
                "http_code": context["http_code"],
                "client_ip": context["client_ip"],
                "rules": entry_rule_ids,
            }
        )

    requested_explain_rule = args.explain_rule or args.rule_id
    report = {
        "file": str(path),
        "format": "json" if is_json else "native",
        "total_entries": len(entries),
        "unique_rules": len(rule_counts),
        "rule_counts": dict(rule_counts.most_common()),
        "top_rules": [
            {"id": rule_id, "count": count, "message": rule_messages.get(rule_id, "")}
            for rule_id, count in rule_counts.most_common(args.top_rules or 10)
        ],
        "entries": entry_details,
    }

    if args.rule_id:
        report["filtered_rule"] = {
            "id": args.rule_id,
            "count": rule_counts.get(args.rule_id, 0),
            "message": rule_messages.get(args.rule_id, ""),
            "samples": rule_samples.get(args.rule_id, [])[:20],
        }

    if args.explain or requested_explain_rule:
        report["explanations"] = explain_rules(rule_matches, requested_explain_rule or None)

    if requested_explain_rule:
        report["explained_rule_samples"] = rule_samples.get(requested_explain_rule, [])[:20]

    return report


def print_text_report(report: dict, args):
    print(f"File: {report['file']} ({report['format']})")
    print(f"Entries: {report['total_entries']}, Unique rules: {report['unique_rules']}")
    print()

    if args.summary or (not args.rule_id and not args.top_rules and not args.explain):
        print("Top triggered rules:")
        for rule in report["top_rules"]:
            print(f"  {rule['id']}: {rule['count']}x — {rule['message'][:80]}...")
        print()
        print("Per-request breakdown:")
        for index, entry in enumerate(report.get("entries", []), start=1):
            rules_str = ", ".join(entry["rules"]) if entry["rules"] else "(none)"
            print(
                f"  [{index}] {entry['method']} {entry['uri']} -> "
                f"{entry['http_code']} rules: {rules_str}"
            )
    elif args.top_rules:
        for rule in report["top_rules"]:
            print(f"  {rule['id']}: {rule['count']}x — {rule['message'][:80]}")

    if args.rule_id:
        filtered = report.get("filtered_rule", {})
        print(f"\nRule {args.rule_id}: {filtered.get('count', 0)} triggers")
        print(f"  {filtered.get('message', '')}")
        if args.detail and filtered.get("samples"):
            print("  Sample matches:")
            for sample in filtered["samples"][:10]:
                print(f"    {sample[:120]}...")

    if report.get("explanations"):
        print("\nRule trigger explanations:")
        for item in report["explanations"]:
            print(
                f"  {item['id']} ({item['family']}, confidence={item['confidence']}): "
                f"{item['likely_trigger']}"
            )
            for target in item.get("top_targets", [])[:3]:
                print(f"    target: {target['target']} ({target['count']}x)")
            for fragment in item.get("top_payload_fragments", [])[:2]:
                print(f"    payload: {fragment['fragment'][:80]} ({fragment['count']}x)")

    if report.get("explained_rule_samples") and args.detail:
        print("\nDetailed evidence samples:")
        for sample in report["explained_rule_samples"][:10]:
            print(f"  {sample}")


def main():
    args = parse_args()
    if not args.logfile.exists():
        print(f"Error: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    report = analyze(args.logfile, args)
    if args.output == "json":
        print(json.dumps(report, indent=2))
        return
    print_text_report(report, args)


if __name__ == "__main__":
    main()
