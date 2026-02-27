#!/usr/bin/env python3
"""
Detect likely protected application profiles from WAF audit logs.

This script is intentionally lightweight and heuristic-based so teams can
extend patterns without pulling in heavy dependencies.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


PROFILE_PATTERNS = {
    "wordpress": {
        "uri": [r"/wp-admin", r"/wp-login\.php", r"/wp-json", r"/xmlrpc\.php"],
        "header": [r"x-pingback", r"x-wp-"],
        "cookie": [r"wordpress_", r"wp-settings-"],
        "param": [r"^wp_", r"^rest_route$"],
        "recommendation": {
            "crs_variable": "tx.crs_exclusions_wordpress=1",
            "package": "WordPress exclusion package",
            "plugin_repo": "https://github.com/coreruleset/wordpress-rule-exclusions-plugin",
        },
    },
    "drupal": {
        "uri": [r"/sites/default", r"/user/login", r"/core/", r"/node/"],
        "header": [r"x-generator:\s*drupal"],
        "cookie": [r"^ses", r"^sse?ss"],
        "param": [r"^form_build_id$", r"^form_id$"],
        "recommendation": {
            "crs_variable": "tx.crs_exclusions_drupal=1",
            "package": "Drupal exclusion package",
            "plugin_repo": "https://github.com/coreruleset/drupal-rule-exclusions-plugin",
        },
    },
    "nextcloud": {
        "uri": [r"/remote\.php/dav", r"/ocs/v2\.php", r"/nextcloud", r"/index\.php/login"],
        "header": [r"oc_sessionpassphrase", r"ocp-"],
        "cookie": [r"oc_sessionpassphrase", r"nc_"],
        "param": [r"^requesttoken$"],
        "recommendation": {
            "crs_variable": "tx.crs_exclusions_nextcloud=1",
            "package": "Nextcloud exclusion package",
            "plugin_repo": "https://github.com/coreruleset/nextcloud-rule-exclusions-plugin",
        },
    },
    "phpmyadmin": {
        "uri": [r"/phpmyadmin", r"route=/", r"/index\.php\?"],
        "header": [],
        "cookie": [r"^pma"],
        "param": [r"^token$", r"^db$", r"^table$"],
        "recommendation": {
            "crs_variable": "tx.crs_exclusions_phpmyadmin=1",
            "package": "phpMyAdmin exclusion package",
            "plugin_repo": "https://github.com/coreruleset/phpmyadmin-rule-exclusions-plugin",
        },
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect likely CMS/framework profile from WAF audit logs."
    )
    parser.add_argument("logfile", type=Path, help="Audit log file (JSON or Native)")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.3,
        help="Only return profiles at or above this confidence (0.0-1.0).",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    return parser.parse_args()


def parse_json_log(path: Path) -> List[Dict]:
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return [obj for obj in parsed if isinstance(obj, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    entries = []
    for line in content.splitlines():
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                entries.append(obj)
        except json.JSONDecodeError:
            continue
    return entries


def parse_native_log(path: Path) -> List[Dict]:
    entries: List[Dict] = []
    current: Dict[str, str] = {}
    current_section = ""
    section_re = re.compile(r"^--[0-9A-Za-z]+-([A-Z])--$")

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = section_re.match(line.strip())
        if m:
            section = m.group(1)
            if section == "A":
                if current:
                    entries.append(current)
                current = {}
            elif section == "Z":
                if current:
                    entries.append(current)
                current = {}
                current_section = ""
                continue
            current_section = section
            continue
        if current_section:
            existing = current.get(current_section, "")
            current[current_section] = (existing + "\n" + line.rstrip()).strip("\n")

    if current:
        entries.append(current)
    return entries


def parse_native_request(entry: Dict) -> Tuple[str, Dict[str, str], Dict[str, str]]:
    uri = ""
    headers: Dict[str, str] = {}
    params: Dict[str, str] = {}
    section_b = entry.get("B", "")
    lines = section_b.splitlines()
    if lines:
        first = lines[0]
        m = re.match(r"[A-Z]+\s+(\S+)\s+HTTP/\d\.\d", first)
        if m:
            uri = m.group(1)
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    for key in re.findall(r"([A-Za-z0-9_.-]+)=", uri):
        params[key] = "1"
    return uri, headers, params


def parse_json_request(entry: Dict) -> Tuple[str, Dict[str, str], Dict[str, str]]:
    txn = entry.get("transaction", {})
    req = txn.get("request", {})
    uri = str(req.get("uri", entry.get("uri", entry.get("request_uri", ""))))
    headers: Dict[str, str] = {}
    params: Dict[str, str] = {}

    if isinstance(req.get("headers"), dict):
        for key, value in req["headers"].items():
            headers[str(key).lower()] = str(value)
    elif isinstance(req.get("headers"), list):
        # Some JSON logs represent headers as [{name, value}, ...].
        for item in req["headers"]:
            if isinstance(item, dict) and "name" in item and "value" in item:
                headers[str(item["name"]).lower()] = str(item["value"])

    # Try extracting query parameter names from the URI.
    for key in re.findall(r"[?&]([A-Za-z0-9_.-]+)=", uri):
        params[key] = "1"
    return uri, headers, params


def add_evidence(evidence: Dict[str, List[str]], profile: str, item: str):
    if item not in evidence[profile]:
        evidence[profile].append(item)


def detect_profiles(logfile: Path) -> Dict[str, Dict[str, object]]:
    raw = logfile.read_text(encoding="utf-8", errors="replace")
    is_json = raw.strip().startswith("{") or raw.strip().startswith("[")
    entries = parse_json_log(logfile) if is_json else parse_native_log(logfile)

    score = defaultdict(int)
    evidence: Dict[str, List[str]] = defaultdict(list)

    for entry in entries:
        if is_json:
            uri, headers, params = parse_json_request(entry)
        else:
            uri, headers, params = parse_native_request(entry)
        cookies_blob = headers.get("cookie", "")
        headers_blob = " ".join(f"{k}:{v}" for k, v in headers.items())

        for profile, spec in PROFILE_PATTERNS.items():
            for pattern in spec["uri"]:
                if re.search(pattern, uri, re.IGNORECASE):
                    score[profile] += 3
                    add_evidence(evidence, profile, f"uri:{pattern}")
            for pattern in spec["header"]:
                if re.search(pattern, headers_blob, re.IGNORECASE):
                    score[profile] += 2
                    add_evidence(evidence, profile, f"header:{pattern}")
            for pattern in spec["cookie"]:
                if re.search(pattern, cookies_blob, re.IGNORECASE):
                    score[profile] += 2
                    add_evidence(evidence, profile, f"cookie:{pattern}")
            for key in params:
                for pattern in spec["param"]:
                    if re.search(pattern, key, re.IGNORECASE):
                        score[profile] += 1
                        add_evidence(evidence, profile, f"param:{key}")

    # Convert heuristic score to confidence bucket.
    detected: Dict[str, Dict[str, object]] = {}
    for profile, raw_score in score.items():
        confidence = min(1.0, raw_score / 8.0)
        detected[profile] = {
            "profile": profile,
            "confidence": round(confidence, 2),
            "score": raw_score,
            "evidence": evidence.get(profile, []),
            "recommendation": PROFILE_PATTERNS[profile]["recommendation"],
        }
    return detected


def render_text(report: Dict[str, object]) -> str:
    lines = []
    lines.append(f"File: {report['file']} ({report['format']})")
    lines.append(f"Profiles detected: {len(report['matches'])}")
    lines.append("")
    for item in report["matches"]:
        rec = item["recommendation"]
        lines.append(
            f"- {item['profile']} confidence={item['confidence']} "
            f"score={item['score']}"
        )
        lines.append(f"  package: {rec['package']}")
        lines.append(f"  setvar: {rec['crs_variable']}")
        lines.append(f"  plugin: {rec['plugin_repo']}")
        lines.append(f"  evidence: {', '.join(item['evidence'][:6]) or 'none'}")
    return "\n".join(lines)


def main():
    args = parse_args()
    if not args.logfile.exists():
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    raw = args.logfile.read_text(encoding="utf-8", errors="replace")
    detected = detect_profiles(args.logfile)
    matches = [
        item
        for item in sorted(
            detected.values(),
            key=lambda row: (row["confidence"], row["score"]),
            reverse=True,
        )
        if item["confidence"] >= args.min_confidence
    ]
    report = {
        "file": str(args.logfile),
        "format": "json" if raw.strip().startswith(("{", "[")) else "native",
        "min_confidence": args.min_confidence,
        "matches": matches,
        "top_match": matches[0] if matches else None,
    }

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))


if __name__ == "__main__":
    main()
