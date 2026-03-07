#!/usr/bin/env python3
"""
Shared audit log parsing for ModSecurity/Coraza JSON and Native formats.

Used by analyze_log.py and detect_app_profile.py.
"""
import json
import re
from pathlib import Path
from typing import Dict, List


def parse_json_log(path: Path) -> List[Dict]:
    """Parse JSON logs. Supports JSONL and single JSON arrays/objects."""
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []

    entries: List[Dict] = []
    try:
        loaded = json.loads(content)
        if isinstance(loaded, list):
            return [entry for entry in loaded if isinstance(entry, dict)]
        if isinstance(loaded, dict):
            return [loaded]
    except json.JSONDecodeError:
        pass

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                entries.append(obj)
        except json.JSONDecodeError:
            continue
    return entries


def parse_native_log(path: Path) -> List[Dict]:
    """Parse native sectioned audit logs into transaction dictionaries."""
    content = path.read_text(encoding="utf-8", errors="replace")
    entries: List[Dict] = []
    current: Dict[str, str] = {}
    current_section = ""
    section_re = re.compile(r"^--[0-9A-Za-z]+-([A-Z])--$")

    for line in content.splitlines():
        m = section_re.match(line.strip())
        if m:
            section_letter = m.group(1)
            if section_letter == "A":
                if current:
                    entries.append(current)
                current = {}
            elif section_letter == "Z":
                if current:
                    entries.append(current)
                current = {}
                current_section = ""
                continue
            current_section = section_letter
            continue

        if current_section:
            existing = current.get(current_section, "")
            current[current_section] = (existing + "\n" + line.rstrip()).strip("\n")

    if current:
        entries.append(current)
    return entries
