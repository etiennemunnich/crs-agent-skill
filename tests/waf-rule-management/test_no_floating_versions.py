"""Guardrail: the skill names a version only when something specific is tied to it.

"Latest/current is X" and "Verified against X" go stale; SKILL.md tells the agent where to
look up what is current instead.
"""
import re
from pathlib import Path

SKILL = Path(__file__).resolve().parents[2] / "src" / "waf-rule-management"
FLOATING = re.compile(
    r"verified against|latest is|current is|currently \d|\(latest v?\d|as of 20\d\d", re.IGNORECASE
)


def test_no_floating_version_claims():
    hits = []
    for path in [SKILL / "SKILL.md", *sorted((SKILL / "references").glob("*.md"))]:
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if FLOATING.search(line):
                hits.append(f"{path.name}:{n}: {line.strip()[:100]}")
    assert not hits, "Floating version claims found:\n" + "\n".join(hits)


def test_skill_points_to_primary_sources():
    text = (SKILL / "SKILL.md").read_text()
    assert "## Versions and Freshness" in text
    for needle in ("coreruleset/main/CHANGES.md", "ModSecurity/v3/master/CHANGES", "known-version-issues.md"):
        assert needle in text, needle
