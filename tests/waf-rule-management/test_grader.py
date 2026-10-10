"""Offline unit tests for eval graders (no API calls)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "waf-rule-management" / "evals"
sys.path.insert(0, str(ROOT))

import grader  # noqa: E402


def test_string_match_min_matches():
    a = {"patterns": ["foo", "bar"], "min_matches": 2}
    assert grader.grade_string_match("FOO and bar", a)[0]
    assert not grader.grade_string_match("foo only", a)[0]


def test_string_absent():
    a = {"patterns": ["SecRuleEngine Off"]}
    assert grader.grade_string_absent("use DetectionOnly", a)[0]
    assert not grader.grade_string_absent("set secruleengine off", a)[0]


def test_regex_absent():
    a = {"pattern": r"\b250000\b"}
    assert grader.grade_regex_absent("use 1500", a)[0]
    assert not grader.grade_regex_absent("use 250000", a)[0]


def test_all_evals_wellformed():
    data = grader.load_evals()
    ids = [e["id"] for e in data["evals"]]
    assert len(ids) == len(set(ids))
    for e in data["evals"]:
        assert "tools_used" in e
        assert e["assertions"], e["id"]
        for a in e["assertions"]:
            if a["grading_method"] == "code":
                assert a["check"] in grader.CODE_GRADERS, (e["id"], a["id"])
            else:
                assert a.get("rubric"), (e["id"], a["id"])


def test_referenced_files_exist():
    base = ROOT.parent
    for e in grader.load_evals()["evals"]:
        for tok in e["prompt"].split():
            if tok.startswith("evals/files/"):
                assert (base / tok.strip(".,")).exists(), tok
