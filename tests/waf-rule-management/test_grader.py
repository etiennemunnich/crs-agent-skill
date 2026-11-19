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


def test_whitespace_normalised_matching():
    assert grader.grade_string_match("SecRule\n  REQUEST_URI", {"patterns": ["SecRule REQUEST_URI"]})[0]
    assert grader.grade_string_match_all("a   b", {"patterns": ["a b"]})[0]


def test_absent_ignores_warnings_against_the_pattern():
    a = {"patterns": ["SecRuleEngine Off"]}
    assert grader.grade_string_absent("Never set SecRuleEngine Off in production.", a)[0]
    assert grader.grade_string_absent("Avoid SecRuleEngine Off; use DetectionOnly", a)[0]
    # A recommendation in a separate sentence is still caught.
    assert not grader.grade_string_absent("Never guess. Set SecRuleEngine Off to fix it.", a)[0]
    # Opt out for strict matching.
    assert not grader.grade_string_absent("Never set SecRuleEngine Off", {**a, "ignore_negated": False})[0]


def test_absent_code_scope_only_checks_fenced_blocks():
    a = {"patterns": ["ProcessPartial"], "scope": "code"}
    prose = "ProcessPartial is risky in blocking mode."
    assert grader.grade_string_absent(prose, a)[0]
    fenced = "Try:\n```\nSecRequestBodyLimitAction ProcessPartial\n```\n"
    assert not grader.grade_string_absent(fenced, a)[0]


def test_regex_absent_respects_negation_and_bad_regex():
    a = {"pattern": r"\b250000\b"}
    assert grader.grade_regex_absent("Do not raise it to 250000.", a)[0]
    ok, detail = grader.grade_regex_absent("x", {"pattern": "("})
    assert not ok and "Invalid regex" in detail


def test_parse_llm_verdict():
    assert grader.parse_llm_verdict("<thinking>t</thinking><result>correct</result>")[0] is True
    assert grader.parse_llm_verdict("<result>incorrect</result>")[0] is False
    # 'incorrect' must not be read as 'correct'; last tag wins; junk is None (error), not False.
    assert grader.parse_llm_verdict("<result>correct</result> ... <result>incorrect</result>")[0] is False
    assert grader.parse_llm_verdict("no tags at all")[0] is None
    assert grader.parse_llm_verdict("<result>maybe</result>")[0] is None


def test_truncate_keeps_head_and_tail():
    text = "H" * 20000 + "TAIL-CONCLUSION"
    out = grader._truncate_middle(text, 1000)
    assert out.startswith("HHH") and out.endswith("TAIL-CONCLUSION") and "truncated" in out
    assert grader._truncate_middle("short", 1000) == "short"


def test_llm_error_is_not_scored_as_failure(monkeypatch):
    monkeypatch.setattr(grader, "grade_llm", lambda *a, **k: (None, "ERROR: no key"))
    spec = grader.find_eval(grader.load_evals(), 1)
    res = grader.grade_assertion("x", next(a for a in spec["assertions"] if a["grading_method"] == "llm"))
    assert res["error"] and not res["passed"]
    out = grader.grade_response("x", 1)
    assert out["errors"] > 0
    assert out["total"] == len(spec["assertions"]) - out["errors"]


def test_critical_failure_reported_and_fingerprint_recorded():
    out = grader.grade_response("Just set SecRuleEngine Off and SecRequestBodyAccess Off.", 12)
    assert out["critical_failed"] == ["A5"]
    assert len(out["grader"]["spec_sha"]) == 12


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
