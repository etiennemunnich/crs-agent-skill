import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "src" / "waf-rule-management" / "scripts" / "analyze_log.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class AnalyzeLogExplainTests(unittest.TestCase):
    def run_cli(self, *args):
        cmd = [sys.executable, str(SCRIPT), *args]
        return subprocess.run(cmd, check=False, capture_output=True, text=True)

    def test_json_explain_rule(self):
        result = self.run_cli(
            str(FIXTURES / "audit_json.log"),
            "--explain-rule",
            "942100",
            "--detail",
            "--output",
            "json",
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        explanations = payload.get("explanations", [])
        self.assertTrue(explanations, "Expected at least one explanation")
        self.assertEqual(explanations[0]["id"], "942100")
        self.assertIn("sqli", explanations[0]["family"])

    def test_native_summary_counts(self):
        result = self.run_cli(
            str(FIXTURES / "audit_native.log"),
            "--top-rules",
            "1",
            "--output",
            "json",
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["top_rules"][0]["id"], "942100")
        self.assertEqual(payload["top_rules"][0]["count"], 1)


if __name__ == "__main__":
    unittest.main()
