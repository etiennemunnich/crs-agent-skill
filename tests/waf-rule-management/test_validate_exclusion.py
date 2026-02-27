import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "src" / "waf-rule-management" / "scripts" / "validate_exclusion.py"


class ValidateExclusionTests(unittest.TestCase):
    def run_cli(self, *args):
        cmd = [sys.executable, str(SCRIPT), *args]
        return subprocess.run(cmd, check=False, capture_output=True, text=True)

    def test_global_whole_rule_exclusion_fails(self):
        result = self.run_cli(
            "--rule-id",
            "942100",
            "--type",
            "runtime",
            "--output",
            "json",
        )
        self.assertEqual(result.returncode, 2, msg=result.stdout)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertGreaterEqual(payload["summary"]["errors"], 1)

    def test_target_scoped_runtime_exclusion_passes(self):
        result = self.run_cli(
            "--rule-id",
            "942100",
            "--type",
            "runtime",
            "--uri",
            "/api/search",
            "--param",
            "ARGS:q",
            "--output",
            "json",
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
