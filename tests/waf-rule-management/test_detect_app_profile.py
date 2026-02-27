import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "src" / "waf-rule-management" / "scripts" / "detect_app_profile.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class DetectAppProfileTests(unittest.TestCase):
    def run_cli(self, *args):
        cmd = [sys.executable, str(SCRIPT), *args]
        return subprocess.run(cmd, check=False, capture_output=True, text=True)

    def test_detects_wordpress_profile_from_log(self):
        result = self.run_cli(
            str(FIXTURES / "audit_json.log"),
            "--output",
            "json",
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertIsNotNone(payload.get("top_match"))
        self.assertEqual(payload["top_match"]["profile"], "wordpress")
        self.assertGreaterEqual(payload["top_match"]["confidence"], 0.3)


if __name__ == "__main__":
    unittest.main()
