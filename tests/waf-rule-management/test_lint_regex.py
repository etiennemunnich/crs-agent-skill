import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "src" / "waf-rule-management" / "scripts"


def extract(content: str, timeout: float = 5):
    """Patterns extract_rx_patterns finds, run in a child process so a
    regression that backtracks forever fails the test instead of hanging it."""
    code = (
        "import sys, json; from pathlib import Path; sys.path.insert(0, sys.argv[1]); import lint_regex; "
        "print(json.dumps([r[2] for r in lint_regex.extract_rx_patterns(sys.stdin.read(), Path('x.conf'))]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(SCRIPTS)],
        input=content, capture_output=True, text=True, timeout=timeout, check=True,
    )
    return json.loads(result.stdout)


class ExtractRxPatternsTests(unittest.TestCase):
    def test_unclosed_quote_with_many_escapes_returns_quickly(self):
        # Before the fix each "\a" could match two ways, so every extra one
        # doubled the time (CodeQL py/redos): 40 of them took hours.
        self.assertEqual(extract('@rx "' + "\\a" * 40 + "\n"), [])

    def test_escaped_quote_stays_inside_the_pattern(self):
        # Before the fix this gave 'a\' and 'c\': the pattern ended at the escaped quote.
        self.assertEqual(extract("@rx 'a\\'b'\n" + '@rx "c\\"d"\n'), ["a'b", 'c"d'])

    def test_quoted_and_slash_patterns(self):
        self.assertEqual(extract('@rx "^(?:foo|bar)$"\n@rx /x+y/\n'), ["x+y", "^(?:foo|bar)$"])


if __name__ == "__main__":
    unittest.main()
