"""Must-catch / must-not-catch verification for rules/appsec.yaml.

Every APPSEC rule must hit its seeded vulnerable line and stay silent on the
safe counterpart (parameterized query, argument-list process call, allowlisted
URL, normalized path, json instead of pickle, explicit CORS origin).
"""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules" / "appsec.yaml"
VULN = REPO / "examples" / "vulnerable-health-app"
SAFE = REPO / "examples" / "safe-health-app"


def _hits(*targets: Path) -> set[tuple[str, str]]:
    proc = subprocess.run(
        ["semgrep", "--config", str(RULES), "--json", "--quiet",
         "--metrics", "off", "--disable-version-check",
         *[str(t) for t in targets]],
        capture_output=True, text=True, check=False)
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data["errors"]
    return {(r["check_id"].split(".")[-1],
             str(Path(r["path"]).resolve().relative_to(REPO)))
            for r in data["results"]}


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class TestAppsecRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hits = _hits(VULN / "backend", SAFE / "backend")

    def test_must_catch_each_weakness(self):
        rel = "examples/vulnerable-health-app/backend/appsec.py"
        for rule in (
            "appsec-sql-injection-python",
            "appsec-command-injection-python",
            "appsec-ssrf-request-url-python",
            "appsec-path-traversal-python",
            "appsec-unsafe-deserialization-python",
            "appsec-permissive-cors-credentials-python",
        ):
            self.assertIn((rule, rel), self.hits, rule)

    def test_safe_counterparts_clean(self):
        flagged = {h for h in self.hits if h[1].startswith("examples/safe-health-app/")}
        self.assertEqual(flagged, set())


if __name__ == "__main__":
    unittest.main()
