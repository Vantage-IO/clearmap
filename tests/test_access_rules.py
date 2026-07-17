"""Must-catch / must-not-catch verification for rules/access.yaml.

Runs semgrep directly on examples/framework-cases plus the corpus fixtures.
Every rule must hit its seeded line and stay silent on the near-misses —
Category A is the highest-FP-risk rule family (R2).
"""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules" / "access.yaml"
CASES = REPO / "examples" / "framework-cases"
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
class TestAccessRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hits = _hits(CASES, VULN / "backend", SAFE / "backend")

    def test_corpus_must_catch(self):
        v = "examples/vulnerable-health-app/backend"
        for rule, rel in (
            ("access-fastapi-unauthenticated-phi-read", f"{v}/api/patients.py"),
            ("access-fastapi-unauthenticated-phi-mutation", f"{v}/api/patients.py"),
            ("access-jwt-no-expiry-py", f"{v}/auth.py"),
        ):
            self.assertIn((rule, rel), self.hits, rule)

    def test_framework_must_catch(self):
        c = "examples/framework-cases"
        for rule, rel in (
            ("access-flask-unauthenticated-phi-route", f"{c}/flask/vulnerable_app.py"),
            ("access-auth-disabled-flag", f"{c}/flask/vulnerable_app.py"),
            ("access-express-unauthenticated-phi-route", f"{c}/express/vulnerable_routes.js"),
            ("access-jwt-no-expiry-js", f"{c}/express/vulnerable_routes.js"),
        ):
            self.assertIn((rule, rel), self.hits, rule)

    def test_must_not_catch_near_misses(self):
        flagged_safe = {h for h in self.hits
                        if Path(h[1]).name in ("safe_app.py", "safe_routes.js")}
        self.assertEqual(flagged_safe, set())

    def test_safe_corpus_backend_clean(self):
        # The safe fixture's guarded routes / env-sourced flags must stay silent.
        flagged = {h for h in self.hits
                   if h[1].startswith("examples/safe-health-app/")}
        self.assertEqual(flagged, set())


if __name__ == "__main__":
    unittest.main()
