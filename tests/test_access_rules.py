"""Must-catch / must-not-catch verification for rules/access.yaml.

Runs semgrep directly on examples/framework-cases plus the corpus fixtures.
Every rule must hit its seeded line and stay silent on the near-misses —
Category A is the highest-FP-risk rule family (R2).
"""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules" / "access.yaml"


def _fires_on_route(path: str) -> bool:
    """True if an unauthenticated FastAPI route at `path` fires a PHI-route rule."""
    code = ("from fastapi import APIRouter\nrouter = APIRouter()\n"
            f"@router.get({path!r})\ndef h(x: str):\n    return x\n")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "r.py"
        p.write_text(code)
        proc = subprocess.run(
            ["semgrep", "--config", str(RULES), "--json", "--quiet",
             "--metrics", "off", "--disable-version-check", str(p)],
            capture_output=True, text=True, check=False)
        return bool(json.loads(proc.stdout)["results"])
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

    def test_graphql_idor_must_catch(self):
        # R9: Strawberry resolvers that take an id but never touch info.context or
        # an ownership helper fire; resolvers that DO authorize stay silent.
        rel = "examples/framework-cases/graphql/vulnerable_resolvers.py"
        self.assertIn(("access-graphql-strawberry-idor", rel), self.hits)

    def test_depends_non_auth_provider_is_still_unauthenticated(self):
        # R1: a PHI route whose only Depends is a DB/session/settings/pagination
        # provider must still fire (get_db is not authentication).
        rel = "examples/framework-cases/fastapi/vulnerable_deps.py"
        self.assertIn(("access-fastapi-unauthenticated-phi-read", rel), self.hits)
        self.assertIn(("access-fastapi-unauthenticated-phi-mutation", rel), self.hits)

    def test_must_not_catch_near_misses(self):
        flagged_safe = {h for h in self.hits
                        if Path(h[1]).name in ("safe_app.py", "safe_routes.js",
                                               "safe_deps.py", "safe_resolvers.py")}
        self.assertEqual(flagged_safe, set())

    def test_safe_corpus_backend_clean(self):
        # The safe fixture's guarded routes / env-sourced flags must stay silent.
        flagged = {h for h in self.hits
                   if h[1].startswith("examples/safe-health-app/")}
        self.assertEqual(flagged, set())


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class TestPhiLexicon(unittest.TestCase):
    """R3: the broadened clinical-workflow lexicon fires on real clinical routes
    while non-PHI routes (and near-miss words like showcase) stay silent."""

    def test_clinical_routes_fire(self):
        for path in ("/appointments/{id}", "/prescriptions/{id}",
                     "/members/{id}/eligibility", "/cases/{id}",
                     "/encounters/{id}", "/conversations/{id}/messages",
                     "/intake/{id}", "/referrals/{id}"):
            self.assertTrue(_fires_on_route(path), path)

    def test_non_phi_routes_silent(self):
        for path in ("/showcase", "/usecases", "/settings", "/healthz",
                     "/status", "/metrics", "/database/migrate"):
            self.assertFalse(_fires_on_route(path), path)


if __name__ == "__main__":
    unittest.main()
