"""Must-catch / must-not-catch verification for rules/appsec.yaml.

Every APPSEC rule must hit its seeded vulnerable line and stay silent on the
safe counterpart (parameterized query, argument-list process call, allowlisted
URL, normalized path, json instead of pickle, explicit CORS origin).
"""
import json
import shutil
import subprocess
import tempfile
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


def _rules_for_snippet(code: str) -> set[str]:
    """Return the set of appsec rule ids that fire on an inline snippet."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "snippet.py"
        p.write_text(code)
        proc = subprocess.run(
            ["semgrep", "--config", str(RULES), "--json", "--quiet",
             "--metrics", "off", "--disable-version-check", str(p)],
            capture_output=True, text=True, check=False)
        data = json.loads(proc.stdout)
        assert not data.get("errors"), data["errors"]
        return {r["check_id"].split(".")[-1] for r in data["results"]}


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


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class TestDynamicStringInjection(unittest.TestCase):
    """P1c: injection rules must fire only on DYNAMIC strings (interpolation,
    concatenation, %, .format), never on constant f-strings."""

    SQL = "appsec-sql-injection-python"
    CMD = "appsec-command-injection-python"

    def test_sql_must_catch_dynamic(self):
        for code in (
            'cur.execute(f"SELECT * FROM patients WHERE id = {pid}")',
            'cur.execute("SELECT * FROM t WHERE id = " + pid)',
            'cur.execute("SELECT * FROM t WHERE id = %s" % pid)',
            'cur.execute("SELECT * FROM t WHERE id = {}".format(pid))',
        ):
            self.assertIn(self.SQL, _rules_for_snippet(code), code)

    def test_sql_must_not_catch_constant(self):
        for code in (
            'cur.execute(f"SELECT count(*) FROM patients")',
            'cur.execute("SELECT count(*) FROM patients")',
        ):
            self.assertNotIn(self.SQL, _rules_for_snippet(code), code)

    def test_command_must_catch_dynamic(self):
        for code in (
            'os.system(f"tar czf /b/{pid}.tgz /data/{pid}")',
            'os.system("tar czf /b/" + pid)',
            'os.system("tar czf /b/%s.tgz" % pid)',
            'os.system("tar czf /b/{}.tgz".format(pid))',
            'os.popen(f"cat /data/{pid}")',
            'subprocess.run(f"rm -rf /tmp/{pid}", shell=True)',
            'subprocess.run("rm -rf /tmp/%s" % pid, shell=True)',
            'subprocess.run("rm -rf /tmp/{}".format(pid), shell=True)',
        ):
            self.assertIn(self.CMD, _rules_for_snippet(code), code)

    def test_command_must_not_catch_constant(self):
        for code in (
            'os.system(f"find /backups -mtime +30 -delete")',
            'os.system("systemctl restart clinic")',
            'subprocess.run(["tar", "czf", "b.tgz", "/data"], shell=False)',
        ):
            self.assertNotIn(self.CMD, _rules_for_snippet(code), code)

    def test_cors_wildcard_via_variable(self):
        # R8: a wildcard bound through a variable must fire; a specific origin
        # bound through a variable must not.
        cors = "appsec-permissive-cors-credentials-python"
        vuln = ("def f(app):\n"
                "    origins = [\"*\"]\n"
                "    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)\n")
        safe = ("def f(app):\n"
                "    origins = [\"https://portal.example.org\"]\n"
                "    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)\n")
        self.assertIn(cors, _rules_for_snippet(vuln))
        self.assertNotIn(cors, _rules_for_snippet(safe))


if __name__ == "__main__":
    unittest.main()
