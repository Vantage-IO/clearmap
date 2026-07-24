"""Must-catch / must-not-catch verification for the ClearMap gitleaks rules.

Focus (P1b): clearmap-db-uri-credentials must fire ONLY on real database driver
connection strings that carry a real embedded password, and must stay silent on
http(s)/git/ssh basic-auth URLs and on templated / placeholder / example
credentials.
"""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CFG = REPO / "rules" / "gitleaks.toml"

MUST_CATCH = {
    "postgres real": 'DB = "postgresql://admin:Sup3rSecret!@db.internal:5432/patients"',
    "mysql real": 'DB = "mysql://root:hunter2xyzq@10.0.0.5:3306/app"',
    "mongodb+srv real": 'DB = "mongodb+srv://svc:aB9kLmNpQr@cluster0.example/db"',
    "jdbc real": 'DB = "jdbc:postgresql://svcuser:realtoken123@db.example:5432/app"',
    "rediss real": 'DB = "rediss://default:S0meR3alT0ken@cache.example:6380/0"',
}

MUST_NOT_CATCH = {
    # Non-DB schemes: basic-auth URLs are not DB credentials.
    "https basic-auth": 'URL = "https://user:secretvalue@api.example.com/hook"',
    "http basic-auth": 'URL = "http://user:secretvalue@api.example.com/hook"',
    "git creds": 'URL = "git://user:token12345@github.example/repo.git"',
    "ssh creds": 'URL = "ssh://deploy:mypasshere@host.example"',
    # Placeholder / templated / example passwords in a real DB scheme.
    "env template": 'DB = "postgresql://app:${DB_PASSWORD}@db.internal:5432/app"',
    "angle template": 'DB = "postgresql://user:<your-password>@db.example/app"',
    "mustache template": 'DB = "postgresql://user:{{db_password}}@db.example/app"',
    "REPLACE_ME": 'DB = "postgresql://user:REPLACE_ME@db.example:5432/app"',
    "CHANGEME": 'DB = "postgresql://admin:changeme@db.example/app"',
    "literal password": 'DB = "postgres://user:password@db.example/app"',
    "user pass": 'DB = "postgresql://user:pass@localhost:5432/app"',
    "xxxx": 'DB = "mysql://root:xxxxxxxx@db/app"',
}


def _db_uri_hits(text: str) -> int:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "sample.py").write_text(text + "\n")
        report = root / "out.json"
        subprocess.run(
            ["gitleaks", "dir", str(root), "--config", str(CFG),
             "--no-banner", "--report-format", "json", "--report-path", str(report)],
            capture_output=True, text=True, check=False)
        leaks = json.loads(report.read_text()) if report.exists() else []
    return sum(1 for lk in leaks if lk.get("RuleID") == "clearmap-db-uri-credentials")


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
class TestDbUriRule(unittest.TestCase):
    def test_must_catch_real_db_credentials(self):
        for label, line in MUST_CATCH.items():
            with self.subTest(label):
                self.assertGreaterEqual(_db_uri_hits(line), 1,
                                        f"{label} should fire clearmap-db-uri-credentials")

    def test_must_not_catch_non_db_or_placeholder(self):
        for label, line in MUST_NOT_CATCH.items():
            with self.subTest(label):
                self.assertEqual(_db_uri_hits(line), 0,
                                 f"{label} must NOT fire clearmap-db-uri-credentials")


if __name__ == "__main__":
    unittest.main()
