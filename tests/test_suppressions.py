"""The suppression ledger: the `clearmap suppressions` command and the report
appendix. The ledger makes every filtered/downgraded finding auditable."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SUPP = REPO / "scripts" / "suppressions.py"
sys.path.insert(0, str(REPO / "scripts"))
import report  # noqa: E402


def _rec(**kw):
    base = {"file": "a.py", "line": 1, "rule_id": "r", "category": "SECRETS",
            "source": "inline", "reason": "approved", "expires": None, "disposition": "suppressed"}
    base.update(kw)
    return base


class TestSuppressionsCommand(unittest.TestCase):
    def _run(self, data, *args):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td, "f.json")
            p.write_text(json.dumps(data))
            return subprocess.run([sys.executable, str(SUPP), str(p), *args],
                                  capture_output=True, text=True)

    def test_classifies_active_expired_downgraded(self):
        data = {"suppressions": [
            _rec(file="a.py", expires="2020-01-01"),                     # expired
            _rec(file="b.py", source="automatic-filter", reason="template"),  # active
            _rec(file="c.py", source="generated-or-vendored", disposition="downgraded"),
        ]}
        proc = self._run(data, "--as-of", "2026-01-01")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("1 active", proc.stdout)
        self.assertIn("EXPIRED", proc.stdout)
        self.assertIn("Downgraded", proc.stdout)

    def test_fail_on_expired(self):
        data = {"suppressions": [_rec(expires="2020-01-01")]}
        proc = self._run(data, "--as-of", "2026-01-01", "--fail-on-expired")
        self.assertEqual(proc.returncode, 1)

    def test_not_expired_when_future(self):
        data = {"suppressions": [_rec(expires="2099-01-01")]}
        proc = self._run(data, "--as-of", "2026-01-01", "--fail-on-expired")
        self.assertEqual(proc.returncode, 0)

    def test_empty_ledger(self):
        proc = self._run({"suppressions": []})
        self.assertEqual(proc.returncode, 0)
        self.assertIn("no suppressions", proc.stdout)


class TestSuppressionAppendix(unittest.TestCase):
    def test_appendix_renders_when_present(self):
        data = {"findings": [], "suppressions": [_rec(reason="approved test key",
                                                      expires="2026-12-31")]}
        md = report.render(data, "repo", "2026-01-01")
        self.assertIn("Appendix: Suppressions", md)
        self.assertIn("approved test key", md)

    def test_no_appendix_when_absent(self):
        md = report.render({"findings": []}, "repo", "2026-01-01")
        self.assertNotIn("Appendix: Suppressions", md)


if __name__ == "__main__":
    unittest.main()
