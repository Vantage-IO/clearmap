"""issues.py: compact open-findings list over the report model."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GOLDEN = REPO / "tests" / "fixtures" / "golden" / "findings.json"


def run(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "issues.py"), *args],
        capture_output=True, text=True, cwd=cwd)


class TestIssues(unittest.TestCase):
    def test_lists_all_findings_with_exit_1_on_critical(self):
        proc = run(str(GOLDEN))
        self.assertEqual(proc.returncode, 1)  # criticals present -> gate trips
        self.assertIn("Database connection string with embedded credentials",
                      proc.stdout)
        self.assertIn("backend/config.py:9", proc.stdout)
        self.assertIn("HIPAA Risk Score", proc.stdout)
        # Reader-facing terms only.
        self.assertIn("Needs verification", proc.stdout)
        self.assertNotIn("deterministic", proc.stdout)

    def test_severity_filter(self):
        proc = run(str(GOLDEN), "--severity", "low")
        # The filter narrows the printed list only; a critical is still open,
        # so the gate still trips. A view filter must never disarm the gate.
        self.assertEqual(proc.returncode, 1)
        self.assertIn("JWT", proc.stdout)
        self.assertNotIn("Database connection string", proc.stdout)

    def test_gate_clean_when_no_critical_or_high(self):
        import tempfile
        data = json.loads(GOLDEN.read_text())
        data["findings"] = [f for f in data["findings"]
                            if f.get("severity") not in ("critical", "high")]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td, "findings.json")
            p.write_text(json.dumps(data))
            proc = run(str(p))
            self.assertEqual(proc.returncode, 0)

    def test_json_format(self):
        proc = run(str(GOLDEN), "--format", "json")
        data = json.loads(proc.stdout)
        self.assertEqual(len(data["findings"]), 7)
        self.assertIn("score", data)

    def test_missing_file_message(self):
        proc = run(cwd=str(REPO / "tests" / "fixtures"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Run an audit first", proc.stderr)

    def test_discovers_clearmap_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            d = Path(td, ".clearmap")
            d.mkdir()
            (d / "findings.json").write_text(GOLDEN.read_text())
            proc = run(cwd=td)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("7 open finding(s)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
