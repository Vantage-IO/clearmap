"""issues.py: compact open-findings list over the report model."""
import json
import subprocess
import sys
import tempfile
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
        # The view is filtered to low, but the exit-1 gate reflects the WHOLE
        # finding set: criticals exist, so the gate still trips (was the bug).
        self.assertEqual(proc.returncode, 1)
        self.assertIn("JWT", proc.stdout)
        self.assertNotIn("Database connection string", proc.stdout)

    def test_gate_independent_of_severity_filter(self):
        # Same critical-tripping gate regardless of which severities are shown.
        for flt in (["--severity", "low"], ["--severity", "medium,low"],
                    ["--severity", "critical"]):
            proc = run(str(GOLDEN), *flt)
            self.assertEqual(proc.returncode, 1, f"filter {flt}")

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
        with tempfile.TemporaryDirectory() as td:
            d = Path(td, ".clearmap")
            d.mkdir()
            (d / "findings.json").write_text(GOLDEN.read_text())
            proc = run(cwd=td)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("7 open finding(s)", proc.stdout)

    def test_agrees_with_report_on_acknowledged(self):
        # issues must load acknowledgments and evaluate expiry the same way the
        # report does, so score, acknowledged status, and the gate never disagree.
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            cm = repo / ".clearmap"
            cm.mkdir()
            findings = {
                "findings": [{
                    "category": "SECRETS", "severity": "critical", "source": "deterministic",
                    "engine": "semgrep", "rule_id": "R-CRIT", "file": "config.py", "line": 9,
                    "title": "Embedded credentials", "hipaa_ref": "164.312(a)(2)(i)",
                    "structural_snippet": "", "why": "w"}],
                "source_layer": "deterministic+reasoning",
                "reasoning": {"provider": "host-agent", "complete": True}}
            (cm / "findings.json").write_text(json.dumps(findings))
            (repo / "clearmap-acknowledgments.json").write_text(json.dumps({"acknowledgments": [
                {"reference": "R-CRIT", "owner": "sam@example.com", "date": "2026-01-01",
                 "reason": "Injected from the secret manager at deploy time, not committed."}]}))

            # issues: acknowledged critical does not trip the gate, shows Acknowledged.
            iss = run(cwd=str(repo))  # discovers .clearmap/findings.json
            self.assertEqual(iss.returncode, 0, iss.stderr + iss.stdout)
            self.assertIn("Acknowledged", iss.stdout)
            iss_json = json.loads(run(str(cm / "findings.json"), "--format", "json").stdout)

            # report json for the same findings + acks.
            rep = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "report.py"), str(cm / "findings.json"),
                 "--repo-path", str(repo), "--format", "json", "--out", str(cm / "r.md")],
                capture_output=True, text=True)
            self.assertEqual(rep.returncode, 0, rep.stderr)
            rep_json = json.loads((cm / "r.json").read_text())

            self.assertEqual(iss_json["score"], rep_json["score"])   # agree on score
            self.assertEqual(rep_json["score"], 95)                  # acknowledged critical
            self.assertEqual(rep_json["acknowledged_count"], 1)
            self.assertEqual(iss_json["findings"][0]["status"], "Acknowledged")


if __name__ == "__main__":
    unittest.main()
