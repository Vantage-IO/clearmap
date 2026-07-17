"""Score integrity and the three score states.

- complete: engines ran and reasoning ran -> a full score.
- incomplete / automated-layer-only: engines ran, reasoning did not -> a REAL
  qualified score with the "(automated layer only)" banner (not "unavailable").
- unavailable: a required engine failed -> the number is withheld.

Also guards the scoring.py CLI regression: it must thread source_layer so a
deterministic-only file does not silently score the reasoning-only categories
(AI-RAG, AUDIT, ~45% of the weight) as clean 100s.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import report  # noqa: E402
from report_html import render_html  # noqa: E402


def det(cat="TRANSIT", sev="critical", ref="164.312(e)(1)"):
    return {"category": cat, "severity": sev, "source": "deterministic", "engine": "semgrep",
            "rule_id": "r", "file": "a.py", "line": 1, "title": "A finding",
            "hipaa_ref": ref, "structural_snippet": "", "why": "why", "remediation": "fix"}


class TestScoreStates(unittest.TestCase):
    def build(self, data):
        return report.build_model(data, "repo", "2026-01-01")

    def test_complete(self):
        m = self.build({"findings": [det()], "source_layer": "deterministic+reasoning",
                        "scan_ok": True})
        self.assertEqual(m["score_state"], "complete")
        md = report.render_md(m)
        self.assertNotIn("Score unavailable", md)
        self.assertNotIn("automated layer only", md)
        self.assertRegex(md, r"\d+/100")

    def test_incomplete_is_still_a_qualified_score(self):
        # deterministic-only: AI-RAG + AUDIT apply (default) but were not reviewed.
        m = self.build({"findings": [det()], "source_layer": "deterministic", "scan_ok": True})
        self.assertEqual(m["score_state"], "incomplete")
        self.assertTrue(m["scores"]["not_reviewed_categories"])
        md = report.render_md(m)
        self.assertIn("(automated layer only)", md)
        self.assertNotIn("Score unavailable", md)
        self.assertRegex(md, r"\d+/100")  # a real number is still shown

    def test_unavailable_on_engine_failure(self):
        m = self.build({"findings": [det()], "source_layer": "deterministic", "scan_ok": False,
                        "engine_status": {"semgrep": {"status": "timeout"},
                                          "gitleaks": {"status": "success"}}})
        self.assertEqual(m["score_state"], "unavailable")
        self.assertIn("semgrep", m["score_reason"])
        for out in (report.render_md(m), render_html(m)):
            self.assertIn("Score unavailable", out)
        # the headline presents "unavailable", never a number
        headline = [ln for ln in report.render_md(m).splitlines()
                    if "Technical Risk Score:" in ln][0]
        self.assertIn("unavailable", headline)
        self.assertNotRegex(headline, r"\d+/100")

    def test_assessment_block(self):
        m = self.build({"findings": [det()], "source_layer": "deterministic+reasoning",
                        "scan_ok": True, "reasoning": {"provider": "host-agent", "model": "x"}})
        a = m["assessment"]
        self.assertEqual(a["automated_layer"], "complete")
        self.assertEqual(a["reasoning_layer"], "complete")
        self.assertEqual(a["reasoning_provider"], "host-agent")

    def test_scoring_cli_threads_source_layer(self):
        """Regression: the standalone scoring CLI must not inflate a det-only run."""
        data = {"findings": [det()], "source_layer": "deterministic"}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        proc = subprocess.run([sys.executable, str(REPO / "scripts" / "scoring.py"), path],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout)
        self.assertTrue(res["not_reviewed_categories"],
                        "CLI scored reasoning-only categories as reviewed (source_layer dropped)")


if __name__ == "__main__":
    unittest.main()
