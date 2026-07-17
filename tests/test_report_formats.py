"""Report output formats: the machine-readable JSON report and the closing note
that appears on every generated report and audit summary."""
import json
import sys
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


class TestReportFormats(unittest.TestCase):
    def model(self):
        return report.build_model(
            {"findings": [det()], "source_layer": "deterministic+reasoning", "scan_ok": True},
            "repo", "2026-01-01")

    def test_json_report_is_valid_and_complete(self):
        doc = json.loads(report.render_json(self.model()))
        self.assertEqual(doc["score_state"], "complete")
        self.assertIsInstance(doc["score"], int)
        self.assertTrue(doc["findings"])
        self.assertIn("category", doc["findings"][0])
        self.assertIn("assessment", doc)
        self.assertIn("counts", doc)

    def test_closing_note_hints_partial_and_links(self):
        doc = json.loads(report.render_json(self.model()))
        self.assertIn("partial", doc["closing_note"].lower())
        self.assertIn("vantageio.com", doc["closing_note"])

    def test_partial_note_in_md_and_html(self):
        m = self.model()
        for out in (report.render_md(m), render_html(m)):
            self.assertIn("vantageio.com", out)
            self.assertIn("partial", out.lower())

    def test_json_passes_banned_phrase_guard(self):
        self.assertIsNone(report.check_banned(report.render_json(self.model())))

    def _egress(self, reasoning=None, source_layer="deterministic+reasoning"):
        data = {"findings": [det()], "source_layer": source_layer, "scan_ok": True}
        if reasoning is not None:
            data["reasoning"] = reasoning
        m = report.build_model(data, "repo", "2026-01-01")
        return next(s for s in m["scope"] if "locally" in s or "reviewed" in s.lower())

    def test_egress_is_provider_honest(self):
        # deterministic-only and local-model: nothing left the machine
        self.assertIn("no source code or PHI left",
                      self._egress(source_layer="deterministic"))
        self.assertIn("no source code or PHI left", self._egress(
            {"provider": "openai-compatible", "manifest": {"privacy_mode": "local-only"}}))
        # host-agent and remote model: must NOT claim nothing left
        host = self._egress({"provider": "host-agent"})
        self.assertNotIn("no source code or PHI left", host)
        self.assertIn("agent's model provider", host)
        remote = self._egress({"provider": "openai-compatible", "model": "gpt-x",
                               "manifest": {"privacy_mode": "provider-managed"}})
        self.assertNotIn("no source code or PHI left", remote)
        self.assertIn("sent the reviewed files", remote)

    def test_unavailable_json_has_null_score(self):
        m = report.build_model(
            {"findings": [det()], "source_layer": "deterministic", "scan_ok": False,
             "engine_status": {"semgrep": {"status": "timeout"}, "gitleaks": {"status": "success"}}},
            "repo", "2026-01-01")
        doc = json.loads(report.render_json(m))
        self.assertIsNone(doc["score"])
        self.assertEqual(doc["score_state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
