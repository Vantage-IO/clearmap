"""Acknowledgments: user-documented accepted risks.

An acknowledgment accepts a valid finding as documented risk (owner + date +
reason, optional expiry). It must: load only well-formed entries, refuse
compliance-claim wording, match findings by reference (and optional file), lapse
when expired, and be EXCLUDED from the score (deductions + ceiling + counts)
while staying visible in the report and its appendix.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import acknowledgments as A  # noqa: E402
import report  # noqa: E402
import scoring  # noqa: E402


def _write(entries):
    d = Path(tempfile.mkdtemp())
    (d / "clearmap-acknowledgments.json").write_text(json.dumps({"acknowledgments": entries}))
    return d


def _ack(**over):
    e = {"reference": "AI-RAG-01", "owner": "sam@example.com", "date": "2026-07-20",
         "reason": "Covered by a signed BAA with zero data retention."}
    e.update(over)
    return e


def det(cat="TRANSIT", sev="critical", rule="r1", file="a.py"):
    return {"category": cat, "severity": sev, "source": "deterministic", "engine": "semgrep",
            "rule_id": rule, "file": file, "line": 1, "title": "A finding",
            "hipaa_ref": "164.312(e)(1)", "structural_snippet": "", "why": "w"}


class TestLoad(unittest.TestCase):
    def test_missing_file_is_empty(self):
        self.assertEqual(A.load(Path(tempfile.mkdtemp())), [])

    def test_valid_entry_loads(self):
        acks = A.load(_write([_ack()]))
        self.assertEqual(len(acks), 1)
        self.assertEqual(acks[0]["reference"], "AI-RAG-01")

    def test_missing_required_fields_skipped(self):
        self.assertEqual(A.load(_write([{"reference": "X"}])), [])

    def test_bad_date_skipped(self):
        self.assertEqual(A.load(_write([_ack(date="2026/07/20")])), [])

    def test_short_reason_skipped(self):
        self.assertEqual(A.load(_write([_ack(reason="ok")])), [])

    def test_compliance_claim_rejected(self):
        # both the shared banned list and the stricter "hipaa compliant" guard
        self.assertEqual(A.load(_write([_ack(reason="This makes us HIPAA compliant now.")])), [])
        self.assertEqual(A.load(_write([_ack(reason="We are fully compliant, trust us.")])), [])

    def test_hipaa_compliance_noun_is_allowed(self):
        acks = A.load(_write([_ack(reason="Part of our HIPAA compliance program, BAA on file.")]))
        self.assertEqual(len(acks), 1)

    def test_one_bad_entry_does_not_sink_the_good_one(self):
        acks = A.load(_write([{"reference": "X"}, _ack(reference="AUDIT-01")]))
        self.assertEqual([a["reference"] for a in acks], ["AUDIT-01"])

    def test_owner_is_redacted(self):
        # Owner is free text that reaches the report; PHI pasted into it (e.g. an
        # SSN) must be redacted just like the reason field.
        acks = A.load(_write([_ack(owner="Owner 123-45-6789")]))
        self.assertEqual(len(acks), 1)
        self.assertNotIn("123-45-6789", acks[0]["owner"])
        self.assertIn("[SSN]", acks[0]["owner"])


class TestMatchAndApply(unittest.TestCase):
    def test_matches_by_reference(self):
        findings = [det(rule="r1"), det(rule="r2")]
        A.apply(findings, [_ack(reference="r1")], "2026-07-20")
        self.assertTrue(findings[0].get("acknowledged"))
        self.assertFalse(findings[1].get("acknowledged"))

    def test_file_narrows_the_match(self):
        findings = [det(rule="r1", file="a.py"), det(rule="r1", file="b.py")]
        A.apply(findings, [_ack(reference="r1", file="a.py")], "2026-07-20")
        self.assertTrue(findings[0].get("acknowledged"))
        self.assertFalse(findings[1].get("acknowledged"))

    def test_expired_does_not_acknowledge(self):
        findings = [det(rule="r1")]
        summ = A.apply(findings, [_ack(reference="r1", expires="2020-01-01")], "2026-07-20")
        self.assertFalse(findings[0].get("acknowledged"))
        self.assertTrue(findings[0].get("acknowledgment_expired"))
        self.assertEqual(summ["n_expired"], 1)
        self.assertEqual(summ["n_acknowledged"], 0)

    def test_future_expiry_is_active(self):
        findings = [det(rule="r1")]
        summ = A.apply(findings, [_ack(reference="r1", expires="2099-01-01")], "2026-07-20")
        self.assertTrue(findings[0].get("acknowledged"))
        self.assertEqual(summ["n_acknowledged"], 1)


class TestScoring(unittest.TestCase):
    def test_acknowledged_finding_does_not_deduct_or_cap(self):
        findings = [det(sev="critical", rule="r1")]
        base = scoring.score_findings([dict(findings[0])])
        findings[0]["acknowledged"] = {"owner": "o", "date": "d", "reason": "r"}
        acked = scoring.score_findings(findings)
        self.assertEqual(base["ceiling_applied"], 75)   # a live critical caps at 75
        self.assertEqual(acked["ceiling_applied"], 95)  # acknowledged: no active critical
        self.assertEqual(acked["n_critical"], 0)
        self.assertEqual(acked["n_acknowledged"], 1)
        self.assertGreater(acked["score"], base["score"])

    def test_all_acknowledged_never_reaches_100(self):
        findings = [det(sev="critical", rule="r1")]
        findings[0]["acknowledged"] = {"owner": "o", "date": "d", "reason": "r"}
        self.assertLessEqual(scoring.score_findings(findings)["score"], 95)

    def test_expired_still_scores(self):
        findings = [det(sev="critical", rule="r1")]
        A.apply(findings, [_ack(reference="r1", expires="2020-01-01")], "2026-07-20")
        self.assertEqual(scoring.score_findings(findings)["ceiling_applied"], 75)


class TestReport(unittest.TestCase):
    def build(self, findings, acks):
        data = {"findings": findings, "source_layer": "deterministic+reasoning",
                "scan_ok": True, "reasoning": {"provider": "host-agent", "complete": True}}
        return report.build_model(data, "repo", "2026-07-20", acknowledgments=acks)

    def test_acknowledged_finding_shows_and_appendix_renders(self):
        acks = A.load(_write([_ack(reference="r1", reason="Covered by BAA, zero retention.")]))
        m = self.build([det(sev="critical", rule="r1")], acks)
        self.assertEqual(m["n_acknowledged"], 1)
        self.assertEqual(len(m["acknowledgments"]), 1)
        md = report.render_md(m)
        from report_html import render_html
        html = render_html(m)
        for out in (md, html):
            self.assertIn("Acknowledgments", out)
            self.assertIn("Acknowledged", out)
            self.assertIsNone(report.check_banned(out))
            self.assertNotIn("—", out)  # house style: no em dash
        # not paraded as a priority action item
        self.assertNotIn("Remediate the 1 critical", md)

    def test_no_acknowledgments_no_appendix(self):
        m = self.build([det(sev="high", rule="r1")], [])
        self.assertEqual(m["n_acknowledged"], 0)
        self.assertNotIn("Appendix: Acknowledgments", report.render_md(m))

    def test_expired_acknowledgment_flagged_in_report(self):
        acks = A.load(_write([_ack(reference="r1", expires="2020-01-01",
                                   reason="Was covered by BAA, now lapsed.")]))
        m = self.build([det(sev="critical", rule="r1")], acks)
        self.assertEqual(m["n_acknowledged"], 0)
        self.assertEqual(m["n_acknowledgments_expired"], 1)
        self.assertEqual(m["scores"]["n_critical"], 1)  # scored again
        self.assertIn("expired", report.render_md(m).lower())


SCRIPT = REPO / "scripts" / "acknowledgments.py"


class TestCLI(unittest.TestCase):
    def _run(self, target, *args):
        import subprocess
        return subprocess.run([sys.executable, str(SCRIPT), *args, "--target", str(target)],
                              capture_output=True, text=True)

    def _entries(self, target):
        p = target / "clearmap-acknowledgments.json"
        return json.loads(p.read_text())["acknowledgments"] if p.is_file() else []

    def test_add_writes_valid_entry(self):
        d = Path(tempfile.mkdtemp())
        r = self._run(d, "add", "--reference", "AI-RAG-01", "--owner", "a@b.com",
                      "--reason", "Covered by BAA with zero data retention.")
        self.assertEqual(r.returncode, 0, r.stderr)
        e = self._entries(d)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["reference"], "AI-RAG-01")
        self.assertTrue(e[0]["date"])  # defaulted to today

    def test_add_same_reference_replaces(self):
        d = Path(tempfile.mkdtemp())
        self._run(d, "add", "--reference", "R", "--owner", "a@b.com", "--reason", "first reason here")
        self._run(d, "add", "--reference", "R", "--owner", "a@b.com", "--reason", "second reason here")
        e = self._entries(d)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["reason"], "second reason here")

    def test_add_rejects_compliance_claim(self):
        d = Path(tempfile.mkdtemp())
        r = self._run(d, "add", "--reference", "R", "--owner", "a@b.com",
                      "--reason", "this makes us HIPAA compliant")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self._entries(d), [])

    def test_remove(self):
        d = Path(tempfile.mkdtemp())
        self._run(d, "add", "--reference", "R", "--owner", "a@b.com", "--reason", "a real reason here")
        r = self._run(d, "remove", "--reference", "R")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._entries(d), [])

    def test_list_empty(self):
        d = Path(tempfile.mkdtemp())
        r = self._run(d, "list")
        self.assertEqual(r.returncode, 0)
        self.assertIn("No acknowledgments", r.stdout)


if __name__ == "__main__":
    unittest.main()
