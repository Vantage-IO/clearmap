"""End-to-end PHI-leak test.

Scans tests/fixtures/phi-canary (every literal in it is FAKE) and asserts that
no canary value survives into findings.json or any rendered report, in any
format. Also asserts the scan finds something — a zero-finding run would make
the leak assertions vacuous.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan.py"
REPORT = REPO / "scripts" / "report.py"
FIXTURE = REPO / "tests" / "fixtures" / "phi-canary"

CANARIES = [
    "987-65-4329",                      # SSN
    "jane.canary@example.org",          # email
    "4455667",                          # MRN digits
    "CanaryPass99XyZ",                  # DB password
    "canaryAAAABBBBCCCCDDDD1234",       # sk- key body
    "ehr_test_canary1234567890",        # EHR key
]


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *cmd], capture_output=True, text=True)


def _report_supports_html() -> bool:
    proc = _run([str(REPORT), "--help"])
    return "--format" in proc.stdout


class TestPhiLeakE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="clearmap-e2e-")
        cls.out = Path(cls.tmp.name)
        cls.findings = cls.out / "findings.json"
        proc = _run([str(SCAN), str(FIXTURE), "--out", str(cls.findings)])
        assert proc.returncode == 0, proc.stderr

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _assert_clean(self, text: str, label: str):
        for canary in CANARIES:
            self.assertNotIn(canary, text, f"canary {canary!r} leaked into {label}")

    def test_scan_finds_something(self):
        data = json.loads(self.findings.read_text())
        self.assertGreaterEqual(len(data["findings"]), 3,
                                "canary fixture must trigger findings or leak tests are vacuous")

    def test_findings_json_clean_and_placeholders_present(self):
        text = self.findings.read_text()
        self._assert_clean(text, "findings.json")
        self.assertIn("[SSN]", text)
        self.assertIn("[EMAIL]", text)
        self.assertIn("[MRN]", text)

    def test_markdown_report_clean(self):
        md = self.out / "report.md"
        proc = _run([str(REPORT), str(self.findings), "--repo", "phi-canary",
                     "--date", "2026-01-01", "--out", str(md)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self._assert_clean(md.read_text(), "markdown report")

    def test_html_report_clean(self):
        if not _report_supports_html():
            self.skipTest("report.py --format not implemented yet (Task 4)")
        html = self.out / "report.html"
        proc = _run([str(REPORT), str(self.findings), "--repo", "phi-canary",
                     "--date", "2026-01-01", "--format", "html", "--out", str(html)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self._assert_clean(html.read_text(), "HTML report")


if __name__ == "__main__":
    unittest.main()
