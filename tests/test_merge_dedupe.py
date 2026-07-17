"""merge_reasoning.py overlap dedupe — a flaw caught by both layers must score once.

Without this dedupe, every also_detectable_by finding would double-deduct.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MERGE = REPO / "scripts" / "merge_reasoning.py"


def _det(category, file, line):
    return {"rule_id": "r", "category": category, "severity": "critical",
            "source": "deterministic", "engine": "semgrep", "file": file,
            "line": line, "title": "t", "structural_snippet": "s", "why": "w"}


def _rea(fid, category, file, line, sev="critical"):
    return {"id": fid, "category": category, "severity": sev,
            "source": "reasoning", "confidence": "high", "file": file,
            "line": line, "title": "t", "structural_snippet": "s", "why": "w"}


class TestMergeDedupe(unittest.TestCase):
    def _merge(self, det_findings, rea_findings):
        with tempfile.TemporaryDirectory() as td:
            d, r, out = Path(td, "d.json"), Path(td, "r.json"), Path(td, "o.json")
            d.write_text(json.dumps({"findings": det_findings}))
            r.write_text(json.dumps({"findings": rea_findings}))
            proc = subprocess.run([sys.executable, str(MERGE), str(d), str(r),
                                   "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(out.read_text())["findings"]

    def test_same_flaw_both_layers_scores_once(self):
        # det anchors the decorator (line 13), agent cites the body (line 20)
        merged = self._merge([_det("AUTH", "api/patients.py", 13)],
                             [_rea("AUTH-01", "AUTH", "api/patients.py", 20)])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "deterministic")

    def test_distinct_findings_survive(self):
        merged = self._merge(
            [_det("AUTH", "api/patients.py", 13)],
            [_rea("AUTH-01", "AUTH", "api/other.py", 20),               # other file
             _rea("AUDIT-01", "AUDIT", "api/patients.py", 14, sev="high"),  # other category
             _rea("AUTH-01", "AUTH", "api/patients.py", 40)])           # far line
        self.assertEqual(len(merged), 4)


if __name__ == "__main__":
    unittest.main()
