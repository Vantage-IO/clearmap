"""calibrate.py input-shape handling.

_findings must accept any of the three on-disk shapes a candidate/expected file
can take: a wrapped object ({"findings": [...]}), an expected-findings manifest
({"must_catch": [...]}), or a bare top-level JSON array. A bare array must not
crash with AttributeError (list has no .get).
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import calibrate  # noqa: E402

F = {"id": "AUTH-01", "category": "AUTH", "severity": "critical",
     "source": "reasoning", "file": "a.py", "line": 3}


class TestCalibrateInputShapes(unittest.TestCase):
    def _findings(self, payload, source="all"):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            p = Path(fh.name)
        self.addCleanup(lambda: p.exists() and p.unlink())
        return calibrate._findings(p, source)

    def test_top_level_list_does_not_crash(self):
        out = self._findings([F])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "AUTH-01")

    def test_findings_object(self):
        self.assertEqual(len(self._findings({"findings": [F]})), 1)

    def test_must_catch_fallback_preserved(self):
        self.assertEqual(len(self._findings({"must_catch": [F, F]})), 2)

    def test_source_filter_still_applies_on_list(self):
        det = {**F, "source": "deterministic"}
        self.assertEqual(len(self._findings([F, det], source="reasoning")), 1)


if __name__ == "__main__":
    unittest.main()
