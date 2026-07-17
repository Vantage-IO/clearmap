"""Presidio opt-in: the zero-dependency default must never break.

With presidio-analyzer absent, `scan.py --presidio` exits 0, scans normally,
and notes the skip on stderr. Without the flag, presidio code never loads.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan.py"
FIXTURE = REPO / "tests" / "fixtures" / "phi-canary"


def _presidio_installed() -> bool:
    return subprocess.run(
        [sys.executable, "-c", "import presidio_analyzer"],
        capture_output=True).returncode == 0


class TestPresidioOptional(unittest.TestCase):
    def test_flag_with_presidio_absent_exits_zero(self):
        if _presidio_installed():
            self.skipTest("presidio installed — absence path not testable here")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "f.json")
            proc = subprocess.run(
                [sys.executable, str(SCAN), str(FIXTURE), "--presidio",
                 "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("presidio", proc.stderr.lower())
            data = json.loads(out.read_text())
            self.assertGreaterEqual(len(data["findings"]), 3)
            self.assertEqual(data["engines"].get("presidio"), "not-installed")

    def test_no_flag_no_presidio_stamp(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "f.json")
            subprocess.run([sys.executable, str(SCAN), str(FIXTURE),
                            "--out", str(out)], capture_output=True, check=True)
            data = json.loads(out.read_text())
            self.assertNotIn("presidio", data["engines"])


if __name__ == "__main__":
    unittest.main()
