"""reason.py candidate selection.

An oversized source file must be RECORDED as skipped, not silently dropped, so a
large unreviewed file (PHI/AI-RAG code included) cannot masquerade as part of a
complete reasoning assessment. merge_reasoning then marks the layer incomplete.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import reason  # noqa: E402


class TestCandidates(unittest.TestCase):
    def test_oversized_file_is_recorded_not_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "small.py").write_text("x = 1\n")
            (root / "big.py").write_text("# pad\n" + ("y = 1\n" * 40_000))  # > 200 KB
            files, oversized = reason._candidates(root)
            names = {p.name for p in files}
            over = {p.name for p in oversized}
            self.assertIn("small.py", names)
            self.assertNotIn("big.py", names)   # not silently treated as reviewed
            self.assertIn("big.py", over)        # recorded so the manifest can flag it

    def test_no_candidates_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            files, oversized = reason._candidates(Path(td))
            self.assertEqual(files, [])
            self.assertEqual(oversized, [])


if __name__ == "__main__":
    unittest.main()
