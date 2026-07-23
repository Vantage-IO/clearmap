"""--diff correctness: NUL-delimited changed-file discovery (paths with spaces
or non-ASCII must not be dropped) and gitleaks honoring the changed-file set."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan.py"
sys.path.insert(0, str(REPO / "scripts"))
import scan  # noqa: E402


def _git(root: Path, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True,
                   capture_output=True, text=True)


def _init_repo(root: Path):
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")


class TestSemgrepDiffTargets(unittest.TestCase):
    def test_diff_excludes_test_and_vendored_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            paths = [str(target / "src" / "app.py"),
                     str(target / "tests" / "test_app.py"),
                     str(target / "pkg" / "__tests__" / "x.ts"),
                     str(target / "node_modules" / "dep" / "d.js"),
                     str(target / "spec" / "e.rb"),
                     str(target / "notes.md")]  # non-source suffix
            out = scan._semgrep_targets(target, paths)
            self.assertIn(str(target / "src" / "app.py"), out)
            for excluded in ("tests", "__tests__", "node_modules", "spec", "notes.md"):
                self.assertFalse(any(excluded in p for p in out),
                                 f"{excluded} should be excluded in diff mode")


class TestChangedFiles(unittest.TestCase):
    def test_tricky_filenames_not_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _init_repo(root)
            (root / "base.py").write_text("x = 1\n")
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", "init")
            # untracked files with a space and a non-ASCII name
            (root / "my file.py").write_text("y = 2\n")
            (root / "café.py").write_text("z = 3\n")
            names = {Path(p).name for p in scan._changed_files(root)}
            self.assertIn("my file.py", names)
            self.assertIn("café.py", names)


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
class TestGitleaksHonorsDiff(unittest.TestCase):
    def test_diff_restricts_gitleaks_to_changed_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _init_repo(root)
            # a committed file with a secret (NOT changed since HEAD)
            (root / "committed.py").write_text(
                'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
                'SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", "init")
            # a changed (untracked) file with no secret
            (root / "changed.py").write_text("clean = 1\n")
            out = root / "f.json"
            proc = subprocess.run(
                [sys.executable, str(SCAN), str(root), "--diff", "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(out.read_text())
            files = {f["file"] for f in data["findings"] if f["engine"] == "gitleaks"}
            # --diff scanned only the clean changed file, so the committed
            # secret must NOT appear.
            self.assertNotIn("committed.py", files)


if __name__ == "__main__":
    unittest.main()
