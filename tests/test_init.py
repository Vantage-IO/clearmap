"""init.py — install/uninstall round-trip must leave the target byte-identical.

Adapters installed, engines checked, reversible uninstall, never touches
application code.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INIT = REPO / "scripts" / "init.py"


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(INIT), *args],
                          capture_output=True, text=True)


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


class TestInit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="clearmap-init-")
        self.target = Path(self._tmp.name)
        (self.target / "app").mkdir()
        (self.target / "app" / "main.py").write_text("print('app')\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_install_uninstall_round_trip_byte_identical(self):
        before = _tree(self.target)
        proc = _run("install", str(self.target))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        manifest = self.target / ".clearmap" / "install-manifest.json"
        self.assertTrue(manifest.exists())
        self.assertTrue((self.target / ".claude" / "skills" / "clearmap" / "SKILL.md").exists())
        self.assertTrue((self.target / ".clearmapignore").exists())
        # application code untouched
        self.assertEqual((self.target / "app" / "main.py").read_text(), "print('app')\n")
        proc = _run("uninstall", str(self.target))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(_tree(self.target), before)

    def test_uninstall_refuses_modified_file_without_force(self):
        _run("install", str(self.target))
        (self.target / ".clearmapignore").write_text("user edits\n")
        proc = _run("uninstall", str(self.target))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("modified after install", proc.stderr)
        proc = _run("uninstall", str(self.target), "--force")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_double_install_refused_without_force(self):
        _run("install", str(self.target))
        proc = _run("install", str(self.target))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("already installed", proc.stderr)

    def test_doctor_reports_engines(self):
        proc = _run("doctor", str(self.target))
        self.assertIn("semgrep", proc.stdout)
        self.assertIn("gitleaks", proc.stdout)

    def test_manifest_lists_all_created_files(self):
        _run("install", str(self.target))
        manifest = json.loads(
            (self.target / ".clearmap" / "install-manifest.json").read_text())
        rels = {e["path"] for e in manifest["files"]}
        self.assertEqual(rels, {".claude/skills/clearmap/SKILL.md", ".clearmapignore"})


if __name__ == "__main__":
    unittest.main()
