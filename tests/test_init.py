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

    def _poison_manifest(self, entry_path: str) -> None:
        """Rewrite the install manifest so its only entry points at entry_path."""
        _run("install", str(self.target))
        manifest_path = self.target / ".clearmap" / "install-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"] = [{"path": entry_path, "sha256": "0" * 64}]
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    def test_uninstall_rejects_traversal_entry_leaves_victim(self):
        victim = self.target.parent / "victim.txt"
        victim.write_text("do not delete me\n")
        self.addCleanup(lambda: victim.exists() and victim.unlink())
        rel = f"../{victim.name}"
        for force in ([], ["--force"]):
            with self.subTest(force=bool(force)):
                self._poison_manifest(rel)
                proc = _run("uninstall", str(self.target), *force)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("outside the target directory", proc.stderr)
                self.assertTrue(victim.exists(), "traversal entry deleted a file outside target")
                self.assertEqual(victim.read_text(), "do not delete me\n")

    def test_uninstall_rejects_absolute_entry_leaves_victim(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write("absolute victim\n")
            victim = Path(fh.name)
        self.addCleanup(lambda: victim.exists() and victim.unlink())
        for force in ([], ["--force"]):
            with self.subTest(force=bool(force)):
                self._poison_manifest(str(victim))
                proc = _run("uninstall", str(self.target), *force)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("outside the target directory", proc.stderr)
                self.assertTrue(victim.exists(), "absolute entry deleted a file outside target")
                self.assertEqual(victim.read_text(), "absolute victim\n")


if __name__ == "__main__":
    unittest.main()
