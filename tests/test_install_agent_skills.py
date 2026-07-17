"""The Agent Skills installer produces a self-contained bundle and uninstall
removes only ClearMap-managed files."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "scripts" / "install_agent_skills.py"


class TestInstaller(unittest.TestCase):
    def _run(self, target, *args):
        return subprocess.run([sys.executable, str(INSTALLER), "--target", str(target), *args],
                              capture_output=True, text=True)

    def test_install_is_self_contained(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            self.assertEqual(self._run(proj, "--scope", "project").returncode, 0)
            base = proj / ".agents" / "skills"
            for skill in ("clearmap-development", "clearmap-audit"):
                self.assertTrue((base / skill / "SKILL.md").is_file(), skill)
            engine = base / "clearmap-engine"
            self.assertTrue((engine / "scripts" / "scan.py").is_file())
            self.assertTrue((engine / "rules").is_dir())
            self.assertTrue((engine / "references" / "taxonomy.json").is_file())
            # launcher keeps its bin/ subdir so its root resolution is correct
            self.assertTrue((engine / "bin" / "clearmap").is_file())
            # no dev-clone junk copied
            self.assertFalse((engine / "scripts" / "__pycache__").exists())

    def test_bundled_launcher_resolves_engine_root(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            self.assertEqual(self._run(proj).returncode, 0)
            launcher = proj / ".agents" / "skills" / "clearmap-engine" / "bin" / "clearmap"
            proc = subprocess.run([str(launcher), "--version"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("clearmap", proc.stdout.lower())

    def test_no_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            self.assertEqual(self._run(proj).returncode, 0)
            self.assertEqual(self._run(proj).returncode, 1)          # refuses
            self.assertEqual(self._run(proj, "--force").returncode, 0)  # allowed

    def test_uninstall_removes_only_managed(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            other = proj / ".agents" / "skills" / "someone-elses-skill"
            other.mkdir(parents=True)
            (other / "SKILL.md").write_text("keep me")
            self.assertEqual(self._run(proj).returncode, 0)
            self.assertEqual(self._run(proj, "--uninstall").returncode, 0)
            self.assertFalse((proj / ".agents" / "skills" / "clearmap-engine").exists())
            self.assertTrue((other / "SKILL.md").is_file())  # untouched

    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            self._run(proj, "--dry-run")
            self.assertFalse((proj / ".agents").exists())


if __name__ == "__main__":
    unittest.main()
