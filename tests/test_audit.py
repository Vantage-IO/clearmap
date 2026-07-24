"""clearmap audit orchestration: host-agent (no agent) yields an explicit
automated-layer-only result, --require-complete flags it, and manual without a
reasoning.json refuses. Uses the safe fixture (fast) and an isolated config."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
AUDIT = REPO / "scripts" / "audit.py"
SCAN = REPO / "scripts" / "scan.py"
SAFE = REPO / "examples" / "safe-health-app"


@unittest.skipUnless(shutil.which("semgrep") and shutil.which("gitleaks"),
                     "engines not installed")
class TestAudit(unittest.TestCase):
    def _audit(self, *args):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "app"
        shutil.copytree(SAFE, target)
        env = dict(os.environ, XDG_CONFIG_HOME=str(Path(tmp.name) / "cfg"))
        for k in ("CLEARMAP_REASONING_PROVIDER", "CLEARMAP_MODEL_BASE_URL"):
            env.pop(k, None)
        proc = subprocess.run([sys.executable, str(AUDIT), str(target), "--format", "md", *args],
                              capture_output=True, text=True, env=env)
        return proc, target

    def test_host_agent_incomplete_is_explicit(self):
        proc, target = self._audit()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Automated layer only", proc.stdout)
        self.assertIn("Not reviewed", proc.stdout)
        self.assertTrue((target / ".clearmap" / "clearmap-report.md").is_file())

    def test_require_complete_flags_incomplete(self):
        proc, _ = self._audit("--require-complete")
        self.assertEqual(proc.returncode, 3)

    def test_manual_without_reasoning_refuses(self):
        proc, _ = self._audit("--provider", "manual")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("reasoning.json", proc.stderr)

    def test_manual_with_reasoning_completes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "app"
        shutil.copytree(SAFE, target)
        (target / ".clearmap").mkdir()
        env = dict(os.environ, XDG_CONFIG_HOME=str(Path(tmp.name) / "cfg"))
        # Scan first to learn this scan's fingerprint; a manual manifest is only
        # Complete when it binds to that fingerprint (and audit re-scans to the same).
        det = target / ".clearmap" / "findings-deterministic.json"
        subprocess.run([sys.executable, str(SCAN), str(target), "--out", str(det)],
                       capture_output=True, text=True, env=env, check=True)
        fp = json.loads(det.read_text())["scan"]["fingerprint"]
        (target / ".clearmap" / "reasoning.json").write_text(json.dumps(
            {"provider": "manual",
             "manifest": {"scan_fingerprint": fp, "batches_completed": 1, "batches_failed": 0,
                          "truncated": False, "files_skipped": []},
             "findings": []}))
        proc = subprocess.run(
            [sys.executable, str(AUDIT), str(target), "--provider", "manual", "--format", "md"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Assessment: Complete", proc.stdout)

    def test_manual_with_stale_reasoning_is_incomplete(self):
        """A reasoning.json bound to a DIFFERENT scan is ignored, not trusted."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "app"
        shutil.copytree(SAFE, target)
        (target / ".clearmap").mkdir()
        env = dict(os.environ, XDG_CONFIG_HOME=str(Path(tmp.name) / "cfg"))
        (target / ".clearmap" / "reasoning.json").write_text(json.dumps(
            {"provider": "manual",
             "manifest": {"scan_fingerprint": "deadbeefdeadbeef", "batches_failed": 0,
                          "truncated": False, "files_skipped": []},
             "findings": []}))
        proc = subprocess.run(
            [sys.executable, str(AUDIT), str(target), "--provider", "manual", "--format", "md",
             "--require-complete"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("different scan revision", proc.stderr)


class TestReadOnlyGuarantee(unittest.TestCase):
    """SECURITY.md: ClearMap writes only inside .clearmap/. It must not modify the
    scanned repo's own .gitignore. It self-ignores from inside the output directory
    instead. This holds with or without the engines installed, because the
    self-ignore is written before any scanning happens (so no engine gate here)."""

    def test_self_ignore_never_touches_the_scanned_repo_gitignore(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "app"
        target.mkdir()
        (target / ".gitignore").write_text("node_modules/\n")
        env = dict(os.environ, XDG_CONFIG_HOME=str(Path(tmp.name) / "cfg"))
        for k in ("CLEARMAP_REASONING_PROVIDER", "CLEARMAP_MODEL_BASE_URL"):
            env.pop(k, None)
        subprocess.run([sys.executable, str(AUDIT), str(target), "--format", "md",
                        "--skip-reasoning"], capture_output=True, text=True, env=env)
        # The scanned repo's own .gitignore is untouched.
        self.assertEqual((target / ".gitignore").read_text(), "node_modules/\n")
        # A self-ignore was written INSIDE the output directory instead.
        self_ignore = target / ".clearmap" / ".gitignore"
        self.assertTrue(self_ignore.is_file())
        self.assertEqual(self_ignore.read_text(), "*\n")


if __name__ == "__main__":
    unittest.main()
