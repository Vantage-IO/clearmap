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
        (target / ".clearmap" / "reasoning.json").write_text(json.dumps(
            {"provider": "manual", "manifest": {"batches_completed": 1, "batches_failed": 0},
             "findings": []}))
        env = dict(os.environ, XDG_CONFIG_HOME=str(Path(tmp.name) / "cfg"))
        proc = subprocess.run(
            [sys.executable, str(AUDIT), str(target), "--provider", "manual", "--format", "md"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Assessment: Complete", proc.stdout)


if __name__ == "__main__":
    unittest.main()
