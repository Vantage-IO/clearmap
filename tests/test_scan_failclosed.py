"""Fail-closed engine behavior for scripts/scan.py.

A missing, erroring, malformed, or timed-out REQUIRED engine must make the scan
exit non-zero and mark the output not-ok, so a "0 findings because the engine
did not run" can never be mistaken for a clean scan. Engines are stubbed with
fake executables on an isolated PATH; no real semgrep/gitleaks is used.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan.py"
PY = sys.executable

FAKE_SEMGREP = f"""#!{PY}
import os, sys, time
a = sys.argv[1:]
if a[:1] == ["--version"]:
    print("1.164.0"); sys.exit(0)
m = os.environ.get("FAKE_SEMGREP", "ok")
if m == "error":
    sys.stderr.write("engine boom\\n"); sys.exit(2)
if m == "config":
    sys.stderr.write("Invalid rule schema\\n"); sys.exit(2)
if m == "malformed":
    sys.stdout.write("<<<not-json>>>\\n"); sys.exit(0)
if m == "timeout":
    time.sleep(5); sys.exit(0)
sys.stdout.write('{{"results": []}}\\n'); sys.exit(0)
"""

FAKE_GITLEAKS = f"""#!{PY}
import os, sys, time
a = sys.argv[1:]
if a[:1] == ["version"]:
    print("8.30.1"); sys.exit(0)
m = os.environ.get("FAKE_GITLEAKS", "ok")
rp = None
for i, x in enumerate(a):
    if x == "--report-path":
        rp = a[i + 1]
if m == "error":
    sys.stderr.write("gitleaks boom\\n"); sys.exit(2)
if m == "malformed":
    if rp: open(rp, "w").write("{{not-json")
    sys.exit(1)
if m == "timeout":
    time.sleep(5); sys.exit(0)
if m == "leaks":
    if rp:
        open(rp, "w").write('[{{"RuleID":"generic-api-key","File":"a.py",'
                            '"StartLine":1,"Description":"k","Match":"z"}}]')
    sys.exit(1)
if rp: open(rp, "w").write("[]")
sys.exit(0)
"""


class FailClosedCase(unittest.TestCase):
    def run_scan(self, *, semgrep="ok", gitleaks="ok", install=("semgrep", "gitleaks"),
                 timeout=30):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        bind = root / "bin"
        bind.mkdir()
        target = root / "repo"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        for name, body in (("semgrep", FAKE_SEMGREP), ("gitleaks", FAKE_GITLEAKS)):
            if name in install:
                p = bind / name
                p.write_text(body)
                p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        out = root / "findings.json"
        env = dict(os.environ, PATH=str(bind), FAKE_SEMGREP=semgrep, FAKE_GITLEAKS=gitleaks)
        proc = subprocess.run(
            [PY, str(SCAN), str(target), "--out", str(out),
             "--engine-timeout", str(timeout)],
            capture_output=True, text=True, env=env,
        )
        data = json.loads(out.read_text()) if out.exists() else None
        return proc.returncode, data

    def assert_failed(self, rc, data, engine, status):
        self.assertEqual(rc, 2, "a failed required engine must exit 2")
        self.assertIsNotNone(data, "an unusable findings file should still be written")
        self.assertFalse(data["scan_ok"], "scan_ok must be False")
        self.assertEqual(data["engine_status"][engine]["status"], status)

    def test_both_healthy(self):
        rc, data = self.run_scan()
        self.assertEqual(rc, 0)
        self.assertTrue(data["scan_ok"])
        self.assertEqual(data["engine_status"]["semgrep"]["status"], "success")
        self.assertEqual(data["engine_status"]["gitleaks"]["status"], "success")

    def test_semgrep_missing(self):
        rc, data = self.run_scan(install=("gitleaks",))
        self.assert_failed(rc, data, "semgrep", "missing")

    def test_gitleaks_missing(self):
        rc, data = self.run_scan(install=("semgrep",))
        self.assert_failed(rc, data, "gitleaks", "missing")

    def test_semgrep_engine_error(self):
        rc, data = self.run_scan(semgrep="error")
        self.assert_failed(rc, data, "semgrep", "error")

    def test_semgrep_config_invalid(self):
        rc, data = self.run_scan(semgrep="config")
        self.assert_failed(rc, data, "semgrep", "config-invalid")

    def test_semgrep_malformed_output(self):
        rc, data = self.run_scan(semgrep="malformed")
        self.assert_failed(rc, data, "semgrep", "malformed-output")

    def test_semgrep_timeout(self):
        rc, data = self.run_scan(semgrep="timeout", timeout=1)
        self.assert_failed(rc, data, "semgrep", "timeout")

    def test_gitleaks_engine_error(self):
        rc, data = self.run_scan(gitleaks="error")
        self.assert_failed(rc, data, "gitleaks", "error")

    def test_gitleaks_malformed_output(self):
        rc, data = self.run_scan(gitleaks="malformed")
        self.assert_failed(rc, data, "gitleaks", "malformed-output")

    def test_gitleaks_timeout(self):
        rc, data = self.run_scan(gitleaks="timeout", timeout=1)
        self.assert_failed(rc, data, "gitleaks", "timeout")

    def test_gitleaks_leaks_found_is_success(self):
        # Gitleaks exits non-zero when it FINDS leaks; that is success, not error.
        rc, data = self.run_scan(gitleaks="leaks")
        self.assertEqual(rc, 0)
        self.assertTrue(data["scan_ok"])
        self.assertEqual(data["engine_status"]["gitleaks"]["status"], "success")
        self.assertTrue(any(f["category"] == "SECRETS" for f in data["findings"]))

    def test_nonexistent_target_fails_without_writing(self):
        # A bad target must not look like a clean scan: nonzero exit, no output.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        out = root / "findings.json"
        proc = subprocess.run(
            [PY, str(SCAN), str(root / "no-such-dir"), "--out", str(out)],
            capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(out.exists(), "no findings.json for an unscannable target")
        self.assertIn("not a directory", proc.stderr)

    def test_out_parent_directories_are_created(self):
        rc, data = self.run_scan()  # baseline sanity
        self.assertEqual(rc, 0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        target = root / "repo"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        nested = root / "deep" / "nested" / "findings.json"
        proc = subprocess.run(
            [PY, str(SCAN), str(target), "--out", str(nested)],
            capture_output=True, text=True)
        # Engines may be absent in CI's isolated env; either way the parent dir
        # for --out must have been created and the file written.
        self.assertTrue(nested.exists(), proc.stderr)


if __name__ == "__main__":
    unittest.main()
