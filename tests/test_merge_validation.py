"""Reasoning-layer validation and provenance in merge_reasoning.py.

Reasoning findings are untrusted model/agent output. The merge step must reject
unknown ids, non-canonical severities, unsafe file paths, PHI-like paths, and
out-of-range lines; redact the title; take authority/citation from the registry;
and only claim source_layer=deterministic+reasoning when a completion manifest
(or, legacy, real findings) confirms the pass ran.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MERGE = REPO / "scripts" / "merge_reasoning.py"


def valid(**over):
    f = {"id": "AUTH-01", "category": "AUTH", "severity": "critical", "source": "reasoning",
         "confidence": "high", "file": "a.py", "line": 1, "title": "Unguarded PHI endpoint",
         "structural_snippet": "s", "why": "w"}
    f.update(over)
    return f


class MergeCase(unittest.TestCase):
    def merge(self, reasoning, *, det=None, make_repo=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        td = Path(tmp.name)
        det = det if det is not None else {"findings": [], "source_layer": "deterministic"}
        d, r, out = td / "d.json", td / "r.json", td / "o.json"
        d.write_text(json.dumps(det))
        r.write_text(json.dumps(reasoning))
        cmd = [sys.executable, str(MERGE), str(d), str(r), "--out", str(out)]
        if make_repo:
            repo = td / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("line1\nline2\nline3\n")
            cmd += ["--repo-path", str(repo)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(out.read_text()) if out.exists() else None
        return proc.returncode, data, proc.stderr

    def assert_rejected(self, reasoning, needle, **kw):
        rc, _, err = self.merge(reasoning, **kw)
        self.assertEqual(rc, 1, f"expected rejection; stderr={err}")
        self.assertIn(needle, err)

    # --- rejections -----------------------------------------------------------
    def test_unknown_check_id(self):
        self.assert_rejected({"findings": [valid(id="NOPE-99")]}, "unknown check id")

    def test_noncanonical_severity(self):
        self.assert_rejected({"findings": [valid(severity="low")]}, "!= canonical")

    def test_absolute_path(self):
        self.assert_rejected({"findings": [valid(file="/etc/passwd")]}, "repo-relative")

    def test_path_traversal(self):
        self.assert_rejected({"findings": [valid(file="../secrets.py")]}, "repo-relative")

    def test_phi_like_filename(self):
        self.assert_rejected({"findings": [valid(file="records/123-45-6789.pdf")]},
                             "PHI/secret-like")

    def test_bad_line_type(self):
        self.assert_rejected({"findings": [valid(line="oops")]}, "line must be")

    def test_line_beyond_eof(self):
        self.assert_rejected({"findings": [valid(line=99)]}, "past end", make_repo=True)

    # --- acceptances + transforms --------------------------------------------
    def test_severity_override_accepted(self):
        rc, data, err = self.merge(
            {"findings": [valid(severity="low", severity_override_reason="context-specific")]})
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(data["findings"]), 1)

    def test_title_is_redacted(self):
        rc, data, _ = self.merge(
            {"findings": [valid(title="Email john@example.com re MRN 12345")]})
        self.assertEqual(rc, 0)
        self.assertNotIn("john@example.com", data["findings"][0]["title"])

    def test_authority_and_citation_from_registry(self):
        # agent supplies a wrong ref; merge must overwrite from the registry
        rc, data, _ = self.merge({"findings": [valid(hipaa_ref="999.999")]})
        self.assertEqual(rc, 0)
        f = data["findings"][0]
        self.assertEqual(f["hipaa_ref"], "164.312(d)")
        self.assertEqual(f["authority_type"], "hipaa-required")

    def test_top_level_list_reasoning_accepted(self):
        # A bare JSON array (legacy shape, no wrapping object) must merge, not
        # crash with AttributeError on .get.
        rc, data, err = self.merge([valid()])
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["id"], "AUTH-01")
        # No wrapping object => no manifest => stays incomplete, never crashes.
        self.assertEqual(data["source_layer"], "deterministic")

    # --- completion gating ----------------------------------------------------
    def test_empty_no_manifest_stays_incomplete(self):
        rc, data, _ = self.merge({"findings": []})
        self.assertEqual(rc, 0)
        self.assertEqual(data["source_layer"], "deterministic")
        self.assertFalse(data["reasoning"]["complete"])

    def test_manifest_clean_marks_complete(self):
        rc, data, _ = self.merge(
            {"findings": [], "manifest": {"batches_completed": 3, "batches_failed": 0}})
        self.assertEqual(rc, 0)
        self.assertEqual(data["source_layer"], "deterministic+reasoning")
        self.assertTrue(data["reasoning"]["complete"])

    def test_manifest_failed_batches_stays_incomplete(self):
        rc, data, _ = self.merge(
            {"findings": [valid()], "manifest": {"batches_completed": 2, "batches_failed": 1}})
        self.assertEqual(rc, 0)
        self.assertEqual(data["source_layer"], "deterministic")
        self.assertFalse(data["reasoning"]["complete"])

    def test_truncated_stays_incomplete(self):
        rc, data, err = self.merge(
            {"findings": [], "manifest": {"batches_failed": 0, "truncated": True,
                                          "files_skipped": ["big.py"]}})
        self.assertEqual(rc, 0)
        self.assertEqual(data["source_layer"], "deterministic")
        self.assertFalse(data["reasoning"]["complete"])
        self.assertIn("truncated", data["reasoning"]["incomplete_reason"])

    def test_skipped_files_stay_incomplete(self):
        rc, data, _ = self.merge(
            {"findings": [], "manifest": {"batches_failed": 0, "files_skipped": ["b.py"]}})
        self.assertEqual(rc, 0)
        self.assertFalse(data["reasoning"]["complete"])

    def test_fingerprint_match_marks_complete(self):
        det = {"findings": [], "source_layer": "deterministic",
               "scan": {"commit": "abc123", "fingerprint": "feedface12345678"}}
        rc, data, _ = self.merge(
            {"findings": [], "manifest": {"scan_fingerprint": "feedface12345678",
                                          "batches_failed": 0, "truncated": False,
                                          "files_skipped": []}}, det=det)
        self.assertEqual(rc, 0)
        self.assertTrue(data["reasoning"]["complete"])

    def test_fingerprint_mismatch_stays_incomplete(self):
        det = {"findings": [], "source_layer": "deterministic",
               "scan": {"commit": "abc123", "fingerprint": "feedface12345678"}}
        rc, data, _ = self.merge(
            {"findings": [], "manifest": {"scan_fingerprint": "0000000000000000",
                                          "batches_failed": 0, "truncated": False,
                                          "files_skipped": []}}, det=det)
        self.assertEqual(rc, 0)
        self.assertEqual(data["source_layer"], "deterministic")
        self.assertFalse(data["reasoning"]["complete"])
        self.assertIn("scan revision", data["reasoning"]["incomplete_reason"])

    def test_missing_fingerprint_when_scan_has_one_stays_incomplete(self):
        # A manifest that omits the fingerprint cannot be bound to this scan.
        det = {"findings": [], "source_layer": "deterministic",
               "scan": {"commit": "abc123", "fingerprint": "feedface12345678"}}
        rc, data, _ = self.merge(
            {"findings": [], "manifest": {"batches_failed": 0, "truncated": False,
                                          "files_skipped": []}}, det=det)
        self.assertEqual(rc, 0)
        self.assertFalse(data["reasoning"]["complete"])

    def test_provider_provenance_recorded(self):
        rc, data, _ = self.merge(
            {"provider": "openai-compatible", "model": "qwen2.5-coder",
             "run_id": "r1", "findings": [valid()]})
        self.assertEqual(rc, 0)
        self.assertEqual(data["reasoning"]["provider"], "openai-compatible")
        self.assertEqual(data["reasoning"]["model"], "qwen2.5-coder")


if __name__ == "__main__":
    unittest.main()
