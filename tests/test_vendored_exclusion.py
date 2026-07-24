"""Vendored / cache path exclusion (P1a).

A gitignored package/cache store (a pnpm content-addressed store, a
yarn/turbo/parcel cache, coverage output) is walked by `gitleaks dir` because
that mode ignores .gitignore. Its extensionless content-hash blobs trip the
entropy rules and were the single biggest real-repo false-positive source.

These tests build a synthetic tree with a fake secret buried inside such a
store and assert the scan excludes it at every layer (gitleaks allowlist +
semgrep walk skip + filters backstop), while a real secret in first-party
source is still reported.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN = REPO / "scripts" / "scan.py"
PY = sys.executable

sys.path.insert(0, str(REPO / "scripts"))
import filters  # noqa: E402

# A fake AWS access key + secret, a shape the gitleaks default ruleset catches.
# Deliberately NOT the AWS documentation example (which gitleaks allowlists as a
# stopword) so the store-exclusion test proves the PATH decision, not a stopword.
FAKE_KEY = "AKIA3XYZK4ABCD7QP2LM"
FAKE_SECRET = "wJ8fXk2LmNpQrStUvWxYz0123456789AbCdEfGhIj"


class TestVendoredPathRegexes(unittest.TestCase):
    """The three exclusion layers must agree on the same vendored locations."""

    VENDORED = [
        ".pnpm-store/v3/files/00/abcdef1234567890",
        "app/.pnpm-store/v3/files/aa/deadbeef",
        ".yarn/cache/some-package.zip",
        ".turbo/cache/hash",
        ".cache/blob",
        ".parcel-cache/x",
        ".svelte-kit/output/x",
        ".nuxt/dist/x",
        ".output/server/x",
        "coverage/lcov.info",
        ".vercel/output/x",
        ".serverless/x",
        ".pnp.cjs",
        "packages/app/.pnp.loader.mjs",
    ]

    def test_filters_treats_vendored_paths_as_vendored(self):
        for rel in self.VENDORED:
            self.assertTrue(
                any(rx.search(rel) for rx in filters.VENDORED_PATH_RES),
                f"{rel} should match a VENDORED_PATH_RE")

    def test_first_party_source_is_not_vendored(self):
        for rel in ("src/app.ts", "backend/config.py", "lib/cache.ts"):
            self.assertFalse(
                any(rx.search(rel) for rx in filters.VENDORED_PATH_RES), rel)


@unittest.skipUnless(shutil.which("gitleaks") and shutil.which("semgrep"),
                     "engines not installed")
class TestVendoredScanExclusion(unittest.TestCase):
    def _scan(self, target: Path) -> dict:
        out = target / "findings.json"
        subprocess.run([PY, str(SCAN), str(target), "--out", str(out)],
                       capture_output=True, text=True, check=False)
        return json.loads(out.read_text())

    def test_secret_in_pnpm_store_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            store = root / ".pnpm-store" / "v3" / "files" / "00"
            store.mkdir(parents=True)
            (store / "abcdef1234567890").write_text(
                f"{FAKE_KEY}\naws_secret={FAKE_SECRET}\n")
            (root / "pnpm-lock.yaml").write_text(
                f"integrity sha512-{FAKE_KEY}\n")
            (root / "src").mkdir()
            (root / "src" / "app.ts").write_text("export const x = 1;\n")
            data = self._scan(root)
            self.assertTrue(data["scan_ok"])
            self.assertEqual(data["findings"], [],
                             "vendored store + lockfile secrets must be excluded")

    def test_real_secret_in_source_still_caught(self):
        # Control: the same key shape in first-party source IS reported, so the
        # exclusion above is a path decision, not a broken detector.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "src").mkdir()
            (root / "src" / "config.py").write_text(
                f'AWS_ACCESS_KEY_ID = "{FAKE_KEY}"\n'
                f'AWS_SECRET_ACCESS_KEY = "{FAKE_SECRET}"\n')
            data = self._scan(root)
            self.assertTrue(any(f["category"] == "SECRETS" for f in data["findings"]),
                            "a secret in first-party source must still be caught")


if __name__ == "__main__":
    unittest.main()
