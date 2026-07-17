"""Version single-sourcing: scripts/_version.py is the source of truth. Every
plugin/marketplace manifest, the report header, and the SARIF driver version
must agree with it, and the calibrated engine pins must match CI."""
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from _version import __version__  # noqa: E402

MANIFEST_VERSIONS = [
    (".claude-plugin/plugin.json", lambda d: d["version"]),
    (".claude-plugin/marketplace.json", lambda d: d["plugins"][0]["version"]),
    (".codex-plugin/plugin.json", lambda d: d["version"]),
    (".agents/plugins/marketplace.json", lambda d: d["plugins"][0]["version"]),
]


class TestVersionConsistency(unittest.TestCase):
    def test_all_manifests_match(self):
        for rel, get in MANIFEST_VERSIONS:
            data = json.loads((REPO / rel).read_text())
            self.assertEqual(get(data), __version__, f"{rel} version drifted")

    def test_report_header_uses_it(self):
        import report
        self.assertEqual(report.CLEARMAP_VERSION, __version__)

    def test_sarif_driver_version(self):
        import export
        sarif = export.to_sarif({"findings": []})
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], __version__)

    def test_semver_shape(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_engine_pins_match_ci(self):
        """init.py ENGINE_PINS are the calibrated versions; the CI-installed
        engine versions must start with those pins."""
        import init
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
        keys = {"semgrep": "SEMGREP_VERSION", "gitleaks": "GITLEAKS_VERSION"}
        for engine, pin in init.ENGINE_PINS.items():
            m = re.search(rf'{keys[engine]}:\s*"([\d.]+)"', ci)
            self.assertIsNotNone(m, f"{keys[engine]} not found in ci.yml")
            self.assertTrue(m.group(1).startswith(pin),
                            f"{engine}: CI {m.group(1)} does not match pin {pin}")


if __name__ == "__main__":
    unittest.main()
