"""Plugin-root resolution: honor host env vars, else fall back to the source
location, and never trust an env var that does not point at a real plugin."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import plugin_root as pr  # noqa: E402


class TestPluginRoot(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in pr._ENV_VARS}
        for k in pr._ENV_VARS:
            os.environ.pop(k, None)
        pr.plugin_root.cache_clear()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        pr.plugin_root.cache_clear()

    def test_fallback_to_source_root(self):
        self.assertTrue((pr.plugin_root() / "scripts" / "scan.py").is_file())
        self.assertTrue(pr.asset("rules").is_dir())

    def test_env_override_to_valid_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scripts").mkdir()
            (root / "scripts" / "scan.py").write_text("")
            (root / "rules").mkdir()
            os.environ["CLEARMAP_PLUGIN_ROOT"] = str(root)
            pr.plugin_root.cache_clear()
            self.assertEqual(pr.plugin_root(), root.resolve())

    def test_bad_env_falls_back(self):
        os.environ["CLAUDE_PLUGIN_ROOT"] = "/does/not/exist/clearmap"
        pr.plugin_root.cache_clear()
        self.assertTrue((pr.plugin_root() / "scripts" / "scan.py").is_file())


if __name__ == "__main__":
    unittest.main()
