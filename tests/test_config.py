"""Reasoning config: precedence, loopback detection, secret-safe handling."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import config  # noqa: E402


class TestConfig(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in list(config._ENV.values()) +
                     ["XDG_CONFIG_HOME", "CLEARMAP_MODEL_API_KEY", "TOK"]}
        for k in config._ENV.values():
            os.environ.pop(k, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # isolate user config into the temp dir
        os.environ["XDG_CONFIG_HOME"] = str(Path(self.tmp.name) / "cfg")

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_defaults(self):
        cfg = config.load()
        self.assertEqual(cfg["provider"], "host-agent")
        self.assertEqual(cfg["privacy_mode"], "local-only")

    def test_precedence_env_over_repo_over_user(self):
        repo = Path(self.tmp.name) / "repo"
        (repo / ".clearmap").mkdir(parents=True)
        config.save({"provider": "manual"}, "user")
        (repo / ".clearmap" / "config.json").write_text(
            json.dumps({"reasoning": {"provider": "openai-compatible", "model": "r"}}))
        self.assertEqual(config.load(repo)["provider"], "openai-compatible")  # repo > user
        os.environ["CLEARMAP_REASONING_PROVIDER"] = "manual"
        self.assertEqual(config.load(repo)["provider"], "manual")             # env > repo
        self.assertEqual(config.load(repo, {"provider": "host-agent"})["provider"],
                         "host-agent")                                        # CLI > env

    def test_loopback_detection(self):
        for url in ("http://127.0.0.1:11434/v1", "http://localhost:1234/v1",
                    "http://[::1]:11434/v1"):
            self.assertTrue(config.is_loopback(url), url)
        for url in ("http://10.0.0.5:11434/v1", "https://openrouter.ai/api/v1",
                    "http://192.168.1.2/v1"):
            self.assertFalse(config.is_loopback(url), url)

    def test_local_only_rejects_remote(self):
        errs = config.validate({"provider": "openai-compatible", "base_url": "https://openrouter.ai/api/v1",
                                "model": "x", "privacy_mode": "local-only"})
        self.assertTrue(any("loopback" in e for e in errs))

    def test_provider_managed_allows_remote(self):
        errs = config.validate({"provider": "openai-compatible", "base_url": "https://openrouter.ai/api/v1",
                                "model": "x", "privacy_mode": "provider-managed"})
        self.assertEqual(errs, [])

    def test_key_never_stored_only_env_name(self):
        os.environ["TOK"] = "sk-secret-value"
        cfg = config.load(overrides={"provider": "openai-compatible", "api_key_env": "TOK",
                                     "api_key": "sk-secret-value"})
        self.assertNotIn("api_key", cfg)
        self.assertEqual(config.resolve_api_key(cfg), "sk-secret-value")
        red = config.redacted(cfg)
        self.assertNotIn("sk-secret-value", json.dumps(red))
        self.assertTrue(red["api_key_present"])
        path = config.save(cfg, "user")
        self.assertNotIn("sk-secret-value", path.read_text())


if __name__ == "__main__":
    unittest.main()
