"""OpenAI-compatible provider client, exercised against a local stub HTTP server
(no live network). Covers success, HTTP errors, malformed / fenced JSON, the
loopback privacy boundary, and JSON extraction."""
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import providers  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    behavior = "ok"

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path.endswith("/models"):
            self._send(200, json.dumps({"data": [{"id": "test-model"}]}))
        else:
            self._send(404, "{}")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        b = _Handler.behavior
        if b == "401":
            self._send(401, '{"error":"unauthorized"}')
        elif b == "500":
            self._send(500, '{"error":"boom"}')
        elif b == "badjson":
            self._send(200, "definitely not json {{{")
        elif b == "fenced":
            content = "```json\n{\"findings\": []}\n```"
            self._send(200, json.dumps({"choices": [{"message": {"content": content}}]}))
        else:
            self._send(200, json.dumps({"model": "test-model",
                       "choices": [{"message": {"content": "{\"findings\": []}"}}]}))


class TestProviders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def cfg(self, **kw):
        base = {"base_url": f"http://127.0.0.1:{self.port}/v1", "model": "test-model",
                "privacy_mode": "local-only", "temperature": 0.0, "max_tokens": 256}
        base.update(kw)
        return base

    def test_success(self):
        _Handler.behavior = "ok"
        r = providers.chat_completion(self.cfg(), [{"role": "user", "content": "hi"}], timeout=5)
        self.assertEqual(providers.extract_json(r["content"]), {"findings": []})
        self.assertEqual(r["model"], "test-model")

    def test_http_401_and_500(self):
        for b in ("401", "500"):
            _Handler.behavior = b
            with self.assertRaises(providers.ProviderError):
                providers.chat_completion(self.cfg(), [{"role": "user", "content": "x"}], timeout=5)

    def test_malformed_json(self):
        _Handler.behavior = "badjson"
        with self.assertRaises(providers.ProviderError):
            providers.chat_completion(self.cfg(), [{"role": "user", "content": "x"}], timeout=5)

    def test_fenced_json_extracted(self):
        _Handler.behavior = "fenced"
        r = providers.chat_completion(self.cfg(), [{"role": "user", "content": "x"}], timeout=5)
        self.assertEqual(providers.extract_json(r["content"]), {"findings": []})

    def test_list_models(self):
        self.assertIn("test-model", providers.list_models(self.cfg(), timeout=5))

    def test_local_only_refuses_remote_without_calling(self):
        with self.assertRaises(providers.ProviderError):
            providers.chat_completion(
                self.cfg(base_url="https://openrouter.ai/api/v1"),
                [{"role": "user", "content": "x"}], timeout=5)

    def test_provider_managed_allows_remote_boundary(self):
        # provider-managed should pass the privacy gate (the call then fails to
        # connect to a non-listening port, which is a transport error, not a
        # privacy refusal).
        with self.assertRaises(providers.ProviderError) as ctx:
            providers.chat_completion(
                self.cfg(base_url="http://127.0.0.1:1/v1", privacy_mode="provider-managed"),
                [{"role": "user", "content": "x"}], timeout=2)
        self.assertNotIn("loopback", str(ctx.exception))

    def test_extract_json_from_prose(self):
        self.assertEqual(providers.extract_json('Here you go: {"a": 1} thanks'), {"a": 1})
        with self.assertRaises(providers.ProviderError):
            providers.extract_json("no json here")


if __name__ == "__main__":
    unittest.main()
