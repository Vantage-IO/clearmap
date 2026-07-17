"""Unit tests for scripts/filters.py, the false-positive kill layer.

The regression that matters most (R3): publishable-token / i18n filters must
NEVER swallow a real secret (for example a live billing-provider test_* key class).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import filters  # noqa: E402


def _f(**kw) -> dict:
    base = {"rule_id": "generic-api-key", "category": "SECRETS", "severity": "high",
            "file": "src/a.ts", "line": 1, "title": "t"}
    base.update(kw)
    return base


class FilterCase(unittest.TestCase):
    """Writes a throwaway target tree per test so filters can re-read raw lines."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="clearmap-filters-")
        self.target = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel: str, text: str):
        p = self.target / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def kept(self, findings):
        return filters.apply_filters(findings, self.target)[0]

    def ledger(self, findings):
        return filters.apply_filters(findings, self.target)[1]

    def warns(self, findings):
        return filters.apply_filters(findings, self.target)[2]


class TestValueHeuristics(FilterCase):
    def test_i18n_label_key_suppressed(self):
        self.write("src/a.ts", '{ value: "x", labelKey: "q1_option_a" },')
        self.assertEqual(self.kept([_f()]), [])

    def test_datadog_publishable_token_suppressed(self):
        self.write("src/a.ts", 'clientToken: "puba1b2c3d4e5f60718293a4b5c6d7e8f",')
        self.assertEqual(self.kept([_f()]), [])

    def test_widget_url_uuid_key_suppressed(self):
        self.write("src/a.ts",
                   'src="https://static.widget-cdn.example/snippet.js?key=11111111-2222-4333-8444-555555555555"')
        self.assertEqual(self.kept([_f()]), [])

    def test_templated_secret_suppressed(self):
        for line in ('SMTP_PASSWORD = "${SMTP_PASSWORD}"',
                     'apiKey: "{{ vault.api_key }}"',
                     'token = os.environ["TOKEN"]'):
            self.write("src/a.ts", line)
            self.assertEqual(self.kept([_f()]), [], line)

    def test_prefixed_secret_key_KEPT(self):
        # test_/live_ prefixed values are REAL secrets, not placeholders.
        self.write("src/a.ts", 'billing.configure(api_key="test_Xy9aB3cD7eF1gH5iJ2kL8mN4oP6q")')
        self.assertEqual(len(self.kept([_f()])), 1)

    def test_api_key_identifier_never_matches_i18n_filter(self):
        self.write("src/a.ts", 'api_key="test_abcdefg123456789hijklmnop"')
        self.assertEqual(len(self.kept([_f()])), 1)

    def test_stripe_secret_key_KEPT_publishable_suppressed(self):
        self.write("src/a.ts", 'const k = "sk_live_a1B2c3D4e5F6g7H8i9J0"')
        self.assertEqual(len(self.kept([_f()])), 1)
        self.write("src/a.ts", 'const k = "pk_live_a1B2c3D4e5F6g7H8i9J0"')
        self.assertEqual(self.kept([_f()]), [])

    def test_heuristics_only_apply_to_secrets_category(self):
        self.write("src/a.ts", 'fetch("http://x.example?key=11111111-2222-4333-8444-555555555555")')
        kept = self.kept([_f(category="TRANSIT", rule_id="transit-external-cleartext-url")])
        self.assertEqual(len(kept), 1)


class TestPathAndIgnoreRules(FilterCase):
    def test_vendored_non_secret_suppressed(self):
        self.write("node_modules/x/a.js", "anything")
        self.assertEqual(self.kept([_f(file="node_modules/x/a.js", category="ACCESS")]), [])

    def test_vendored_secret_downgraded_not_hidden(self):
        # A real secret in a vendored path stays VISIBLE (downgraded to low),
        # never silently dropped by path alone.
        self.write("node_modules/x/a.js", 'apiKey = "abc123def456ghi789"')
        kept = self.kept([_f(file="node_modules/x/a.js")])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["severity"], "low")
        ledger = self.ledger([_f(file="node_modules/x/a.js")])
        self.assertEqual(ledger[0]["disposition"], "downgraded")

    def test_clearmapignore_glob_and_rule_scoped(self):
        self.write("gen/sdk.ts", 'apiKey = "abc123def456ghi789"')
        self.write(".clearmapignore", "# comment\ngen/*\nsrc/legacy.ts generic-api-key\n")
        self.assertEqual(self.kept([_f(file="gen/sdk.ts")]), [])
        self.write("src/legacy.ts", 'apiKey = "abc123def456ghi789"')
        self.assertEqual(self.kept([_f(file="src/legacy.ts")]), [])
        # rule-scoped ignore must not hit other rules on the same file
        kept = self.kept([_f(file="src/legacy.ts", rule_id="clearmap-ehr-api-key",
                             line=1)])
        self.assertEqual(len(kept), 1)

    def test_inline_allow_same_line_and_line_above(self):
        self.write("src/a.ts",
                   'const a = "x"; // clearmap:allow generic-api-key reason="fixture"\n'
                   '// clearmap:allow * reason="whole block is a template"\nconst b = "y";\n'
                   'const c = "z";\n')
        self.assertEqual(self.kept([_f(line=1)]), [])
        self.assertEqual(self.kept([_f(line=3)]), [])
        self.assertEqual(len(self.kept([_f(line=4)])), 1)
        # the reason is captured in the ledger
        self.assertEqual(self.ledger([_f(line=1)])[0]["reason"], "fixture")

    def test_inline_wildcard_without_reason_rejected(self):
        self.write("src/a.ts", 'const a = "x"; // clearmap:allow *\n')
        self.assertEqual(len(self.kept([_f(line=1)])), 1)  # not suppressed
        self.assertTrue(any("requires" in w for w in self.warns([_f(line=1)])))

    def test_test_path_secrets_downgraded_not_dropped(self):
        self.write("tests/test_x.py", 'jwt = "eyJhbGciOiJIUzI1NiJ9.x.y"')
        kept = self.kept([_f(file="tests/test_x.py", rule_id="jwt")])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["severity"], "low")
        self.assertIn("test-fixture path", kept[0]["title"])


if __name__ == "__main__":
    unittest.main()
