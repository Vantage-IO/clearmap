"""Unit tests for scripts/redact.py — every pattern, including edge forms.

No raw PHI-like value or secret may survive redaction.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from redact import redact  # noqa: E402


class TestRedact(unittest.TestCase):
    def test_openai_style_key(self):
        out = redact('key = "sk-canaryAAAABBBBCCCCDDDD1234"')
        self.assertNotIn("sk-canary", out)
        self.assertIn("[REDACTED_API_KEY]", out)

    def test_ehr_key_live_and_test(self):
        for v in ("ehr_live_abc12345XYZ", "ehr_test_canary1234567890"):
            out = redact(f'EHR_KEY = "{v}"')
            self.assertNotIn(v, out)
            self.assertIn("[REDACTED_API_KEY]", out)

    def test_secret_assignment(self):
        for line in ('password = "hunter2secretvalue"',
                     "api_key: 'abcd1234efgh'",
                     'DB_PASSWORD="topsecret99"'):
            out = redact(line)
            self.assertIn("[REDACTED]", out)
            for leak in ("hunter2secretvalue", "abcd1234efgh", "topsecret99"):
                self.assertNotIn(leak, out)

    def test_connection_string_credentials(self):
        out = redact("postgres://canary_admin:CanaryPass99XyZ@db.host.com:5432/records")
        self.assertNotIn("CanaryPass99XyZ", out)
        self.assertIn("canary_admin:[REDACTED]@", out)

    def test_ssn(self):
        out = redact("ssn: '987-65-4329'")
        self.assertNotIn("987-65-4329", out)
        self.assertIn("[SSN]", out)

    def test_mrn_colon_hash_equals(self):
        for form in ("MRN: 4455667", "MRN#4455667", "mrn=4455667", "MRN 4455667"):
            out = redact(f"note {form} end")
            self.assertNotIn("4455667", out, form)
            self.assertIn("[MRN]", out, form)

    def test_dob_like_date(self):
        out = redact("dob: 3/14/1985")
        self.assertNotIn("3/14/1985", out)
        self.assertIn("[DATE]", out)

    def test_email(self):
        out = redact("contact jane.canary@example.org now")
        self.assertNotIn("jane.canary@example.org", out)
        self.assertIn("[EMAIL]", out)

    def test_iso_date(self):
        out = redact('birth_date_field.value == "1985-03-14"')
        self.assertNotIn("1985-03-14", out)
        self.assertIn("[DATE]", out)

    def test_us_phone_forms(self):
        for form in ("555-867-5309", "(555) 867-5309", "555.867.5309",
                     "+1 555-867-5309", "1-555-867-5309"):
            out = redact(f"call {form} today")
            self.assertNotIn("867", out, form)
            self.assertIn("[PHONE]", out, form)

    def test_phone_does_not_eat_ssn_or_versions(self):
        self.assertIn("[SSN]", redact("987-65-4329"))
        self.assertNotIn("[PHONE]", redact("ver 1.2.3.4000"))

    def test_street_address(self):
        for addr in ("742 Evergreen Terrace Ave", "12 Main St.", "9800 Savin Hill Rd"):
            out = redact(f"lives at {addr},")
            self.assertIn("[ADDRESS]", out, addr)

    def test_name_keyed_literals(self):
        for line in ('patient_name = "Jane Canary"', "first_name: 'Jane'",
                     'dob = "March 14 1985"', 'fullName: "J. Canary"'):
            out = redact(line)
            self.assertNotIn("Jane", out, line)
            self.assertNotIn("March 14", out, line)
            self.assertIn("[REDACTED_PHI]", out, line)

    def test_structure_is_preserved(self):
        out = redact('localStorage.setItem("patient", x)')
        self.assertIn("localStorage.setItem", out)


if __name__ == "__main__":
    unittest.main()
