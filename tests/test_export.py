"""scripts/export.py — SARIF 2.1.0 and CSV export tests."""
import csv
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import export  # noqa: E402

DATA = json.loads((REPO / "tests" / "fixtures" / "golden" / "findings.json").read_text())


class TestSarif(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sarif = export.to_sarif(DATA)
        cls.sarif_run = cls.sarif["runs"][0]

    def test_version_and_schema(self):
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0", self.sarif["$schema"])

    def test_every_finding_has_a_result(self):
        self.assertEqual(len(self.sarif_run["results"]), len(DATA["findings"]))

    def test_rules_deduped_and_sorted(self):
        ids = [r["id"] for r in self.sarif_run["tool"]["driver"]["rules"]]
        self.assertEqual(ids, sorted(set(ids)))

    def test_severity_level_mapping(self):
        by_rule = {r["ruleId"]: r["level"] for r in self.sarif_run["results"]}
        self.assertEqual(by_rule["clearmap-db-uri-credentials"], "error")   # critical
        self.assertEqual(by_rule["AI-RAG-02"], "warning")                   # medium
        self.assertEqual(by_rule["jwt"], "note")                            # low

    def test_hipaa_ref_in_rule_tags(self):
        rule = next(r for r in self.sarif_run["tool"]["driver"]["rules"]
                    if r["id"] == "clearmap-db-uri-credentials")
        self.assertIn("164.312(a)(2)(i)", rule["properties"]["tags"])
        self.assertIn("hipaa", rule["properties"]["tags"])

    def test_locations_are_valid(self):
        for r in self.sarif_run["results"]:
            loc = r["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"])
            self.assertGreaterEqual(loc["region"]["startLine"], 1)

    def test_valid_json_roundtrip(self):
        json.loads(json.dumps(self.sarif))


class TestCsv(unittest.TestCase):
    def test_row_count_and_header(self):
        rows = list(csv.DictReader(io.StringIO(export.to_csv(DATA))))
        self.assertEqual(len(rows), len(DATA["findings"]))
        self.assertEqual(list(rows[0].keys()), export.CSV_COLUMNS)

    def test_fields_survive(self):
        rows = list(csv.DictReader(io.StringIO(export.to_csv(DATA))))
        first = rows[0]
        self.assertEqual(first["category"], "ACCESS")
        self.assertEqual(first["file"], "backend/config.py")


class TestDeterminism(unittest.TestCase):
    def test_byte_stable_across_runs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td, "f.json")
            src.write_text(json.dumps(DATA))
            outs = []
            for i in range(2):
                out = Path(td, f"o{i}.sarif")
                subprocess.run([sys.executable, str(REPO / "scripts" / "export.py"),
                                str(src), "--format", "sarif", "--out", str(out)],
                               check=True, capture_output=True)
                outs.append(out.read_bytes())
            self.assertEqual(outs[0], outs[1])


if __name__ == "__main__":
    unittest.main()
