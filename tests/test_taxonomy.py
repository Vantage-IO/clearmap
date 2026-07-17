"""Canonical taxonomy registry integrity.

references/taxonomy.json is the single source of truth for every finding id.
These tests assert it is internally valid, that every category is scoreable,
that every regulatory reference resolves in the baseline, and that the reasoning
checklists document exactly the reasoning-layer ids (no drift, no orphans).
"""
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import report  # noqa: E402
import scoring  # noqa: E402
import taxonomy  # noqa: E402

BASELINE = json.loads((REPO / "references" / "regulatory-baseline.json").read_text())
CHECKLISTS = ["clinical-checks.md", "audit-checks.md"]
ID_RE = re.compile(r"\b(?:ACCESS|AUTH|AUDIT|INTEGRITY|TRANSIT|SESSION|TRACKING|AI-RAG|SECRETS|APPSEC)-\d+\b")


class TestRegistryStructure(unittest.TestCase):
    def setUp(self):
        self.reg = taxonomy.load_taxonomy()
        self.findings = self.reg["findings"]

    def test_top_level_shape(self):
        self.assertIn("taxonomy_version", self.reg)
        self.assertEqual(set(self.reg["required_fields"]), {"deterministic", "reasoning"})
        self.assertTrue(self.findings, "registry has no findings")

    def test_every_entry_is_valid(self):
        auth_types = taxonomy.authority_types()
        valid_categories = set(scoring.WEIGHTS)
        known_refs = set(BASELINE["regulations"])
        for fid, e in self.findings.items():
            self.assertRegex(fid, ID_RE, f"{fid} is not a well-formed finding id")
            self.assertIn(e["category"], valid_categories,
                          f"{fid}: category {e['category']} is not a scored category")
            self.assertIn(e["layer"], taxonomy.VALID_LAYERS, f"{fid}: bad layer")
            self.assertIn(e["severity"], taxonomy.VALID_SEVERITIES, f"{fid}: bad severity")
            self.assertIn(e["authority_type"], auth_types, f"{fid}: bad authority_type")
            self.assertIn(e["hipaa_ref"], known_refs,
                          f"{fid}: hipaa_ref {e['hipaa_ref']!r} does not resolve in the baseline")

    def test_loader_helpers(self):
        first = next(iter(self.findings))
        self.assertEqual(taxonomy.entry(first), self.findings[first])
        self.assertIsNone(taxonomy.entry("NOPE-99"))
        self.assertIn("title", taxonomy.required_fields("reasoning"))


class TestChecklistDrift(unittest.TestCase):
    """The reasoning checklists must document exactly the reasoning-layer ids."""

    def test_checklists_document_the_reasoning_layer(self):
        reasoning_ids = {fid for fid, e in taxonomy.findings().items()
                         if e["layer"] == "reasoning"}
        referenced = set()
        for name in CHECKLISTS:
            text = (REPO / "references" / name).read_text()
            referenced |= set(ID_RE.findall(text))
        # every id mentioned in the checklists is canonical
        unknown = referenced - set(taxonomy.findings())
        self.assertFalse(unknown, f"checklists reference unknown ids: {sorted(unknown)}")
        # every reasoning check has documentation
        undocumented = reasoning_ids - referenced
        self.assertFalse(undocumented, f"reasoning ids missing from checklists: {sorted(undocumented)}")


class TestAuthorityConsistency(unittest.TestCase):
    """A finding id's registry authority_type must match the authority derived
    from its citation in the baseline (single source of truth, no drift)."""

    def test_registry_authority_matches_citation(self):
        for fid, e in taxonomy.findings().items():
            self.assertEqual(
                e["authority_type"], report.authority_of(e["hipaa_ref"], BASELINE),
                f"{fid}: registry authority_type disagrees with its citation")


if __name__ == "__main__":
    unittest.main()
