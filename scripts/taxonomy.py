"""Canonical taxonomy registry loader.

`references/taxonomy.json` is the single source of truth for every canonical
finding id: its category, the layer that produces it (deterministic rules or
AI-assisted reasoning), the canonical severity, the authority type, and the
regulatory reference. Rules metadata, the fixture manifest, the reasoning
validator, and the reasoning checklists all validate against it, so the
taxonomy is never duplicated across files or parsed from prose.

Stdlib-only. Works in both layouts: repo (<root>/references, scripts/ beside
it) and pip-installed package (clearmap/references inside the package dir).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_HERE = Path(__file__).resolve().parent
TAXONOMY_PATH = next(
    (p for p in (_HERE.parent / "references" / "taxonomy.json",
                 _HERE / "references" / "taxonomy.json") if p.is_file()),
    _HERE.parent / "references" / "taxonomy.json")

VALID_LAYERS = {"deterministic", "reasoning"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@lru_cache(maxsize=1)
def load_taxonomy() -> dict:
    """Return the full registry dict (cached)."""
    return json.loads(TAXONOMY_PATH.read_text())


def findings() -> dict:
    """Map of finding id -> {category, layer, severity, authority_type, hipaa_ref}."""
    return load_taxonomy()["findings"]


def authority_types() -> set[str]:
    return set(load_taxonomy()["authority_types"])


def entry(finding_id: str) -> dict | None:
    """Registry entry for a finding id, or None if the id is not canonical."""
    return findings().get(finding_id)


def required_fields(layer: str) -> list[str]:
    return list(load_taxonomy()["required_fields"].get(layer, []))
