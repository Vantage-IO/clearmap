"""Resolve the installed ClearMap plugin root.

Works whether ClearMap runs as an installed Claude Code / Codex plugin (the host
sets CLAUDE_PLUGIN_ROOT or PLUGIN_ROOT to the plugin's cache directory) or from
the source tree. Never depends on the current working directory or a source
checkout living elsewhere. Every bundled asset (scripts, rules, references,
skills) lives under this root, so commands, hooks, skills, and bin/clearmap all
resolve their engine through this one helper.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

_ENV_VARS = ("CLEARMAP_PLUGIN_ROOT", "CLAUDE_PLUGIN_ROOT", "PLUGIN_ROOT")


def _looks_like_root(p: Path) -> bool:
    return (p / "scripts" / "scan.py").is_file() and (p / "rules").is_dir()


@lru_cache(maxsize=1)
def plugin_root() -> Path:
    """Absolute path to the plugin root, honoring host env vars then falling back
    to this file's location (scripts/plugin_root.py -> <root>/scripts -> <root>)."""
    for env in _ENV_VARS:
        v = os.environ.get(env)
        if v:
            p = Path(v).expanduser().resolve()
            if _looks_like_root(p):
                return p
    return Path(__file__).resolve().parent.parent


def asset(*parts: str) -> Path:
    """Path to a bundled asset under the plugin root, e.g. asset('rules')."""
    return plugin_root().joinpath(*parts)


def scripts_dir() -> Path:
    return plugin_root() / "scripts"
