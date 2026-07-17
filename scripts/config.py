#!/usr/bin/env python3
"""ClearMap configuration: how the AI-assisted reasoning review runs.

Stdlib-only. Precedence, highest first: CLI flags (passed by the caller) > env
vars > repository config (<repo>/.clearmap/config.json) > user config
(~/.config/clearmap/config.json) > safe defaults. The default provider is the
host agent, which needs no key and makes no network calls. Raw API keys are
NEVER stored: config records the NAME of an env var that holds the key. Under
privacy mode `local-only` an OpenAI-compatible endpoint must be a loopback
address; a remote provider requires `provider-managed`, chosen explicitly.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROVIDERS = ("host-agent", "openai-compatible", "manual")
PRIVACY_MODES = ("local-only", "provider-managed")

DEFAULTS = {
    "provider": "host-agent",
    "base_url": None,
    "model": None,
    "api_key_env": "CLEARMAP_MODEL_API_KEY",
    "privacy_mode": "local-only",
    "temperature": 0.0,
    "max_tokens": 4096,
}

_ENV = {
    "provider": "CLEARMAP_REASONING_PROVIDER",
    "base_url": "CLEARMAP_MODEL_BASE_URL",
    "model": "CLEARMAP_MODEL_NAME",
    "api_key_env": "CLEARMAP_MODEL_API_KEY_ENV",
    "privacy_mode": "CLEARMAP_PRIVACY_MODE",
}


def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "clearmap" / "config.json"


def repo_config_path(repo: Path) -> Path:
    return Path(repo) / ".clearmap" / "config.json"


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data.get("reasoning", data) if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def is_loopback(url: str | None) -> bool:
    """True if the URL host is a loopback address (127.0.0.0/8, ::1, localhost)."""
    if not url:
        return False
    host = (urlparse(url).hostname or "").strip("[]")
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load(repo: Path | None = None, overrides: dict | None = None) -> dict:
    """Merge defaults < user < repo < env < CLI overrides."""
    cfg = dict(DEFAULTS)
    cfg.update({k: v for k, v in _read(user_config_path()).items() if v is not None})
    if repo is not None:
        cfg.update({k: v for k, v in _read(repo_config_path(repo)).items() if v is not None})
    for key, env in _ENV.items():
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})
    # never let a raw key live in the config object
    cfg.pop("api_key", None)
    return cfg


def validate(cfg: dict) -> list[str]:
    """Return a list of problems; empty means the config is usable."""
    errs: list[str] = []
    if cfg.get("provider") not in PROVIDERS:
        errs.append(f"provider must be one of {PROVIDERS} (got {cfg.get('provider')!r})")
    if cfg.get("privacy_mode") not in PRIVACY_MODES:
        errs.append(f"privacy_mode must be one of {PRIVACY_MODES}")
    if cfg.get("provider") == "openai-compatible":
        if not cfg.get("base_url"):
            errs.append("openai-compatible provider requires base_url")
        if not cfg.get("model"):
            errs.append("openai-compatible provider requires model")
        if cfg.get("privacy_mode") == "local-only" and cfg.get("base_url") \
                and not is_loopback(cfg["base_url"]):
            errs.append(f"privacy_mode local-only allows only loopback endpoints; "
                        f"{cfg['base_url']} is remote. Set privacy_mode=provider-managed "
                        "to use a remote provider, and understand that the files under "
                        "review are sent to it.")
    return errs


def resolve_api_key(cfg: dict) -> str | None:
    """Read the API key from the env var named by api_key_env. Never stored."""
    env = cfg.get("api_key_env") or DEFAULTS["api_key_env"]
    return os.environ.get(env)


def redacted(cfg: dict) -> dict:
    """A copy safe to print: no key value, only the env-var name."""
    out = {k: v for k, v in cfg.items() if k != "api_key"}
    out["api_key_present"] = bool(resolve_api_key(cfg))
    return out


def save(cfg: dict, scope: str, repo: Path | None = None) -> Path:
    """Persist config to the user or repo scope, stripping any raw key."""
    path = repo_config_path(repo) if scope == "repo" and repo else user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    keep = {k: cfg.get(k) for k in DEFAULTS if k in cfg}
    keep.pop("api_key", None)
    path.write_text(json.dumps({"reasoning": keep}, indent=2) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Show or validate ClearMap configuration")
    ap.add_argument("action", choices=["show", "validate"])
    ap.add_argument("--repo", type=Path, default=Path("."))
    args = ap.parse_args()
    cfg = load(args.repo)
    if args.action == "show":
        print(json.dumps(redacted(cfg), indent=2))
        print(f"\nuser config:  {user_config_path()}"
              f"  ({'present' if user_config_path().is_file() else 'none'})")
        print(f"repo config:  {repo_config_path(args.repo)}"
              f"  ({'present' if repo_config_path(args.repo).is_file() else 'none'})")
        return 0
    errs = validate(cfg)
    for e in errs:
        print(f"clearmap: {e}", file=sys.stderr)
    if errs:
        return 1
    print("clearmap: configuration is valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
