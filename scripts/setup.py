#!/usr/bin/env python3
"""clearmap setup: configure how the AI-assisted reasoning review runs.

Default is the host agent (the coding agent running ClearMap): no API key, no
network. Optionally point at an OpenAI-compatible endpoint, local (Ollama, LM
Studio) or remote (OpenRouter and similar). A remote endpoint requires an
explicit opt-in and only stores the NAME of the env var holding the key.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
import providers  # noqa: E402


def _interactive() -> dict:
    print("ClearMap reasoning setup.\n"
          "Default is the host agent (this coding agent): no API key, no network.\n")
    print("How should the AI-assisted review run?")
    print("  1) host-agent          (recommended)")
    print("  2) openai-compatible   (a local model, or a remote one like OpenRouter)")
    print("  3) manual              (you supply reasoning.json yourself)")
    provider = {"1": "host-agent", "2": "openai-compatible", "3": "manual"}.get(
        input("Choose [1]: ").strip() or "1", "host-agent")
    cfg = {"provider": provider}
    if provider != "openai-compatible":
        return cfg
    print("\nProbing common local model servers...")
    for base, models in providers.probe_local():
        shown = ", ".join(models[:5]) or "(no models listed)"
        print(f"  found {base}  -> {shown}")
    base = input("Base URL [http://127.0.0.1:11434/v1]: ").strip() or "http://127.0.0.1:11434/v1"
    model = input("Model id: ").strip()
    cfg["base_url"] = base
    cfg["model"] = model
    if config.is_loopback(base):
        cfg["privacy_mode"] = "local-only"
    else:
        print("\nThis is a REMOTE endpoint. The files under review will be sent to it.")
        if input("Type 'yes' to allow a remote provider: ").strip().lower() != "yes":
            print("Keeping host-agent.")
            return {"provider": "host-agent"}
        cfg["privacy_mode"] = "provider-managed"
        cfg["api_key_env"] = (input("Env var holding the API key "
                                    "[CLEARMAP_MODEL_API_KEY]: ").strip()
                              or "CLEARMAP_MODEL_API_KEY")
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description="Configure the ClearMap reasoning provider")
    ap.add_argument("--non-interactive", action="store_true")
    ap.add_argument("--provider", choices=config.PROVIDERS)
    ap.add_argument("--base-url")
    ap.add_argument("--model")
    ap.add_argument("--api-key-env")
    ap.add_argument("--privacy-mode", choices=config.PRIVACY_MODES)
    ap.add_argument("--config-scope", choices=["user", "repo"], default="user")
    ap.add_argument("--repo", type=Path, default=Path("."))
    args = ap.parse_args()

    if args.non_interactive or args.provider:
        overrides = {k: v for k, v in {
            "provider": args.provider, "base_url": args.base_url, "model": args.model,
            "api_key_env": args.api_key_env, "privacy_mode": args.privacy_mode}.items() if v}
    else:
        overrides = _interactive()
    cfg = config.load(args.repo, overrides=overrides)

    errs = config.validate(cfg)
    for e in errs:
        print(f"clearmap: {e}", file=sys.stderr)
    if errs:
        return 1
    path = config.save(cfg, args.config_scope, args.repo)
    print(f"clearmap: saved {args.config_scope} config -> {path}")
    print(json.dumps(config.redacted(cfg), indent=2))
    if cfg["provider"] == "openai-compatible" and not config.is_loopback(cfg.get("base_url")) \
            and not config.resolve_api_key(cfg):
        print(f"clearmap: set the API key in ${cfg['api_key_env']} before an audit.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
