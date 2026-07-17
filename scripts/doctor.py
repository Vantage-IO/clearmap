#!/usr/bin/env python3
"""clearmap doctor: check the scanner engines, the configuration, and the
reasoning provider, and report the exact next action for anything missing."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
import init as initmod  # noqa: E402
import providers  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose ClearMap readiness")
    ap.add_argument("target", type=Path, nargs="?", default=Path("."))
    args = ap.parse_args()
    target = args.target.resolve()

    print("Engines:")
    ok = initmod.doctor(target) == 0

    print("\nReasoning provider:")
    cfg = config.load(target)
    print(f"  provider: {cfg['provider']}   privacy mode: {cfg['privacy_mode']}")
    errs = config.validate(cfg)
    for e in errs:
        print(f"  ✗ {e}")
        ok = False
    if cfg["provider"] == "openai-compatible" and not errs:
        local = config.is_loopback(cfg.get("base_url"))
        print(f"  endpoint: {cfg['base_url']} ({'local' if local else 'remote'})")
        if not local and not config.resolve_api_key(cfg):
            print(f"  ✗ API key env {cfg['api_key_env']} is not set")
            ok = False
        try:
            models = providers.list_models(cfg, timeout=5)
            if cfg.get("model") and models and cfg["model"] not in models:
                print(f"  ~ model {cfg['model']} not offered by the endpoint "
                      f"({len(models)} available)")
            else:
                print(f"  ✓ endpoint reachable ({len(models)} models)")
        except providers.ProviderError as e:
            print(f"  ✗ {e}")
            ok = False
    else:
        print("  (host-agent / manual: no endpoint to reach)")

    print("\nReady." if ok else "\nNot ready: resolve the items marked with an X above.")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
