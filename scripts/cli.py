#!/usr/bin/env python3
"""`clearmap` console entry point.

Thin dispatcher over the pipeline scripts, so a pip install exposes one
command. The `python3 scripts/<name>.py` invocations keep working unchanged.

    clearmap setup [--provider ...] [--config-scope user|repo]
    clearmap config show|validate
    clearmap doctor [<target>]
    clearmap audit <target> [--provider ...] [--diff] [--history] [--format both]
    clearmap scan <target> [--out ...]
    clearmap report <findings.json> [--format both] [--out ...]
    clearmap merge <deterministic.json> <reasoning.json> --out <combined.json>
    clearmap export <findings.json> --format sarif|csv --out <file>
    clearmap issues [findings.json] [--severity ...]
    clearmap suppressions [findings.json] [--as-of DATE] [--fail-on-expired]
    clearmap init install|uninstall|doctor <target>
    clearmap calibrate --expected <exp.json> --candidate <run.json> ...
    clearmap score <findings.json>
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _version import __version__  # noqa: E402

COMMANDS = {
    "scan": "scan",
    "report": "report",
    "merge": "merge_reasoning",
    "export": "export",
    "issues": "issues",
    "init": "init",
    "calibrate": "calibrate",
    "score": "scoring",
    "suppressions": "suppressions",
    "setup": "setup",
    "config": "config",
    "doctor": "doctor",
    "audit": "audit",
    "reason": "reason",
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if sys.argv[1] in ("-V", "--version"):
        print(f"clearmap {__version__}")
        return 0
    cmd = sys.argv[1]
    if cmd not in COMMANDS:
        print(f"clearmap: unknown command {cmd!r} "
              f"(expected one of: {', '.join(COMMANDS)})", file=sys.stderr)
        return 2
    del sys.argv[1]  # let the target module's argparse see its own args
    mod = importlib.import_module(COMMANDS[cmd])
    return int(mod.main() or 0)


if __name__ == "__main__":
    sys.exit(main())
