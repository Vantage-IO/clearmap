"""Post-scan finding filters — the false-positive kill layer.

Applied by scan.py after dedupe, before output. Every filter is a pure
function of the target tree (no clocks, no network), so determinism
is preserved. Suppressions are counted, never silent: scan.py writes
`suppressed_count` into findings.json.

Filters re-read the raw source line from disk because engine snippets are
redacted (gitleaks --redact, ClearMap redact()) and value-aware heuristics
need the actual text.

Suppression order (first match wins):
  1. vendored/generated path
  2. inline `clearmap:allow <rule-id|*>` comment (finding line or line above)
  3. `.clearmapignore` globs at the target root (`pattern [rule-id]` per line)
  4. value heuristics, SECRETS findings only:
       templated secret  — ${VAR} / {{var}} / <YOUR_..> / env lookups / CHANGEME
       i18n key          — labelKey/i18nKey-style identifier + dotted/word value
       publishable token — pk_test_/pk_live_/phc_/Datadog pub<hex> client tokens
       widget URL key    — ?key=<uuid> inside an http(s) URL (embed snippets)
       gitignored .env   — secrets in a .env* file the repo already gitignores
  5. test-path SECRETS findings are downgraded to low (kept, not suppressed)
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path

VENDORED_PATH_RES = [re.compile(p) for p in (
    r"(^|/)node_modules/", r"(^|/)vendor/", r"(^|/)dist/", r"(^|/)build/",
    r"(^|/)\.next/", r"(^|/)__snapshots__/", r"\.min\.(js|css)$", r"\.(js|css)\.map$",
)]

_TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|__mocks__|spec)/")


def _is_phi_literal(f: dict) -> bool:
    """A Presidio PHI-literal finding is filed under SECRETS but is a real-looking
    patient identifier, not a credential. It must never be downgraded with
    secret/credential wording: a real PHI literal in a fixture is still a leak."""
    return f.get("rule_id") == "presidio-phi-literal" or f.get("engine") == "presidio"

_TEMPLATED_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"      # ${VAR}
    r"|\{\{\s*[\w.]+\s*\}\}"             # {{ var }}
    r"|<\s*YOUR[\w ]*>"                   # <YOUR_KEY_HERE>
    r"|process\.env\.|os\.environ|getenv\("
    r"|[\"'](CHANGEME|REPLACE_ME|xxxxx+)[\"']", re.IGNORECASE)

# Semantic i18n identifier + word-like value (never matches api_key/token vars).
_I18N_RE = re.compile(
    r"(?i)\b(label|i18n|translation|message|locale|trans|text|title|placeholder)"
    r"[_-]?key\s*[:=]\s*[\"'][a-z][a-z0-9_.]{2,80}[\"']")

# Publishable-by-design client tokens. Markers only, never `test`/`live`
# substrings (a billing-provider test_* key is a REAL secret and must keep firing).
_PUBLISHABLE_RE = re.compile(
    r"[\"'](pk_(test|live)_[A-Za-z0-9]+|phc_[A-Za-z0-9]+|pub[0-9a-f]{20,})[\"']")

# Widget/embed script URLs carrying a public key= UUID (Zendesk, intercom-style).
_URL_UUID_KEY_RE = re.compile(
    r"https?://[^\s\"']+[?&]key=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

# clearmap:allow <rule|*> [reason="..."] [expires="YYYY-MM-DD"]
_ALLOW_RE = re.compile(r"clearmap:allow\s+(\S+)(.*)$")
_KV_RE = re.compile(r'(reason|expires)\s*=\s*"([^"]*)"')


def _directives(s: str) -> dict:
    return {k: v for k, v in _KV_RE.findall(s or "")}


def _raw_line(target: Path, rel: str, line: int, cache: dict) -> str:
    if rel not in cache:
        try:
            cache[rel] = (target / rel).read_text(errors="ignore").splitlines()
        except OSError:
            cache[rel] = []
    lines = cache[rel]
    return lines[line - 1] if 0 < line <= len(lines) else ""


def load_clearmapignore(target: Path) -> list[tuple[str, str, str, str | None]]:
    """Parse <target>/.clearmapignore -> [(glob, rule_or_*, reason, expires)].
    Line format: `pattern [rule-id] [reason="..."] [expires="YYYY-MM-DD"]`."""
    path = target / ".clearmapignore"
    rules: list[tuple[str, str, str, str | None]] = []
    if not path.exists():
        return rules
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        d = _directives(line)
        core = _KV_RE.sub("", line).split()  # pattern + optional rule, directives stripped
        if not core:
            continue
        pattern = core[0]
        rule = core[1] if len(core) > 1 else "*"
        rules.append((pattern, rule, d.get("reason", ""), d.get("expires")))
    return rules


def _clearmapignore_match(f: dict, ignores) -> tuple[str, str, str, str | None] | None:
    rel = f.get("file", "")
    for pattern, rule, reason, expires in ignores:
        if rule not in ("*", f.get("rule_id")):
            continue
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*"):
            return (pattern, rule, reason, expires)
    return None


def _inline_allow(f: dict, target: Path, cache: dict) -> dict | None:
    """Return {rule, reason, expires, wildcard} for an inline allow on the finding
    line or the line above, else None."""
    line_no = f.get("line", 0)
    for n in (line_no, line_no - 1):
        m = _ALLOW_RE.search(_raw_line(target, f.get("file", ""), n, cache))
        if not m:
            continue
        rule, rest = m.group(1), m.group(2)
        if rule not in ("*", f.get("rule_id")):
            continue
        d = _directives(rest)
        return {"rule": rule, "reason": d.get("reason", ""),
                "expires": d.get("expires"), "wildcard": rule == "*"}
    return None


def _gitignored_env_file(f: dict, target: Path, git_cache: dict) -> bool:
    rel = f.get("file", "")
    if not Path(rel).name.startswith(".env"):
        return False
    if rel not in git_cache:
        try:
            proc = subprocess.run(["git", "-C", str(target), "check-ignore", "-q", rel],
                                  capture_output=True, check=False, timeout=30)
            git_cache[rel] = proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            git_cache[rel] = False  # a hung/absent git => treat as not gitignored
    return git_cache[rel]


def _value_heuristic(raw: str, f: dict, target: Path, git_cache: dict) -> str | None:
    """Reason string if a SECRETS finding matches a known false-positive class."""
    if _TEMPLATED_RE.search(raw):
        return "templated placeholder, not a real credential"
    if _I18N_RE.search(raw):
        return "i18n label key, not secret material"
    if _PUBLISHABLE_RE.search(raw):
        return "publishable client token (ships in the browser by design)"
    if _URL_UUID_KEY_RE.search(raw):
        return "widget embed URL with a public key= UUID"
    if _gitignored_env_file(f, target, git_cache):
        return "value in a gitignored .env file"
    return None


def _rec(f: dict, rel: str, source: str, reason: str, expires, disposition: str) -> dict:
    return {"file": rel, "line": f.get("line"), "rule_id": f.get("rule_id"),
            "category": f.get("category"), "source": source,
            "reason": reason or "", "expires": expires, "disposition": disposition}


def apply_filters(findings: list[dict], target: Path) -> tuple[list[dict], list[dict], list[str]]:
    """Return (kept, ledger, warnings).

    ledger is a sanitized, auditable record of every suppression and downgrade
    ({file, line, rule_id, category, source, reason, expires, disposition}).
    Real secrets in generated/vendored paths are DOWNGRADED (kept visible), never
    silently dropped by path alone. Explicit suppressions carry a reason; a
    wildcard allow with no reason is refused (finding kept + warning), and a
    reason-less specific allow is honored with a deprecation warning."""
    ignores = load_clearmapignore(target)
    line_cache: dict[str, list[str]] = {}
    git_cache: dict[str, bool] = {}
    kept: list[dict] = []
    ledger: list[dict] = []
    warnings: list[str] = []
    for f in findings:
        rel = f.get("file", "")
        cat = f.get("category")
        raw = _raw_line(target, rel, f.get("line", 0), line_cache)
        source = reason = None
        expires = None

        vendored = any(rx.search(rel) for rx in VENDORED_PATH_RES)
        if vendored and cat == "SECRETS":
            # Keep real secrets visible: downgrade, do not suppress by path alone.
            f = {**f, "severity": "low", "title": f.get("title", "")
                 + " (in a generated/vendored path: verify it is not a real secret)"}
            ledger.append(_rec(f, rel, "generated-or-vendored",
                               "vendored/generated path (secret kept visible)", None, "downgraded"))
            kept.append(f)
            continue
        if vendored:
            source, reason = "generated-or-vendored", "vendored/generated path"

        if source is None:
            inl = _inline_allow(f, target, line_cache)
            if inl is not None:
                if inl["wildcard"] and not inl["reason"]:
                    warnings.append(f'{rel}:{f.get("line")} `clearmap:allow *` requires '
                                    'reason="..."; finding kept')
                else:
                    if not inl["reason"]:
                        warnings.append(f'{rel}:{f.get("line")} `clearmap:allow` without '
                                        'reason="..." is deprecated')
                    source, reason, expires = "inline", inl["reason"], inl["expires"]

        if source is None:
            ci = _clearmapignore_match(f, ignores)
            if ci is not None:
                _pat, _rule, r, e = ci
                if not r:  # path-scoped globs stay backward-compatible; nudge toward a reason
                    warnings.append(f'.clearmapignore `{_pat}` without reason="..." is deprecated')
                source, reason, expires = "clearmapignore", r, e

        if source is None and cat == "SECRETS":
            vh = _value_heuristic(raw, f, target, git_cache)
            if vh:
                source, reason = "automatic-filter", vh

        if source is not None:
            ledger.append(_rec(f, rel, source, reason, expires, "suppressed"))
            continue

        if (cat == "SECRETS" and _TEST_PATH_RE.search(rel)
                and not _is_phi_literal(f)):
            f = {**f, "severity": "low", "title": f.get("title", "")
                 + " (test-fixture path: verify it is not a real credential)"}
            ledger.append(_rec(f, rel, "test-path-downgrade", "test-fixture path", None, "downgraded"))
        kept.append(f)
    return kept, ledger, warnings
