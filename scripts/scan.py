#!/usr/bin/env python3
"""ClearMap deterministic layer.

Wraps Semgrep (ClearMap `rules/`) + Gitleaks, normalizes their output into a
single `findings.json` with `source: deterministic`. Same input + pinned engine
versions => byte-stable output (findings sorted; no timestamps in the finding
set). Snippets are redacted (no raw PHI/secret values).

Usage:
    python3 scripts/scan.py <target> [--out findings.json] [--diff] [--rules DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact  # noqa: E402
from filters import apply_filters  # noqa: E402

# Data paths work in both layouts: repo (<root>/rules, scripts/ beside it)
# and pip-installed package (clearmap/rules inside the package dir).
_HERE = Path(__file__).resolve().parent
REPO = _HERE.parent
DEFAULT_RULES = next((p for p in (REPO / "rules", _HERE / "rules") if p.is_dir()),
                     REPO / "rules")
BASELINE = next(
    (p for p in (REPO / "references" / "regulatory-baseline.json",
                 _HERE / "references" / "regulatory-baseline.json") if p.is_file()),
    REPO / "references" / "regulatory-baseline.json")

# Gitleaks rule-id -> ClearMap finding metadata. Most gitleaks hits are a
# secret-in-source (SECRETS); a connection string with embedded credentials is
# an access-control credential exposure (ACCESS).
GITLEAKS_DEFAULT = {
    "category": "SECRETS",
    "severity": "high",
    "hipaa_ref": "164.312(a)(1)",
    "remediation": "Move the secret to a secret manager / env var and rotate it.",
}
GITLEAKS_RULE_OVERRIDES = {
    "clearmap-db-uri-credentials": {
        "category": "ACCESS",
        "severity": "critical",
        "hipaa_ref": "164.312(a)(2)(i)",
        "remediation": "Load DB credentials from a secret manager / env vars; rotate the exposed password.",
    },
}

# ClearMap metadata / output files — never scan these (they legitimately contain
# example secrets and finding text). Matched by basename.
EXCLUDE_BASENAMES = {
    "expected-findings.json", "findings.json", "clearmap-report.md",
    "clearmap-report.html", "findings-deterministic.json", "reasoning.json",
    "regulatory-baseline.json",
}


# Calibrated engine pins (a version that does not match is recorded, not fatal).
ENGINE_PINS = {"semgrep": "1.164", "gitleaks": "8.30"}

# Engine statuses that mean the engine ran and its results are trustworthy.
_HEALTHY = {"success"}


def _engine_version(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
        return (r.stdout.strip() or r.stderr.strip()) or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _sanitize_reason(text: str | None) -> str:
    """Collapse and redact engine stderr so no source/secret text reaches output."""
    if not text:
        return ""
    return redact(" ".join(text.split()))[:200]


def _looks_config_error(stderr: str) -> bool:
    low = (stderr or "").lower()
    return any(k in low for k in ("invalid", "unable to parse", "could not parse", "rule schema"))


def _engine_status(name: str, status: str, version: str | None = None, *,
                   exit_code: int | None = None, files: int | None = None,
                   mode: str = "full", reason: str | None = None) -> dict:
    """A byte-stable per-engine status record. NOTE: no timing/clock fields are
    stored here; scan output must be byte-identical across runs."""
    st: dict = {"status": status, "version": version, "exit_code": exit_code,
                "files_considered": files, "mode": mode}
    pin = ENGINE_PINS.get(name)
    if version and pin:
        st["version_matches_pin"] = version.startswith(pin)
    reason = _sanitize_reason(reason)
    if reason:
        st["reason"] = reason
    return st


def _scan_block(target: Path, findings: list[dict]) -> dict:
    """Byte-stable fingerprint that binds a reasoning pass to THIS scan and
    revision. commit = the target's git HEAD (or 'no-git'); fingerprint = a hash
    of the commit plus the sorted findings, so a reasoning.json can prove it was
    produced for the current code, not a stale run."""
    try:
        commit = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=False, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = ""
    commit = commit or "no-git"
    payload = commit + json.dumps(findings, sort_keys=True)
    return {"commit": commit, "fingerprint": hashlib.sha256(payload.encode()).hexdigest()[:16]}


def _changed_files(target: Path) -> list[str]:
    """Files changed vs HEAD (staged + unstaged) plus untracked files. Uses
    NUL-delimited git output so paths with spaces, tabs, newlines, or non-ASCII
    characters are never split or silently dropped."""
    def _z(cmd: list[str]) -> list[str]:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 check=False, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return []  # a hung/absent git must not hang or crash the scan
        return [p for p in out.split("\0") if p]
    diff = _z(["git", "-C", str(target), "diff", "-z", "--name-only", "HEAD"])
    untracked = _z(["git", "-C", str(target), "ls-files", "-z", "--others", "--exclude-standard"])
    files = dict.fromkeys(diff + untracked)  # ordered de-dupe
    return [str(target / f) for f in files if (target / f).exists()]


# Dirs whose code-pattern findings are noise (semgrep rules skip them); gitleaks
# still scans everything, so secrets/PHI literals in test code remain covered.
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "__mocks__", "__snapshots__"}


def _semgrep_targets(target: Path, paths: list[str] | None) -> list[str]:
    """Enumerate source files explicitly. Semgrep's default behavior (git-tracked
    files only + a built-in ignore list) silently skips untracked files — exactly
    what an in-progress healthcare repo is full of. Explicit file targets bypass
    that and make the scanned set a deterministic function of the tree.
    """
    if paths is not None:
        # Diff mode: apply the SAME directory exclusions as a full walk so
        # semgrep never flags code-pattern noise in test/vendored dirs on --diff
        # that it would skip on a full scan (gitleaks still sees these files, so
        # secrets in test code stay covered).
        excluded = _SKIP_DIRS | _TEST_DIRS
        troot = target.resolve()
        out: list[str] = []
        for p in paths:
            if Path(p).suffix not in _SRC_EXT:
                continue
            try:
                rel_parts = Path(p).resolve().relative_to(troot).parts
            except ValueError:
                rel_parts = Path(p).parts
            if any(part in excluded for part in rel_parts[:-1]):
                continue
            out.append(p)
        return out
    files: list[str] = []
    import os
    for root, dirs, names in os.walk(target):
        rel_root = Path(root)
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and d not in _TEST_DIRS)
        for n in sorted(names):
            if Path(n).suffix in _SRC_EXT:
                files.append(str(rel_root / n))
    return files


def run_semgrep(target: Path, rules: Path, paths: list[str] | None,
                timeout: int = 300) -> tuple[list[dict], dict]:
    """Run Semgrep and return (findings, engine_status). Fails closed: a missing
    binary, an engine/config error, malformed JSON, or a timeout yields an empty
    findings list and a non-'success' status so the caller can refuse to score."""
    version = _engine_version(["semgrep", "--version"])
    mode = "diff" if paths is not None else "full"
    if not shutil.which("semgrep"):
        return [], _engine_status("semgrep", "missing", version, mode=mode)
    scan_paths = _semgrep_targets(target, paths)
    files = len(scan_paths)
    if not scan_paths:
        return [], _engine_status("semgrep", "success", version, exit_code=0, files=0, mode=mode)
    results: list[dict] = []
    last_rc = 0
    BATCH = 1500  # keep argv well under ARG_MAX on large repos
    for i in range(0, len(scan_paths), BATCH):
        try:
            proc = subprocess.run(
                ["semgrep", "--config", str(rules), "--json", "--quiet",
                 "--metrics", "off", "--disable-version-check", *scan_paths[i:i + BATCH]],
                capture_output=True, text=True, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [], _engine_status("semgrep", "timeout", version, files=files,
                                      mode=mode, reason=f"exceeded {timeout}s")
        last_rc = proc.returncode
        if proc.returncode >= 2:  # semgrep: 0 = ok, 1 = findings, >=2 = error
            st = "config-invalid" if _looks_config_error(proc.stderr) else "error"
            return [], _engine_status("semgrep", st, version, exit_code=proc.returncode,
                                      files=files, mode=mode, reason=proc.stderr)
        if not proc.stdout.strip():
            continue
        try:
            results.extend(json.loads(proc.stdout).get("results", []))
        except json.JSONDecodeError as e:
            return [], _engine_status("semgrep", "malformed-output", version,
                                      exit_code=proc.returncode, files=files, mode=mode,
                                      reason=str(e))
    findings = []
    line_cache: dict[str, list[str]] = {}
    for r in results:
        meta = r.get("extra", {}).get("metadata", {})
        snippet = _source_lines(r.get("path", ""),
                                r.get("start", {}).get("line", 0),
                                r.get("end", {}).get("line", 0), line_cache)
        findings.append({
            "rule_id": r.get("check_id", "").split(".")[-1],
            "category": meta.get("clearmap_category", "UNKNOWN"),
            "severity": meta.get("clearmap_severity", "medium"),
            "source": "deterministic",
            "engine": "semgrep",
            "hipaa_ref": meta.get("hipaa_ref", ""),
            "file": _rel(r.get("path", ""), target),
            "line": r.get("start", {}).get("line", 0),
            "title": meta.get("clearmap_title", r.get("extra", {}).get("message", "")),
            # Truncate AFTER redaction: cutting first would strip a value's
            # closing quote and leak the prefix through the redactor.
            "structural_snippet": redact(snippet.strip())[:SNIPPET_CHARS],
            "why": r.get("extra", {}).get("message", "").strip(),
            "remediation": meta.get("remediation", ""),
        })
    return findings, _engine_status("semgrep", "success", version,
                                    exit_code=last_rc, files=files, mode=mode)


# Display length of a redacted snippet; the caller truncates to this AFTER
# redaction (never before, or a cut could leak a value prefix).
SNIPPET_CHARS = 300


def _source_lines(path: str, start: int, end: int,
                  cache: dict[str, list[str]], max_chars: int = 4000) -> str:
    """Read the matched line range from the source file. Semgrep's own
    `extra.lines` field is login-gated ("requires login"), so the snippet is
    extracted here and redacted by the caller. `max_chars` is a generous read
    bound (redaction runs on the full snippet; the caller trims to SNIPPET_CHARS
    afterwards)."""
    if not path or start < 1:
        return ""
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(errors="ignore").splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path][start - 1:max(start, end)]
    return "\n".join(ln.strip() for ln in lines)[:max_chars]


def run_gitleaks(target: Path, rules: Path, paths: list[str] | None,
                 timeout: int = 300, history: bool = False) -> tuple[list[dict], dict]:
    """Run Gitleaks and return (findings, engine_status). Uses the current 8.30
    subcommands: `git` for history, `dir` for the working tree. `dir` scans a
    single path, so for --diff the changed files are mirrored into a temp tree
    (preserving repo-relative paths) and reported paths are mapped back, making
    --diff restrict BOTH engines. Gitleaks exits non-zero when it FINDS leaks
    (success); a real error is an unparseable/absent report plus a non-zero exit."""
    version = _engine_version(["gitleaks", "version"])
    mode = "history" if history else ("diff" if paths is not None else "full")
    if not shutil.which("gitleaks"):
        return [], _engine_status("gitleaks", "missing", version, mode=mode)
    cfg = rules / "gitleaks.toml"
    tmp = tempfile.NamedTemporaryFile(prefix="clearmap-gitleaks-", suffix=".json", delete=False)
    report = Path(tmp.name)
    tmp.close()
    mirror: Path | None = None
    if history:
        scan_root, cmd = target, ["gitleaks", "git", str(target)]
    elif paths is not None:
        mirror = Path(tempfile.mkdtemp(prefix="clearmap-gl-diff-"))
        for p in paths:
            rel = _rel(p, target)
            if rel.startswith("/") or ".." in Path(rel).parts:
                continue
            dest = mirror / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(p, dest)
            except OSError:
                pass
        scan_root, cmd = mirror, ["gitleaks", "dir", str(mirror)]
    else:
        scan_root, cmd = target, ["gitleaks", "dir", str(target)]
    cmd += ["--report-format", "json", "--report-path", str(report), "--redact", "--no-banner"]
    if cfg.exists():
        cmd += ["--config", str(cfg)]

    def _cleanup():
        report.unlink(missing_ok=True)
        if mirror:
            shutil.rmtree(mirror, ignore_errors=True)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        _cleanup()
        return [], _engine_status("gitleaks", "timeout", version, mode=mode, reason=f"exceeded {timeout}s")
    rc = proc.returncode
    raw = report.read_text() if report.exists() else ""
    try:
        if raw.strip():
            try:
                leaks = json.loads(raw)
            except json.JSONDecodeError as e:
                return [], _engine_status("gitleaks", "malformed-output", version,
                                          exit_code=rc, mode=mode, reason=str(e))
            if not isinstance(leaks, list):
                return [], _engine_status("gitleaks", "malformed-output", version,
                                          exit_code=rc, mode=mode, reason="report is not a JSON array")
        elif rc == 0:
            leaks = []  # ran cleanly, found nothing
        else:
            return [], _engine_status("gitleaks", "error", version, exit_code=rc,
                                      mode=mode, reason=proc.stderr)
        findings = []
        for lk in leaks:
            rule = lk.get("RuleID", "secret")
            meta = GITLEAKS_RULE_OVERRIDES.get(rule, GITLEAKS_DEFAULT)
            f = {
                "rule_id": rule,
                "category": meta["category"],
                "severity": meta["severity"],
                "source": "deterministic",
                "engine": "gitleaks",
                "hipaa_ref": meta["hipaa_ref"],
                "file": _rel(lk.get("File", ""), scan_root),
                "line": lk.get("StartLine", 0),
                "title": lk.get("Description", "Hardcoded secret"),
                "structural_snippet": redact(lk.get("Match", "").strip()),
                "why": lk.get("Description", ""),
                "remediation": meta["remediation"],
            }
            if history:
                f["scan_scope"] = "history"
            findings.append(f)
        return findings, _engine_status("gitleaks", "success", version, exit_code=rc,
                                        files=(len(paths) if paths else None), mode=mode)
    finally:
        _cleanup()


def _rel(path: str, target: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target.resolve()))
    except ValueError:
        return path


_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build",
              ".next", "__pycache__", "htmlcov", ".trunk", ".clearmap"}
_SRC_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte", ".rb", ".go",
            ".java", ".php", ".cs", ".env", ".toml", ".yaml", ".yml"}
import re as _re  # noqa: E402

_SIG = {
    "frontend_client": _re.compile(
        r"localStorage|sessionStorage|document\.cookie|window\.|navigator\.|"
        r"from ['\"]react|analytics\.", _re.I),
    "ai": _re.compile(
        r"openai|anthropic|xai_sdk|langchain|llama_index|cohere|bedrock|vertexai|"
        r"generativeai|litellm|chat\.completions|ChatCompletion", _re.I),
    "network": _re.compile(
        r"requests\.|httpx|aiohttp|urllib|http\.client|fetch\(|axios|WebSocket", _re.I),
    "backend": _re.compile(
        r"fastapi|flask|django|APIRouter|@app\.(route|get|post|put|delete)|@router\.|"
        r"express\(|http\.server|wsgi|asgi", _re.I),
}


def detect_applicability(target: Path, paths: list[str] | None) -> dict[str, bool]:
    """Best-effort, CONSERVATIVE detection of which category surfaces exist.
    Only the surface-specific categories can be marked not-applicable; SECRETS is
    always applicable, and a category with any finding is forced applicable later.
    """
    import os
    sig = {k: False for k in _SIG}
    files = [Path(p) for p in paths] if paths else None
    if files is None:
        files = []
        for root, dirs, names in os.walk(target):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            for n in sorted(names):
                if Path(n).suffix in _SRC_EXT:
                    files.append(Path(root) / n)
    budget = 8_000_000
    for fp in files:
        if budget <= 0:
            break
        try:
            text = fp.read_text(errors="ignore")[:200_000]
        except OSError:
            continue
        budget -= len(text)
        for k, rx in _SIG.items():
            if not sig[k] and rx.search(text):
                sig[k] = True
    return {
        "ACCESS": sig["backend"] or sig["frontend_client"],
        "AUTH": sig["backend"] or sig["frontend_client"],
        "AUDIT": sig["backend"],
        "INTEGRITY": sig["backend"],
        "TRANSIT": sig["network"] or sig["backend"],
        "SESSION": sig["frontend_client"],
        "TRACKING": sig["frontend_client"],
        "AI-RAG": sig["ai"],
        "APPSEC": sig["backend"],
        "SECRETS": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="ClearMap deterministic scan")
    ap.add_argument("target", type=Path)
    ap.add_argument("--out", type=Path, default=Path("findings.json"))
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    ap.add_argument("--diff", action="store_true", help="scan only files changed vs HEAD")
    ap.add_argument("--presidio", action="store_true",
                    help="opt-in: Presidio PHI-literal check on seed/fixture/template "
                         "files (requires presidio-analyzer; absent = skipped)")
    ap.add_argument("--engine-timeout", type=int, default=300,
                    help="per-engine timeout in seconds (default 300)")
    ap.add_argument("--history", action="store_true",
                    help="also scan git history for secrets (gitleaks git); slower, off by default")
    args = ap.parse_args()

    target = args.target.resolve()
    # Fail closed on a bad target: scanning nothing must never look like a clean
    # scan. Error out before writing any findings.json.
    if not target.is_dir():
        print(f"clearmap: target is not a directory: {target}", file=sys.stderr)
        return 2
    paths = _changed_files(target) if args.diff else None
    mode = "diff" if paths is not None else "full"
    if args.diff and not paths:
        print("clearmap: no changed files to scan", file=sys.stderr)

    sem_findings, sem_status = run_semgrep(target, args.rules, paths, args.engine_timeout)
    gl_findings, gl_status = run_gitleaks(target, args.rules, paths, args.engine_timeout)
    findings = sem_findings + gl_findings
    engine_status = {"semgrep": sem_status, "gitleaks": gl_status}
    if args.history:
        # Separate pass over git history; history-only secrets are tagged so
        # current-tree and history findings stay distinguishable.
        hist_findings, hist_status = run_gitleaks(target, args.rules, None,
                                                  args.engine_timeout, history=True)
        engine_status["gitleaks_history"] = hist_status
        cur_keys = {(f.get("file"), f.get("rule_id")) for f in gl_findings}
        findings += [f for f in hist_findings
                     if (f.get("file"), f.get("rule_id")) not in cur_keys]
    if args.presidio:
        from presidio_check import run_presidio, presidio_available
        pv = presidio_available()
        try:
            findings += run_presidio(target, paths)
            engine_status["presidio"] = _engine_status(
                "presidio", "success" if pv else "missing", pv or None, mode=mode)
        except Exception as e:  # presidio is opt-in and never required
            engine_status["presidio"] = _engine_status(
                "presidio", "error", pv or None, reason=str(e), mode=mode)
    # Drop ClearMap metadata/output files (they legitimately contain example secrets).
    findings = [f for f in findings if Path(f["file"]).name not in EXCLUDE_BASENAMES]
    # Dedupe identical hits (same rule firing per PHI-field line).
    seen: set[tuple] = set()
    deduped = []
    for f in findings:
        key = (f["file"], f["line"], f["category"], f["rule_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped
    # False-positive kill layer (vendored paths, i18n keys, publishable tokens,
    # .clearmapignore, inline clearmap:allow). Ledgered, never silent.
    findings, ledger, filter_warnings = apply_filters(findings, target)
    for w in filter_warnings:
        print(f"clearmap: {w}", file=sys.stderr)
    suppressed = sum(1 for r in ledger if r["disposition"] == "suppressed")
    # Stable ordering for byte-identical output.
    findings.sort(key=lambda f: (f["file"], f["line"], f["category"], f["rule_id"]))
    ledger.sort(key=lambda r: (r["file"], r["line"] or 0, r["rule_id"] or "", r["source"]))

    # Fail closed: a required engine that did not complete cleanly makes the
    # result set untrustworthy. The file is still written (so the report can
    # render "Score unavailable"), marked not-ok, and the process exits non-zero.
    required = ("semgrep", "gitleaks")
    scan_ok = all(engine_status[e]["status"] in _HEALTHY for e in required)

    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    # Authority type per finding, derived once from the cited regulation's status
    # (or an explicit authority_type) in the baseline. Single source of truth.
    _regs = baseline.get("regulations", {})
    _status_auth = {"required": "hipaa-required", "addressable": "hipaa-addressable",
                    "guidance": "ocr-guidance", "certification criterion": "onc-certification-criterion"}
    for f in findings:
        reg = _regs.get(f.get("hipaa_ref"), {})
        auth = reg.get("authority_type") or _status_auth.get(reg.get("status", ""), "")
        if auth:
            f["authority_type"] = auth
    out = {
        "schema_version": "0.2",
        "source_layer": "deterministic",
        "scan_ok": scan_ok,
        "scan": _scan_block(target, findings),
        "engines": {k: (v.get("version") or "not-installed") for k, v in engine_status.items()},
        "engine_status": engine_status,
        "regulatory_baseline": {
            "version": baseline.get("baseline_version"),
            "as_of": baseline.get("as_of"),
        },
        "applicability": detect_applicability(target, paths),
        "suppressed_count": suppressed,
        "suppressions": ledger,
        "findings": findings,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    print(f"clearmap: {len(findings)} deterministic findings "
          f"({suppressed} suppressed) -> {args.out}")
    for cat in sorted(by_cat):
        print(f"  {cat:10s} {by_cat[cat]}")
    if not scan_ok:
        for e in required:
            st = engine_status[e]
            if st["status"] not in _HEALTHY:
                extra = f": {st['reason']}" if st.get("reason") else ""
                print(f"clearmap: {e} did not complete ({st['status']}{extra})",
                      file=sys.stderr)
        print("clearmap: scan incomplete; results are not scoreable. "
              "Run 'clearmap doctor <target>' to diagnose.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
