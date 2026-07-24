#!/usr/bin/env python3
"""ClearMap report renderer.

Renders findings + scores into a professional compliance-grade report:
  executive summary · scope and method · score · category scorecard ·
  findings table · priority findings · AI/LLM/RAG findings · reviewer
  questions · regulatory citations (joined from the versioned baseline) ·
  scoring appendix · about/disclaimer appendix with a neutral closing note.

Formats: markdown (default), self-contained HTML (--format html), or both.
Content decisions live in build_model() ONCE; render_md() here and
render_html() in report_html.py are mechanical emitters of the same model, so
the two formats can never drift in content.

No price, no "HIPAA compliant"/certification language (the banned-phrase guard
runs on every rendered output), disclaimer always present. Findings are
already redacted upstream. Output copy never contains em or en
dashes (house style); _normalize_dashes() enforces it on the final text.

    python3 scripts/report.py findings.json --out clearmap-report.md \
        [--repo NAME] [--date YYYY-MM-DD] [--format md|html|both]
"""
from __future__ import annotations

import argparse
import datetime
import html
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acknowledgments as ack_mod  # noqa: E402
import scoring  # noqa: E402
from _version import __version__ as CLEARMAP_VERSION  # noqa: E402
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Data path works in both layouts: repo (<root>/references, scripts/ beside
# it) and pip-installed package (clearmap/references inside the package dir).
_HERE = Path(__file__).resolve().parent
BASELINE_PATH = next(
    (p for p in (_HERE.parent / "references" / "regulatory-baseline.json",
                 _HERE / "references" / "regulatory-baseline.json") if p.is_file()),
    _HERE.parent / "references" / "regulatory-baseline.json")

# Reader-facing labels for the two analysis layers. Pipeline-internal terms
# ("deterministic", "reasoning") must never appear in rendered output.
VERIFICATION_LABEL = {
    "deterministic": "Confirmed by automated rule",
    "reasoning": "Identified by AI-assisted review, requires human verification",
}
VERIFICATION_SHORT = {"deterministic": "Confirmed", "reasoning": "Needs verification"}

# Rolled-up reviewer questions per category (the "what an enterprise reviewer
# will ask" framing, used when individual findings don't carry one).
CATEGORY_REVIEWER_Q = {
    "ACCESS": "Are PHI actions restricted to permitted roles, and sessions revocable?",
    "AUTH": "Is every PHI access authenticated?",
    "AUDIT": "Is every PHI access and model call recorded to an audit trail?",
    "INTEGRITY": "Are PHI mutations authenticated and AI output marked unverified until reviewed?",
    "TRANSIT": "Is all PHI encrypted in transit on every external path?",
    "SESSION": "Does any PHI reach browser storage or a third-party client SDK?",
    "TRACKING": "Do analytics/tracking on patient surfaces carry any health data?",
    "AI-RAG": "Is PHI redacted before prompts, output cited + bounded to sources, and model calls audited?",
    "SECRETS": "Are all credentials loaded from a secret manager rather than source?",
    "APPSEC": "Is untrusted input kept out of SQL, shell, file paths, URLs, and deserializers?",
}

DISCLAIMER = """ClearMap is a **technical risk signal, not a legal HIPAA compliance certification.**
A ClearMap score does not mean a product is or is not HIPAA compliant. ClearMap
does not cover administrative safeguards (45 CFR 164.308), physical safeguards
(164.310), BAAs, organizational policy, or a full risk analysis, and does not
replace a security review, a penetration test, or counsel. Regulatory citations
are an engineering target; counsel must confirm them."""

# Score display label and the one-line qualification rendered next to the number.
SCORE_LABEL = "ClearMap HIPAA Technical Risk Score"
SCORE_QUALIFICATION = ("Technical code-risk signal only. Not a compliance score, "
                       "certification, formal HIPAA risk analysis, or legal determination.")

# Closing note (Appendix B). ClearMap-voiced, small Vantage IO attribution.
# No price, no compliance claim.
CTA_FOOTER = (
    "Prepared with ClearMap, an open-source HIPAA technical-risk scanner by Vantage IO. "
    "This is a partial, automated technical review, not a full audit. A complete "
    "reliability assessment goes further: deeper and broader detection coverage, expert "
    "verification of every finding, and review of the safeguards no automated tool can "
    "see. For that deeper look, visit vantageio.com."
)
CTA_URL = "https://vantageio.com"

# Banned-phrase guard: never emit an AFFIRMATIVE compliance/certification claim.
# (The disclaimer legitimately uses "...is or is not HIPAA compliant", so the
# guard targets affirmative phrasings only, not the word pair itself.)
BANNED_PHRASES = [
    "is hipaa compliant", "is hipaa-compliant", "are hipaa compliant",
    "fully compliant", "guarantees hipaa", "ensures hipaa compliance",
    "certified compliant", "is compliant with hipaa", "hipaa certified",
    "meets hipaa requirements", "satisfies hipaa",
]


def check_banned(text: str) -> str | None:
    """Return the first banned affirmative-compliance phrase found, else None."""
    low = text.lower()
    for b in BANNED_PHRASES:
        if b in low:
            return b
    return None


def _normalize_dashes(text: str) -> str:
    """House style: no em or en dashes in any rendered output."""
    return (text.replace(" — ", ": ").replace("—", "-")
                .replace(" – ", ": ").replace("–", "-"))


def _humanize(rule_id: str) -> str:
    """Readable fallback title from a rule slug (used only when title is missing)."""
    words = rule_id.replace("_", "-").split("-")
    return " ".join(w for w in words if w).capitalize()


# ------------------------------------------------------------ provenance --

def _sanitize_remote(url: str) -> str:
    """Never surface an embedded credential (https://user:token@host/...) that
    might live in a remote URL. Strip the userinfo, keep the host/path."""
    return re.sub(r"(https?://)[^/@\s]+@", r"\1", url)


def _git(repo_path: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo_path), *args],
                             capture_output=True, text=True, check=False, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def git_provenance(repo_path: Path) -> dict | None:
    """Source provenance for the scanned repo: branch, commit, last-commit
    date/time + committer, and the origin remote (the source of the repo).
    Returns None if the path is not a git work tree, so the report simply omits
    the block. Captured at report time (never in the byte-stable scan output)."""
    if _git(repo_path, "rev-parse", "--is-inside-work-tree") != "true":
        return None
    commit_full = _git(repo_path, "rev-parse", "HEAD")
    if not commit_full:
        return None
    branch = _git(repo_path, "rev-parse", "--abbrev-ref", "HEAD")
    return {
        "branch": branch if branch and branch != "HEAD" else "(detached HEAD)",
        "commit": commit_full[:9],
        "commit_full": commit_full,
        "committed_at": _git(repo_path, "log", "-1",
                             "--date=format:%Y-%m-%d %H:%M:%S %z", "--format=%cd"),
        "committer": _git(repo_path, "log", "-1", "--format=%cn"),
        "subject": _git(repo_path, "log", "-1", "--format=%s"),
        "source": _git(repo_path, "remote", "get-url", "origin"),
    }


# ------------------------------------------------------------- citations --

def load_baseline() -> dict:
    """Read the versioned regulatory baseline; empty dict if unavailable."""
    try:
        return json.loads(BASELINE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


# A citation's legal weight (status) maps to a structured authority type; a
# citation may also set authority_type explicitly (e.g. security-best-practice).
STATUS_AUTHORITY = {
    "required": "hipaa-required",
    "addressable": "hipaa-addressable",
    "guidance": "ocr-guidance",
    "certification criterion": "onc-certification-criterion",
}
AUTHORITY_LABEL = {
    "hipaa-required": "HIPAA Security Rule requirement",
    "hipaa-addressable": "HIPAA Security Rule addressable specification",
    "ocr-guidance": "HHS OCR guidance",
    "onc-certification-criterion": "ONC certification criterion",
    "security-best-practice": "Security best practice",
    "clinical-safety-practice": "Clinical safety practice",
}


def authority_of(ref: str, baseline: dict) -> str:
    """Structured authority type for a citation (explicit field, else by status)."""
    reg = (baseline.get("regulations") or {}).get(ref) or {}
    return reg.get("authority_type") or STATUS_AUTHORITY.get(reg.get("status", ""), "")


def resolve_citation(ref: str, baseline: dict) -> dict:
    """Join a finding's hipaa_ref against the regulatory baseline.

    Returns {ref, display, title, status_label, authority_type, authority_label,
    scope_note, pending, url, short, text}. Unknown refs degrade to the raw
    string and never crash the report.
    """
    fallback = {"ref": ref, "display": ref, "title": "", "status_label": "",
                "authority_type": "", "authority_label": "", "scope_note": "",
                "pending": "", "url": "", "short": ref, "text": ref}
    reg = (baseline.get("regulations") or {}).get(ref)
    if not reg:
        return fallback
    fw = (baseline.get("frameworks") or {}).get(reg.get("framework", ""), {})
    frm = reg.get("framework", "")
    # Display string by framework, not by sniffing the ref text.
    if frm == "hipaa-security-technical":
        display, short = f"45 CFR {ref}", ref
    elif frm == "onc-hti-1":
        display, short = "45 CFR 170.315(b)(11) (ONC HTI-1)", "HTI-1 (b)(11)"
    elif frm == "ocr-online-tracking":
        display, short = "HHS OCR online-tracking guidance", "OCR tracking guidance"
    else:
        root = fw.get("citation_root", "")
        display, short = (f"{root} {ref}".strip() if root and root not in ref else ref), ref
    status = reg.get("status", "")
    authority = reg.get("authority_type") or STATUS_AUTHORITY.get(status, "")
    if status == "addressable" and reg.get("clearmap_treatment") == "required":
        status_label = "Addressable, treated as Required per 164.306(d)(3)"
    else:
        status_label = AUTHORITY_LABEL.get(authority, status)
    title = reg.get("title", "").replace(" (standard)", "")
    scope_note = reg.get("scope_note", "")
    pending = ""
    pid = reg.get("pending")
    if pid:
        pc = next((p for p in baseline.get("pending_changes", []) if p.get("id") == pid), None)
        if pc:
            pending = f"{pc.get('title', '')} ({pc.get('status', 'proposed')})"
    text = f"{display}: {title}" + (f" ({status_label})" if status_label else "")
    return {"ref": ref, "display": display, "title": title, "status_label": status_label,
            "authority_type": authority, "authority_label": AUTHORITY_LABEL.get(authority, ""),
            "scope_note": scope_note, "pending": pending,
            "url": (fw.get("sources") or [""])[0], "short": short, "text": text}


# -------------------------------------------------------------- the model --

def _finding_view(f: dict, baseline: dict) -> dict:
    """Everything an emitter needs to render one finding, decided once."""
    sev = f.get("severity") or ""
    src = f.get("source", "deterministic")
    conf = f.get("confidence")
    verification = VERIFICATION_LABEL.get(src, VERIFICATION_LABEL["deterministic"])
    if src == "reasoning" and conf:
        verification += f" ({conf} confidence)"
    rid = f.get("id") or f.get("rule_id") or ""
    engine = f.get("engine", "")
    ref_line = rid
    if rid and engine in ("semgrep", "gitleaks"):
        ref_line += f" ({engine} rule)"
    file, line = f.get("file"), f.get("line")
    location = f"{file}:{line}" if file and line else (file or "")
    citation = resolve_citation(f["hipaa_ref"], baseline) if f.get("hipaa_ref") else None
    ack = f.get("acknowledged")
    verification_short = VERIFICATION_SHORT.get(src, "Confirmed")
    acknowledgment_line = ""
    if ack:
        verification_short = "Acknowledged"
        expires = f", expires {ack['expires']}" if ack.get("expires") else ""
        verification = (f"Acknowledged as accepted risk by {ack['owner']} on "
                        f"{ack['date']}{expires}")
        acknowledgment_line = ack.get("reason", "")
    elif f.get("acknowledgment_expired"):
        exp = f["acknowledgment_expired"]
        acknowledgment_line = (f"A previous acknowledgment by {exp['owner']} "
                               f"expired on {exp.get('expires', '')}; this finding is live again.")
    return {
        "title": f.get("title") or (_humanize(rid) if rid else "Finding"),
        "severity": sev,
        "severity_label": sev.capitalize() if sev else "Unrated",
        "category": f.get("category", ""),
        "location": location,
        "citation": citation,
        "evidence": f.get("structural_snippet", ""),
        "why": f.get("why", ""),
        "reviewer_question": (f.get("reviewer_question")
                              or CATEGORY_REVIEWER_Q.get(f.get("category", ""), "")),
        "remediation": f.get("remediation", ""),
        "verification": verification,
        "verification_short": verification_short,
        "acknowledged": bool(ack),
        "acknowledgment_line": acknowledgment_line,
        "ref_line": ref_line,
    }


def _findings_label(c: dict) -> str:
    """Scorecard cell: '2 confirmed + 1 to verify' with graceful singletons."""
    det, rea = c["deterministic_findings"], c["reasoning_findings"]
    parts = []
    if det:
        parts.append(f"{det} confirmed")
    if rea:
        parts.append(f"{rea} to verify")
    return " + ".join(parts) if parts else "0"


def build_model(data: dict, repo: str, date: str,
                provenance: dict | None = None,
                acknowledgments: list[dict] | None = None) -> dict:
    """All content decisions for the report, shared by every output format."""
    findings = data.get("findings", [])
    # Annotate acknowledged / expired findings before scoring so an accepted risk
    # does not deduct. Acknowledged findings stay in `findings` (shown, marked);
    # they are only excluded from the exec "top" list and the priority list, which
    # are action lists. The Acknowledgments appendix records each one.
    ack = ack_mod.apply(findings, acknowledgments or [], date)
    if provenance:
        provenance = dict(provenance)
        if provenance.get("source"):
            provenance["source"] = _sanitize_remote(provenance["source"])
    try:
        baseline = load_baseline()
    except Exception:
        baseline = {}
    scores = scoring.score_findings(findings, data.get("applicability"),
                                    source_layer=data.get("source_layer"))

    def sev_key(f):
        return (SEV_ORDER.get(f.get("severity"), 9), f.get("category", ""), f.get("file", ""))

    active = [f for f in findings if not f.get("acknowledged")]
    ordered = sorted(findings, key=sev_key)
    priority = sorted([f for f in active if f.get("severity") in ("critical", "high")
                       and f.get("category") != "AI-RAG"], key=sev_key)
    ai = sorted([f for f in findings if f.get("category") == "AI-RAG"], key=sev_key)

    # Scorecard rows: applicable first (by weight desc), then N/A.
    cat_rows = sorted(scores["categories"].items(),
                      key=lambda kv: (not kv[1]["applicable"], -kv[1]["weight"]))
    for _, c in cat_rows:
        c["findings_label"] = _findings_label(c)

    n_det = sum(1 for f in findings if f.get("source") == "deterministic")
    n_rea = sum(1 for f in findings if f.get("source") == "reasoning")
    suppressed = data.get("suppressed_count", 0)
    n_applicable = sum(1 for _, c in cat_rows if c["applicable"])

    # Citation join: every distinct hipaa_ref, resolved once, in finding order.
    seen: dict[str, dict] = {}
    for f in ordered:
        ref = f.get("hipaa_ref")
        if ref and ref not in seen:
            seen[ref] = resolve_citation(ref, baseline)
    citations = list(seen.values())

    # Interpretation notes relevant to the citations actually referenced.
    notes_src = baseline.get("interpretation_notes", {})
    notes: list[str] = []
    regs = baseline.get("regulations", {})
    if any(regs.get(c["ref"], {}).get("status") == "addressable" for c in citations):
        if notes_src.get("addressable_is_not_optional"):
            notes.append(notes_src["addressable_is_not_optional"])
    if any(c["ref"].startswith("164.312(e)") for c in citations):
        if notes_src.get("encryption_in_transit_is_effectively_required"):
            notes.append(notes_src["encryption_in_transit_is_effectively_required"])
    # Per-citation scope notes (e.g. OCR-tracking limits, ONC applicability) and
    # any proposed regulatory change relevant to the cited authorities.
    for c in citations:
        if c.get("scope_note") and c["scope_note"] not in notes:
            notes.append(c["scope_note"])
    pend = sorted({c["pending"] for c in citations if c.get("pending")})
    if pend:
        notes.append("Proposed regulatory change relevant to these findings: "
                     + "; ".join(pend) + ".")

    # Baseline provenance: findings were mapped against a stamped version;
    # if the local baseline file has moved on, say so rather than crash.
    stamped = (data.get("regulatory_baseline") or {}).get("version")
    loaded_version = baseline.get("baseline_version")
    baseline_caveat = ""
    if stamped and loaded_version and stamped != loaded_version:
        baseline_caveat = (
            f"Note: findings were mapped against regulatory baseline {stamped}, but the "
            f"citation details below come from baseline {loaded_version}. Re-run the scan "
            "to realign them.")

    # Executive summary.
    n_medium = scores.get("n_medium", sum(1 for f in findings if f.get("severity") == "medium"))
    n_low = scores.get("n_low", sum(1 for f in findings if f.get("severity") == "low"))
    top = [_finding_view(f, baseline) for f in sorted(active, key=sev_key)[:3]]
    next_steps: list[str] = []
    if scores["n_critical"]:
        s = "s" if scores["n_critical"] > 1 else ""
        next_steps.append(f"Remediate the {scores['n_critical']} critical finding{s} first. "
                          "The worst finding caps the overall score.")
    elif scores["n_high"]:
        s = "s" if scores["n_high"] > 1 else ""
        next_steps.append(f"Remediate the {scores['n_high']} high-severity finding{s} first.")
    if n_rea:
        s = "s" if n_rea > 1 else ""
        next_steps.append(f"Have an engineer verify the {n_rea} finding{s} identified by "
                          "AI-assisted review.")
    next_steps.append("Re-run ClearMap after remediation to confirm the score improves.")

    total = len(findings)
    cats_with_findings = sum(1 for _, c in cat_rows
                             if c["deterministic_findings"] + c["reasoning_findings"] > 0)
    summary_bits = [f"{total} finding{'s' if total != 1 else ''} across "
                    f"{cats_with_findings} of {n_applicable} applicable safeguard categories"]
    mix = []
    if n_det:
        mix.append(f"{n_det} confirmed by automated rules")
    if n_rea:
        mix.append(f"{n_rea} identified by AI-assisted review (pending engineer verification)")
    summary_line = summary_bits[0] + (": " + " and ".join(mix) if mix else "") + "."
    if suppressed:
        summary_line += (f" {suppressed} likely false positive"
                         f"{'s were' if suppressed != 1 else ' was'} suppressed automatically.")
    n_acknowledged = ack["n_acknowledged"]
    if n_acknowledged:
        summary_line += (f" {n_acknowledged} finding{'s were' if n_acknowledged != 1 else ' was'} "
                         "acknowledged as accepted risk and excluded from the score; "
                         "see the Acknowledgments appendix.")
    if ack["n_expired"]:
        summary_line += (f" {ack['n_expired']} acknowledgment"
                         f"{'s have' if ack['n_expired'] != 1 else ' has'} expired and "
                         "the underlying finding is scored again.")

    # Scope and method paragraphs (plain language, no pipeline jargon).
    engines = data.get("engines", {})
    engine_bits = " and ".join(f"{name.capitalize()} {ver}" for name, ver in engines.items())
    scope: list[str] = [
        f"**Scanned:** {repo}. {n_applicable} of {len(cat_rows)} safeguard categories apply "
        "to this codebase; categories with no matching surface are excluded from scoring "
        "rather than scored 100.",
        "**Automated pattern analysis:** curated ClearMap rules"
        + (f" executed by {engine_bits}" if engine_bits else "")
        + ". These findings are reproducible from run to run and appear below as Confirmed.",
    ]
    # Whether an AI-assisted review actually ran this pass. A completed review that
    # found nothing still ran; finding counts describe results, never whether the
    # review happened, so this must not key off n_rea alone.
    reasoning_meta = data.get("reasoning") or {}
    reasoning_provider = reasoning_meta.get("provider")
    reasoning_model = reasoning_meta.get("model")
    reasoning_privacy = (reasoning_meta.get("manifest") or {}).get("privacy_mode")
    reasoning_present = (bool(reasoning_provider) or scores.get("reasoning_ran")
                         or n_rea > 0)
    if reasoning_present:
        scope.append(
            "**AI-assisted code review:** an AI agent reviewed the code against ClearMap's "
            "clinical and audit checklists, covering risks that pattern matching cannot "
            "judge. Any issues it raised appear below as Needs verification and should be "
            "confirmed by an engineer.")
    else:
        scope.append(
            "**AI-assisted code review:** not part of this run. The results reflect "
            "automated pattern analysis only.")
    if suppressed:
        scope.append(
            f"**Suppressed:** {suppressed} finding{'s' if suppressed != 1 else ''} filtered "
            "as known false-positive classes (vendored paths, publishable tokens, i18n keys, "
            "templated placeholders) or by explicit allow rules.")
    # Data-egress statement, honest about where the AI-assisted review ran.
    # The deterministic scan is always local; the reasoning review may reach a
    # provider (the host agent, or a local/remote model), so never claim "nothing
    # left the machine" unless it is actually true.
    if not reasoning_present:
        scope.append("The automated scan ran locally; no source code or PHI left this machine.")
    elif reasoning_provider == "openai-compatible" and reasoning_privacy == "local-only":
        scope.append("All analysis ran locally, including the AI-assisted review on a local "
                     "model; no source code or PHI left this machine.")
    elif reasoning_provider == "openai-compatible":
        scope.append("The automated scan ran locally. The AI-assisted review sent the "
                     "reviewed files to the configured model provider"
                     + (f" ({reasoning_model})" if reasoning_model else "") + ".")
    elif reasoning_provider == "host-agent":
        scope.append("The automated scan ran locally. The AI-assisted review was performed by "
                     "your coding agent, so the reviewed code was processed by that agent's "
                     "model provider.")
    elif reasoning_provider == "manual":
        scope.append("The automated scan ran locally. The AI-assisted review findings were "
                     "supplied externally and merged in.")
    else:
        scope.append("The automated scan ran locally. An AI-assisted review was included; the "
                     "reviewed code was processed by whichever agent or model provider ran it.")
    if baseline_caveat:
        scope.append(baseline_caveat)

    # Incomplete-assessment banner: reasoning-only categories that apply but
    # were never reviewed (the AI-assisted pass did not run). Prevents a
    # deterministic-only run from reading as a clean low-risk result.
    # Completion is authoritative from the merge step when reasoning metadata is
    # present (it accounts for skipped files, failed/truncated batches, and a scan
    # fingerprint bound to this run). Only a legacy findings file without that
    # metadata falls back to whether the reasoning layer ran at all. Never infer
    # completeness from finding counts: a truncated review that happened to find
    # one issue per category is still incomplete.
    if "complete" in reasoning_meta:
        reasoning_complete = bool(reasoning_meta.get("complete"))
    else:
        reasoning_complete = bool(scores.get("reasoning_ran"))

    not_reviewed = scores.get("not_reviewed_categories", [])
    incomplete = ""
    if not_reviewed:
        names = " and ".join(f"{c} ({scores['categories'][c]['name']})" for c in not_reviewed)
        incomplete = (
            f"Assessment incomplete. {names} apply to this codebase but can only be "
            "evaluated by the AI-assisted review, which was not run. They are shown below "
            "as Not reviewed and excluded from the score. The result reflects the automated "
            "pattern-analysis layer only. Run the full audit for a complete rating.")
    elif reasoning_present and not reasoning_complete:
        detail = reasoning_meta.get("incomplete_reason") or "the review did not finish"
        incomplete = (
            f"Assessment incomplete. The AI-assisted review did not finish ({detail}), so any "
            "issues it raised are shown below but the review is partial. This result reflects "
            "the automated pattern-analysis layer plus an incomplete AI review. Re-run the "
            "full audit for a complete rating.")

    # Score state: distinguish a complete assessment, an automated-layer-only
    # assessment (reasoning did not run: still a real, qualified number), and an
    # unavailable score (a required engine failed, the baseline could not load,
    # or nothing applies: the number is withheld).
    scan_ok = data.get("scan_ok", True)  # absent => legacy scan, treat as ok
    engine_status = data.get("engine_status", {})
    if not scan_ok:
        failed = [n for n in ("semgrep", "gitleaks")
                  if engine_status.get(n, {}).get("status") not in ("success", None)]
        detail = ", ".join(f"{n} ({engine_status[n]['status']})" for n in failed) \
            or "a required scanning engine did not complete"
        score_state = "unavailable"
        score_reason = (f"A required scanning engine did not complete ({detail}), so the "
                        "codebase was not fully analyzed. ClearMap does not produce a score "
                        "from an incomplete scan.")
    elif not baseline:
        score_state = "unavailable"
        score_reason = ("The regulatory baseline could not be loaded, so findings cannot be "
                        "mapped or scored.")
    elif n_applicable == 0:
        score_state = "unavailable"
        score_reason = "No applicable safeguard categories were detected in this codebase."
    elif not reasoning_complete:
        score_state = "incomplete"
        score_reason = ""
    else:
        score_state = "complete"
        score_reason = ""

    if score_state == "unavailable":
        incomplete = ""  # the unavailable reason supersedes the reasoning-not-run banner

    assessment = {
        "engines_completed": scan_ok,
        "automated_layer": "complete" if scan_ok else "incomplete",
        "reasoning_layer": ("complete" if reasoning_complete else
                            "incomplete" if reasoning_present else "not run"),
        "reasoning_provider": reasoning_provider,
        "reasoning_model": reasoning_model,
        "baseline_version": baseline.get("baseline_version"),
        "authority_types": sorted({c["authority_type"] for c in citations
                                   if c.get("authority_type")}),
        "completeness": {"complete": "complete", "incomplete": "automated layer only",
                         "unavailable": "unavailable"}[score_state],
    }
    scope.append(
        f"**Assessment coverage:** automated scan {assessment['automated_layer']}; "
        f"AI-assisted review {assessment['reasoning_layer']}"
        + (f" via {assessment['reasoning_provider']}" if assessment['reasoning_provider'] else "")
        + (f". Regulatory baseline {assessment['baseline_version']}."
           if assessment['baseline_version'] else ".")
        + (f" Authority basis cited: {', '.join(assessment['authority_types'])}."
           if assessment['authority_types'] else ""))

    return {
        "score_state": score_state,
        "score_reason": score_reason,
        "score_label": SCORE_LABEL,
        "score_qualification": SCORE_QUALIFICATION,
        "assessment": assessment,
        "repo": repo,
        "date": date,
        "provenance": provenance,
        "provenance_rows": provenance_rows(provenance, repo) if provenance else [],
        "version": CLEARMAP_VERSION,
        "incomplete": incomplete,
        "baseline": data.get("regulatory_baseline", {}),
        "scores": scores,
        "findings": findings,
        "ordered": [_finding_view(f, baseline) for f in ordered],
        "priority": [_finding_view(f, baseline) for f in priority],
        "ai": [_finding_view(f, baseline) for f in ai],
        "cat_rows": cat_rows,
        "reviewer_categories": sorted({f.get("category") for f in findings}
                                      & set(CATEGORY_REVIEWER_Q)),
        "reviewer_questions": CATEGORY_REVIEWER_Q,
        "n_det": n_det,
        "n_rea": n_rea,
        "n_medium": n_medium,
        "n_low": n_low,
        "suppressed_count": suppressed,
        "suppressions": data.get("suppressions", []),
        "acknowledgments": ack["applied"],
        "n_acknowledged": n_acknowledged,
        "n_acknowledgments_expired": ack["n_expired"],
        "exec": {"top": top, "next_steps": next_steps, "summary_line": summary_line},
        "scope": scope,
        "citations": citations,
        "interpretation_notes": notes,
        "disclaimer": DISCLAIMER,
        "cta": CTA_FOOTER,
        "cta_url": CTA_URL,
    }


# ---------------------------------------------------------------- markdown --

def _cell(text: str, n: int = 90) -> str:
    """Single-line, pipe-safe table cell, truncated."""
    t = " ".join(str(text).split()).replace("|", "/")
    return t if len(t) <= n else t[: n - 1].rstrip() + "…"


def _block(v: dict) -> str:
    """One finding, markdown."""
    lines = [f"#### {v['title']} ({v['severity_label']})"]
    if v["location"]:
        lines.append(f"- **Location:** `{v['location']}`")
    if v["citation"]:
        lines.append(f"- **Regulation:** {v['citation']['text']}")
    if v["evidence"]:
        lines.append(f"- **Evidence (redacted):** `{v['evidence']}`")
    if v["why"]:
        lines.append(f"- **Why it matters:** {v['why']}")
    if v["reviewer_question"]:
        lines.append(f"- **Reviewer question:** {v['reviewer_question']}")
    if v["remediation"]:
        lines.append(f"- **Remediation:** {v['remediation']}")
    lines.append(f"- **Verification:** {v['verification']}")
    if v["acknowledged"] and v["acknowledgment_line"]:
        lines.append(f"- **Accepted risk:** {v['acknowledgment_line']}")
    if v["ref_line"]:
        lines.append(f"- **Reference:** {v['ref_line']}")
    return "\n".join(lines)


def provenance_rows(p: dict, repo: str) -> list[str]:
    """Ordered (label, value) provenance rows, shared by both emitters so the
    source block can never drift between markdown and HTML."""
    rows: list[tuple[str, str]] = [("Repository", repo)]
    if p.get("branch"):
        rows.append(("Branch", p["branch"]))
    if p.get("commit"):
        rows.append(("Commit", p["commit"]))
    if p.get("source"):
        rows.append(("Source", p["source"]))
    if p.get("committed_at") or p.get("committer"):
        by = f" by {p['committer']}" if p.get("committer") else ""
        rows.append(("Last commit", f"{p.get('committed_at', '')}{by}".strip()))
    if p.get("subject"):
        rows.append(("Latest commit message", p["subject"]))
    return [(label, val) for label, val in rows if val]


def render_md(m: dict) -> str:
    scores = m["scores"]
    baseline = m["baseline"]

    out: list[str] = []
    # Header
    out.append(f"# ClearMap HIPAA Risk Report: {m['repo']}\n")
    out.append(f"**Generated:** {m['date']} · **ClearMap:** v{m['version']} · "
               f"**Regulatory baseline:** {baseline.get('version','?')} "
               f"(as of {baseline.get('as_of','?')})\n")
    if m.get("provenance_rows"):
        # Provenance values (commit subject, committer, branch, remote) are
        # untrusted repo text. Neutralize raw HTML (angle brackets, ampersands)
        # so a crafted commit message cannot inject markup when the markdown is
        # later rendered to HTML. The HTML emitter escapes via _e() already.
        out.append("  \n".join(f"**{label}:** {html.escape(str(val), quote=False)}"
                               for label, val in m["provenance_rows"]) + "\n")
    out.append("> **Technical risk signal, not a certification.** This report is not a HIPAA "
               "compliance certification and does not mean the product is or is not HIPAA compliant.\n")

    # 1. Executive summary
    out.append("## 1. Executive summary\n")
    if m["incomplete"]:
        out.append(f"> **{m['incomplete']}**\n")
    if m["score_state"] == "unavailable":
        out.append(f"**{m['score_label']}: unavailable.** {m['score_reason']}\n")
    else:
        q = " (automated layer only)" if m["score_state"] == "incomplete" else ""
        out.append(f"**{m['score_label']}: {scores['score']}/100{q}.** {scores['posture']}\n")
    out.append(f"*{m['score_qualification']}*\n")
    out.append("| Critical | High | Medium | Low |")
    out.append("|----------|------|--------|-----|")
    out.append(f"| {scores['n_critical']} | {scores['n_high']} | {m['n_medium']} | {m['n_low']} |")
    out.append("")
    out.append(m["exec"]["summary_line"] + "\n")
    if m["exec"]["top"]:
        out.append("**Top findings**\n")
        for i, v in enumerate(m["exec"]["top"], 1):
            loc = f" · `{v['location']}`" if v["location"] else ""
            out.append(f"{i}. **{v['title']}** ({v['severity_label']}){loc}")
        out.append("")
    out.append("**Suggested next steps**\n")
    for step in m["exec"]["next_steps"]:
        out.append(f"- {step}")
    out.append("")

    # 2. Scope and method
    out.append("## 2. Scope and method\n")
    for para in m["scope"]:
        out.append(para + "\n")

    # 3. Score
    out.append("## 3. HIPAA Risk Score\n")
    if m["score_state"] == "unavailable":
        out.append(f"**Score unavailable.** {m['score_reason']}\n")
    else:
        q = " (automated layer only)" if m["score_state"] == "incomplete" else ""
        out.append(f"**{scores['score']}/100{q}.** {scores['posture']}\n")
        out.append(f"*The score is capped at {scores['ceiling_applied']}/100 "
                   f"({scores['ceiling_reason']}). The worst finding sets the cap, and critical "
                   f"findings compound with diminishing returns. ClearMap checks technical "
                   f"safeguards only and never reports a perfect score. Appendix A explains how "
                   f"the score is built.*\n")

    # 4. Category scorecard
    out.append("## 4. Category scorecard\n")
    out.append("| Category | Score | Findings | Weight | Applies? |")
    out.append("|----------|-------|----------|--------|----------|")
    for code, c in m["cat_rows"]:
        if c.get("not_reviewed"):
            out.append(f"| {code}: {c['name']} | Not reviewed | | {c['weight']:.2f} | "
                       "needs AI-assisted review |")
        elif not c["applicable"]:
            out.append(f"| {code}: {c['name']} | N/A | | | not detected |")
        else:
            out.append(f"| {code}: {c['name']} | {c['blended_score']} | "
                       f"{c['findings_label']} | {c['effective_weight']:.2f} | yes |")
    out.append("\n*N/A means that category's surface (for example frontend or AI/LLM) was not "
               "detected in this codebase; it is excluded from the score, not scored 100. "
               "Weights are renormalized across the categories that apply.*")
    if m["incomplete"]:
        out.append("\n*Not reviewed means the category applies but has no deterministic rules, "
                   "so it can only be assessed by the AI-assisted review, which was not run. It "
                   "is excluded from the score rather than assumed clean.*")
    out.append("")

    # 5. Findings table
    out.append("## 5. Findings\n")
    if m["ordered"]:
        out.append("| Severity | Finding | Location | Citation | Status |")
        out.append("|----------|---------|----------|----------|--------|")
        for v in m["ordered"]:
            loc = f"`{v['location']}`" if v["location"] else ""
            cit = v["citation"]["short"] if v["citation"] else ""
            out.append(f"| {v['severity_label']} | {_cell(v['title'], 70)} | {loc} | "
                       f"{_cell(cit, 30)} | {v['verification_short']} |")
        out.append("")
    else:
        out.append("*No findings in the categories that apply to this codebase.*\n")

    # 6. Priority findings
    out.append("## 6. Priority findings: critical and high\n")
    out.append("*AI/LLM/RAG findings are detailed separately in section 7.*\n")
    if m["priority"]:
        for v in m["priority"]:
            out.append(_block(v) + "\n")
    else:
        out.append("*None.*\n")

    # 7. AI/LLM/RAG
    out.append("## 7. AI / LLM / RAG findings\n")
    if m["ai"]:
        for v in m["ai"]:
            out.append(_block(v) + "\n")
    else:
        out.append("*No AI/LLM/RAG findings.*\n")

    # 8. Reviewer questions
    out.append("## 8. What an enterprise reviewer will ask\n")
    if m["reviewer_categories"]:
        for code in m["reviewer_categories"]:
            out.append(f"- **{code}:** {m['reviewer_questions'][code]}")
    else:
        out.append("- No findings in the categories ClearMap checks.")
    out.append("")

    # 9. Regulatory citations
    out.append("## 9. Regulatory citations referenced\n")
    if m["citations"]:
        out.append(f"Findings in this report map to the following requirements "
                   f"(regulatory baseline {baseline.get('version','?')}).\n")
        out.append("| Citation | Requirement | Status | Source |")
        out.append("|----------|-------------|--------|--------|")
        for c in m["citations"]:
            out.append(f"| {c['display']} | {_cell(c['title'], 60)} | "
                       f"{_cell(c['status_label'], 60)} | {c['url']} |")
        out.append("")
        for note in m["interpretation_notes"]:
            out.append(f"- {note}")
        if m["interpretation_notes"]:
            out.append("")
    else:
        out.append("*No regulatory citations were referenced by these findings.*\n")

    # Appendix A: scoring
    out.append("## Appendix A: How the score is built\n")
    mix = []
    if m["n_det"]:
        mix.append(f"{m['n_det']} confirmed by automated rules")
    if m["n_rea"]:
        mix.append(f"{m['n_rea']} identified by AI-assisted review (marked Needs verification)")
    out.append(f"- **Findings mix:** {' + '.join(mix) if mix else 'no findings'}.")
    out.append(f"- **Rule-confirmed composite:** {scores['composite_deterministic']}/100, "
               f"computed from automated-rule findings only (reproducible: same input, "
               f"same number).")
    out.append(f"- **With AI-assisted findings included:** {scores['composite_blended_raw']}/100 "
               f"before the severity cap.")
    out.append(f"- **Severity cap:** {scores['ceiling_applied']}/100 "
               f"({scores['ceiling_reason']}). The reported score is the lower of the two.")
    out.append("- **Method:** each category starts at 100 and loses points per finding by "
               "severity. The overall score is a weighted composite across the categories "
               "that apply (categories that do not apply are excluded, not scored 100), "
               "then capped by the worst severity present: one critical finding caps the "
               "score at 75, and additional criticals lower the cap further with "
               "diminishing returns toward a floor of 40. ClearMap never reports a perfect "
               "score because it checks technical safeguards only.\n")

    # Appendix: suppressions ledger (only when the scan recorded one)
    if m["suppressions"]:
        out.append("## Appendix: Suppressions\n")
        out.append("Findings filtered as likely false positives or downgraded, each recorded "
                   "with its source and reason so the decision is auditable.\n")
        out.append("| Location | Source | Rule | Reason | Expires |")
        out.append("|----------|--------|------|--------|---------|")
        for r in m["suppressions"]:
            loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
            out.append(f"| {_cell(loc, 40)} | {_cell(r.get('source', ''), 24)} | "
                       f"{_cell(r.get('rule_id') or r.get('category') or '', 24)} | "
                       f"{_cell(r.get('reason', ''), 60)} | {_cell(r.get('expires') or '', 12)} |")
        out.append("")

    # Appendix: acknowledgments (accepted, documented risks)
    if m["acknowledgments"]:
        out.append("## Appendix: Acknowledgments\n")
        out.append("Findings the code owner has accepted as documented risk, each with an owner, "
                   "date, and explanation. Active acknowledgments are excluded from the score; "
                   "expired ones are scored again. This records a decision, it does not remove "
                   "the finding.\n")
        out.append("| Reference | Scope | Owner | Date | Expires | Status | Reason |")
        out.append("|-----------|-------|-------|------|---------|--------|--------|")
        for a in m["acknowledgments"]:
            scope_txt = a.get("file") or "all matching findings"
            out.append(f"| {_cell(a['reference'], 24)} | {_cell(scope_txt, 30)} | "
                       f"{_cell(a['owner'], 24)} | {a['date']} | {a.get('expires') or ''} | "
                       f"{a['status']} | {_cell(a['reason'], 80)} |")
        out.append("")

    # Appendix B: about + disclaimer + closing note
    out.append("## Appendix B: About this report\n")
    out.append(m["disclaimer"] + "\n")
    out.append("---\n")
    out.append(f"*{m['cta']}*\n")
    return _normalize_dashes("\n".join(out))


def render(data: dict, repo: str, date: str) -> str:
    """Back-compat wrapper: findings.json dict -> markdown."""
    return render_md(build_model(data, repo, date))


def render_json(m: dict) -> str:
    """Structured JSON of the report: score, assessment, findings, suppressions,
    and the closing note. A machine-readable companion to the markdown/HTML."""
    s = m["scores"]
    keys = ("id", "rule_id", "category", "severity", "source", "confidence", "engine",
            "file", "line", "title", "hipaa_ref", "authority_type", "why", "remediation",
            "structural_snippet", "reviewer_question")
    doc = {
        "clearmap_version": m["version"],
        "repo": m["repo"],
        "date": m["date"],
        "regulatory_baseline": m["baseline"],
        "score": None if m["score_state"] == "unavailable" else s["score"],
        "score_state": m["score_state"],
        "score_label": m["score_label"],
        "score_reason": m["score_reason"] or None,
        "posture": s["posture"],
        "qualification": m["score_qualification"],
        "counts": {"critical": s["n_critical"], "high": s["n_high"],
                   "medium": m["n_medium"], "low": m["n_low"]},
        "assessment": m["assessment"],
        "not_reviewed_categories": s.get("not_reviewed_categories", []),
        "findings": [{**{k: f.get(k) for k in keys},
                      "acknowledged": f.get("acknowledged") or None} for f in m["findings"]],
        "suppressions": m["suppressions"],
        "suppressed_count": m["suppressed_count"],
        "acknowledgments": m["acknowledgments"],
        "acknowledged_count": m["n_acknowledged"],
        "disclaimer": m["disclaimer"],
        "closing_note": m["cta"],
        "closing_url": m["cta_url"],
    }
    return _normalize_dashes(json.dumps(doc, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser(description="ClearMap report renderer")
    ap.add_argument("findings", type=Path)
    ap.add_argument("--out", type=Path, default=Path("clearmap-report.md"))
    ap.add_argument("--repo", default=None)
    ap.add_argument("--repo-path", type=Path, default=None,
                    help="path to the scanned git repo; embeds source provenance "
                         "(branch, commit, last commit, remote) at the top of the report")
    ap.add_argument("--acknowledgments", type=Path, default=None,
                    help="directory holding clearmap-acknowledgments.json "
                         "(defaults to --repo-path)")
    ap.add_argument("--date", default=None)
    ap.add_argument("--format", choices=["md", "html", "json", "both", "all"], default="md",
                    help="markdown, self-contained HTML, JSON, both (md+html), or all "
                         "(html/json paths = --out with .html/.json)")
    args = ap.parse_args()

    data = json.loads(args.findings.read_text())
    provenance = git_provenance(args.repo_path) if args.repo_path else None
    repo = args.repo or (args.repo_path.resolve().name if args.repo_path
                         else "the scanned repository")
    date = args.date or datetime.date.today().isoformat()
    ack_root = args.acknowledgments or args.repo_path
    acks = ack_mod.load(ack_root) if ack_root else []
    model = build_model(data, repo, date, provenance, acknowledgments=acks)

    outputs: list[tuple[Path, str]] = []
    if args.format in ("md", "both", "all"):
        outputs.append((args.out if args.out.suffix != ".html" else args.out.with_suffix(".md"),
                        render_md(model)))
    if args.format in ("html", "both", "all"):
        from report_html import render_html  # lazy: md-only runs never import it
        html_path = args.out if args.out.suffix == ".html" else args.out.with_suffix(".html")
        outputs.append((html_path, render_html(model)))
    if args.format in ("json", "all"):
        json_path = args.out if args.out.suffix == ".json" else args.out.with_suffix(".json")
        outputs.append((json_path, render_json(model)))

    for _path, text in outputs:
        bad = check_banned(text)
        if bad:
            print(f"clearmap: refusing to write report, contains banned phrase {bad!r}",
                  file=sys.stderr)
            return 1

    for path, text in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")

    s = model["scores"]
    written = " + ".join(str(p) for p, _ in outputs)
    print(f"clearmap: report -> {written}  (score {s['score']}/100: {s['posture']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
