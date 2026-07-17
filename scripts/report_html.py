"""Self-contained HTML renderer for the ClearMap report.

render_html(model) consumes the SAME model dict as report.render_md (built by
report.build_model): content can never drift between formats. Output is one
file with everything inlined: no JS required, no external resources fetched
(local-first: the report may contain finding locations from a PHI codebase and
must be viewable offline / attachable without phoning home). Regulatory
citations link to their official sources (ecfr.gov, hhs.gov, ...); plain
anchors make no request until clicked, so the no-phone-home guarantee holds.
@media print rules make Print -> PDF produce a clean, fileable artifact.

Visual system: ClearMap product brand on the Vantage IO palette (ink #0B1730,
primary blue #0046BD, on-dark accent #3B7BF0) with Sora / Inter / JetBrains
Mono font stacks that degrade to system fonts when not installed locally.
"""
from __future__ import annotations

import html
import re

SEV_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#475569",
}

CSS = """
:root {
  --ink: #0D1A30; --muted: #46536A; --muted2: #79859A; --line: #dbe4f0;
  --bg: #F6F8FB; --card: #ffffff; --tint: #E5EDFB;
  --blue: #0046BD; --blue-deep: #00348C; --blue-dark: #3B7BF0; --header: #0B1730;
  --critical: #b91c1c; --high: #c2410c; --medium: #a16207; --low: #475569;
  --font-display: 'Sora', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.65 var(--font-body); }
.page { max-width: 860px; margin: 0 auto; padding: 0 28px 64px; }
a { color: var(--blue); }
header.band { background: var(--header); color: #e8edf6; padding: 40px 0 30px;
  margin-bottom: 36px; }
header.band .page { padding-bottom: 0; }
.wordmark { font-family: var(--font-display); font-size: 13px;
  letter-spacing: .22em; text-transform: uppercase; color: var(--blue-dark);
  font-weight: 700; }
h1 { font-family: var(--font-display); font-size: 30px; letter-spacing: -.01em;
  margin: 8px 0 6px; color: #ffffff; font-weight: 700; }
.meta { font-size: 13px; color: #9FB0C4; }
.callout { margin-top: 20px; padding: 11px 16px;
  border-left: 4px solid var(--blue-dark); background: rgba(59,123,240,.10);
  font-size: 13px; color: #cfe0ff; border-radius: 0 6px 6px 0; }
h2 { font-family: var(--font-display); font-size: 21px; letter-spacing: -.01em;
  margin: 44px 0 14px; padding-bottom: 8px; border-bottom: 2px solid var(--line); }
h2 .secno { color: var(--muted2); font-weight: 600; margin-right: 10px; }
.headline { font-size: 17px; font-weight: 650; margin: 0 0 14px; }
.warn { margin: 0 0 16px; padding: 12px 16px; border-left: 4px solid #a16207;
  background: #fbf4e6; color: #7a4d06; font-size: 13.5px; border-radius: 0 6px 6px 0; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin: 0 0 16px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 18px; min-width: 96px; text-align: center; }
.tile .n { font-family: var(--font-display); font-size: 26px; font-weight: 700;
  line-height: 1.15; display: block; }
.tile .lbl { font-size: 11.5px; text-transform: uppercase; letter-spacing: .07em;
  color: var(--muted); }
ol.top { padding-left: 22px; margin: 8px 0 0; }
ol.top li { margin: 5px 0; }
ul.steps { padding-left: 22px; margin: 8px 0 0; }
ul.steps li { margin: 5px 0; }
.scoreband { display: flex; align-items: center; gap: 28px; flex-wrap: wrap;
  background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 24px; }
.ring { width: 132px; height: 132px; border-radius: 50%; flex: none;
  display: flex; align-items: center; justify-content: center; }
.ring .hole { width: 104px; height: 104px; border-radius: 50%;
  background: var(--card); display: flex; flex-direction: column;
  align-items: center; justify-content: center; }
.ring .num { font-family: var(--font-display); font-size: 34px;
  font-weight: 800; line-height: 1; }
.ring .of { font-size: 12px; color: var(--muted2); }
.posture { font-size: 16px; font-weight: 650; margin-bottom: 6px; }
.scorenote { font-size: 13px; color: var(--muted); max-width: 560px; }
table { width: 100%; border-collapse: collapse; background: var(--card);
  border: 1px solid var(--line); border-radius: 10px; overflow: hidden;
  font-size: 13.5px; }
th { text-align: left; background: var(--tint); padding: 9px 12px;
  font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em;
  color: var(--blue-deep); }
td { padding: 9px 12px; border-top: 1px solid var(--line); vertical-align: top; }
td.url { font-size: 12px; word-break: break-all; }
code, .loc { font: 12.5px/1.5 var(--font-mono); background: var(--tint);
  padding: 1px 5px; border-radius: 4px; }
.chip { display: inline-block; padding: 1px 10px; border-radius: 999px;
  font-size: 11.5px; font-weight: 700; color: #fff; white-space: nowrap; }
.chip.outline { background: transparent !important; border: 1.5px solid currentColor; }
.legend { font-size: 12.5px; color: var(--muted); margin-top: 8px; }
.bar { background: var(--line); border-radius: 4px; height: 8px; min-width: 90px;
  position: relative; overflow: hidden; }
.bar > i { position: absolute; inset: 0 auto 0 0; border-radius: 4px; }
.finding { background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; margin: 14px 0; border-left-width: 4px; }
.finding summary { cursor: pointer; padding: 13px 16px; font-weight: 650;
  display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;
  font-family: var(--font-display); font-size: 14.5px; }
.finding summary::-webkit-details-marker { display: none; }
.finding .body { padding: 2px 16px 14px; border-top: 1px solid var(--line); }
.finding dl { margin: 10px 0 0; display: grid; grid-template-columns: 160px 1fr;
  row-gap: 7px; column-gap: 12px; font-size: 13.5px; }
.finding dt { color: var(--muted); font-weight: 600; }
.finding dd { margin: 0; }
.finding .refline { color: var(--muted2); font-family: var(--font-mono);
  font-size: 12px; }
.srcnote { display: block; font-size: 11px; color: var(--muted2); margin-top: 3px; }
ul.qs { padding-left: 20px; }
.build { background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; padding: 16px 20px; font-size: 14px; }
.build ul { margin: 6px 0 0; padding-left: 20px; }
.notes { font-size: 13px; color: var(--muted); margin-top: 10px;
  padding-left: 20px; }
footer.disclaimer { margin-top: 44px; padding: 18px 20px; font-size: 12.5px;
  color: var(--muted); background: var(--tint); border-radius: 10px;
  border: 1px solid var(--line); }
.cta { margin-top: 18px; padding: 18px 20px; border-radius: 10px;
  background: var(--header); color: #cfe0ff; font-size: 13.5px; }
.cta a { color: var(--blue-dark); font-weight: 650; }
.na { color: var(--muted2); }
p.para strong { color: var(--ink); }
@page { margin: 18mm; }
@media print {
  body { background: #fff; font-size: 12px; }
  header.band { background: #fff; color: #000; border-bottom: 3px solid #000;
    padding: 0 0 12px; }
  header.band h1 { color: #000; }
  .wordmark { color: #000; }
  .callout { color: #333; border-left-color: #000; background: #fff; }
  .meta { color: #333; }
  .scoreband, .finding, table, .tile, .build, .cta { break-inside: avoid;
    border-color: #999; }
  h2 { break-after: avoid; }
  .finding { page-break-inside: avoid; }
  .cta { background: #fff; color: #000; border: 1px solid #999; }
  .cta a { color: #000; }
  a { color: inherit; text-decoration: none; }
}
"""


def _normalize_dashes(text: str) -> str:
    """House style: no em or en dashes in any rendered output."""
    return (text.replace(" — ", ": ").replace("—", "-")
                .replace(" – ", ": ").replace("–", "-"))


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _bold(md_text: str) -> str:
    """Escape, then honor the model's **bold** markers."""
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", _e(md_text))


def _sev_chip(v: dict) -> str:
    color = SEV_COLORS.get(v["severity"], SEV_COLORS["low"])
    return f'<span class="chip" style="background:{color}">{_e(v["severity_label"])}</span>'


def _status_chip(v: dict) -> str:
    if v["verification_short"] == "Confirmed":
        return '<span class="chip" style="background:#15803d">Confirmed</span>'
    return ('<span class="chip outline" style="color:#00348C">'
            'Needs verification</span>')


def _score_color(score: int) -> str:
    if score >= 90:
        return "#15803d"
    if score >= 76:
        return "#0046BD"
    if score >= 50:
        return "#a16207"
    return "#b91c1c"


def _citation_html(cit: dict) -> str:
    text = _e(cit["text"])
    if cit["url"]:
        return f'<a href="{_e(cit["url"])}">{text}</a>'
    return text


def _finding_card(v: dict) -> str:
    rows = []
    if v["location"]:
        rows.append(("Location", f'<span class="loc">{_e(v["location"])}</span>'))
    if v["citation"]:
        rows.append(("Regulation", _citation_html(v["citation"])))
    if v["evidence"]:
        rows.append(("Evidence", f"<code>{_e(v['evidence'])}</code> "
                                 '<span class="srcnote">(redacted, no raw PHI)</span>'))
    if v["why"]:
        rows.append(("Why it matters", _e(v["why"])))
    if v["reviewer_question"]:
        rows.append(("Reviewer question", _e(v["reviewer_question"])))
    if v["remediation"]:
        rows.append(("Remediation", _e(v["remediation"])))
    rows.append(("Verification", _e(v["verification"])))
    if v["ref_line"]:
        rows.append(("Reference", f'<span class="refline">{_e(v["ref_line"])}</span>'))
    dl = "".join(f"<dt>{k}</dt><dd>{val}</dd>" for k, val in rows)
    border = SEV_COLORS.get(v["severity"], SEV_COLORS["low"])
    return (f'<details class="finding" open style="border-left-color:{border}">'
            f'<summary>{_sev_chip(v)} <span>{_e(v["title"])}</span></summary>'
            f'<div class="body"><dl>{dl}</dl></div></details>')


def render_html(m: dict) -> str:
    s = m["scores"]
    baseline = m["baseline"]
    color = _score_color(s["score"])
    pct = max(0, min(100, s["score"]))

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>ClearMap HIPAA Risk Report: {_e(m['repo'])}</title>")
    parts.append(f"<style>{CSS}</style></head><body>")

    # Header band
    parts.append('<header class="band"><div class="page">')
    parts.append('<div class="wordmark">ClearMap</div>')
    parts.append(f"<h1>HIPAA Risk Report: {_e(m['repo'])}</h1>")
    parts.append(f'<div class="meta">Generated {_e(m["date"])} · ClearMap v{_e(m["version"])} · '
                 f'Regulatory baseline {_e(baseline.get("version", "?"))} '
                 f'(as of {_e(baseline.get("as_of", "?"))})</div>')
    if m.get("provenance_rows"):
        prov = "<br>".join(f"<strong>{_e(label)}:</strong> {_e(val)}"
                           for label, val in m["provenance_rows"])
        parts.append('<div class="meta" style="margin-top:10px;line-height:1.7">'
                     f'{prov}</div>')
    parts.append('<div class="callout"><strong>Technical risk signal, not a certification.</strong> '
                 'This report is not a HIPAA compliance certification and does not mean the '
                 'product is or is not HIPAA compliant.</div>')
    parts.append("</div></header>")
    parts.append('<div class="page">')

    # 1. Executive summary
    parts.append('<h2><span class="secno">1</span>Executive summary</h2>')
    if m["incomplete"]:
        parts.append(f'<div class="warn"><strong>{_e(m["incomplete"])}</strong></div>')
    if m["score_state"] == "unavailable":
        parts.append(f'<p class="headline">{_e(m["score_label"])}: unavailable. '
                     f'{_e(m["score_reason"])}</p>')
    else:
        qualifier = " (automated layer only)" if m["score_state"] == "incomplete" else ""
        parts.append(f'<p class="headline">{_e(m["score_label"])}: {s["score"]}/100{qualifier}. '
                     f'{_e(s["posture"])}</p>')
    parts.append(f'<p class="scorenote">{_e(m["score_qualification"])}</p>')
    parts.append('<div class="tiles">')
    for label, n, c in (("Critical", s["n_critical"], SEV_COLORS["critical"]),
                        ("High", s["n_high"], SEV_COLORS["high"]),
                        ("Medium", m["n_medium"], SEV_COLORS["medium"]),
                        ("Low", m["n_low"], SEV_COLORS["low"])):
        parts.append(f'<div class="tile"><span class="n" style="color:{c}">{n}</span>'
                     f'<span class="lbl">{label}</span></div>')
    parts.append("</div>")
    parts.append(f'<p class="para">{_e(m["exec"]["summary_line"])}</p>')
    if m["exec"]["top"]:
        parts.append("<p><strong>Top findings</strong></p>")
        parts.append('<ol class="top">')
        for v in m["exec"]["top"]:
            loc = f' · <span class="loc">{_e(v["location"])}</span>' if v["location"] else ""
            parts.append(f'<li><strong>{_e(v["title"])}</strong> '
                         f'({_e(v["severity_label"])}){loc}</li>')
        parts.append("</ol>")
    parts.append("<p><strong>Suggested next steps</strong></p>")
    parts.append('<ul class="steps">')
    parts.extend(f"<li>{_e(step)}</li>" for step in m["exec"]["next_steps"])
    parts.append("</ul>")

    # 2. Scope and method
    parts.append('<h2><span class="secno">2</span>Scope and method</h2>')
    for para in m["scope"]:
        parts.append(f'<p class="para">{_bold(para)}</p>')

    # 3. Score
    parts.append('<h2><span class="secno">3</span>HIPAA Risk Score</h2>')
    if m["score_state"] == "unavailable":
        parts.append('<div class="scoreband"><div><div class="posture">Score unavailable</div>'
                     f'<div class="scorenote">{_e(m["score_reason"])}</div></div></div>')
    else:
        q = " (automated layer only)" if m["score_state"] == "incomplete" else ""
        parts.append('<div class="scoreband">')
        parts.append(f'<div class="ring" style="background:conic-gradient({color} {pct}%, var(--line) 0)">'
                     f'<div class="hole"><span class="num" style="color:{color}">{s["score"]}</span>'
                     f'<span class="of">/ 100</span></div></div>')
        parts.append(f'<div><div class="posture">{_e(s["posture"])}{q}</div>'
                     f'<div class="scorenote">The score is capped at {s["ceiling_applied"]}/100 '
                     f'({_e(s["ceiling_reason"])}). The worst finding sets the cap, and critical '
                     f'findings compound with diminishing returns. ClearMap checks technical '
                     f'safeguards only and never reports a perfect score. Appendix A explains '
                     f'how the score is built.</div></div>')
        parts.append("</div>")

    # 4. Category scorecard
    parts.append('<h2><span class="secno">4</span>Category scorecard</h2>')
    parts.append("<table><thead><tr><th>Category</th><th>Score</th><th></th>"
                 "<th>Findings</th><th>Weight</th><th>Applies?</th></tr></thead><tbody>")
    for code, c in m["cat_rows"]:
        name = f"{_e(code)}: {_e(c['name'])}"
        if c.get("not_reviewed"):
            parts.append(f'<tr class="na"><td>{name}</td>'
                         f'<td><strong style="color:#a16207">Not reviewed</strong></td><td></td>'
                         f"<td></td><td>{c['weight']:.2f}</td>"
                         f"<td>needs AI-assisted review</td></tr>")
        elif not c["applicable"]:
            parts.append(f'<tr class="na"><td>{name}</td><td>N/A</td><td></td>'
                         f"<td></td><td></td><td>not detected</td></tr>")
        else:
            sc = c["blended_score"]
            parts.append(f"<tr><td>{name}</td><td><strong>{sc}</strong></td>"
                         f'<td><div class="bar"><i style="width:{max(0, min(100, sc))}%;'
                         f'background:{_score_color(sc)}"></i></div></td>'
                         f"<td>{_e(c['findings_label'])}</td>"
                         f"<td>{c['effective_weight']:.2f}</td><td>yes</td></tr>")
    parts.append("</tbody></table>")
    scnote = ('N/A means that category\'s surface (for example frontend or AI/LLM) was not '
              'detected in this codebase; it is excluded from the score, not scored 100. '
              'Weights are renormalized across the categories that apply.')
    if m["incomplete"]:
        scnote += (' Not reviewed means the category applies but has no deterministic rules, '
                   'so it can only be assessed by the AI-assisted review, which was not run; '
                   'it is excluded from the score rather than assumed clean.')
    parts.append(f'<p class="scorenote">{scnote}</p>')

    # 5. Findings table
    parts.append('<h2><span class="secno">5</span>Findings</h2>')
    if m["ordered"]:
        parts.append("<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th>"
                     "<th>Citation</th><th>Status</th></tr></thead><tbody>")
        for v in m["ordered"]:
            loc = f'<span class="loc">{_e(v["location"])}</span>' if v["location"] else ""
            cit = _e(v["citation"]["short"]) if v["citation"] else ""
            parts.append(f"<tr><td>{_sev_chip(v)}</td><td>{_e(v['title'])}</td>"
                         f"<td>{loc}</td><td>{cit}</td><td>{_status_chip(v)}</td></tr>")
        parts.append("</tbody></table>")
        parts.append('<p class="legend">Confirmed = found by an automated rule, reproducible '
                     'from run to run. Needs verification = identified by AI-assisted review '
                     'and awaiting confirmation by an engineer.</p>')
    else:
        parts.append("<p><em>No findings in the categories that apply to this codebase.</em></p>")

    # 6. Priority findings
    parts.append('<h2><span class="secno">6</span>Priority findings: critical and high</h2>')
    parts.append('<p class="scorenote">AI/LLM/RAG findings are detailed separately in '
                 'section 7.</p>')
    if m["priority"]:
        parts.extend(_finding_card(v) for v in m["priority"])
    else:
        parts.append("<p><em>None.</em></p>")

    # 7. AI-RAG
    parts.append('<h2><span class="secno">7</span>AI / LLM / RAG findings</h2>')
    if m["ai"]:
        parts.extend(_finding_card(v) for v in m["ai"])
    else:
        parts.append("<p><em>No AI/LLM/RAG findings.</em></p>")

    # 8. Reviewer questions
    parts.append('<h2><span class="secno">8</span>What an enterprise reviewer will ask</h2>')
    if m["reviewer_categories"]:
        parts.append('<ul class="qs">')
        parts.extend(f"<li><strong>{_e(code)}:</strong> {_e(m['reviewer_questions'][code])}</li>"
                     for code in m["reviewer_categories"])
        parts.append("</ul>")
    else:
        parts.append("<p>No findings in the categories ClearMap checks.</p>")

    # 9. Regulatory citations
    parts.append('<h2><span class="secno">9</span>Regulatory citations referenced</h2>')
    if m["citations"]:
        parts.append(f'<p class="para">Findings in this report map to the following '
                     f'requirements (regulatory baseline '
                     f'{_e(baseline.get("version", "?"))}).</p>')
        parts.append("<table><thead><tr><th>Citation</th><th>Requirement</th>"
                     "<th>Status</th><th>Source</th></tr></thead><tbody>")
        for c in m["citations"]:
            if c["url"]:
                shown = re.sub(r"^https?://", "", c["url"])
                src = f'<a href="{_e(c["url"])}">{_e(shown)}</a>'
            else:
                src = ""
            parts.append(f"<tr><td>{_e(c['display'])}</td><td>{_e(c['title'])}</td>"
                         f'<td>{_e(c["status_label"])}</td><td class="url">{src}</td></tr>')
        parts.append("</tbody></table>")
        if m["interpretation_notes"]:
            parts.append('<ul class="notes">')
            parts.extend(f"<li>{_e(note)}</li>" for note in m["interpretation_notes"])
            parts.append("</ul>")
    else:
        parts.append("<p><em>No regulatory citations were referenced by these "
                     "findings.</em></p>")

    # Appendix A: scoring
    parts.append('<h2><span class="secno">A</span>Appendix A: How the score is built</h2>')
    mix = []
    if m["n_det"]:
        mix.append(f"{m['n_det']} confirmed by automated rules")
    if m["n_rea"]:
        mix.append(f"{m['n_rea']} identified by AI-assisted review "
                   "(marked <em>Needs verification</em>)")
    parts.append('<div class="build"><ul>'
                 f"<li><strong>Findings mix:</strong> {' + '.join(mix) if mix else 'no findings'}.</li>"
                 f"<li><strong>Rule-confirmed composite:</strong> {s['composite_deterministic']}/100, "
                 "computed from automated-rule findings only (reproducible: same input, "
                 "same number).</li>"
                 f"<li><strong>With AI-assisted findings included:</strong> "
                 f"{s['composite_blended_raw']}/100 before the severity cap.</li>"
                 f"<li><strong>Severity cap:</strong> {s['ceiling_applied']}/100 "
                 f"({_e(s['ceiling_reason'])}). The reported score is the lower of the two.</li>"
                 "<li><strong>Method:</strong> each category starts at 100 and loses points "
                 "per finding by severity. The overall score is a weighted composite across "
                 "the categories that apply (categories that do not apply are excluded, not "
                 "scored 100), then capped by the worst severity present: one critical "
                 "finding caps the score at 75, and additional criticals lower the cap "
                 "further with diminishing returns toward a floor of 40. ClearMap never "
                 "reports a perfect score because it checks technical safeguards "
                 "only.</li></ul></div>")

    # Appendix: suppressions ledger (only when the scan recorded one)
    if m["suppressions"]:
        parts.append('<h2><span class="secno">S</span>Appendix: Suppressions</h2>')
        parts.append('<p class="para">Findings filtered as likely false positives or downgraded, '
                     'each recorded with its source and reason so the decision is auditable.</p>')
        parts.append('<table class="grid"><thead><tr><th>Location</th><th>Source</th>'
                     '<th>Rule</th><th>Reason</th><th>Expires</th></tr></thead><tbody>')
        for r in m["suppressions"]:
            loc = f'{r.get("file", "?")}:{r.get("line", "?")}'
            parts.append(
                f'<tr><td>{_e(loc)}</td><td>{_e(r.get("source", ""))}</td>'
                f'<td>{_e(r.get("rule_id") or r.get("category") or "")}</td>'
                f'<td>{_e(r.get("reason", ""))}</td><td>{_e(r.get("expires") or "")}</td></tr>')
        parts.append("</tbody></table>")

    # Appendix B: about + disclaimer + closing note
    parts.append('<h2><span class="secno">B</span>Appendix B: About this report</h2>')
    parts.append(f'<footer class="disclaimer">{_bold(m["disclaimer"])}</footer>')
    cta = _e(m["cta"]).replace(
        "vantageio.com", f'<a href="{_e(m["cta_url"])}">vantageio.com</a>')
    parts.append(f'<div class="cta">{cta}</div>')

    parts.append("</div></body></html>")
    return _normalize_dashes("\n".join(parts))
