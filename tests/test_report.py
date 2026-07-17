"""report.py rendering tests.

- Golden tests: markdown AND html output for the pinned fixture must stay
  byte-identical. If you change report CONTENT intentionally, regenerate both:
    python3 scripts/report.py tests/fixtures/golden/findings.json \
        --repo golden-fixture --date 2026-01-01 --format both \
        --out tests/fixtures/golden/report.md
  and review the diff line by line: that diff IS the design review.
- Banned-phrase guard refuses output in every format.
- HTML: all sections present, no auto-fetching external resources (anchor
  links to allowlisted regulatory sources are permitted: an <a href> makes no
  request until clicked), user text escaped.
- Invariants (byte-independent): human titles as headings, citations joined
  from the regulatory baseline, no pipeline jargon, no em/en dashes, no
  broken-data artifacts like '(untitled)' or '?:?'.
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import report  # noqa: E402
from report_html import render_html  # noqa: E402

GOLDEN_DIR = REPO / "tests" / "fixtures" / "golden"
DATA = json.loads((GOLDEN_DIR / "findings.json").read_text())

SECTION_HEADINGS = [
    "Executive summary", "Scope and method", "HIPAA Risk Score",
    "Category scorecard", "Findings", "Priority findings: critical and high",
    "AI / LLM / RAG findings", "What an enterprise reviewer will ask",
    "Regulatory citations referenced", "Appendix A: How the score is built",
    "Appendix B: About this report",
]

# Domains an href may point at. Regulatory sources + the ClearMap/Vantage
# closing note. Anything else (for example injected via a poisoned finding)
# fails the self-containment test.
ALLOWED_LINK_DOMAINS = (
    "www.ecfr.gov", "www.law.cornell.edu", "www.hhs.gov",
    "www.federalregister.gov", "www.healthit.gov", "vantageio.com",
)


def _render_both(data: dict) -> tuple[str, str]:
    model = report.build_model(data, "golden-fixture", "2026-01-01")
    return report.render_md(model), render_html(model)


class TestMarkdownGolden(unittest.TestCase):
    def test_byte_identical_to_golden(self):
        model = report.build_model(DATA, "golden-fixture", "2026-01-01")
        rendered = report.render_md(model) + "\n"
        self.assertEqual(rendered, (GOLDEN_DIR / "report.md").read_text())


class TestHtmlGolden(unittest.TestCase):
    def test_byte_identical_to_golden(self):
        """Golden HTML fixture. Regenerate with the same command as the
        markdown golden (--format both); review the diff before accepting."""
        model = report.build_model(DATA, "golden-fixture", "2026-01-01")
        rendered = render_html(model) + "\n"
        self.assertEqual(rendered, (GOLDEN_DIR / "report.html").read_text())


class TestBannedPhraseGuard(unittest.TestCase):
    def test_clean_report_passes(self):
        md, html = _render_both(DATA)
        self.assertIsNone(report.check_banned(md))
        self.assertIsNone(report.check_banned(html))

    def test_poisoned_finding_refused(self):
        bad = json.loads(json.dumps(DATA))
        bad["findings"][0]["why"] = "After this fix the product is HIPAA compliant."
        with tempfile.TemporaryDirectory() as td:
            src = Path(td, "f.json")
            src.write_text(json.dumps(bad))
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "report.py"), str(src),
                 "--out", str(Path(td, "r.md"))],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("banned phrase", proc.stderr)
            self.assertFalse(Path(td, "r.md").exists())


class TestReaderFacingLanguage(unittest.TestCase):
    """The report is a client deliverable: no pipeline jargon, no engine
    enum values, no repo paths, no em/en dashes, no broken-data artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.md, cls.html = _render_both(DATA)

    def test_no_pipeline_jargon(self):
        for banned in ("deterministic", "det/reason", "agent-identified",
                       "Ruling", "reasoning finding"):
            self.assertNotIn(banned, self.md, banned)
            self.assertNotIn(banned, self.html, banned)

    def test_no_repo_paths_leak(self):
        for out in (self.md, self.html):
            self.assertNotIn("references/scoring-methodology.md", out)

    def test_no_em_or_en_dashes(self):
        for out in (self.md, self.html):
            self.assertNotIn("—", out)
            self.assertNotIn("–", out)

    def test_no_broken_data_artifacts(self):
        for out in (self.md, self.html):
            self.assertNotIn("(untitled)", out)
            self.assertNotIn("?:?", out)

    def test_headings_are_titles_not_rule_slugs(self):
        # Finding headings lead with the human title; the rule id is demoted
        # to a Reference row.
        self.assertIn("#### Database connection string with embedded credentials "
                      "(Critical)", self.md)
        self.assertNotIn("#### clearmap-db-uri-credentials", self.md)
        self.assertIn("- **Reference:** clearmap-db-uri-credentials (gitleaks rule)",
                      self.md)

    def test_no_price_fr51(self):
        for out in (self.md, self.html):
            self.assertNotIn("$", out)


class TestCitationJoin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = report.load_baseline()
        cls.md, cls.html = _render_both(DATA)

    def test_known_citation_joins_title_and_status(self):
        c = report.resolve_citation("164.312(a)(2)(i)", self.baseline)
        self.assertEqual(
            c["text"],
            "45 CFR 164.312(a)(2)(i): Unique user identification (HIPAA Security Rule requirement)")
        self.assertEqual(c["authority_type"], "hipaa-required")
        self.assertTrue(c["url"].startswith("https://www.ecfr.gov/"))
        self.assertIn(c["text"], self.md)

    def test_addressable_treated_as_required(self):
        c = report.resolve_citation("164.312(e)(2)(ii)", self.baseline)
        self.assertEqual(c["status_label"],
                         "Addressable, treated as Required per 164.306(d)(3)")

    def test_non_cfr_frameworks_resolve(self):
        c = report.resolve_citation("ONC HTI-1 170.315(b)(11)", self.baseline)
        self.assertEqual(c["display"], "45 CFR 170.315(b)(11) (ONC HTI-1)")
        c = report.resolve_citation("OCR online-tracking guidance", self.baseline)
        self.assertEqual(c["display"], "HHS OCR online-tracking guidance")

    def test_unknown_ref_degrades_gracefully(self):
        c = report.resolve_citation("164.999(z)", self.baseline)
        self.assertEqual(c["text"], "164.999(z)")
        bad = json.loads(json.dumps(DATA))
        bad["findings"][0]["hipaa_ref"] = "164.999(z)"
        md, html = _render_both(bad)  # must not crash
        self.assertIn("164.999(z)", md)

    def test_citation_links_in_html(self):
        self.assertIn('href="https://www.ecfr.gov/current/title-45/section-164.312"',
                      self.html)


class TestIncompleteAssessment(unittest.TestCase):
    """A deterministic-only run must not report AI-RAG / AUDIT as a clean 100:
    those categories have no deterministic rules and can only be assessed by the
    AI-assisted review. Without it, they are 'Not reviewed' and the report says so."""

    def _det_only(self):
        # Golden data minus reasoning findings, marked deterministic-only.
        d = json.loads(json.dumps(DATA))
        d["source_layer"] = "deterministic"
        d["findings"] = [f for f in d["findings"] if f.get("source") != "reasoning"]
        return d

    def test_reasoning_only_categories_marked_not_reviewed(self):
        import scoring
        d = self._det_only()
        s = scoring.score_findings(d["findings"], d["applicability"],
                                   source_layer=d["source_layer"])
        self.assertIn("AI-RAG", s["not_reviewed_categories"])
        self.assertIn("AUDIT", s["not_reviewed_categories"])
        self.assertFalse(s["categories"]["AI-RAG"]["applicable"])  # excluded from composite

    def test_report_shows_incomplete_banner(self):
        d = self._det_only()
        md, html = _render_both(d)
        for out in (md, html):
            self.assertIn("Assessment incomplete", out)
            self.assertIn("Not reviewed", out)
            self.assertIn("automated layer only", out)

    def test_full_run_has_no_banner(self):
        # Golden (deterministic+reasoning) must NOT show the incomplete banner.
        md, html = _render_both(DATA)
        self.assertNotIn("Assessment incomplete", md)
        self.assertNotIn("Assessment incomplete", html)

    def test_backcompat_no_source_layer(self):
        import scoring
        s = scoring.score_findings(DATA["findings"], DATA["applicability"])
        self.assertEqual(s["not_reviewed_categories"], [])  # None => assume reviewed


class TestProvenance(unittest.TestCase):
    """Source provenance block at the top of the report: repo, branch, commit,
    last-commit date/time + committer, and the origin remote."""

    PROV = {
        "branch": "hipaa",
        "commit": "2e6e675ab",
        "commit_full": "2e6e675ab1122334455",
        "committed_at": "2026-07-05 14:23:07 -0500",
        "committer": "Jane Doe",
        "subject": "Enhance authorization and session management",
        "source": "git@github.com:example-health/patient-portal.git",
    }

    def test_block_rendered_in_both_formats(self):
        model = report.build_model(DATA, "patient-portal", "2026-07-06", self.PROV)
        md, html = report.render_md(model), render_html(model)
        for out in (md, html):
            self.assertIn("hipaa", out)
            self.assertIn("2e6e675ab", out)
            self.assertIn("Jane Doe", out)
            self.assertIn("2026-07-05 14:23:07", out)
            self.assertIn("git@github.com:example-health/patient-portal.git", out)
            self.assertIn("Enhance authorization and session management", out)

    def test_absent_by_default_keeps_golden_stable(self):
        # The golden path passes no provenance: no block, output byte-stable.
        model = report.build_model(DATA, "golden-fixture", "2026-01-01")
        self.assertIsNone(model["provenance"])
        self.assertEqual(model["provenance_rows"], [])
        self.assertNotIn("Latest commit message", report.render_md(model))

    def test_credential_stripped_from_remote(self):
        prov = dict(self.PROV, source="https://ci-bot:ghp_supersecret@github.com/x/y.git")
        model = report.build_model(DATA, "patient-portal", "2026-07-06", prov)
        md, html = report.render_md(model), render_html(model)
        for out in (md, html):
            self.assertNotIn("ghp_supersecret", out)
            self.assertIn("https://github.com/x/y.git", out)


class TestHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = render_html(report.build_model(DATA, "golden-fixture", "2026-01-01"))

    def test_all_sections_present(self):
        import html as html_mod
        unescaped = html_mod.unescape(self.html)
        for heading in SECTION_HEADINGS:
            self.assertIn(heading, unescaped, heading)

    def test_disclaimer_and_no_cert_callout(self):
        self.assertIn("not a legal HIPAA compliance certification", self.html)

    def test_no_autofetching_resources(self):
        """Nothing in the report may trigger a network request on open.
        Plain <a href> anchors are allowed (no request until clicked)."""
        for pat in (r'src\s*=\s*["\']https?://', r'<link[^>]+href\s*=\s*["\']https?://',
                    r'@import\b', r'url\(\s*["\']?https?://'):
            self.assertIsNone(re.search(pat, self.html), pat)

    def test_links_only_to_allowlisted_domains(self):
        for url in re.findall(r'href="(https?://[^"]+)"', self.html):
            domain = re.match(r"https?://([^/]+)", url).group(1)
            self.assertIn(domain, ALLOWED_LINK_DOMAINS, url)

    def test_poisoned_finding_cannot_inject_links(self):
        bad = json.loads(json.dumps(DATA))
        bad["findings"][0]["why"] = 'See <a href="https://evil.example/x">this</a>.'
        html = render_html(report.build_model(bad, "x", "2026-01-01"))
        self.assertNotIn("evil.example/x</a>", html)
        self.assertNotIn('href="https://evil.example', html)

    def test_user_text_is_escaped(self):
        bad = json.loads(json.dumps(DATA))
        bad["findings"][0]["title"] = '<script>alert("x")</script>'
        html = render_html(report.build_model(bad, "x", "2026-01-01"))
        self.assertNotIn('<script>alert', html)
        self.assertIn('&lt;script&gt;', html)

    def test_score_and_findings_rendered(self):
        model = report.build_model(DATA, "golden-fixture", "2026-01-01")
        self.assertIn(str(model["scores"]["score"]), self.html)
        self.assertIn("backend/config.py:9", self.html)


if __name__ == "__main__":
    unittest.main()
