"""Skill structure and activation signals. Behavioral eval prompts (must-activate
/ must-not-activate / must-remain-useful) live under evals/ for `claude plugin
eval`; these assertions keep the skills well-formed and carrying the required
guidance so they activate for healthcare work and stay out of generic work."""
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILLS = REPO / "skills"


def frontmatter(path: Path) -> dict:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path} has no frontmatter"
    end = text.index("\n---\n", 4)
    fm: dict = {}
    for line in text[4:end].splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            fm[k.strip()] = v.strip()
    return fm, text[end + 5:]


class TestSkillStructure(unittest.TestCase):
    def test_every_skill_has_name_and_description(self):
        for skill in SKILLS.iterdir():
            sm = skill / "SKILL.md"
            if not sm.is_file():
                continue
            fm, _ = frontmatter(sm)
            self.assertEqual(fm.get("name"), skill.name, sm)
            self.assertGreater(len(fm.get("description", "")), 40, f"{sm} description too thin")

    def test_referenced_files_exist(self):
        for skill in SKILLS.iterdir():
            sm = skill / "SKILL.md"
            if not sm.is_file():
                continue
            _, body = frontmatter(sm)
            for token in ("references/safe-patterns.md", "references/planning.md",
                          "references/categories.md"):
                if token in body:
                    self.assertTrue((skill / token).is_file(), f"{sm} references missing {token}")


class TestDevelopmentSkill(unittest.TestCase):
    def setUp(self):
        self.fm, self.body = frontmatter(SKILLS / "clearmap-development" / "SKILL.md")

    def test_activation_signals(self):
        desc = self.fm["description"].lower()
        for signal in ("phi", "patient", "symptom", "diagnos", "clinical", "ssn"):
            self.assertIn(signal, desc, f"description missing activation signal: {signal}")

    def test_has_boundary_against_generic_work(self):
        self.assertIn("not", self.fm["description"].lower())
        self.assertRegex(self.fm["description"].lower(), r"generic|non-healthcare")

    def test_carries_required_guidance(self):
        b = self.body.lower()
        self.assertIn("minimum-necessary", b)
        self.assertIn("do not blindly follow", b)
        self.assertIn("ssn", b)
        for cat in ("ACCESS", "AI-RAG", "APPSEC", "SECRETS"):
            self.assertIn(cat, self.body)

    def test_disclaims_compliance(self):
        b = self.body.lower()
        self.assertTrue("not a compliance certification" in b
                        or "never means the result is hipaa compliant" in b,
                        "development skill must disclaim certification/compliance")
        # no AFFIRMATIVE compliance claim
        for affirmative in ("is now hipaa compliant", "makes it hipaa compliant",
                            "this is hipaa compliant"):
            self.assertNotIn(affirmative, b)


class TestAuditSkill(unittest.TestCase):
    def setUp(self):
        self.fm, self.body = frontmatter(SKILLS / "clearmap-audit" / "SKILL.md")

    def test_activation_and_pipeline(self):
        self.assertIn("audit", self.fm["description"].lower())
        for step in ("scan.py", "merge_reasoning.py", "report.py"):
            self.assertIn(step, self.body)

    def test_states_and_summary(self):
        for token in ("Score unavailable", "Assessment incomplete", "Technical Risk Score"):
            self.assertIn(token, self.body)


if __name__ == "__main__":
    unittest.main()
