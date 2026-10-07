"""Guards that keep the top-level documentation in step with the repository (see docs/enterprise-suite/MANIFEST.md).

These are cheap structural checks, not a proofread: images and links in the README resolve, the FAQ markdown and the FAQ page agree, CLAUDE.md names each
package that exists, and a few strings that must not reappear (the earlier working name, an employer's name, stale counts) do not.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Questions added in the 2026-10 documentation sweep: each must exist verbatim in docs/FAQ.md and in dashboard/static/js/pages/faq.js.
SWEEP_QUESTIONS = [
    "Why was this incident routed to me?",
    "Why are there no cases to create?",
    "What is in an incident investigation report, and how far can I trust it?",
    'How do suggested hunts work, and why do they say "cannot tell"?',
    "How do I feed the attack surface page?",
    "What does the Integrity page check, and what will it repair?",
    "How do I enable the MCP endpoint safely?",
    "What is the confidence gate, and when can Quanta act without a person?",
    "What are Insights on Home, and what is structured Ask?",
    "What is the Anthropic CVD feed, and how do I use it?",
    "How do I use the command palette and live updates?",
]

PACKAGES = [
    "remediation/insights", "remediation/ontology", "remediation/decisions", "remediation/integrity", "remediation/asm", "remediation/mcp",
    "remediation/cvd", "remediation/hunting/engine", "remediation/soc/incidents", "remediation/investigation", "remediation/posture",
    "remediation/simulation", "remediation/graphs",
]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.readme = text("README.md")

    def test_every_local_image_exists(self):
        paths = set(re.findall(r'src="([^"]+)"', self.readme)) | set(re.findall(r"!\[[^\]]*\]\(([^)\s]+)", self.readme))
        local = [p for p in paths if not re.match(r"^[a-z]+://", p)]
        self.assertTrue(local, "the README is expected to carry screenshots")
        missing = [p for p in local if not (ROOT / p).is_file()]
        self.assertEqual(missing, [])

    def test_every_docs_link_resolves(self):
        links = set(re.findall(r"\]\((docs/[^)#\s]+)", self.readme)) | set(re.findall(r'href="(docs/[^"#]+)"', self.readme))
        self.assertTrue(links)
        missing = [p for p in links if not (ROOT / p).exists()]
        self.assertEqual(missing, [])

    def test_other_relative_markdown_links_resolve(self):
        links = {p for p in re.findall(r"\]\(([A-Za-z_]+\.md)", self.readme)}
        missing = [p for p in links if not (ROOT / p).exists()]
        self.assertEqual(missing, [])

    def test_mermaid_fences_are_balanced(self):
        self.assertEqual(self.readme.count("```") % 2, 0)

    def test_new_docs_are_linked_from_the_readme(self):
        for name in ("SOC_INCIDENTS", "INVESTIGATION_REPORTS", "HUNT_ENGINE", "DECISIONS", "ATTACK_SURFACE", "CVD_FEED", "INSIGHTS",
                     "MCP_ENDPOINT", "INTEGRITY", "POSTURE", "ONTOLOGY", "ENVIRONMENTS", "RELEASE_PROCESS", "SIMULATION", "UI_KIT",
                     "SOC_HUNT_UI", "REVIEWER_GUIDE"):
            self.assertIn(f"docs/{name}.md", self.readme, name)

    def test_test_count_is_not_the_old_figure(self):
        for rel in ("README.md", "CLAUDE.md"):
            body = text(rel)
            self.assertNotIn("2,302 tests", body, rel)
            self.assertNotIn("2475 tests", body, rel)
            self.assertNotIn("tests-2475", body, rel)


class FaqSyncTests(unittest.TestCase):
    def setUp(self):
        self.md = text("docs/FAQ.md")
        self.js = text("dashboard/static/js/pages/faq.js")
        self.md_questions = re.findall(r"^### (.+)$", self.md, re.M)
        self.js_questions = re.findall(r'^  \["(.+?)",\s*$', self.js, re.M)

    def test_sweep_questions_exist_in_both(self):
        for q in SWEEP_QUESTIONS:
            self.assertIn(q, self.md_questions, q)
            self.assertIn(q.replace('"', '\\"'), self.js_questions, q)

    def test_counts_stay_close(self):
        self.assertTrue(self.md_questions and self.js_questions)
        self.assertLessEqual(abs(len(self.md_questions) - len(self.js_questions)), 2, (len(self.md_questions), len(self.js_questions)))

    def test_no_duplicate_questions(self):
        self.assertEqual(len(self.md_questions), len(set(self.md_questions)))
        self.assertEqual(len(self.js_questions), len(set(self.js_questions)))

    def test_posture_check_count_is_current(self):
        for rel in ("docs/FAQ.md", "dashboard/static/js/pages/faq.js", "docs/enterprise-suite/user-guide.html"):
            self.assertNotIn("183 checks", text(rel), rel)
        self.assertIn("194 checks", text("docs/POSTURE.md"))

    def test_user_guide_details_are_balanced_and_carry_the_new_entries(self):
        guide = text("docs/enterprise-suite/user-guide.html")
        self.assertEqual(guide.count("<details"), guide.count("</details>"))
        for q in SWEEP_QUESTIONS:
            self.assertIn(q.replace("&", "&amp;"), guide.replace("&quot;", '"'), q)


class ClaudeMdTests(unittest.TestCase):
    def setUp(self):
        self.claude = text("CLAUDE.md")

    def test_each_new_package_exists_and_is_mentioned(self):
        for pkg in PACKAGES:
            self.assertTrue((ROOT / pkg).is_dir(), f"{pkg} is expected to exist")
            self.assertIn(pkg + "/", self.claude, pkg)

    def test_migration_count_is_current(self):
        from remediation.utils.migrations import MIGRATIONS
        self.assertIn(f"{len(MIGRATIONS)} today", self.claude)

    def test_ci_and_changelog_conventions_are_recorded(self):
        for needle in ("scripts/ci_shard.py", "900 s", "Server-Sent Events", "next free number", "[Unreleased]", "keep BOTH"):
            self.assertIn(needle, self.claude, needle)

    def test_cases_are_described_as_automatic(self):
        self.assertIn("cases are auto-created from incidents", self.claude.replace("Cases are", "cases are"))
        self.assertNotIn("cases created by analysts", self.claude)

    def test_every_api_key_scope_is_listed(self):
        from remediation.apikeys.store import SCOPES
        for scope in SCOPES:
            self.assertIn(scope, self.claude, scope)
            self.assertIn(scope, text("docs/enterprise-suite/architecture.html"), scope)


class ForbiddenStringTests(unittest.TestCase):
    """The earlier working name survives only in the GitHub repository URL; an employer's name must not appear in the product documentation."""

    def doc_files(self):
        files = [ROOT / "README.md"]
        files += sorted((ROOT / "docs").glob("*.md"))
        files += sorted((ROOT / "docs" / "enterprise-suite").glob("*.html"))
        files += [ROOT / "dashboard/static/js/pages/faq.js"]
        return files

    def test_no_employer_name(self):
        for f in self.doc_files():
            self.assertNotIn("deloitte", f.read_text(encoding="utf-8").lower(), str(f.relative_to(ROOT)))

    def test_old_working_name_only_in_repository_url(self):
        for f in self.doc_files():
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if "vulnhunter" in line.lower():
                    self.assertTrue("github.com/pavankumar-evani/VulnHunter" in line or "cd VulnHunter" in line,
                                    f"{f.relative_to(ROOT)}:{n} uses the old working name")

    def test_no_wrong_hunt_migration_number(self):
        self.assertNotIn("migration 7, tables `hunt_hypotheses`", text("CHANGELOG.md"))


if __name__ == "__main__":
    unittest.main()
