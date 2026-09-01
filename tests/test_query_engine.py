"""
Tests for remediation/search/query_engine.py - the deterministic, pattern-based "ask
your data" search engine. Every test asserts against a small, hand-built real-shaped
fixture (queue findings + assets), never the shipped app data, so these stay fast and
independent of dataset size/content.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.search import query_engine as qe  # noqa: E402


def _finding(id_, title, severity, cve=None, kev=False, days_remaining=10, breached=False,
             asset_name="WIN-DC01", owner=None, team=None):
    return {
        "id": id_, "title": title, "severity": severity, "cve": cve,
        "kev": {"listed": kev}, "sla": {"breached": breached, "days_remaining": days_remaining},
        "asset": {"name": asset_name, "type": "windows-server"},
        "owner": owner, "team": team,
    }


ASSETS = [
    {"name": "WIN-DC01", "owner": "Priya Nair", "team": "Identity", "finding_count": 3,
     "highest_severity": "Critical", "risk_score": 88},
    {"name": "LNX-DB03", "owner": "Alex Chen", "team": "Platform", "finding_count": 1,
     "highest_severity": "Medium", "risk_score": 40},
]


class FindingIdLookup(unittest.TestCase):
    def test_exact_id_in_queue_returns_a_real_answer(self):
        findings = [_finding("FIND-1", "Log4Shell", "Critical", cve="CVE-2021-44228")]
        result = qe.answer_query("what is FIND-1", queue_findings=findings, assets=ASSETS)
        self.assertEqual(result["intent"], "finding_lookup")
        self.assertIn("Log4Shell", result["answer"])
        self.assertIn("WIN-DC01", result["answer"])
        self.assertEqual(result["link"], "/queue?highlight=FIND-1")

    def test_id_not_found_says_so_honestly(self):
        result = qe.answer_query("FIND-9999999", queue_findings=[], assets=[])
        self.assertEqual(result["intent"], "finding_lookup")
        self.assertIn("No finding", result["answer"])
        self.assertEqual(result["results"], [])

    def test_falls_back_to_vulnhunt_findings_for_a_code_scan_id(self):
        vulnhunt = [{"ID": "FIND-2", "Title": "SQL Injection", "Severity": "High"}]
        result = qe.answer_query("FIND-2", queue_findings=[], vulnhunt_findings=vulnhunt, assets=[])
        self.assertEqual(result["intent"], "finding_lookup")
        self.assertIn("SQL Injection", result["answer"])

    def test_id_match_is_case_insensitive(self):
        findings = [_finding("FIND-1", "Log4Shell", "Critical")]
        result = qe.answer_query("find-1 please", queue_findings=findings, assets=[])
        self.assertEqual(result["intent"], "finding_lookup")
        self.assertIn("Log4Shell", result["answer"])


class CveLookup(unittest.TestCase):
    def test_real_cve_reports_affected_asset_count(self):
        findings = [
            _finding("FIND-1", "Log4Shell", "Critical", cve="CVE-2021-44228", asset_name="WIN-DC01"),
            _finding("FIND-2", "Log4Shell", "Critical", cve="CVE-2021-44228", asset_name="LNX-DB03"),
        ]
        result = qe.answer_query("tell me about CVE-2021-44228", queue_findings=findings, assets=ASSETS)
        self.assertEqual(result["intent"], "cve_lookup")
        self.assertIn("2 real finding(s)", result["answer"])
        self.assertIn("2 asset(s)", result["answer"])
        self.assertEqual(result["link"], "/queue?cve=CVE-2021-44228")

    def test_unmatched_cve_says_so_honestly(self):
        result = qe.answer_query("CVE-2099-99999", queue_findings=[], assets=[])
        self.assertEqual(result["intent"], "cve_lookup")
        self.assertIn("No findings", result["answer"])


class CountAndFilterQueries(unittest.TestCase):
    def setUp(self):
        self.findings = [
            _finding("FIND-1", "A", "Critical", kev=True, breached=True, days_remaining=-2, owner="Priya Nair", team="Identity", asset_name="WIN-DC01"),
            _finding("FIND-2", "B", "Critical", kev=False, breached=False, days_remaining=1, owner="Priya Nair", team="Identity", asset_name="WIN-DC01"),
            _finding("FIND-3", "C", "Low", kev=False, breached=False, days_remaining=30, owner="Alex Chen", team="Platform", asset_name="LNX-DB03"),
        ]

    def test_how_many_critical(self):
        result = qe.answer_query("how many critical findings do we have", queue_findings=self.findings, assets=ASSETS)
        self.assertEqual(result["intent"], "count")
        self.assertIn("2 finding(s)", result["answer"])

    def test_how_many_kev(self):
        result = qe.answer_query("how many KEV findings are there", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("1 finding(s)", result["answer"])
        self.assertEqual(result["link"], "/queue?kevOnly=true")

    def test_how_many_breached(self):
        result = qe.answer_query("how many findings are breached", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("1 finding(s)", result["answer"])
        self.assertEqual(result["link"], "/queue?slaStatus=breached")

    def test_combined_severity_and_kev_filter(self):
        result = qe.answer_query("how many critical KEV findings", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("1 finding(s)", result["answer"])

    def test_team_filter_resolves_a_real_team_name(self):
        result = qe.answer_query("how many findings for team Identity", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("2 finding(s)", result["answer"])
        self.assertIn("Identity", result["answer"])

    def test_owner_filter_resolves_a_real_owner_name(self):
        result = qe.answer_query("findings owned by Alex Chen", queue_findings=self.findings, assets=ASSETS)
        self.assertEqual(result["intent"], "list")
        self.assertIn("1 finding(s)", result["answer"])

    def test_asset_filter_combined_with_severity(self):
        # Both FIND-1 and FIND-2 are Critical and on WIN-DC01 - a real count of 2.
        result = qe.answer_query("how many critical findings on WIN-DC01", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("2 finding(s)", result["answer"])
        self.assertIn("asset=WIN-DC01", result["link"])

    def test_list_intent_shows_top_results_without_a_count_word(self):
        result = qe.answer_query("show me low severity findings", queue_findings=self.findings, assets=ASSETS)
        self.assertEqual(result["intent"], "list")
        self.assertIn("FIND-3", result["answer"])

    def test_no_matches_reports_zero_not_an_error(self):
        result = qe.answer_query("how many medium findings", queue_findings=self.findings, assets=ASSETS)
        self.assertIn("0 finding(s)", result["answer"])
        self.assertEqual(result["results"], [])


class AssetLookup(unittest.TestCase):
    def test_bare_asset_name_returns_asset_summary(self):
        result = qe.answer_query("WIN-DC01", queue_findings=[], assets=ASSETS)
        self.assertEqual(result["intent"], "asset_lookup")
        self.assertIn("Priya Nair", result["answer"])
        self.assertEqual(result["link"], "/assets?highlight=WIN-DC01")

    def test_longest_matching_asset_name_wins(self):
        assets = ASSETS + [{"name": "WIN-DC", "owner": "Someone Else", "team": "Other", "finding_count": 0}]
        result = qe.answer_query("what about WIN-DC01", queue_findings=[], assets=assets)
        self.assertIn("Priya Nair", result["answer"])


class StripMarkdownEmphasis(unittest.TestCase):
    def test_strips_bold_and_code_spans(self):
        self.assertEqual(qe._strip_markdown_emphasis("a **bold** and `code` word"), "a bold and code word")

    def test_strips_a_bold_span_that_wraps_across_a_source_line_break(self):
        # Markdown source often line-wraps a long paragraph for readability - a bold
        # span crossing that wrap must still be recognized (regex `.` needs re.DOTALL).
        text = "connectors are **built against each vendor's\ndocumented API contract**, verified"
        self.assertEqual(
            qe._strip_markdown_emphasis(text),
            "connectors are built against each vendor's\ndocumented API contract, verified",
        )

    def test_plain_text_is_unchanged(self):
        self.assertEqual(qe._strip_markdown_emphasis("plain text, nothing to strip"), "plain text, nothing to strip")


class FaqFallback(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.faq_path = Path(self.tmpdir.name) / "FAQ.md"
        self.faq_path.write_text(
            "# FAQ\n\n"
            "### Does this actually scan production infrastructure?\n\n"
            "No. It ingests vulnerability data from Tenable and Armis exports; it never "
            "connects to or scans a live host or network device directly.\n\n"
            "### What languages can the code scanner find vulnerabilities in?\n\n"
            "Python, JavaScript, Java, Go, PHP, and Perl.\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_matches_the_right_faq_entry_by_keyword_overlap(self):
        result = qe.search_faq("does this scan production infrastructure", path=self.faq_path)
        self.assertIsNotNone(result)
        self.assertIn("scan production infrastructure", result["question"])

    def test_answer_query_falls_back_to_faq_when_nothing_else_matches(self):
        real_faq = qe.FAQ_PATH
        qe.FAQ_PATH = self.faq_path
        try:
            result = qe.answer_query("what languages does the scanner support", queue_findings=[], assets=[])
        finally:
            qe.FAQ_PATH = real_faq
        self.assertEqual(result["intent"], "faq")
        self.assertEqual(result["link"], "/faq")
        self.assertIsNotNone(result["matched_faq"])

    def test_no_keyword_overlap_returns_none_not_a_weak_guess(self):
        result = qe.search_faq("xyzzy plugh quux", path=self.faq_path)
        self.assertIsNone(result)

    def test_missing_faq_file_returns_none(self):
        result = qe.search_faq("anything", path=Path(self.tmpdir.name) / "does-not-exist.md")
        self.assertIsNone(result)


class NoMatchAndEmpty(unittest.TestCase):
    def test_empty_query_returns_a_real_hint_not_a_crash(self):
        result = qe.answer_query("", queue_findings=[], assets=[])
        self.assertEqual(result["intent"], "empty")

    def test_gibberish_with_no_faq_overlap_is_an_honest_no_match(self):
        real_faq = qe.FAQ_PATH
        qe.FAQ_PATH = Path("/nonexistent/path/FAQ.md")
        try:
            result = qe.answer_query("xyzzy plugh quux", queue_findings=[], assets=[])
        finally:
            qe.FAQ_PATH = real_faq
        self.assertEqual(result["intent"], "no_match")
        self.assertIsNone(result["link"])


if __name__ == "__main__":
    unittest.main()
