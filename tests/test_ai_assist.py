"""
Tests for dashboard/ai_assist.py - pure prompt-construction logic, no subprocess calls,
no network, no API spend. dashboard/app.py owns actually invoking `claude` for real; that
path is exercised (dry-run only, never confirmed) in tests/test_dashboard.py.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))

import ai_assist  # noqa: E402


class PromptConstruction(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "id": "FIND-12",
            "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
            "severity": "Critical",
            "cve": "CVE-2021-44228",
            "asset": {"name": "APP-ORDERS01", "type": "application"},
            "description": "The order-processing application bundles a vulnerable Log4j2.",
        }

    def test_explain_action_asks_for_plain_english_explanation(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("Explain, in plain English", prompt)

    def test_remediate_action_asks_for_remediation_steps(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "remediate")
        self.assertIn("remediation steps", prompt)

    def test_summarize_action_asks_for_executive_summary(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "summarize")
        self.assertIn("executive summary", prompt)

    def test_prompt_includes_finding_id_and_title(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("FIND-12", prompt)
        self.assertIn("Log4Shell", prompt)

    def test_prompt_includes_asset_name_and_type(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("APP-ORDERS01", prompt)
        self.assertIn("application", prompt)

    def test_prompt_includes_cve_and_severity(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("CVE-2021-44228", prompt)
        self.assertIn("Critical", prompt)

    def test_prompt_includes_description_when_present(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("order-processing application", prompt)

    def test_missing_cve_renders_as_not_applicable(self):
        finding = dict(self.finding, cve=None)
        prompt = ai_assist.build_ai_assist_prompt(finding, "explain")
        self.assertIn("CVE: N/A", prompt)

    def test_missing_description_is_omitted_without_error(self):
        finding = dict(self.finding)
        del finding["description"]
        prompt = ai_assist.build_ai_assist_prompt(finding, "explain")
        self.assertNotIn("Description:", prompt)

    def test_unknown_action_raises_value_error(self):
        with self.assertRaises(ValueError):
            ai_assist.build_ai_assist_prompt(self.finding, "delete_everything")

    def test_same_inputs_produce_the_same_prompt(self):
        """Pure function: no hidden state, no timestamps baked into the prompt itself."""
        first = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        second = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertEqual(first, second)

    def test_prompt_requests_plain_text_concise_response(self):
        prompt = ai_assist.build_ai_assist_prompt(self.finding, "explain")
        self.assertIn("plain text only", prompt)
        self.assertIn("under 150 words", prompt)


if __name__ == "__main__":
    unittest.main()
