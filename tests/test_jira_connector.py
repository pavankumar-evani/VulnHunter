"""
Tests for remediation/connectors/jira_connector.py. All HTTP mocked - no real Jira
Cloud site touched, no credentials needed. See remediation/connectors/README.md for
what this suite does and doesn't prove.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.jira_connector import (  # noqa: E402
    JiraConnector, JiraError, build_issue_body,
)


def fake_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


SAMPLE_FINDING = {
    "id": "FIND-1",
    "title": "MS Windows Print Spooler Remote Code Execution (PrintNightmare)",
    "description": "The Windows Print Spooler service allows remote code execution.",
    "cve": "CVE-2021-34527",
    "severity": "Critical",
    "asset": {"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server"},
    "recommended_fix": "Apply KB5004945.",
    "kev": {"listed": True, "date_added": "2021-11-03"},
    "epss": {"score": 0.99759, "percentile": 0.99955},
}


class BuildIssueBodyPureFunction(unittest.TestCase):
    """No network, no connector instance needed - this is what the dashboard's preview
    mode calls directly to show what WOULD be sent without real credentials."""

    def test_builds_correct_body_with_no_network_calls(self):
        body = build_issue_body(SAMPLE_FINDING, "PROJ")
        self.assertEqual(body["fields"]["project"]["key"], "PROJ")
        self.assertIn("FIND-1", body["fields"]["summary"])
        self.assertEqual(body["fields"]["labels"], ["vulnhunter-FIND-1"])

    def test_create_issue_and_build_issue_body_produce_same_shape(self):
        """Regression guard: the refactor that extracted build_issue_body must not
        have changed what create_issue actually sends."""
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"id": "10000", "key": "PROJ-1"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        conn.create_issue(SAMPLE_FINDING)
        sent_body = session.post.call_args.kwargs["json"]
        self.assertEqual(sent_body, build_issue_body(SAMPLE_FINDING, "PROJ"))

    def test_description_is_valid_minimal_adf_doc(self):
        body = build_issue_body(SAMPLE_FINDING, "PROJ")
        description = body["fields"]["description"]
        self.assertEqual(description["type"], "doc")
        self.assertEqual(description["version"], 1)
        paragraph = description["content"][0]
        self.assertEqual(paragraph["type"], "paragraph")
        text_node = paragraph["content"][0]
        self.assertEqual(text_node["type"], "text")
        self.assertIsInstance(text_node["text"], str)

    def test_description_text_includes_kev_and_epss_context(self):
        body = build_issue_body(SAMPLE_FINDING, "PROJ")
        text = body["fields"]["description"]["content"][0]["content"][0]["text"]
        self.assertIn("KEV-listed", text)
        self.assertIn("EPSS score", text)
        self.assertIn("CVE-2021-34527", text)

    def test_issue_type_defaults_to_bug(self):
        body = build_issue_body(SAMPLE_FINDING, "PROJ")
        self.assertEqual(body["fields"]["issuetype"]["name"], "Bug")

    def test_issue_type_can_be_overridden(self):
        body = build_issue_body(SAMPLE_FINDING, "PROJ", issue_type="Task")
        self.assertEqual(body["fields"]["issuetype"]["name"], "Task")

    def test_label_used_as_idempotency_key_across_findings(self):
        other = {**SAMPLE_FINDING, "id": "FIND-2"}
        self.assertEqual(build_issue_body(SAMPLE_FINDING, "PROJ")["fields"]["labels"], ["vulnhunter-FIND-1"])
        self.assertEqual(build_issue_body(other, "PROJ")["fields"]["labels"], ["vulnhunter-FIND-2"])


class AuthAndConstruction(unittest.TestCase):
    def test_session_gets_basic_auth_configured(self):
        session = MagicMock()
        JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok1", "PROJ", session=session)
        self.assertEqual(session.auth, ("e@acme.com", "tok1"))

    def test_base_url_stored_and_trailing_slash_stripped(self):
        session = MagicMock()
        conn = JiraConnector("https://acme.atlassian.net/", "e@acme.com", "tok", "PROJ", session=session)
        self.assertEqual(conn.base_url, "https://acme.atlassian.net")

    def test_project_key_stored_on_connector(self):
        session = MagicMock()
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)
        self.assertEqual(conn.project_key, "PROJ")


class FindExistingIssue(unittest.TestCase):
    def test_finds_existing_issue_by_label_jql(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": [{"id": "10000", "key": "PROJ-1"}]})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        existing = conn.find_existing_issue("FIND-1")
        self.assertEqual(existing["key"], "PROJ-1")
        params = session.get.call_args.kwargs["params"]
        self.assertIn("vulnhunter-FIND-1", params["jql"])

    def test_returns_none_when_nothing_found(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)
        self.assertIsNone(conn.find_existing_issue("FIND-999"))


class CreateIssue(unittest.TestCase):
    def test_creates_new_issue_when_none_exists(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"id": "10001", "key": "PROJ-2"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        result = conn.create_issue(SAMPLE_FINDING)
        self.assertEqual(result["_vulnhunter_status"], "created")
        self.assertEqual(result["key"], "PROJ-2")

    def test_skips_creation_when_issue_already_exists(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": [{"id": "10000", "key": "PROJ-1"}]})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        result = conn.create_issue(SAMPLE_FINDING)
        self.assertEqual(result["_vulnhunter_status"], "already_existed")
        session.post.assert_not_called()

    def test_skip_if_exists_false_always_creates(self):
        session = MagicMock()
        session.post.return_value = fake_response({"id": "10002", "key": "PROJ-3"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        conn.create_issue(SAMPLE_FINDING, skip_if_exists=False)
        session.get.assert_not_called()  # no existence check performed
        session.post.assert_called_once()

    def test_raises_on_unexpected_response_shape(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)
        with self.assertRaises(JiraError):
            conn.create_issue(SAMPLE_FINDING)

    def test_create_issue_posts_to_issue_endpoint(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"id": "10003", "key": "PROJ-4"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        conn.create_issue(SAMPLE_FINDING)
        called_url = session.post.call_args.args[0]
        self.assertEqual(called_url, "https://acme.atlassian.net/rest/api/3/issue")


class CreateIssuesForFindingsBatch(unittest.TestCase):
    def test_batch_creates_issues_for_all_findings(self):
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"id": "10000", "key": "PROJ-1"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        results = conn.create_issues_for_findings([SAMPLE_FINDING])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "created")
        self.assertEqual(results[0]["issue_key"], "PROJ-1")

    def test_batch_continues_past_a_single_finding_failure(self):
        """One malformed finding must not abort the whole batch."""
        session = MagicMock()
        session.get.return_value = fake_response({"issues": []})
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = JiraConnector("https://acme.atlassian.net", "e@acme.com", "tok", "PROJ", session=session)

        results = conn.create_issues_for_findings([SAMPLE_FINDING, {"id": "FIND-2", "title": "t", "asset": {}}])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "error" for r in results))
        self.assertIsNotNone(results[0]["error"])


if __name__ == "__main__":
    unittest.main()
