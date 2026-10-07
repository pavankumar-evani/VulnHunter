"""The ITSM comment calls on the ServiceNow and Jira connectors, against hand-rolled fake sessions: the exact requests, reference validation, and no retry on the write."""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors import jira_connector, servicenow_connector  # noqa: E402


class Resp:
    def __init__(self, data=None, status=200):
        self._d, self.status_code = data if data is not None else {}, status

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class Session:
    def __init__(self, get=None, post_status=200, patch_status=200):
        self.headers, self.auth, self.calls = {}, None, []
        self._get, self.post_status, self.patch_status = get, post_status, patch_status

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return Resp(self._get)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return Resp({"id": "10001"}, self.post_status)

    def patch(self, url, **kw):
        self.calls.append(("PATCH", url, kw))
        return Resp({}, self.patch_status)


class ServiceNow(unittest.TestCase):
    def test_the_note_goes_to_work_notes_of_the_incident_found_by_number(self):
        s = Session(get={"result": [{"sys_id": "abc123", "number": "INC0012"}]})
        out = servicenow_connector.ServiceNowConnector("acme", "u", "p", session=s).add_comment("INC0012", "hello")
        self.assertEqual(out, {"ticket": "INC0012", "status": "commented"})
        self.assertEqual([c[0] for c in s.calls], ["GET", "PATCH"])
        self.assertIn("number=INC0012", s.calls[0][2]["params"]["sysparm_query"])
        self.assertTrue(s.calls[1][1].endswith("/api/now/table/incident/abc123"))
        self.assertEqual(s.calls[1][2]["json"], {"work_notes": "hello"})

    def test_an_unknown_incident_and_a_bad_reference_are_refused_before_any_write(self):
        s = Session(get={"result": []})
        c = servicenow_connector.ServiceNowConnector("acme", "u", "p", session=s)
        with self.assertRaises(servicenow_connector.ServiceNowError):
            c.add_comment("INC9999", "x")
        self.assertEqual([x[0] for x in s.calls], ["GET"])
        for bad in ("INC1/../x", "a b", "", None):
            with self.assertRaises(servicenow_connector.ServiceNowError):
                c.add_comment(bad, "x")

    def test_a_failed_write_raises_and_is_not_retried(self):
        s = Session(get={"result": [{"sys_id": "a", "number": "INC1234"}]}, patch_status=500)
        with self.assertRaises(RuntimeError):
            servicenow_connector.ServiceNowConnector("acme", "u", "p", session=s).add_comment("INC1234", "x")
        self.assertEqual(sum(1 for c in s.calls if c[0] == "PATCH"), 1)


class Jira(unittest.TestCase):
    def test_the_comment_is_posted_in_atlassian_document_format(self):
        s = Session()
        out = jira_connector.JiraConnector("https://acme.atlassian.net", "e@x", "tok", "SEC", session=s).add_comment("SEC-12", "line one\n\nline three")
        self.assertEqual((out["ticket"], out["status"]), ("SEC-12", "commented"))
        method, url, kw = s.calls[0]
        self.assertEqual((method, url), ("POST", "https://acme.atlassian.net/rest/api/3/issue/SEC-12/comment"))
        doc = kw["json"]["body"]
        self.assertEqual((doc["type"], doc["version"]), ("doc", 1))
        self.assertEqual([p["content"][0]["text"] if p["content"] else "" for p in doc["content"]], ["line one", "", "line three"])

    def test_a_bad_key_is_refused_and_a_failed_write_is_not_retried(self):
        s = Session(post_status=403)
        c = jira_connector.JiraConnector("https://acme.atlassian.net", "e@x", "tok", "SEC", session=s)
        for bad in ("sec-1", "SEC-1/../../x", "", None):
            with self.assertRaises(jira_connector.JiraError):
                c.add_comment(bad, "x")
        self.assertEqual(s.calls, [])
        with self.assertRaises(RuntimeError):
            c.add_comment("SEC-1", "x")
        self.assertEqual(len(s.calls), 1)


if __name__ == "__main__":
    unittest.main()
