"""
Tests for remediation/connectors/servicenow_connector.py. All HTTP mocked - no real
ServiceNow instance touched, no credentials needed. See remediation/connectors/README.md
for what this suite does and doesn't prove.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.servicenow_connector import (  # noqa: E402
    ServiceNowConnector, ServiceNowError, build_incident_body,
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


class BuildIncidentBodyPureFunction(unittest.TestCase):
    """No network, no connector instance needed - this is what the dashboard's preview
    mode calls directly to show what WOULD be sent without real credentials."""

    def test_builds_correct_body_with_no_network_calls(self):
        body = build_incident_body(SAMPLE_FINDING)
        self.assertEqual(body["correlation_id"], "FIND-1")
        self.assertIn("FIND-1", body["short_description"])
        self.assertEqual(body["urgency"], "1")

    def test_create_incident_and_build_incident_body_produce_same_shape(self):
        """Regression guard: the refactor that extracted build_incident_body must not
        have changed what create_incident actually sends."""
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"result": {"sys_id": "x", "number": "INC1"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        conn.create_incident(SAMPLE_FINDING)
        sent_body = session.post.call_args.kwargs["json"]
        self.assertEqual(sent_body, build_incident_body(SAMPLE_FINDING))


class AuthAndConstruction(unittest.TestCase):
    def test_session_gets_basic_auth_configured(self):
        session = MagicMock()
        ServiceNowConnector("mycompany", "user1", "pass1", session=session)
        self.assertEqual(session.auth, ("user1", "pass1"))

    def test_base_url_built_from_instance_name(self):
        session = MagicMock()
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)
        self.assertEqual(conn.base_url, "https://mycompany.service-now.com")

    def test_default_table_is_incident(self):
        session = MagicMock()
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)
        self.assertEqual(conn.table, "incident")

    def test_can_target_a_different_table(self):
        session = MagicMock()
        conn = ServiceNowConnector("mycompany", "u", "p", table="sn_vul_vulnerable_item", session=session)
        self.assertEqual(conn.table, "sn_vul_vulnerable_item")


class FindExistingIncident(unittest.TestCase):
    def test_finds_existing_incident_by_correlation_id(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": [{"sys_id": "abc123", "number": "INC0010001"}]})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)
        existing = conn.find_existing_incident("FIND-1")
        self.assertEqual(existing["number"], "INC0010001")
        params = session.get.call_args.kwargs["params"]
        self.assertIn("FIND-1", params["sysparm_query"])

    def test_returns_none_when_nothing_found(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)
        self.assertIsNone(conn.find_existing_incident("FIND-999"))


class CreateIncident(unittest.TestCase):
    def test_creates_new_incident_when_none_exists(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"result": {"sys_id": "xyz", "number": "INC0010002"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        result = conn.create_incident(SAMPLE_FINDING)
        self.assertEqual(result["_vulnhunter_status"], "created")
        self.assertEqual(result["number"], "INC0010002")

    def test_skips_creation_when_incident_already_exists(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": [{"sys_id": "abc", "number": "INC0010001"}]})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        result = conn.create_incident(SAMPLE_FINDING)
        self.assertEqual(result["_vulnhunter_status"], "already_existed")
        session.post.assert_not_called()

    def test_skip_if_exists_false_always_creates(self):
        session = MagicMock()
        session.post.return_value = fake_response({"result": {"sys_id": "new", "number": "INC0010003"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        conn.create_incident(SAMPLE_FINDING, skip_if_exists=False)
        session.get.assert_not_called()  # no existence check performed
        session.post.assert_called_once()

    def test_incident_body_includes_kev_and_epss_context(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"result": {"sys_id": "x", "number": "INC1"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        conn.create_incident(SAMPLE_FINDING)
        body = session.post.call_args.kwargs["json"]
        self.assertIn("FIND-1", body["short_description"])
        self.assertIn("KEV-listed", body["description"])
        self.assertIn("EPSS score", body["description"])
        self.assertEqual(body["correlation_id"], "FIND-1")

    def test_severity_maps_to_urgency_and_impact(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"result": {"sys_id": "x", "number": "INC1"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        conn.create_incident(SAMPLE_FINDING)  # severity: Critical
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["urgency"], "1")
        self.assertEqual(body["impact"], "1")

    def test_raises_on_unexpected_response_shape(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)
        with self.assertRaises(ServiceNowError):
            conn.create_incident(SAMPLE_FINDING)


class CreateIncidentsForFindingsBatch(unittest.TestCase):
    def test_batch_creates_incidents_for_all_findings(self):
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"result": {"sys_id": "x", "number": "INC0010001"}})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        results = conn.create_incidents_for_findings([SAMPLE_FINDING])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "created")
        self.assertEqual(results[0]["incident_number"], "INC0010001")

    def test_batch_continues_past_a_single_finding_failure(self):
        """One malformed finding must not abort the whole batch."""
        session = MagicMock()
        session.get.return_value = fake_response({"result": []})
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = ServiceNowConnector("mycompany", "u", "p", session=session)

        results = conn.create_incidents_for_findings([SAMPLE_FINDING, {"id": "FIND-2", "title": "t", "asset": {}}])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "error" for r in results))
        self.assertIsNotNone(results[0]["error"])


if __name__ == "__main__":
    unittest.main()
