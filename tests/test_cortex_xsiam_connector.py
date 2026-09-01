"""
Tests for the live Cortex XSIAM connector (remediation/connectors/cortex_xsiam_connector.py).

Every HTTP interaction is mocked - these tests never touch the network or require real
API credentials. They verify: x-xdr-auth-id/Authorization header construction, the
get_incidents request shape (including the status filter and search_from/search_to
paging window), severity mapping (including the info->Low collapse), the epoch-ms ->
ISO-date conversion, and correct normalization into VulnHunter's Finding schema
(including the deliberate cve/cvss/kev/epss=None, id=None, and asset.type="unknown"
properties - see the module docstring).

These do NOT prove the connector works against a real Cortex XSIAM tenant - only that it
behaves correctly against responses shaped like Cortex XSIAM's public API documentation.
See remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.cortex_xsiam_connector import (  # noqa: E402
    CortexXsiamAuthError, CortexXsiamConnector, _epoch_ms_to_iso_date,
)


def fake_response(json_data, raise_error=False):
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


class CortexXsiamConstruction(unittest.TestCase):
    def test_requires_base_url(self):
        with self.assertRaises(ValueError):
            CortexXsiamConnector("api-key", "42", base_url=None)

    def test_session_gets_auth_headers(self):
        session = MagicMock()
        CortexXsiamConnector("api-key-value", 42, base_url="https://api-example.xdr.us.paloaltonetworks.com", session=session)
        header = session.headers.update.call_args[0][0]
        self.assertEqual(header["x-xdr-auth-id"], "42")
        self.assertEqual(header["Authorization"], "api-key-value")

    def test_base_url_strips_trailing_slash(self):
        session = MagicMock()
        conn = CortexXsiamConnector("k", "1", base_url="https://api-example.xdr.us.paloaltonetworks.com/", session=session)
        self.assertEqual(conn.base_url, "https://api-example.xdr.us.paloaltonetworks.com")


class CortexXsiamTestConnection(unittest.TestCase):
    def test_test_connection_uses_search_to_one(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": []}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        result = conn.test_connection()
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["request_data"]["search_to"], 1)
        self.assertEqual(result, {"ok": True})

    def test_test_connection_raises_on_http_error(self):
        session = MagicMock()
        session.post.return_value = fake_response(None, raise_error=True)
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class CortexXsiamFetchIncidents(unittest.TestCase):
    def test_hits_correct_url(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": []}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        conn.fetch_incidents()
        url = session.post.call_args[0][0]
        self.assertEqual(url, "https://x.example.com/public_api/v1/incidents/get_incidents")

    def test_includes_status_filter_when_given(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": []}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        conn.fetch_incidents(statuses=["new", "under_investigation"])
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["request_data"]["filters"], [
            {"field": "status", "operator": "eq", "value": ["new", "under_investigation"]},
        ])

    def test_omits_filters_when_no_statuses_given(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": []}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        conn.fetch_incidents()
        body = session.post.call_args.kwargs["json"]
        self.assertNotIn("filters", body["request_data"])

    def test_returns_incidents_list(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": [{"incident_id": "1"}]}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        self.assertEqual(conn.fetch_incidents(), [{"incident_id": "1"}])

    def test_raises_on_unexpected_shape(self):
        session = MagicMock()
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        with self.assertRaises(CortexXsiamAuthError):
            conn.fetch_incidents()

    def test_raises_on_http_error(self):
        session = MagicMock()
        session.post.return_value = fake_response(None, raise_error=True)
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        with self.assertRaises(Exception):
            conn.fetch_incidents()


class EpochMsToIsoDate(unittest.TestCase):
    def test_converts_known_epoch_ms(self):
        # 2024-01-15T00:00:00Z in epoch milliseconds
        self.assertEqual(_epoch_ms_to_iso_date(1705276800000), "2024-01-15")

    def test_falsy_value_falls_back_to_today(self):
        import datetime
        self.assertEqual(_epoch_ms_to_iso_date(None), datetime.date.today().isoformat())
        self.assertEqual(_epoch_ms_to_iso_date(0), datetime.date.today().isoformat())


class CortexXsiamNormalizeIncident(unittest.TestCase):
    def _sample_incident(self, **overrides):
        incident = {
            "incident_id": "INC-42",
            "incident_name": "Multi-stage attack detected",
            "severity": "high",
            "status": "new",
            "description": "Correlated detection across 2 hosts.",
            "hosts": ["web01.corp.local", "web02.corp.local"],
            "creation_time": 1705276800000,
            "modification_time": 1705320000000,
        }
        incident.update(overrides)
        return incident

    def test_normalize_maps_documented_shape(self):
        finding = CortexXsiamConnector.normalize_incident(self._sample_incident())
        self.assertIsNone(finding["id"])
        self.assertEqual(finding["source"], "cortex-xsiam")
        self.assertEqual(finding["source_ref"], "INC-42")
        self.assertEqual(finding["asset"]["name"], "web01.corp.local")
        self.assertEqual(finding["asset"]["type"], "unknown")
        self.assertIsNone(finding["asset"]["ip"])
        self.assertEqual(finding["title"], "Multi-stage attack detected")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["first_seen"], "2024-01-15")

    def test_cve_cvss_kev_epss_always_none(self):
        finding = CortexXsiamConnector.normalize_incident(self._sample_incident())
        self.assertIsNone(finding["cve"])
        self.assertIsNone(finding["cvss"])
        self.assertIsNone(finding["kev"])
        self.assertIsNone(finding["epss"])

    def test_info_severity_maps_to_low(self):
        finding = CortexXsiamConnector.normalize_incident(self._sample_incident(severity="info"))
        self.assertEqual(finding["severity"], "Low")

    def test_falls_back_to_incident_name_when_no_hosts(self):
        finding = CortexXsiamConnector.normalize_incident(self._sample_incident(hosts=[]))
        self.assertEqual(finding["asset"]["name"], "Multi-stage attack detected")

    def test_handles_missing_fields_gracefully(self):
        finding = CortexXsiamConnector.normalize_incident({"incident_id": "INC-1"})
        self.assertEqual(finding["title"], "Cortex XSIAM incident")
        self.assertEqual(finding["severity"], "Medium")
        self.assertIsNone(finding["asset"]["name"])


class CortexXsiamFetchAndNormalizeIncidents(unittest.TestCase):
    def test_returns_normalized_list(self):
        session = MagicMock()
        session.post.return_value = fake_response({"reply": {"incidents": [
            {"incident_id": "1", "incident_name": "a", "severity": "critical", "hosts": ["h1"]},
            {"incident_id": "2", "incident_name": "b", "severity": "low", "hosts": []},
        ]}})
        conn = CortexXsiamConnector("k", "1", base_url="https://x.example.com", session=session)
        findings = conn.fetch_and_normalize_incidents()
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertTrue(all(f["source"] == "cortex-xsiam" for f in findings))


if __name__ == "__main__":
    unittest.main()
