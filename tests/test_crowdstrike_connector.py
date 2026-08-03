"""
Tests for remediation/connectors/crowdstrike_connector.py. All HTTP mocked - no real
CrowdStrike Falcon tenant touched, no credentials needed. See
remediation/connectors/README.md for what this suite does and doesn't prove.
"""
import datetime
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.crowdstrike_connector import (  # noqa: E402
    CrowdStrikeAuthError, CrowdStrikeConnector,
)


def fake_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


SAMPLE_ALERT = {
    "composite_id": "abcd1234:ind:5678",
    "name": "Suspicious PowerShell encoded command",
    "description": "A process executed a base64-encoded PowerShell command.",
    "severity": 95,
    "severity_name": "Critical",
    "first_behavior": "2026-07-28T10:00:00Z",
    "last_behavior": "2026-08-02T14:30:00Z",
    "device": {
        "hostname": "WIN-DC01",
        "local_ip": "10.20.30.41",
        "platform_name": "Windows",
        "os_version": "Windows Server 2019",
    },
}


class AuthFlow(unittest.TestCase):
    def _connector(self):
        session = MagicMock()
        session.headers = {}
        return CrowdStrikeConnector("client-id-1", "client-secret-1", session=session), session

    def test_authenticate_posts_client_credentials(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"access_token": "tok-abc", "expires_in": 1799})

        conn.authenticate()
        called_url = session.post.call_args.args[0]
        sent_data = session.post.call_args.kwargs["data"]
        self.assertEqual(called_url, "https://api.crowdstrike.com/oauth2/token")
        self.assertEqual(sent_data, {"client_id": "client-id-1", "client_secret": "client-secret-1"})

    def test_authenticate_sets_bearer_token_header(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"access_token": "tok-abc", "expires_in": 1799})

        conn.authenticate()
        self.assertEqual(session.headers["Authorization"], "Bearer tok-abc")
        self.assertEqual(conn._access_token, "tok-abc")

    def test_authenticate_raises_on_unexpected_response_shape(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"unexpected": "shape"})

        with self.assertRaises(CrowdStrikeAuthError):
            conn.authenticate()

    def test_ensure_authenticated_triggers_auth_on_first_use(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"access_token": "tok-abc", "expires_in": 1799})
        session.get.return_value = fake_response({"resources": []})

        self.assertIsNone(conn._access_token)
        conn.fetch_alert_ids()
        self.assertEqual(conn._access_token, "tok-abc")

    def test_ensure_authenticated_only_authenticates_once(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"access_token": "tok-abc", "expires_in": 1799})
        session.get.return_value = fake_response({"resources": []})

        conn.fetch_alert_ids()
        conn.fetch_alert_ids()
        self.assertEqual(session.post.call_count, 1)  # only the one auth call, not two


class FetchAlertIds(unittest.TestCase):
    def _authed_connector(self):
        session = MagicMock()
        session.headers = {}
        conn = CrowdStrikeConnector("cid", "secret", session=session)
        session.post.return_value = fake_response({"access_token": "tok", "expires_in": 1799})
        return conn, session

    def test_returns_resources_array(self):
        conn, session = self._authed_connector()
        session.get.return_value = fake_response({"resources": ["id1", "id2"]})

        ids = conn.fetch_alert_ids()
        self.assertEqual(ids, ["id1", "id2"])

    def test_passes_filter_query_param_when_given(self):
        conn, session = self._authed_connector()
        session.get.return_value = fake_response({"resources": []})

        conn.fetch_alert_ids(filter_query="status:'new'")
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["filter"], "status:'new'")

    def test_omits_filter_param_when_none(self):
        conn, session = self._authed_connector()
        session.get.return_value = fake_response({"resources": []})

        conn.fetch_alert_ids()
        params = session.get.call_args.kwargs["params"]
        self.assertNotIn("filter", params)

    def test_passes_limit_query_param(self):
        conn, session = self._authed_connector()
        session.get.return_value = fake_response({"resources": []})

        conn.fetch_alert_ids(limit=50)
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 50)


class FetchAlertDetails(unittest.TestCase):
    def test_posts_composite_ids_and_returns_resources(self):
        session = MagicMock()
        session.headers = {}
        conn = CrowdStrikeConnector("cid", "secret", session=session)
        session.post.return_value = fake_response({"access_token": "tok", "expires_in": 1799})

        session.post.return_value = fake_response({"resources": [SAMPLE_ALERT]})
        # authenticate first so the mocked POST above is for fetch_alert_details, not auth
        conn._access_token = "tok"
        session.headers["Authorization"] = "Bearer tok"

        alerts = conn.fetch_alert_details(["abcd1234:ind:5678"])
        self.assertEqual(alerts, [SAMPLE_ALERT])
        called_url = session.post.call_args.args[0]
        sent_body = session.post.call_args.kwargs["json"]
        self.assertEqual(called_url, "https://api.crowdstrike.com/alerts/entities/alerts/v2")
        self.assertEqual(sent_body, {"composite_ids": ["abcd1234:ind:5678"]})


class NormalizeAlert(unittest.TestCase):
    def setUp(self):
        session = MagicMock()
        session.headers = {}
        self.conn = CrowdStrikeConnector("cid", "secret", session=session)

    def test_maps_basic_identity_and_asset_fields(self):
        finding = self.conn.normalize_alert(SAMPLE_ALERT)
        self.assertEqual(finding["source"], "crowdstrike")
        self.assertEqual(finding["source_ref"], "abcd1234:ind:5678")
        self.assertEqual(finding["title"], "Suspicious PowerShell encoded command")
        self.assertEqual(finding["asset"]["name"], "WIN-DC01")
        self.assertEqual(finding["asset"]["ip"], "10.20.30.41")

    def test_windows_platform_maps_to_windows_endpoint(self):
        finding = self.conn.normalize_alert(SAMPLE_ALERT)
        self.assertEqual(finding["asset"]["type"], "windows-endpoint")

    def test_non_windows_platform_maps_to_unix_server(self):
        alert = {**SAMPLE_ALERT, "device": {**SAMPLE_ALERT["device"], "platform_name": "Linux"}}
        finding = self.conn.normalize_alert(alert)
        self.assertEqual(finding["asset"]["type"], "unix-server")

    def test_cve_cvss_kev_epss_are_always_none(self):
        finding = self.conn.normalize_alert(SAMPLE_ALERT)
        self.assertIsNone(finding["cve"])
        self.assertIsNone(finding["cvss"])
        self.assertIsNone(finding["kev"])
        self.assertIsNone(finding["epss"])

    def test_severity_name_used_when_it_matches_a_known_tier(self):
        alert = {**SAMPLE_ALERT, "severity": 10, "severity_name": "High"}
        finding = self.conn.normalize_alert(alert)
        self.assertEqual(finding["severity"], "High")

    def test_severity_numeric_threshold_critical(self):
        alert = {**SAMPLE_ALERT, "severity_name": None, "severity": 95}
        self.assertEqual(self.conn.normalize_alert(alert)["severity"], "Critical")

    def test_severity_numeric_threshold_high(self):
        alert = {**SAMPLE_ALERT, "severity_name": None, "severity": 75}
        self.assertEqual(self.conn.normalize_alert(alert)["severity"], "High")

    def test_severity_numeric_threshold_medium(self):
        alert = {**SAMPLE_ALERT, "severity_name": None, "severity": 50}
        self.assertEqual(self.conn.normalize_alert(alert)["severity"], "Medium")

    def test_severity_numeric_threshold_low(self):
        alert = {**SAMPLE_ALERT, "severity_name": None, "severity": 10}
        self.assertEqual(self.conn.normalize_alert(alert)["severity"], "Low")

    def test_severity_defaults_to_low_when_no_severity_info_at_all(self):
        alert = {k: v for k, v in SAMPLE_ALERT.items() if k not in ("severity", "severity_name")}
        self.assertEqual(self.conn.normalize_alert(alert)["severity"], "Low")

    def test_uses_first_and_last_behavior_when_present(self):
        finding = self.conn.normalize_alert(SAMPLE_ALERT)
        self.assertEqual(finding["first_seen"], "2026-07-28T10:00:00Z")
        self.assertEqual(finding["last_seen"], "2026-08-02T14:30:00Z")

    def test_defaults_dates_to_today_when_behavior_fields_missing(self):
        alert = {k: v for k, v in SAMPLE_ALERT.items() if k not in ("first_behavior", "last_behavior")}
        finding = self.conn.normalize_alert(alert)
        today = datetime.date.today().isoformat()
        self.assertEqual(finding["first_seen"], today)
        self.assertEqual(finding["last_seen"], today)


class FetchAndNormalizeAlerts(unittest.TestCase):
    def test_chains_ids_details_and_normalize(self):
        session = MagicMock()
        session.headers = {}
        conn = CrowdStrikeConnector("cid", "secret", session=session)

        session.post.side_effect = [
            fake_response({"access_token": "tok", "expires_in": 1799}),
            fake_response({"resources": [SAMPLE_ALERT]}),
        ]
        session.get.return_value = fake_response({"resources": ["abcd1234:ind:5678"]})

        findings = conn.fetch_and_normalize_alerts()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_ref"], "abcd1234:ind:5678")
        self.assertEqual(findings[0]["source"], "crowdstrike")

    def test_returns_empty_list_when_no_alert_ids_found(self):
        session = MagicMock()
        session.headers = {}
        conn = CrowdStrikeConnector("cid", "secret", session=session)

        session.post.return_value = fake_response({"access_token": "tok", "expires_in": 1799})
        session.get.return_value = fake_response({"resources": []})

        findings = conn.fetch_and_normalize_alerts()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
