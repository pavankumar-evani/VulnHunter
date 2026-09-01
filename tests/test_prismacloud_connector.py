"""
Tests for the live Prisma Cloud connector (remediation/connectors/prismacloud_connector.py).

Every HTTP interaction is mocked - these tests never touch the network or require real
API credentials. They verify: the login/token-exchange flow and x-redlock-auth header
construction, the alert-search request shape, severity mapping, and correct normalization
into VulnHunter's Finding schema (including the deliberate cve/cvss/kev/epss=None and
id=None properties - see the module docstring).

These do NOT prove the connector works against a real Prisma Cloud tenant - only that it
behaves correctly against responses shaped like Prisma Cloud's public API documentation.
See remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.prismacloud_connector import (  # noqa: E402
    PrismaCloudAuthError, PrismaCloudConnector,
)


def fake_response(json_data, raise_error=False):
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


class PrismaCloudConstruction(unittest.TestCase):
    def test_requires_base_url(self):
        with self.assertRaises(ValueError):
            PrismaCloudConnector("access-key", "secret", base_url=None)

    def test_base_url_strips_trailing_slash(self):
        session = MagicMock()
        conn = PrismaCloudConnector("k", "s", base_url="https://api2.prismacloud.io/", session=session)
        self.assertEqual(conn.base_url, "https://api2.prismacloud.io")


class PrismaCloudAuthentication(unittest.TestCase):
    def test_authenticate_sets_token_and_header(self):
        session = MagicMock()
        session.post.return_value = fake_response({"token": "tok-abc", "customerNames": ["acme"]})
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        token = conn.authenticate()
        self.assertEqual(token, "tok-abc")
        self.assertEqual(session.headers.__setitem__.call_args, unittest.mock.call("x-redlock-auth", "tok-abc"))

    def test_authenticate_sends_username_password_body(self):
        session = MagicMock()
        session.post.return_value = fake_response({"token": "tok-abc"})
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        conn.authenticate()
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body, {"username": "access-key", "password": "secret"})

    def test_authenticate_raises_on_bad_shape(self):
        session = MagicMock()
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        with self.assertRaises(PrismaCloudAuthError):
            conn.authenticate()

    def test_fetch_alerts_triggers_authentication_if_needed(self):
        session = MagicMock()
        session.post.side_effect = [
            fake_response({"token": "tok-abc"}),
            fake_response({"items": [], "totalRows": 0}),
        ]
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        conn.fetch_alerts()
        self.assertEqual(session.post.call_count, 2)


class PrismaCloudTestConnection(unittest.TestCase):
    def test_test_connection_calls_authenticate(self):
        session = MagicMock()
        session.post.return_value = fake_response({"token": "tok-abc"})
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        result = conn.test_connection()
        self.assertEqual(result, {"ok": True})

    def test_test_connection_raises_on_bad_credentials(self):
        session = MagicMock()
        session.post.return_value = fake_response(None, raise_error=True)
        conn = PrismaCloudConnector("access-key", "secret", base_url="https://api.prismacloud.io", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class PrismaCloudFetchAlerts(unittest.TestCase):
    def test_fetch_alerts_hits_correct_url_and_status_filter(self):
        session = MagicMock()
        session.post.side_effect = [
            fake_response({"token": "tok-abc"}),
            fake_response({"items": [], "totalRows": 0}),
        ]
        conn = PrismaCloudConnector("k", "s", base_url="https://api.prismacloud.io", session=session)
        conn.fetch_alerts(status="open")
        url = session.post.call_args[0][0]
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(url, "https://api.prismacloud.io/v2/alert")
        self.assertEqual(body["filters"], [{"name": "alert.status", "value": "open", "operator": "="}])


class PrismaCloudNormalizeAlert(unittest.TestCase):
    def _sample_alert(self, **overrides):
        alert = {
            "id": "alert-1",
            "firstSeen": 1700000000000,
            "lastSeen": 1700100000000,
            "reason": "Resource matched policy",
            "policy": {
                "name": "S3 bucket is publicly readable",
                "severity": "high",
                "description": "An S3 bucket allows public read access.",
                "policyType": "config",
            },
            "resource": {
                "id": "arn:aws:s3:::example-bucket",
                "name": "example-bucket",
                "cloudType": "aws",
                "region": "us-east-1",
                "account": "123456789012",
            },
        }
        alert.update(overrides)
        return alert

    def test_normalize_maps_documented_shape(self):
        finding = PrismaCloudConnector.normalize_alert(self._sample_alert())
        self.assertIsNone(finding["id"])
        self.assertEqual(finding["source"], "prismacloud")
        self.assertEqual(finding["source_ref"], "alert-1")
        self.assertEqual(finding["asset"]["name"], "example-bucket")
        self.assertEqual(finding["asset"]["type"], "cloud-infrastructure")
        self.assertIsNone(finding["asset"]["ip"])
        self.assertEqual(finding["title"], "S3 bucket is publicly readable")
        self.assertEqual(finding["severity"], "High")

    def test_cve_cvss_kev_epss_always_none(self):
        finding = PrismaCloudConnector.normalize_alert(self._sample_alert())
        self.assertIsNone(finding["cve"])
        self.assertIsNone(finding["cvss"])
        self.assertIsNone(finding["kev"])
        self.assertIsNone(finding["epss"])

    def test_severity_defaults_to_medium_when_missing(self):
        alert = self._sample_alert(policy={"name": "x"})
        finding = PrismaCloudConnector.normalize_alert(alert)
        self.assertEqual(finding["severity"], "Medium")

    def test_falls_back_to_resource_id_when_name_missing(self):
        alert = self._sample_alert(resource={"id": "arn:aws:s3:::fallback-bucket"})
        finding = PrismaCloudConnector.normalize_alert(alert)
        self.assertEqual(finding["asset"]["name"], "arn:aws:s3:::fallback-bucket")

    def test_handles_missing_policy_and_resource_gracefully(self):
        finding = PrismaCloudConnector.normalize_alert({"id": "alert-2"})
        self.assertEqual(finding["title"], "Prisma Cloud alert")
        self.assertIsNone(finding["asset"]["name"])
        self.assertEqual(finding["severity"], "Medium")


class PrismaCloudFetchAndNormalizeAlerts(unittest.TestCase):
    def test_returns_normalized_list(self):
        session = MagicMock()
        session.post.side_effect = [
            fake_response({"token": "tok-abc"}),
            fake_response({"items": [
                {"id": "a1", "policy": {"name": "p1", "severity": "critical"}, "resource": {"name": "r1"}},
                {"id": "a2", "policy": {"name": "p2", "severity": "low"}, "resource": {"name": "r2"}},
            ], "totalRows": 2}),
        ]
        conn = PrismaCloudConnector("k", "s", base_url="https://api.prismacloud.io", session=session)
        findings = conn.fetch_and_normalize_alerts()
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertTrue(all(f["source"] == "prismacloud" for f in findings))

    def test_handles_empty_items(self):
        session = MagicMock()
        session.post.side_effect = [
            fake_response({"token": "tok-abc"}),
            fake_response({"items": [], "totalRows": 0}),
        ]
        conn = PrismaCloudConnector("k", "s", base_url="https://api.prismacloud.io", session=session)
        findings = conn.fetch_and_normalize_alerts()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
