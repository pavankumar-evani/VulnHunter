"""
Tests for the live Tenable/Armis connectors (remediation/connectors/).

Every HTTP interaction is mocked - these tests never touch the network or require real
API credentials. They verify: correct auth header/flow construction, correct endpoint
URLs and pagination handling, correct mapping from each vendor's documented raw response
shape into the same file format the sample data already uses, and that error conditions
(bad response shape, ERROR/CANCELLED status, a runaway pagination loop) are handled
rather than crashing or looping forever.

These do NOT prove the connectors work against a real Tenable/Armis tenant - only that
they behave correctly against responses shaped like each vendor's public documentation.
See remediation/connectors/README.md.
"""
import csv
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.tenable_connector import (  # noqa: E402
    TenableConnector, TenableExportError, CSV_FIELDNAMES,
)
from remediation.connectors.armis_connector import (  # noqa: E402
    ArmisConnector, ArmisAuthError,
)


def fake_response(json_data, raise_error=False):
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


class TenableAuthAndExportRequest(unittest.TestCase):
    def test_session_gets_correct_apikeys_header(self):
        session = MagicMock()
        TenableConnector("access123", "secret456", session=session)
        header = session.headers.update.call_args[0][0]["X-ApiKeys"]
        self.assertEqual(header, "accessKey=access123;secretKey=secret456")

    def test_request_export_returns_uuid(self):
        session = MagicMock()
        session.post.return_value = fake_response({"export_uuid": "uuid-abc"})
        conn = TenableConnector("k", "s", session=session)
        self.assertEqual(conn.request_export(), "uuid-abc")

    def test_request_export_includes_since_filter_when_given(self):
        session = MagicMock()
        session.post.return_value = fake_response({"export_uuid": "uuid-abc"})
        conn = TenableConnector("k", "s", session=session)
        conn.request_export(since=1700000000)
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["filters"]["since"], 1700000000)

    def test_request_export_raises_on_unexpected_shape(self):
        session = MagicMock()
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = TenableConnector("k", "s", session=session)
        with self.assertRaises(TenableExportError):
            conn.request_export()


class TenableTestConnection(unittest.TestCase):
    def test_test_connection_hits_session_endpoint(self):
        session = MagicMock()
        session.get.return_value = fake_response({"username": "alice", "email": "alice@example.com"})
        conn = TenableConnector("k", "s", session=session)
        result = conn.test_connection()
        session.get.assert_called_once_with(f"{conn.base_url}/session", timeout=30)
        self.assertEqual(result, {"ok": True, "username": "alice", "email": "alice@example.com"})

    def test_test_connection_raises_on_http_error(self):
        session = MagicMock()
        session.get.return_value = fake_response(None, raise_error=True)
        conn = TenableConnector("k", "s", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class TenablePollAndDownload(unittest.TestCase):
    def test_poll_returns_chunks_when_finished(self):
        session = MagicMock()
        session.get.return_value = fake_response({"status": "FINISHED", "chunks_available": [1, 2]})
        conn = TenableConnector("k", "s", session=session)
        self.assertEqual(conn.poll_export_status("uuid", poll_interval_seconds=0), [1, 2])

    def test_poll_raises_on_error_status(self):
        session = MagicMock()
        session.get.return_value = fake_response({"status": "ERROR"})
        conn = TenableConnector("k", "s", session=session)
        with self.assertRaises(TenableExportError):
            conn.poll_export_status("uuid", poll_interval_seconds=0)

    def test_poll_raises_on_timeout(self):
        session = MagicMock()
        session.get.return_value = fake_response({"status": "PROCESSING"})
        conn = TenableConnector("k", "s", session=session)
        with self.assertRaises(TenableExportError):
            conn.poll_export_status("uuid", poll_interval_seconds=0, timeout_seconds=0)

    def test_download_chunk_returns_records(self):
        session = MagicMock()
        session.get.return_value = fake_response([{"plugin": {"id": 1}}])
        conn = TenableConnector("k", "s", session=session)
        self.assertEqual(conn.download_chunk("uuid", 1), [{"plugin": {"id": 1}}])


class TenableRecordMapping(unittest.TestCase):
    def test_to_csv_row_maps_documented_shape(self):
        record = {
            "plugin": {
                "id": 57608, "cve": ["CVE-2021-34527"], "risk_factor": "Critical",
                "cvss3_base_score": 8.8, "name": "PrintNightmare RCE",
                "synopsis": "Something bad", "solution": "Patch it",
            },
            "asset": {
                "hostname": "WIN-DC01", "ipv4": "10.20.30.41",
                "fqdn": "win-dc01.corp.local", "operating_system": ["Windows Server 2019"],
            },
            "port": {"port": 445, "protocol": "tcp"},
            "first_found": "2026-07-28T00:00:00Z",
            "last_found": "2026-08-02T00:00:00Z",
        }
        row = TenableConnector.to_csv_row(record)
        self.assertEqual(row["Plugin ID"], 57608)
        self.assertEqual(row["CVE"], "CVE-2021-34527")
        self.assertEqual(row["Risk"], "Critical")
        self.assertEqual(row["Host"], "WIN-DC01")
        self.assertEqual(row["IP Address"], "10.20.30.41")
        self.assertEqual(row["OS"], "Windows Server 2019")
        self.assertEqual(row["Port"], 445)
        self.assertEqual(row["Protocol"], "tcp")

    def test_to_csv_row_handles_missing_cve_gracefully(self):
        record = {"plugin": {"id": 1}, "asset": {}}
        row = TenableConnector.to_csv_row(record)
        self.assertEqual(row["CVE"], "")


class TenableWritesSampleCompatibleCsv(unittest.TestCase):
    def test_fetch_and_write_csv_matches_sample_schema(self):
        session = MagicMock()
        session.post.return_value = fake_response({"export_uuid": "uuid-x"})
        session.get.side_effect = [
            fake_response({"status": "FINISHED", "chunks_available": [1]}),
            fake_response([{
                "plugin": {"id": 1, "cve": ["CVE-2024-0001"], "risk_factor": "High",
                           "cvss3_base_score": 7.0, "name": "Test Finding",
                           "synopsis": "s", "solution": "sol"},
                "asset": {"hostname": "HOST1", "ipv4": "10.0.0.1", "fqdn": "", "operating_system": ["Linux"]},
                "port": {"port": 22, "protocol": "tcp"},
                "first_found": "2026-01-01", "last_found": "2026-01-02",
            }]),
        ]
        conn = TenableConnector("k", "s", session=session)

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "live_export.csv"
            conn.fetch_and_write_csv(out_path, poll_interval_seconds=0)

            with out_path.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                self.assertEqual(reader.fieldnames, CSV_FIELDNAMES)
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Host"], "HOST1")


class ArmisAuthentication(unittest.TestCase):
    def test_authenticate_sets_token_and_header(self):
        session = MagicMock()
        session.post.return_value = fake_response({"data": {"access_token": "tok-123"}})
        conn = ArmisConnector("secret", session=session)
        token = conn.authenticate()
        self.assertEqual(token, "tok-123")
        session.headers.update.assert_called_with({"Authorization": "tok-123"})

    def test_authenticate_raises_on_bad_shape(self):
        session = MagicMock()
        session.post.return_value = fake_response({"unexpected": "shape"})
        conn = ArmisConnector("secret", session=session)
        with self.assertRaises(ArmisAuthError):
            conn.authenticate()

    def test_search_triggers_authentication_if_needed(self):
        session = MagicMock()
        session.post.return_value = fake_response({"data": {"access_token": "tok-123"}})
        session.get.return_value = fake_response({"data": {"results": [], "next": None}})
        conn = ArmisConnector("secret", session=session)
        conn.search("in:alerts")
        session.post.assert_called_once()  # authenticated exactly once


class ArmisPagination(unittest.TestCase):
    def test_search_all_pages_follows_next_cursor(self):
        session = MagicMock()
        session.post.return_value = fake_response({"data": {"access_token": "tok"}})
        session.get.side_effect = [
            fake_response({"data": {"results": [{"id": 1}], "next": 100}}),
            fake_response({"data": {"results": [{"id": 2}], "next": None}}),
        ]
        conn = ArmisConnector("secret", session=session)
        results = conn.search_all_pages("in:alerts", page_size=1)
        self.assertEqual(results, [{"id": 1}, {"id": 2}])
        self.assertEqual(session.get.call_count, 2)

    def test_search_all_pages_respects_max_pages_safety_cap(self):
        """Regression guard: a misbehaving API that always returns a `next` cursor must
        not cause an infinite loop."""
        session = MagicMock()
        session.post.return_value = fake_response({"data": {"access_token": "tok"}})
        session.get.return_value = fake_response({"data": {"results": [{"id": 1}], "next": 999}})
        conn = ArmisConnector("secret", session=session)
        results = conn.search_all_pages("in:alerts", page_size=1, max_pages=3)
        self.assertEqual(len(results), 3)


class ArmisDeviceAndAlertAssembly(unittest.TestCase):
    def test_alert_to_sample_shape_mapping(self):
        alert = {"type": "Policy Violation", "title": "Open Telnet", "description": "d",
                  "cve": None, "firstSeen": "2026-07-10", "lastSeen": "2026-08-01"}
        mapped = ArmisConnector._alert_to_sample_shape(alert)
        self.assertEqual(mapped["alertType"], "Policy Violation")
        self.assertEqual(mapped["title"], "Open Telnet")
        self.assertIsNone(mapped["cve"])

    def test_fetch_and_write_json_assembles_devices_with_alerts(self):
        session = MagicMock()
        session.post.return_value = fake_response({"data": {"access_token": "tok"}})

        def get_side_effect(url, **kwargs):
            if "/search/" in url:
                return fake_response({"data": {
                    "results": [{"deviceId": 481203, "type": "Policy Violation",
                                 "title": "Open Telnet", "description": "d"}],
                    "next": None,
                }})
            if "/devices/481203/" in url:
                return fake_response({"data": {
                    "name": "AXIS-CAM-LOBBY-03", "type": "IP Camera",
                    "manufacturer": "Axis", "model": "M3046-V",
                    "ipAddress": "10.20.50.12", "macAddress": "AC:CC:8E:11:9F:02",
                    "site": "HQ-Floor1", "riskLevel": "High",
                }})
            raise AssertionError(f"unexpected URL: {url}")

        session.get.side_effect = get_side_effect
        conn = ArmisConnector("secret", session=session)

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "live_armis.json"
            conn.fetch_and_write_json(out_path)
            output = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(len(output["devices"]), 1)
        device = output["devices"][0]
        self.assertEqual(device["deviceName"], "AXIS-CAM-LOBBY-03")
        self.assertEqual(len(device["alerts"]), 1)
        self.assertEqual(device["alerts"][0]["title"], "Open Telnet")


if __name__ == "__main__":
    unittest.main()
