"""
Tests for the live Axonius cyber asset management connector
(remediation/connectors/axonius_connector.py).

Every HTTP interaction is mocked - these tests never touch the network or require real
API credentials. They verify: correct api-key/api-secret header construction, correct
/api/devices request body (pagination), correct mapping from Axonius's documented
(flattened-assumption) device shape into VulnHunter's shared asset-record shape
(including IP/MAC list-vs-scalar extraction and the os_type -> asset.type mapping), and
defensive handling of an empty/missing-field response so it doesn't crash.

These do NOT prove the connector works against a real Axonius tenant - only that it
behaves correctly against responses shaped like Axonius's public API documentation
(with the documented envelope-key and field-flattening caveats noted in the connector
module's docstring). See remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.axonius_connector import (  # noqa: E402
    AxoniusConnector, DEFAULT_PAGE_SIZE,
)


def fake_response(json_data, raise_error=False):
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


class AxoniusConstruction(unittest.TestCase):
    def test_session_gets_api_key_and_secret_headers(self):
        session = MagicMock()
        AxoniusConnector("https://axonius.example.com", "key123", "secret456", session=session)
        header = session.headers.update.call_args[0][0]
        self.assertEqual(header["api-key"], "key123")
        self.assertEqual(header["api-secret"], "secret456")

    def test_base_url_strips_trailing_slash(self):
        session = MagicMock()
        conn = AxoniusConnector("https://axonius.example.com/", "key", "secret", session=session)
        self.assertEqual(conn.base_url, "https://axonius.example.com")

    def test_session_gets_content_type_header(self):
        session = MagicMock()
        AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        header = session.headers.update.call_args[0][0]
        self.assertEqual(header["Content-Type"], "application/json")


class AxoniusFetchDevices(unittest.TestCase):
    def test_fetch_devices_hits_correct_url(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": []})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        conn.fetch_devices()
        url = session.post.call_args[0][0]
        self.assertEqual(url, "https://axonius.example.com/api/devices")

    def test_fetch_devices_sends_pagination_body(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": []})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        conn.fetch_devices(page_size=50, offset=100)
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body, {"page": {"offset": 100, "limit": 50}})

    def test_fetch_devices_defaults_offset_to_zero(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": []})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        conn.fetch_devices(page_size=DEFAULT_PAGE_SIZE)
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["page"]["offset"], 0)
        self.assertEqual(body["page"]["limit"], DEFAULT_PAGE_SIZE)

    def test_fetch_devices_returns_raw_json(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": [{"hostname": "h1"}]})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        result = conn.fetch_devices()
        self.assertEqual(result, {"assets": [{"hostname": "h1"}]})

    def test_fetch_devices_raises_on_http_error(self):
        session = MagicMock()
        session.post.return_value = fake_response(None, raise_error=True)
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        with self.assertRaises(Exception):
            conn.fetch_devices()


class AxoniusTestConnection(unittest.TestCase):
    def test_test_connection_fetches_a_single_device(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": [{"hostname": "h1"}]})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        result = conn.test_connection()
        body = session.post.call_args.kwargs["json"]
        self.assertEqual(body["page"], {"offset": 0, "limit": 1})
        self.assertEqual(result, {"ok": True})

    def test_test_connection_raises_on_http_error(self):
        session = MagicMock()
        session.post.return_value = fake_response(None, raise_error=True)
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class AxoniusNormalizeDevice(unittest.TestCase):
    def test_normalize_maps_documented_flattened_shape(self):
        device = {
            "internal_axon_id": "abc123",
            "hostname": "WIN-APP01",
            "ip": "10.5.5.5",
            "mac": "AA:BB:CC:DD:EE:FF",
            "os_type": "Windows",
            "adapters": ["active_directory_adapter", "aws_adapter"],
        }
        asset = AxoniusConnector.normalize_device(device)
        self.assertEqual(asset["name"], "WIN-APP01")
        self.assertEqual(asset["ip"], "10.5.5.5")
        self.assertEqual(asset["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(asset["type"], "windows-server")
        self.assertEqual(asset["source"], "axonius")
        self.assertEqual(asset["source_ref"], "abc123")
        self.assertEqual(asset["extra"]["adapters"], ["active_directory_adapter", "aws_adapter"])

    def test_normalize_falls_back_to_ips_and_macs_lists(self):
        """When scalar `ip`/`mac` keys aren't present, fall back to the first entry
        of the `ips`/`macs` list variants."""
        device = {"hostname": "host1", "ips": ["192.168.1.1", "192.168.1.2"],
                  "macs": ["11:22:33:44:55:66"]}
        asset = AxoniusConnector.normalize_device(device)
        self.assertEqual(asset["ip"], "192.168.1.1")
        self.assertEqual(asset["mac"], "11:22:33:44:55:66")

    def test_normalize_maps_linux_os_type(self):
        device = {"hostname": "linuxbox", "os_type": "Linux"}
        asset = AxoniusConnector.normalize_device(device)
        self.assertEqual(asset["type"], "unix-server")

    def test_normalize_defaults_missing_or_unrecognized_os_type_to_unknown(self):
        for device in ({"hostname": "iot1", "os_type": "SomeEmbeddedThing"}, {"hostname": "no-os-info"}):
            with self.subTest(device=device):
                asset = AxoniusConnector.normalize_device(device)
                self.assertEqual(asset["type"], "unknown")

    def test_normalize_handles_no_ips_or_macs_gracefully(self):
        device = {"hostname": "bare-device", "ips": [], "macs": []}
        asset = AxoniusConnector.normalize_device(device)
        self.assertIsNone(asset["ip"])
        self.assertIsNone(asset["mac"])

    def test_normalize_handles_missing_adapters_gracefully(self):
        device = {"hostname": "no-adapters"}
        asset = AxoniusConnector.normalize_device(device)
        self.assertEqual(asset["extra"]["adapters"], [])


class AxoniusFetchAndNormalizeDevices(unittest.TestCase):
    def test_fetch_and_normalize_devices_returns_normalized_list(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": [
            {"internal_axon_id": "id1", "hostname": "host1", "ip": "10.0.0.1", "os_type": "Linux"},
            {"internal_axon_id": "id2", "hostname": "host2"},
        ]})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        assets = conn.fetch_and_normalize_devices()
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]["type"], "unix-server")
        self.assertEqual(assets[1]["type"], "unknown")
        self.assertTrue(all(a["source"] == "axonius" for a in assets))

    def test_fetch_and_normalize_devices_handles_empty_response(self):
        session = MagicMock()
        session.post.return_value = fake_response({"assets": []})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        assets = conn.fetch_and_normalize_devices()
        self.assertEqual(assets, [])

    def test_fetch_and_normalize_devices_handles_missing_assets_key(self):
        session = MagicMock()
        session.post.return_value = fake_response({})
        conn = AxoniusConnector("https://axonius.example.com", "key", "secret", session=session)
        assets = conn.fetch_and_normalize_devices()
        self.assertEqual(assets, [])


if __name__ == "__main__":
    unittest.main()
