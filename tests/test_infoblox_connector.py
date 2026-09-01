"""
Tests for the live Infoblox NIOS WAPI connector (remediation/connectors/infoblox_connector.py).

Every HTTP interaction is mocked - these tests never touch the network or require real
API credentials. They verify: correct Basic-auth session construction, correct WAPI
endpoint URL/params construction, correct mapping from Infoblox's documented
record:host response shape into VulnHunter's shared asset-record shape (including IP
extraction and the honest "mac/type unknown" handling), and defensive handling of an
empty/missing-field response so it doesn't crash.

These do NOT prove the connector works against a real Infoblox grid/appliance - only
that it behaves correctly against responses shaped like Infoblox's public WAPI
documentation. See remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.infoblox_connector import (  # noqa: E402
    InfobloxConnector, DEFAULT_API_VERSION, RETURN_FIELDS,
)


def fake_response(json_data, raise_error=False):
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


class InfobloxConstruction(unittest.TestCase):
    def test_session_gets_basic_auth(self):
        session = MagicMock()
        InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        self.assertEqual(session.auth, ("admin", "pw"))

    def test_base_url_uses_default_api_version(self):
        session = MagicMock()
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        self.assertEqual(conn.base_url, f"https://gm.example.com/wapi/{DEFAULT_API_VERSION}")

    def test_base_url_honors_custom_api_version(self):
        session = MagicMock()
        conn = InfobloxConnector("gm.example.com", "admin", "pw", api_version="v2.5", session=session)
        self.assertEqual(conn.base_url, "https://gm.example.com/wapi/v2.5")

    def test_session_gets_accept_header(self):
        session = MagicMock()
        InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        header = session.headers.update.call_args[0][0]
        self.assertEqual(header["Accept"], "application/json")


class InfobloxFetchHostRecords(unittest.TestCase):
    def test_fetch_host_records_hits_correct_url(self):
        session = MagicMock()
        session.get.return_value = fake_response([])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        conn.fetch_host_records()
        url = session.get.call_args[0][0]
        self.assertEqual(url, f"{conn.base_url}/record:host")

    def test_fetch_host_records_sends_return_fields_and_max_results(self):
        session = MagicMock()
        session.get.return_value = fake_response([])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        conn.fetch_host_records(max_results=250)
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["_return_fields"], RETURN_FIELDS)
        self.assertEqual(params["_max_results"], 250)

    def test_fetch_host_records_defaults_max_results_to_1000(self):
        session = MagicMock()
        session.get.return_value = fake_response([])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        conn.fetch_host_records()
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["_max_results"], 1000)

    def test_fetch_host_records_returns_raw_json_array(self):
        session = MagicMock()
        session.get.return_value = fake_response([{"name": "host1"}, {"name": "host2"}])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        records = conn.fetch_host_records()
        self.assertEqual(records, [{"name": "host1"}, {"name": "host2"}])

    def test_fetch_host_records_raises_on_http_error(self):
        session = MagicMock()
        session.get.return_value = fake_response(None, raise_error=True)
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        with self.assertRaises(Exception):
            conn.fetch_host_records()


class InfobloxTestConnection(unittest.TestCase):
    def test_test_connection_fetches_a_single_host_record(self):
        session = MagicMock()
        session.get.return_value = fake_response([{"name": "host1"}])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        result = conn.test_connection()
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["_max_results"], 1)
        self.assertEqual(result, {"ok": True})

    def test_test_connection_raises_on_http_error(self):
        session = MagicMock()
        session.get.return_value = fake_response(None, raise_error=True)
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class InfobloxNormalizeHostRecord(unittest.TestCase):
    def test_normalize_maps_documented_shape(self):
        record = {
            "_ref": "record:host/ZG5zLmhvc3QkLl9kZWZhdWx0:winhost01/default",
            "name": "winhost01.corp.local",
            "ipv4addrs": [{"ipv4addr": "10.1.2.3"}],
            "view": "default",
            "extattrs": {"Owner": {"value": "IT"}},
        }
        asset = InfobloxConnector.normalize_host_record(record)
        self.assertEqual(asset["name"], "winhost01.corp.local")
        self.assertEqual(asset["ip"], "10.1.2.3")
        self.assertIsNone(asset["mac"])
        self.assertEqual(asset["type"], "unknown")
        self.assertEqual(asset["source"], "infoblox")
        self.assertEqual(asset["source_ref"], record["_ref"])
        self.assertEqual(asset["extra"]["view"], "default")
        self.assertEqual(asset["extra"]["extattrs"], {"Owner": {"value": "IT"}})

    def test_normalize_takes_first_ip_when_multiple_present(self):
        record = {
            "name": "multi-ip-host",
            "ipv4addrs": [{"ipv4addr": "10.0.0.1"}, {"ipv4addr": "10.0.0.2"}],
        }
        asset = InfobloxConnector.normalize_host_record(record)
        self.assertEqual(asset["ip"], "10.0.0.1")

    def test_normalize_handles_no_ips_gracefully(self):
        """Covers both an explicit empty ipv4addrs list and a record missing the key
        entirely - neither should crash, both should yield ip=None."""
        for record in ({"name": "no-ip-host", "ipv4addrs": []}, {"name": "sparse-host"}):
            with self.subTest(record=record):
                asset = InfobloxConnector.normalize_host_record(record)
                self.assertIsNone(asset["ip"])
                self.assertEqual(asset["extra"]["extattrs"], {})

    def test_normalize_handles_missing_name(self):
        record = {"ipv4addrs": [{"ipv4addr": "10.0.0.9"}]}
        asset = InfobloxConnector.normalize_host_record(record)
        self.assertIsNone(asset["name"])
        self.assertEqual(asset["ip"], "10.0.0.9")


class InfobloxFetchAndNormalizeHosts(unittest.TestCase):
    def test_fetch_and_normalize_hosts_returns_normalized_list(self):
        session = MagicMock()
        session.get.return_value = fake_response([
            {"_ref": "ref1", "name": "host1", "ipv4addrs": [{"ipv4addr": "10.0.0.1"}], "view": "default"},
            {"_ref": "ref2", "name": "host2", "ipv4addrs": [], "view": "default"},
        ])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        assets = conn.fetch_and_normalize_hosts()
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]["name"], "host1")
        self.assertEqual(assets[0]["ip"], "10.0.0.1")
        self.assertIsNone(assets[1]["ip"])
        self.assertTrue(all(a["source"] == "infoblox" for a in assets))

    def test_fetch_and_normalize_hosts_passes_through_max_results(self):
        session = MagicMock()
        session.get.return_value = fake_response([])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        conn.fetch_and_normalize_hosts(max_results=42)
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["_max_results"], 42)

    def test_fetch_and_normalize_hosts_handles_empty_response(self):
        session = MagicMock()
        session.get.return_value = fake_response([])
        conn = InfobloxConnector("gm.example.com", "admin", "pw", session=session)
        assets = conn.fetch_and_normalize_hosts()
        self.assertEqual(assets, [])


if __name__ == "__main__":
    unittest.main()
