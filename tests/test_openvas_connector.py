"""
Tests for the live OpenVAS/Greenbone (GVM) scan-engine connector
(remediation/connectors/openvas_connector.py).

Every test injects a fake GMP client double (the same convention
tests/test_active_directory_connector.py already established for this repo's other
stateful-protocol connector) - none of these tests ever open a real socket or require a
real GVM instance. They verify: connection ownership semantics, the test-connection
call shape, target/task creation and scan startup, task-status polling (Done/Stopped/
timeout), GMP <result> XML -> Tenable-shaped CSV row mapping (with and without a CVE),
and the end-to-end CSV write.

These do NOT prove the connector works against a real GVM server - only that it behaves
correctly against XML shaped like GMP's public protocol documentation. See
remediation/connectors/README.md.
"""
import csv
import sys
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.openvas_connector import (  # noqa: E402
    OpenVasConnector, OpenVasScanError, _severity_band, _extract_cves, _parse_nvt_tags,
)


def _result_element(*, name="Sample NVT", host_ip="10.0.0.5", hostname="host5.corp.local",
                     port="445/tcp", oid="1.3.6.1.4.1.25623.1.0.100000", cve="CVE-2021-34527",
                     cvss_base="8.8", severity="8.8", tags="summary=Test summary|solution=Apply the vendor patch|solution_type=VendorFix",
                     description="Full description of the issue.",
                     creation_time="2026-08-01T00:00:00Z", modification_time="2026-08-02T00:00:00Z"):
    """Builds one <result> element programmatically (not via string parsing) so the
    <host> element's mixed content (IP text + nested <hostname>) is unambiguous."""
    result = Element("result", {"id": "r1"})
    if creation_time:
        result.set("creation_time", creation_time)
    if modification_time:
        result.set("modification_time", modification_time)
    ET.SubElement(result, "name").text = name
    host = SubElement(result, "host")
    host.text = host_ip
    if hostname:
        SubElement(host, "hostname").text = hostname
    SubElement(result, "port").text = port
    SubElement(result, "severity").text = severity
    SubElement(result, "description").text = description
    nvt = SubElement(result, "nvt", {"oid": oid})
    if cve:
        SubElement(nvt, "cve").text = cve
    SubElement(nvt, "cvss_base").text = cvss_base
    SubElement(nvt, "tags").text = tags
    return result


class FakeGmp:
    """A minimal stand-in for python-gvm's authenticated Gmp client - records calls
    and returns pre-configured canned XML elements."""

    def __init__(self, version="22.4", task_status="Done", task_progress="100",
                 results=None):
        self._version = version
        self._task_status = task_status
        self._task_progress = task_progress
        self._results = results if results is not None else [_result_element()]
        self.connected = False
        self.disconnected = False
        self.authenticated_with = None
        self.created_targets = []
        self.created_tasks = []
        self.started_tasks = []

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.disconnected = True

    def authenticate(self, username, password):
        self.authenticated_with = (username, password)

    def get_version(self):
        return ET.fromstring(f"<get_version_response status='200'><version>{self._version}</version></get_version_response>")

    def create_target(self, name, hosts):
        self.created_targets.append({"name": name, "hosts": hosts})
        return ET.fromstring("<create_target_response id='target-123' status='201'/>")

    def create_task(self, name, config_id, target_id, scanner_id):
        self.created_tasks.append({
            "name": name, "config_id": config_id, "target_id": target_id, "scanner_id": scanner_id,
        })
        return ET.fromstring("<create_task_response id='task-456' status='201'/>")

    def start_task(self, task_id):
        self.started_tasks.append(task_id)
        return ET.fromstring("<start_task_response status='202'/>")

    def get_task(self, task_id):
        root = Element("get_tasks_response")
        task = SubElement(root, "task", {"id": task_id})
        SubElement(task, "status").text = self._task_status
        SubElement(task, "progress").text = self._task_progress
        return root

    def get_results(self, task_id, details=True):
        root = Element("get_results_response")
        for result in self._results:
            root.append(result)
        return root


class OpenVasConnectionOwnership(unittest.TestCase):
    def test_injected_client_is_not_connected_or_disconnected(self):
        gmp = FakeGmp()
        conn = OpenVasConnector(gmp_client=gmp)
        conn.test_connection()
        self.assertFalse(gmp.connected)
        self.assertFalse(gmp.disconnected)
        self.assertIsNone(gmp.authenticated_with)

    def test_own_connection_is_disconnected_after_use(self):
        import unittest.mock as mock
        gmp = FakeGmp()
        conn = OpenVasConnector(hostname="gvm.example.com", username="admin", password="secret")
        with mock.patch.object(conn, "_connect", return_value=(gmp, True)):
            conn.test_connection()
        self.assertTrue(gmp.disconnected)


class OpenVasTestConnection(unittest.TestCase):
    def test_returns_ok_and_version(self):
        gmp = FakeGmp(version="22.4.1")
        conn = OpenVasConnector(gmp_client=gmp)
        result = conn.test_connection()
        self.assertEqual(result, {"ok": True, "gmp_version": "22.4.1"})


class OpenVasCreateAndStartScan(unittest.TestCase):
    def test_creates_target_task_and_starts_it(self):
        gmp = FakeGmp()
        conn = OpenVasConnector(gmp_client=gmp, scan_config_id="cfg-1", scanner_id="scanner-1")
        task_id = conn.create_and_start_scan("Corp LAN", ["10.20.30.0/24"])
        self.assertEqual(task_id, "task-456")
        self.assertEqual(gmp.created_targets, [{"name": "Corp LAN", "hosts": ["10.20.30.0/24"]}])
        self.assertEqual(gmp.created_tasks[0]["config_id"], "cfg-1")
        self.assertEqual(gmp.created_tasks[0]["scanner_id"], "scanner-1")
        self.assertEqual(gmp.created_tasks[0]["target_id"], "target-123")
        self.assertEqual(gmp.started_tasks, ["task-456"])

    def test_default_task_name_mentions_target(self):
        gmp = FakeGmp()
        conn = OpenVasConnector(gmp_client=gmp)
        conn.create_and_start_scan("Corp LAN", ["10.20.30.0/24"])
        self.assertIn("Corp LAN", gmp.created_tasks[0]["name"])


class OpenVasTaskStatus(unittest.TestCase):
    def test_get_task_status_parses_status_and_progress(self):
        gmp = FakeGmp(task_status="Running", task_progress="42")
        conn = OpenVasConnector(gmp_client=gmp)
        status = conn.get_task_status("task-456")
        self.assertEqual(status, {"status": "Running", "progress": 42})

    def test_wait_for_task_returns_when_done(self):
        gmp = FakeGmp(task_status="Done", task_progress="100")
        conn = OpenVasConnector(gmp_client=gmp)
        status = conn.wait_for_task("task-456", poll_interval_seconds=0, timeout_seconds=5)
        self.assertEqual(status["status"], "Done")

    def test_wait_for_task_raises_on_stopped(self):
        gmp = FakeGmp(task_status="Stopped")
        conn = OpenVasConnector(gmp_client=gmp)
        with self.assertRaises(OpenVasScanError):
            conn.wait_for_task("task-456", poll_interval_seconds=0, timeout_seconds=5)

    def test_wait_for_task_raises_on_timeout(self):
        gmp = FakeGmp(task_status="Running")
        conn = OpenVasConnector(gmp_client=gmp)
        with self.assertRaises(OpenVasScanError):
            conn.wait_for_task("task-456", poll_interval_seconds=0, timeout_seconds=0)


class OpenVasSeverityBand(unittest.TestCase):
    def test_bands_match_project_cvss_thresholds(self):
        self.assertEqual(_severity_band(9.8), "Critical")
        self.assertEqual(_severity_band(7.5), "High")
        self.assertEqual(_severity_band(5.0), "Medium")
        self.assertEqual(_severity_band(2.0), "Low")

    def test_invalid_score_returns_empty(self):
        self.assertEqual(_severity_band(None), "")
        self.assertEqual(_severity_band("n/a"), "")


class OpenVasExtractCves(unittest.TestCase):
    def test_direct_cve_child(self):
        nvt = Element("nvt")
        SubElement(nvt, "cve").text = "CVE-2021-34527"
        self.assertEqual(_extract_cves(nvt), ["CVE-2021-34527"])

    def test_nocve_placeholder_yields_empty(self):
        nvt = Element("nvt")
        SubElement(nvt, "cve").text = "NOCVE"
        self.assertEqual(_extract_cves(nvt), [])

    def test_refs_shape_fallback(self):
        nvt = Element("nvt")
        refs = SubElement(nvt, "refs")
        SubElement(refs, "ref", {"type": "cve", "id": "CVE-2022-1234"})
        SubElement(refs, "ref", {"type": "url", "id": "https://example.com"})
        self.assertEqual(_extract_cves(nvt), ["CVE-2022-1234"])

    def test_missing_nvt_yields_empty(self):
        self.assertEqual(_extract_cves(None), [])


class OpenVasParseNvtTags(unittest.TestCase):
    def test_parses_pipe_delimited_tags(self):
        tags = _parse_nvt_tags("summary=A summary|solution=Apply patch|solution_type=VendorFix")
        self.assertEqual(tags["summary"], "A summary")
        self.assertEqual(tags["solution"], "Apply patch")

    def test_empty_string_yields_empty_dict(self):
        self.assertEqual(_parse_nvt_tags(""), {})
        self.assertEqual(_parse_nvt_tags(None), {})


class OpenVasToCsvRow(unittest.TestCase):
    def test_maps_documented_shape(self):
        row = OpenVasConnector.to_csv_row(_result_element())
        self.assertEqual(row["CVE"], "CVE-2021-34527")
        self.assertEqual(row["Risk"], "High")
        self.assertEqual(row["CVSS v3.0 Base Score"], "8.8")
        self.assertEqual(row["IP Address"], "10.0.0.5")
        self.assertEqual(row["Host"], "host5.corp.local")
        self.assertEqual(row["FQDN"], "host5.corp.local")
        self.assertEqual(row["Name"], "Sample NVT")
        self.assertEqual(row["Synopsis"], "Test summary")
        self.assertEqual(row["Solution"], "Apply the vendor patch")
        self.assertEqual(row["Port"], "445")
        self.assertEqual(row["Protocol"], "tcp")
        self.assertEqual(row["Plugin ID"], "1.3.6.1.4.1.25623.1.0.100000")
        self.assertEqual(row["First Discovered"], "2026-08-01T00:00:00Z")

    def test_no_cve_result_leaves_cve_blank(self):
        row = OpenVasConnector.to_csv_row(_result_element(cve=None))
        self.assertEqual(row["CVE"], "")

    def test_falls_back_to_description_when_no_summary_tag(self):
        row = OpenVasConnector.to_csv_row(_result_element(tags="solution=Apply patch"))
        self.assertEqual(row["Synopsis"], "Full description of the issue.")


class OpenVasFetchAndWriteCsv(unittest.TestCase):
    def test_writes_expected_rows(self):
        import tempfile
        gmp = FakeGmp(results=[_result_element(), _result_element(host_ip="10.0.0.6", cve=None)])
        conn = OpenVasConnector(gmp_client=gmp)
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "openvas_export.csv"
            conn.fetch_and_write_csv(out_path, task_id="task-456")
            with out_path.open(encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["IP Address"], "10.0.0.5")
        self.assertEqual(rows[1]["IP Address"], "10.0.0.6")
        self.assertEqual(rows[1]["CVE"], "")


if __name__ == "__main__":
    unittest.main()
