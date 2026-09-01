"""
Tests for the live Qualys VMDR connector (remediation/connectors/qualys_connector.py).

Every HTTP interaction is mocked with real Qualys-shaped XML text - these tests never
touch the network or require real API credentials. They verify: correct Basic-auth +
X-Requested-With header construction, correct VM-detection endpoint/param construction
(including id_min pagination), correct XML parsing of hosts/detections and the
knowledge-base QID->CVE lookup, correct severity-number-to-tier mapping, and correct
flattening into Tenable's exact CSV column shape.

These do NOT prove the connector works against a real Qualys subscription - only that it
behaves correctly against XML shaped like Qualys's public API documentation. See
remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.qualys_connector import QualysConnector, SEVERITY_MAP  # noqa: E402
from remediation.connectors.tenable_connector import CSV_FIELDNAMES  # noqa: E402


def fake_xml_response(xml_text, raise_error=False):
    resp = MagicMock()
    resp.text = xml_text
    if raise_error:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    else:
        resp.raise_for_status.return_value = None
    return resp


HOST_DETECTION_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ID>1001</ID>
        <IP>10.1.1.5</IP>
        <DNS>web01.corp.local</DNS>
        <OS>Red Hat Enterprise Linux 8.4</OS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>38173</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>4</SEVERITY>
            <PORT>443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <FIRST_FOUND_DATETIME>2026-06-01T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-08-01T00:00:00Z</LAST_FOUND_DATETIME>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

HOST_DETECTION_XML_PAGE_1_WITH_WARNING = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>1</ID><IP>10.0.0.1</IP><DNS>h1</DNS><OS>Linux</OS><DETECTION_LIST></DETECTION_LIST></HOST>
    </HOST_LIST>
    <WARNING>
      <TEXT>Truncated</TEXT>
      <URL>https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&amp;id_min=2</URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

HOST_DETECTION_XML_PAGE_2_NO_WARNING = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>2</ID><IP>10.0.0.2</IP><DNS>h2</DNS><OS>Linux</OS><DETECTION_LIST></DETECTION_LIST></HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

KB_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <VULN_LIST>
      <VULN>
        <QID>38173</QID>
        <TITLE>Apache HTTP Server Multiple Vulnerabilities</TITLE>
        <SEVERITY_LEVEL>4</SEVERITY_LEVEL>
        <SOLUTION>Upgrade to the latest Apache HTTP Server version.</SOLUTION>
        <CVE_LIST>
          <CVE><ID>CVE-2024-12345</ID></CVE>
        </CVE_LIST>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"""


class QualysConstruction(unittest.TestCase):
    def test_session_gets_basic_auth(self):
        session = MagicMock()
        QualysConnector("user", "pw", session=session)
        self.assertEqual(session.auth, ("user", "pw"))

    def test_session_gets_x_requested_with_header(self):
        session = MagicMock()
        QualysConnector("user", "pw", session=session)
        header = session.headers.update.call_args[0][0]
        self.assertEqual(header["X-Requested-With"], "VulnHunter")

    def test_base_url_strips_trailing_slash(self):
        session = MagicMock()
        conn = QualysConnector("user", "pw", platform_url="https://qualysapi.qg2.apps.qualys.eu/", session=session)
        self.assertEqual(conn.base_url, "https://qualysapi.qg2.apps.qualys.eu")


class QualysTestConnection(unittest.TestCase):
    def test_test_connection_uses_truncation_limit_one(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML)
        conn = QualysConnector("user", "pw", session=session)
        result = conn.test_connection()
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["truncation_limit"], 1)
        self.assertEqual(result, {"ok": True})

    def test_test_connection_raises_on_http_error(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response("", raise_error=True)
        conn = QualysConnector("user", "pw", session=session)
        with self.assertRaises(Exception):
            conn.test_connection()


class QualysFetchHostDetectionsPage(unittest.TestCase):
    def test_hits_correct_url(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML)
        conn = QualysConnector("user", "pw", session=session)
        conn.fetch_host_detections_page()
        url = session.get.call_args[0][0]
        self.assertEqual(url, f"{conn.base_url}/api/2.0/fo/asset/host/vm/detection/")

    def test_parses_host_and_detection_fields(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML)
        conn = QualysConnector("user", "pw", session=session)
        hosts, next_id_min = conn.fetch_host_detections_page()
        self.assertIsNone(next_id_min)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host["ip"], "10.1.1.5")
        self.assertEqual(host["dns"], "web01.corp.local")
        self.assertEqual(host["os"], "Red Hat Enterprise Linux 8.4")
        self.assertEqual(len(host["detections"]), 1)
        det = host["detections"][0]
        self.assertEqual(det["qid"], "38173")
        self.assertEqual(det["severity"], "4")
        self.assertEqual(det["port"], "443")

    def test_extracts_next_id_min_from_warning_url(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML_PAGE_1_WITH_WARNING)
        conn = QualysConnector("user", "pw", session=session)
        _, next_id_min = conn.fetch_host_detections_page()
        self.assertEqual(next_id_min, "2")

    def test_omits_id_min_param_when_not_given(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML)
        conn = QualysConnector("user", "pw", session=session)
        conn.fetch_host_detections_page()
        params = session.get.call_args.kwargs["params"]
        self.assertNotIn("id_min", params)

    def test_passes_through_id_min_when_given(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML)
        conn = QualysConnector("user", "pw", session=session)
        conn.fetch_host_detections_page(id_min="500")
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["id_min"], "500")

    def test_raises_on_http_error(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response("", raise_error=True)
        conn = QualysConnector("user", "pw", session=session)
        with self.assertRaises(Exception):
            conn.fetch_host_detections_page()


class QualysFetchAllHostDetections(unittest.TestCase):
    def test_follows_id_min_continuation_across_pages(self):
        session = MagicMock()
        session.get.side_effect = [
            fake_xml_response(HOST_DETECTION_XML_PAGE_1_WITH_WARNING),
            fake_xml_response(HOST_DETECTION_XML_PAGE_2_NO_WARNING),
        ]
        conn = QualysConnector("user", "pw", session=session)
        hosts = conn.fetch_all_host_detections()
        self.assertEqual(len(hosts), 2)
        self.assertEqual(session.get.call_count, 2)

    def test_respects_max_pages_safety_cap(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(HOST_DETECTION_XML_PAGE_1_WITH_WARNING)  # always signals "more"
        conn = QualysConnector("user", "pw", session=session)
        hosts = conn.fetch_all_host_detections(max_pages=3)
        self.assertEqual(session.get.call_count, 3)
        self.assertEqual(len(hosts), 3)


class QualysFetchKnowledgeBase(unittest.TestCase):
    def test_returns_empty_dict_without_network_call_for_no_qids(self):
        session = MagicMock()
        conn = QualysConnector("user", "pw", session=session)
        kb = conn.fetch_knowledge_base([])
        self.assertEqual(kb, {})
        session.get.assert_not_called()

    def test_sends_deduplicated_sorted_ids_param(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(KB_XML)
        conn = QualysConnector("user", "pw", session=session)
        conn.fetch_knowledge_base(["38173", "38173", "100"])
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["ids"], "100,38173")

    def test_parses_qid_title_cve_and_solution(self):
        session = MagicMock()
        session.get.return_value = fake_xml_response(KB_XML)
        conn = QualysConnector("user", "pw", session=session)
        kb = conn.fetch_knowledge_base(["38173"])
        entry = kb["38173"]
        self.assertEqual(entry["title"], "Apache HTTP Server Multiple Vulnerabilities")
        self.assertEqual(entry["cve"], "CVE-2024-12345")
        self.assertEqual(entry["severity_level"], "4")
        self.assertIn("Upgrade", entry["solution"])


class QualysToCsvRows(unittest.TestCase):
    def test_flattens_one_row_per_detection_with_kb_enrichment(self):
        hosts = [{
            "id": "1001", "ip": "10.1.1.5", "dns": "web01.corp.local", "os": "RHEL 8.4",
            "detections": [{
                "qid": "38173", "type": "Confirmed", "severity": "4",
                "port": "443", "protocol": "tcp",
                "first_found": "2026-06-01T00:00:00Z", "last_found": "2026-08-01T00:00:00Z",
            }],
        }]
        kb = {"38173": {"title": "Apache HTTP Server Multiple Vulnerabilities",
                         "cve": "CVE-2024-12345", "severity_level": "4", "solution": "Upgrade."}}
        rows = QualysConnector.to_csv_rows(hosts, kb)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(set(row.keys()), set(CSV_FIELDNAMES))
        self.assertEqual(row["CVE"], "CVE-2024-12345")
        self.assertEqual(row["Risk"], "High")
        self.assertEqual(row["Host"], "web01.corp.local")
        self.assertEqual(row["IP Address"], "10.1.1.5")
        self.assertEqual(row["Port"], "443")

    def test_missing_kb_entry_yields_blank_cve_and_risk_not_a_crash(self):
        hosts = [{"id": "1", "ip": "10.0.0.1", "dns": "", "os": "",
                   "detections": [{"qid": "999", "type": "Potential", "severity": "2",
                                    "port": "", "protocol": "", "first_found": "", "last_found": ""}]}]
        rows = QualysConnector.to_csv_rows(hosts, {})
        self.assertEqual(rows[0]["CVE"], "")
        self.assertEqual(rows[0]["Risk"], "")

    def test_severity_map_covers_all_five_qualys_levels(self):
        self.assertEqual(SEVERITY_MAP, {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Low"})


class QualysFetchAndWriteCsv(unittest.TestCase):
    def test_writes_header_and_rows_matching_tenable_shape(self):
        import tempfile
        session = MagicMock()
        session.get.side_effect = [
            fake_xml_response(HOST_DETECTION_XML),  # host detections page (1 page, no WARNING)
            fake_xml_response(KB_XML),  # knowledge base lookup for QID 38173
        ]
        conn = QualysConnector("user", "pw", session=session)
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "qualys_export.csv"
            conn.fetch_and_write_csv(out_path)
            text = out_path.read_text(encoding="utf-8")
        self.assertIn(",".join(CSV_FIELDNAMES), text.splitlines()[0])
        self.assertIn("CVE-2024-12345", text)


if __name__ == "__main__":
    unittest.main()
