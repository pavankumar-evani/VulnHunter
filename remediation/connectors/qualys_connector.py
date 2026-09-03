"""
Live Qualys VMDR (host-based vulnerability management) connector.

Implements Qualys Cloud Platform's documented VM API (the long-established, XML-based
API that is still the real, primary integration surface for host-based VM detections -
the newer QPS REST API covers other Qualys modules, not this one):
  1. GET {platform_url}/api/2.0/fo/asset/host/vm/detection/
       ?action=list&truncation_limit=N[&id_min=M]
                                 -> XML <HOST_LIST_VM_DETECTION_OUTPUT> with one <HOST>
                                    per asset, each with a <DETECTION_LIST> of
                                    <DETECTION> (QID + severity + first/last-found dates
                                    + port/protocol), paginated via a
                                    <WARNING><URL> continuation link carrying the next
                                    id_min - absence of a WARNING means this was the
                                    last page.
  2. GET {platform_url}/api/2.0/fo/knowledge_base/vuln/?action=list&ids=Q1,Q2,...
                                 -> XML <KNOWLEDGE_BASE_VULN_LIST_OUTPUT> resolving each
                                    QID (Qualys's own vulnerability ID) to its title,
                                    CVE(s), and severity level. A detection never carries
                                    a CVE directly - this second call is required to get
                                    one.

Reference: Qualys API (VM/PC) v2 User Guide, publicly documented. Built against Qualys's
publicly documented API contract and unit-tested against mocked HTTP (see
tests/test_qualys_connector.py) - this has NOT been exercised against a real Qualys
subscription, because no credentials were available while building it. Same honesty
convention as every other connector here (remediation/connectors/README.md); before
pointing this at a real account, verify field names/nesting against your own pod's
actual XML response. `platform_url` is a required constructor argument, not defaulted
to a single "correct" value - Qualys assigns a different API URL per platform/region
(https://qualysapi.qualys.com is only US Platform 1), and there is no honest single
default that works for every subscription.

Output mapping: unlike the Infoblox/Axonius asset connectors, Qualys - like Tenable - is
a CVE-scoped host-vulnerability-scanner source. Rather than teaching
vuln-ingest-normalizer.md a second, redundant tabular ingestion format, this connector
deliberately reuses Tenable's exact sample-compatible CSV column shape
(tenable_connector.CSV_FIELDNAMES) - both vendors fundamentally report the same
real-world facts (host, CVE, severity, port/protocol, first/last seen), so producing the
same flat shape means `/remediate <qualys_export.csv>` works today with zero normalizer
changes, exactly like the Tenable/Armis outputs it sits alongside in
remediation/live-data/. This is a deliberate reuse decision, not an accidental
coincidence - see fetch_and_write_csv() below.
"""
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from remediation.connectors.tenable_connector import CSV_FIELDNAMES
from remediation.utils.retry import retry_with_backoff

DEFAULT_PLATFORM_URL = "https://qualysapi.qualys.com"

# Qualys's own 1-5 numeric severity scale -> this repo's Critical/High/Medium/Low.
# Reasonable-but-arbitrary 4-bucket collapse (Qualys's own docs describe 5 as "urgent"
# and 1 as "minimal" but don't prescribe this exact mapping) - same disclosed-as-
# approximate spirit as CrowdStrike's 90/70/40 numeric severity thresholds; retune
# against real data before relying on it for triage prioritization.
SEVERITY_MAP = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Low"}

_RETRYABLE_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)


def _text(el, tag):
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else ""


class QualysConnector:
    def __init__(self, username, password, platform_url=DEFAULT_PLATFORM_URL, session=None):
        self.base_url = platform_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.auth = (username, password)
        # Qualys requires a non-empty, real identifier on every API call via this
        # header (a documented requirement, not optional) - requests without it are
        # rejected outright.
        self.session.headers.update({"X-Requested-With": "VulnHunter"})

    def test_connection(self):
        """Cheap, real connectivity/credential check - a host-detection list call
        truncated to a single result, the smallest real authenticated VM API call.
        Used by the dashboard's "Test Connection" action."""
        self.fetch_host_detections_page(truncation_limit=1)
        return {"ok": True}

    def fetch_host_detections_page(self, truncation_limit=1000, id_min=None):
        """One page of GET .../vm/detection/. Returns (hosts, next_id_min):
        - hosts: list of {id, ip, dns, os, detections: [{qid, type, severity, port,
          protocol, first_found, last_found}]}
        - next_id_min: the id_min to request next, or None if this was the last page
          (Qualys signals more pages via a <WARNING><URL> continuation link containing
          the next id_min - no WARNING element means done)."""
        params = {"action": "list", "truncation_limit": truncation_limit, "show_asset_id": 1}
        if id_min is not None:
            params["id_min"] = id_min

        def _do_get():
            resp = self.session.get(
                f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/", params=params, timeout=30
            )
            resp.raise_for_status()
            return resp.text

        root = ET.fromstring(retry_with_backoff(_do_get, retryable_exceptions=_RETRYABLE_EXCEPTIONS))

        hosts = []
        for host_el in root.findall(".//HOST"):
            detections = []
            for det_el in host_el.findall(".//DETECTION_LIST/DETECTION"):
                detections.append({
                    "qid": _text(det_el, "QID"),
                    "type": _text(det_el, "TYPE"),
                    "severity": _text(det_el, "SEVERITY"),
                    "port": _text(det_el, "PORT"),
                    "protocol": _text(det_el, "PROTOCOL"),
                    "first_found": _text(det_el, "FIRST_FOUND_DATETIME"),
                    "last_found": _text(det_el, "LAST_FOUND_DATETIME"),
                })
            hosts.append({
                "id": _text(host_el, "ID"),
                "ip": _text(host_el, "IP"),
                "dns": _text(host_el, "DNS"),
                "os": _text(host_el, "OS"),
                "detections": detections,
            })

        next_id_min = None
        warning_url = root.findtext(".//WARNING/URL")
        if warning_url and "id_min=" in warning_url:
            next_id_min = warning_url.split("id_min=")[1].split("&")[0]
        return hosts, next_id_min

    def fetch_all_host_detections(self, truncation_limit=1000, max_pages=50):
        """Follows the id_min continuation link until Qualys reports no more pages, or
        max_pages is hit - a safety cap against a real account with more pages than
        expected, same defensive-pagination spirit as
        ArmisConnector.search_all_pages()."""
        all_hosts = []
        id_min = None
        for _ in range(max_pages):
            hosts, id_min = self.fetch_host_detections_page(truncation_limit=truncation_limit, id_min=id_min)
            all_hosts.extend(hosts)
            if id_min is None:
                break
        return all_hosts

    def fetch_knowledge_base(self, qids):
        """Resolves a list of QIDs to title/CVE/severity-level via the knowledge base
        API - a detection only ever carries a QID, this is the one real call that
        turns a QID into a CVE. Returns {qid: {title, cve, severity_level, solution}}.
        Returns {} without a network call when qids is empty."""
        if not qids:
            return {}

        def _do_get():
            resp = self.session.get(
                f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/",
                params={"action": "list", "ids": ",".join(str(q) for q in sorted(set(qids)))},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.text

        root = ET.fromstring(retry_with_backoff(_do_get, retryable_exceptions=_RETRYABLE_EXCEPTIONS))

        kb = {}
        for vuln_el in root.findall(".//VULN"):
            qid = _text(vuln_el, "QID")
            if not qid:
                continue
            cve_ids = [c.text for c in vuln_el.findall(".//CVE_LIST/CVE/ID") if c.text]
            kb[qid] = {
                "title": _text(vuln_el, "TITLE"),
                "cve": cve_ids[0] if cve_ids else "",
                "severity_level": _text(vuln_el, "SEVERITY_LEVEL"),
                "solution": _text(vuln_el, "SOLUTION"),
            }
        return kb

    @staticmethod
    def to_csv_rows(hosts, kb):
        """Flattens (host, detection, kb-lookup) into one CSV row per detection,
        matching tenable_connector.CSV_FIELDNAMES exactly - see module docstring for
        why this reuses Tenable's shape rather than a Qualys-specific one."""
        rows = []
        for host in hosts:
            for det in host["detections"]:
                info = kb.get(det["qid"], {})
                severity_level = info.get("severity_level")
                risk = SEVERITY_MAP.get(int(severity_level), "") if severity_level and severity_level.isdigit() else ""
                rows.append({
                    "Plugin ID": det["qid"] or "",
                    "CVE": info.get("cve", ""),
                    "Risk": risk,
                    "CVSS v3.0 Base Score": "",
                    "Host": host.get("dns") or host.get("ip") or "",
                    "IP Address": host.get("ip", ""),
                    "FQDN": host.get("dns", ""),
                    "OS": host.get("os", ""),
                    "Name": info.get("title", ""),
                    "Synopsis": info.get("title", ""),
                    "Solution": info.get("solution", ""),
                    "Port": det.get("port", ""),
                    "Protocol": det.get("protocol", ""),
                    "First Discovered": det.get("first_found", ""),
                    "Last Observed": det.get("last_found", ""),
                })
        return rows

    def fetch_and_write_csv(self, output_path, truncation_limit=1000):
        """Orchestrates the full fetch (host detections -> knowledge-base lookup ->
        flatten), writes the exact same CSV shape as tenable_export.csv - drop-in
        alongside the live Tenable/Armis output, no normalizer changes needed."""
        hosts = self.fetch_all_host_detections(truncation_limit=truncation_limit)
        all_qids = [d["qid"] for h in hosts for d in h["detections"] if d["qid"]]
        kb = self.fetch_knowledge_base(all_qids)
        rows = self.to_csv_rows(hosts, kb)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        return output_path
