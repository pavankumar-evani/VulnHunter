"""
Live OpenVAS / Greenbone Community Edition (GVM) connector - the open-source scan
*engine* this project was missing. Every connector before this one (Tenable, Qualys,
Prisma Cloud, ...) only ever pulls findings out of a scanner someone else already
bought, deployed, and pointed at their network. GVM is the one well-known,
enterprise-used, genuinely free/open-source engine in that category (the actual
upstream Nessus forked from, still maintained by Greenbone) - this connector lets
VulnHunter drive it directly: define a target, launch a real authenticated scan
against it, poll until done, and pull real per-host CVE results back. See
docs/VULNERABILITY_ENGINE_ARCHITECTURE.md for the full design and why GVM was chosen
over Nuclei/OWASP ZAP/Trivy for this role.

Talks GMP (Greenbone Management Protocol - XML over a TLS socket or a local Unix
socket, not HTTP) via the `python-gvm` library, Greenbone's own official Python client
- the direct GMP analog of this repo's existing `ldap3` dependency for LDAP: a real
protocol library, not a hand-rolled one, but still thin enough that every call this
module makes is a small, stable, long-documented GMP primitive (authenticate,
create_target, create_task, start_task, get_task, get_results) rather than a deep
vendor SDK surface.

Reference: Greenbone's GMP protocol documentation (https://docs.greenbone.net/API/GMP/)
and python-gvm (https://github.com/greenbone/python-gvm). Built against that publicly
documented protocol and unit-tested against a hand-rolled fake GMP client double (see
tests/test_openvas_connector.py - the same test-double convention
active_directory_connector.py already established for this repo's other stateful-
protocol connector, rather than mocking python-gvm's own internals) - this has NOT been
exercised against a real GVM instance, because none was available while building it.
Same honesty convention as every other connector here (remediation/connectors/README.md).

Two specific things every real deployment must verify before trusting live output:
  1. DEFAULT_SCAN_CONFIG_ID / DEFAULT_SCANNER_ID below are Greenbone's own documented
     default seed data (present on every fresh GVM install) - if your instance's
     defaults were renamed, removed, or you want a different scan policy, look up the
     real IDs via gmp.get_scan_configs()/gmp.get_scanners() and pass them explicitly
     instead of relying on the defaults.
  2. GMP's <result> XML shape has drifted slightly across GVM major versions (where a
     CVE reference lives under <nvt>, in particular). _extract_cves() below checks both
     documented shapes it's aware of, but verify against your own instance's actual
     response before relying on this at scale - the same caveat every other connector
     in this project carries about its own source's schema.

Output mapping: like qualys_connector.py, results are flattened into the exact same CSV
column shape as tenable_connector.py's CSV_FIELDNAMES - GVM is a CVE-scoped
host-vulnerability source like Tenable/Qualys (not an already-normalized posture source
like Prisma Cloud/Cortex XSIAM), so it needs the same judgment-based asset-type
classification step (vuln-ingest-normalizer, via `/remediate`) they do, and reusing
their exact CSV shape means zero normalizer changes are needed to consume it.
"""
import csv
import time
from pathlib import Path
from xml.etree import ElementTree

from remediation.connectors.tenable_connector import CSV_FIELDNAMES

# Greenbone's documented default seed data, stable across fresh Community Edition
# installs: the "Full and fast" scan config and the local "OpenVAS Default" scanner.
# See point 1 in the module docstring above.
DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

# GVM reports severity as a raw CVSS base score (0.0-10.0), not a qualitative band -
# this project's own standard CVSS bands (also used by risk.js/poc_enrichment.py) are
# used here rather than GMP's own coarser High/Medium/Low/Log <threat> labels, which
# have no "Critical" tier at all and would collapse a 9.8 and a 7.1 into one bucket.
_SEVERITY_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"))


class OpenVasScanError(RuntimeError):
    pass


def _severity_band(cvss_score):
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return ""
    for threshold, band in _SEVERITY_BANDS:
        if score >= threshold:
            return band
    return "Low"


def _text(element, path, default=""):
    found = element.find(path) if element is not None else None
    return found.text if found is not None and found.text is not None else default


def _extract_cves(nvt_element):
    """GMP has documented a CVE reference on an NVT two different ways across GVM
    major versions: a direct <cve> child, or a <refs><ref type="cve" id="..."/></refs>
    entry. Checks both; returns [] if neither is present (a real, common case - most
    NVTs are policy/config checks with no CVE, the same "cve is nullable" fact this
    project's own schema already documents for Armis)."""
    if nvt_element is None:
        return []
    direct = nvt_element.find("cve")
    if direct is not None and direct.text and direct.text.upper() != "NOCVE":
        return [c.strip() for c in direct.text.split(",") if c.strip()]
    return [ref.get("id") for ref in nvt_element.findall(".//ref[@type='cve']") if ref.get("id")]


def _parse_nvt_tags(tags_text):
    """GMP's NVT <tags> is one pipe-delimited string, e.g.
    "summary=...|insight=...|solution=...|solution_type=Mitigation|..." - a real,
    long-documented GMP convention, not something this project invented."""
    tags = {}
    for part in (tags_text or "").split("|"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key] = value
    return tags


class OpenVasConnector:
    def __init__(self, hostname=None, port=9390, username=None, password=None,
                 socket_path=None, scan_config_id=DEFAULT_SCAN_CONFIG_ID,
                 scanner_id=DEFAULT_SCANNER_ID, gmp_client=None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.socket_path = socket_path
        self.scan_config_id = scan_config_id
        self.scanner_id = scanner_id
        # Injectable, real-or-test-double authenticated GMP client - same pattern
        # active_directory_connector.py already establishes for this repo's other
        # stateful-protocol connector, so tests never open a real socket. When
        # injected, the caller owns authentication and lifecycle (mirrors
        # ActiveDirectoryConnector's owns_connection=False for an injected connection).
        self._injected_gmp = gmp_client

    def _connect(self):
        """Returns (gmp, owns_connection). owns_connection is False when a GMP client
        was injected (the caller owns its lifecycle, e.g. a test) - only a connection
        this method opens and authenticates itself should later be disconnected."""
        if self._injected_gmp is not None:
            return self._injected_gmp, False
        import gvm.connections
        import gvm.protocols.gmp

        if self.socket_path:
            connection = gvm.connections.UnixSocketConnection(path=self.socket_path)
        else:
            connection = gvm.connections.TLSConnection(hostname=self.hostname, port=self.port)
        gmp = gvm.protocols.gmp.Gmp(connection=connection)
        gmp.connect()
        gmp.authenticate(self.username, self.password)
        return gmp, True

    def test_connection(self):
        """Cheap, real connectivity/credential check - authenticate() IS the
        credential check for GMP (a bad username/password raises), followed by
        get_version(), the lightest real post-auth call GMP offers (no target, no
        task, no scan). Used by the dashboard's "Test Connection" action so a real
        GVM username/password pair can be verified before anyone launches an actual
        scan against a real network."""
        gmp, owns_connection = self._connect()
        try:
            version_response = gmp.get_version()
            version = _text(version_response, ".//version") or _text(version_response, "version")
            return {"ok": True, "gmp_version": version or None}
        finally:
            if owns_connection:
                gmp.disconnect()

    def create_target(self, name, hosts):
        """hosts: a list of IPs/hostnames/CIDR ranges, e.g. ["10.20.30.0/24"]."""
        gmp, owns_connection = self._connect()
        try:
            response = gmp.create_target(name=name, hosts=hosts)
            return response.get("id")
        finally:
            if owns_connection:
                gmp.disconnect()

    def create_and_start_scan(self, target_name, hosts, task_name=None):
        """Creates a target, creates a task against it using this connector's
        scan_config_id/scanner_id, starts the task, and returns immediately with the
        new task_id - it does NOT wait for the scan to finish (a real GVM scan against
        even a small network can run for many minutes to hours; blocking a dashboard
        request for that long is the wrong shape - see
        docs/VULNERABILITY_ENGINE_ARCHITECTURE.md). Poll get_task_status(task_id)
        separately."""
        gmp, owns_connection = self._connect()
        try:
            target_response = gmp.create_target(name=target_name, hosts=hosts)
            target_id = target_response.get("id")
            task_response = gmp.create_task(
                name=task_name or f"VulnHunter scan of {target_name}",
                config_id=self.scan_config_id,
                target_id=target_id,
                scanner_id=self.scanner_id,
            )
            task_id = task_response.get("id")
            gmp.start_task(task_id)
            return task_id
        finally:
            if owns_connection:
                gmp.disconnect()

    def get_task_status(self, task_id):
        """Returns {"status": "Requested|Running|Done|Stopped|Interrupted", "progress": 0-100}.
        "Done" is the only status get_results() should be trusted against."""
        gmp, owns_connection = self._connect()
        try:
            response = gmp.get_task(task_id)
            status = _text(response, ".//task/status") or _text(response, "task/status")
            progress = _text(response, ".//task/progress") or _text(response, "task/progress") or "0"
            return {"status": status or "Unknown", "progress": int(float(progress))}
        finally:
            if owns_connection:
                gmp.disconnect()

    def wait_for_task(self, task_id, poll_interval_seconds=10, timeout_seconds=1800):
        """Polls get_task_status() until Done, or raises OpenVasScanError on
        Stopped/Interrupted or timeout. Uses a wall-clock deadline (not an accumulator
        incremented by poll_interval_seconds) so poll_interval_seconds=0 in tests can
        never produce elapsed==0 forever - same convention
        tenable_connector.poll_export_status() already uses for the same reason.
        Default timeout is 30 minutes, well above a typical Tenable export's 10, because
        an authenticated GVM host scan is a genuinely slower operation than reading
        results out of a scanner that already ran - see the module docstring's caveat
        about not blocking a request on this in the dashboard."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            status = self.get_task_status(task_id)
            if status["status"] == "Done":
                return status
            if status["status"] in ("Stopped", "Interrupted"):
                raise OpenVasScanError(f"Task {task_id} ended with status {status['status']}")
            if time.monotonic() >= deadline:
                raise OpenVasScanError(f"Task {task_id} did not finish within {timeout_seconds}s")
            time.sleep(poll_interval_seconds)

    def get_results(self, task_id):
        """Returns the raw list of <result> XML elements for a finished task."""
        gmp, owns_connection = self._connect()
        try:
            response = gmp.get_results(task_id=task_id, details=True)
            return response.findall(".//result")
        finally:
            if owns_connection:
                gmp.disconnect()

    @staticmethod
    def to_csv_row(result):
        """Maps one raw GMP <result> element to a flat row matching Tenable's CSV
        column shape (see module docstring)."""
        nvt = result.find("nvt")
        cves = _extract_cves(nvt)
        cvss = _text(result, "severity") or (_text(nvt, "cvss_base") if nvt is not None else "")
        tags = _parse_nvt_tags(_text(nvt, "tags") if nvt is not None else "")
        host_ip = _text(result, "host")
        hostname = _text(result, "host/hostname")
        port_proto = _text(result, "port")  # e.g. "445/tcp"
        port, _, protocol = port_proto.partition("/")
        return {
            "Plugin ID": nvt.get("oid", "") if nvt is not None else "",
            "CVE": cves[0] if cves else "",
            "Risk": _severity_band(cvss),
            "CVSS v3.0 Base Score": cvss,
            "Host": hostname,
            "IP Address": host_ip,
            "FQDN": hostname,
            "OS": "",
            "Name": _text(result, "name"),
            "Synopsis": tags.get("summary") or _text(result, "description"),
            "Solution": tags.get("solution", ""),
            "Port": port,
            "Protocol": protocol,
            "First Discovered": result.get("creation_time", ""),
            "Last Observed": result.get("modification_time", result.get("creation_time", "")),
        }

    def fetch_and_write_csv(self, output_path, task_id):
        """Pulls results for an already-Done task_id and writes them to output_path in
        the exact same CSV shape as remediation/sample-data/tenable_export.csv - no
        normalizer changes needed, same as qualys_connector.py."""
        results = self.get_results(task_id)
        rows = [self.to_csv_row(r) for r in results]
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        return output_path
