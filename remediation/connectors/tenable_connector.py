"""
Live Tenable.io vulnerability export connector.

Implements Tenable.io's documented asynchronous Vulnerability Export workflow:
  1. POST /vulns/export           -> {"export_uuid": "..."}
  2. GET  /vulns/export/{uuid}/status -> {"status": ..., "chunks_available": [...]}
  3. GET  /vulns/export/{uuid}/chunks/{chunk_id} -> [ {vuln record}, ... ]

Reference: https://developer.tenable.com/reference/exports-vulns-request-export
(Tenable's API is versioned and evolves - verify field names against your tenant's
current API docs before relying on this against a real account. This module was built
against the publicly documented schema; it has NOT been exercised against a live
Tenable.io tenant, since no API credentials were available while building it. See
remediation/connectors/README.md for what "tested" means here.)

Output mapping: raw Tenable export records are flattened into the exact same CSV column
shape as remediation/sample-data/tenable_export.csv, so vuln-ingest-normalizer.md's
ingestion logic needs zero changes to consume live data instead of the sample file -
only the source of the CSV changes.
"""
import csv
import time
from pathlib import Path

import requests

DEFAULT_BASE_URL = "https://cloud.tenable.com"
CSV_FIELDNAMES = [
    "Plugin ID", "CVE", "Risk", "CVSS v3.0 Base Score", "Host", "IP Address", "FQDN",
    "OS", "Name", "Synopsis", "Solution", "Port", "Protocol",
    "First Discovered", "Last Observed",
]


class TenableExportError(RuntimeError):
    pass


class TenableConnector:
    def __init__(self, access_key, secret_key, base_url=DEFAULT_BASE_URL, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
        })

    def test_connection(self):
        """Cheap, real connectivity/credential check - GET /session returns the
        authenticated API user's own profile, Tenable.io's lightest documented
        authenticated endpoint (no export job, no pagination). Used by the
        dashboard's "Test Connection" action so a real access/secret key pair can be
        verified in under a second, before anyone kicks off a full (multi-minute)
        vulnerability export."""
        resp = self.session.get(f"{self.base_url}/session")
        resp.raise_for_status()
        data = resp.json()
        return {"ok": True, "username": data.get("username"), "email": data.get("email")}

    def request_export(self, since=None, num_assets=50):
        """Kick off an export job. `since` is a unix timestamp (only vulns last seen
        on/after this time are included) - omit for a full export."""
        body = {"num_assets": num_assets}
        if since is not None:
            body["filters"] = {"since": int(since)}
        resp = self.session.post(f"{self.base_url}/vulns/export", json=body)
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["export_uuid"]
        except KeyError:
            raise TenableExportError(f"Unexpected export response shape: {data!r}")

    def poll_export_status(self, export_uuid, poll_interval_seconds=5, timeout_seconds=600):
        """Poll until the export is FINISHED, returning the list of available chunk IDs.
        Raises TenableExportError on ERROR/CANCELLED status or on timeout.

        Uses a wall-clock deadline (not an accumulator incremented by
        poll_interval_seconds) so a poll_interval_seconds of 0 - used in tests to avoid
        real sleeps - can never produce elapsed==0 forever and loop infinitely."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            resp = self.session.get(f"{self.base_url}/vulns/export/{export_uuid}/status")
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status")
            if status == "FINISHED":
                return data.get("chunks_available", [])
            if status in ("ERROR", "CANCELLED"):
                raise TenableExportError(f"Export {export_uuid} ended with status {status}")
            if time.monotonic() >= deadline:
                raise TenableExportError(f"Export {export_uuid} did not finish within {timeout_seconds}s")
            time.sleep(poll_interval_seconds)

    def download_chunk(self, export_uuid, chunk_id):
        resp = self.session.get(f"{self.base_url}/vulns/export/{export_uuid}/chunks/{chunk_id}")
        resp.raise_for_status()
        return resp.json()

    def fetch_vulnerabilities(self, since=None, num_assets=50,
                               poll_interval_seconds=5, timeout_seconds=600):
        """Orchestrates the full export workflow, returns the combined list of raw
        vulnerability records across all chunks."""
        export_uuid = self.request_export(since=since, num_assets=num_assets)
        chunk_ids = self.poll_export_status(
            export_uuid, poll_interval_seconds=poll_interval_seconds, timeout_seconds=timeout_seconds
        )
        records = []
        for chunk_id in chunk_ids:
            records.extend(self.download_chunk(export_uuid, chunk_id))
        return records

    @staticmethod
    def to_csv_row(record):
        """Maps one raw Tenable export record to a flat row matching the sample CSV's
        columns. Tenable's export schema nests fields under 'plugin' and 'asset' -
        verify these paths against your tenant's actual export payload; this mapping
        follows the publicly documented shape."""
        plugin = record.get("plugin", {})
        asset = record.get("asset", {})
        cves = plugin.get("cve") or []
        return {
            "Plugin ID": plugin.get("id", ""),
            "CVE": cves[0] if cves else "",
            "Risk": plugin.get("risk_factor", record.get("severity", "")),
            "CVSS v3.0 Base Score": plugin.get("cvss3_base_score", ""),
            "Host": asset.get("hostname", asset.get("netbios_name", "")),
            "IP Address": asset.get("ipv4", ""),
            "FQDN": asset.get("fqdn", ""),
            "OS": asset.get("operating_system", [""])[0] if asset.get("operating_system") else "",
            "Name": plugin.get("name", ""),
            "Synopsis": plugin.get("synopsis", ""),
            "Solution": plugin.get("solution", ""),
            "Port": record.get("port", {}).get("port", "") if isinstance(record.get("port"), dict) else record.get("port", ""),
            "Protocol": record.get("port", {}).get("protocol", "") if isinstance(record.get("port"), dict) else record.get("protocol", ""),
            "First Discovered": record.get("first_found", ""),
            "Last Observed": record.get("last_found", ""),
        }

    def fetch_and_write_csv(self, output_path, since=None, **kwargs):
        """Fetches live vulnerabilities and writes them to output_path in the exact
        same CSV shape as remediation/sample-data/tenable_export.csv - drop-in
        replacement for the sample file, no normalizer changes needed."""
        records = self.fetch_vulnerabilities(since=since, **kwargs)
        rows = [self.to_csv_row(r) for r in records]
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        return output_path
