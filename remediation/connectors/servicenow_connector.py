"""
ServiceNow Table API connector - creates an Incident per finding, idempotently.

Implements ServiceNow's documented Table API against the generic `incident` table,
which exists in every ServiceNow instance without any additional plugin. Orgs with the
Security Operations "Vulnerability Response" module installed may prefer targeting
`sn_vul_vulnerable_item` instead - swap the `table` constructor argument; the request/
response shape this module relies on (Table API's generic REST semantics) is the same.

Reference: https://docs.servicenow.com/bundle/latest-release/page/integrate/inbound-rest/concept/c_TableAPI.html

Like the Tenable/Armis connectors, this was built against ServiceNow's publicly
documented API contract and has NOT been exercised against a real ServiceNow instance -
no credentials were available while building it. See remediation/connectors/README.md.
"""
from pathlib import Path

import requests

DEFAULT_TABLE = "incident"

# VulnHunter risk_tier / severity -> ServiceNow's urgency/impact scale (1=High, 2=Medium, 3=Low)
SEVERITY_TO_URGENCY = {"Critical": "1", "High": "1", "Medium": "2", "Low": "3"}
SEVERITY_TO_IMPACT = {"Critical": "1", "High": "2", "Medium": "2", "Low": "3"}


class ServiceNowError(RuntimeError):
    pass


def build_incident_body(finding):
    """Builds the incident request body for one finding - pure function, no network,
    so callers (like the dashboard's preview mode) can show exactly what would be
    sent without needing real credentials or a live instance."""
    severity = finding.get("severity", "Medium")
    asset = finding.get("asset", {})
    kev = finding.get("kev") or {}
    epss = finding.get("epss") or {}

    description_lines = [
        finding.get("description", ""),
        "",
        f"Asset: {asset.get('name', '?')} ({asset.get('ip', '?')}, {asset.get('type', '?')})",
        f"CVE: {finding.get('cve') or 'N/A'}",
        f"Severity: {severity}",
    ]
    if kev.get("listed"):
        description_lines.append(f"⚠ CISA KEV-listed since {kev.get('date_added', '?')} (actively exploited)")
    if epss.get("score") is not None:
        description_lines.append(f"EPSS score: {epss['score']:.1%}")
    description_lines.append(f"Recommended fix: {finding.get('recommended_fix', '?')}")

    return {
        "short_description": f"[VulnHunter {finding['id']}] {finding.get('title', '')}",
        "description": "\n".join(description_lines),
        "urgency": SEVERITY_TO_URGENCY.get(severity, "3"),
        "impact": SEVERITY_TO_IMPACT.get(severity, "3"),
        "correlation_id": finding["id"],
        "correlation_display": "VulnHunter",
    }


class ServiceNowConnector:
    def __init__(self, instance, username, password, table=DEFAULT_TABLE, session=None):
        self.base_url = f"https://{instance}.service-now.com"
        self.table = table
        self.session = session or requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def find_existing_incident(self, correlation_id):
        """Looks up an incident already created for this finding, keyed by
        correlation_id (set to the VulnHunter finding ID) - prevents creating a
        duplicate ticket every time the pipeline re-runs against the same finding."""
        resp = self.session.get(
            f"{self.base_url}/api/now/table/{self.table}",
            params={"sysparm_query": f"correlation_id={correlation_id}", "sysparm_limit": 1},
        )
        resp.raise_for_status()
        results = resp.json().get("result", [])
        return results[0] if results else None

    def create_incident(self, finding, skip_if_exists=True):
        """Creates one incident for a normalized finding (see
        remediation/schema/normalized-finding-schema.md). Returns the created (or
        pre-existing, if skip_if_exists found one) incident record."""
        finding_id = finding["id"]

        if skip_if_exists:
            existing = self.find_existing_incident(finding_id)
            if existing:
                return {**existing, "_vulnhunter_status": "already_existed"}

        body = build_incident_body(finding)
        resp = self.session.post(f"{self.base_url}/api/now/table/{self.table}", json=body)
        resp.raise_for_status()
        result = resp.json().get("result")
        if not result:
            raise ServiceNowError(f"Unexpected create-incident response shape: {resp.json()!r}")
        return {**result, "_vulnhunter_status": "created"}

    def create_incidents_for_findings(self, findings, skip_if_exists=True):
        """Creates (or finds existing) incidents for a whole findings list. Returns a
        list of {finding_id, status, incident_number, error} - never raises for a
        single finding's failure, so one bad record doesn't abort the whole batch."""
        results = []
        for f in findings:
            try:
                incident = self.create_incident(f, skip_if_exists=skip_if_exists)
                results.append({
                    "finding_id": f["id"],
                    "status": incident.get("_vulnhunter_status", "created"),
                    "incident_number": incident.get("number"),
                    "error": None,
                })
            except Exception as exc:  # noqa: BLE001 - one failure must not abort the batch
                results.append({
                    "finding_id": f.get("id", "?"),
                    "status": "error",
                    "incident_number": None,
                    "error": str(exc),
                })
        return results
