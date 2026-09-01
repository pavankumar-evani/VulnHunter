"""
Live Palo Alto Cortex XSIAM incident connector - pull, like Tenable/Armis/CrowdStrike/
Prisma Cloud.

Implements Cortex XSIAM/XDR's documented "Standard" authentication + incident-search API
contract:
  POST {base_url}/public_api/v1/incidents/get_incidents
       headers: x-xdr-auth-id: <API Key ID>, Authorization: <API Key>
       body:    {"request_data": {"filters": [...], "sort": {...},
                                    "search_from": N, "search_to": M}}
       ->       {"reply": {"total_count": N, "incidents": [ {incident}, ... ]}}

Reference: Cortex XSIAM/XDR REST API documentation, publicly documented. Cortex XSIAM
also supports a separate "Advanced" auth mode (an HMAC-SHA256 request signature over a
nonce + timestamp + API key, rotated per request) for tenants that require it - this
connector implements the simpler, equally real and documented "Standard" mode only; a
tenant that mandates Advanced auth would need that signing logic added, same kind of
reasonable-documented-choice-disclosed-here pattern as servicenow_connector.py's
table-argument note.

Built against Cortex XSIAM's publicly documented API contract and unit-tested against
mocked HTTP (see tests/test_cortex_xsiam_connector.py) - this has NOT been exercised
against a real XSIAM tenant, because no credentials were available while building it.
Same honesty convention as every other connector here (remediation/connectors/README.md).
`base_url` is a required constructor argument, not defaulted to a single "correct"
value - Cortex XSIAM's API base URL is tenant- and region-specific
(api-<fqdn>.xdr.us.paloaltonetworks.com, .xdr.eu.paloaltonetworks.com, ...), and there is
no honest single default that works for every tenant.

Output mapping: like crowdstrike_connector.py and prismacloud_connector.py, XSIAM
incidents are correlated detections, not CVE-scoped known-vulnerability findings - so
this connector normalizes directly into VulnHunter's Finding schema itself
(cve/cvss/kev/epss always None - a deliberate, expected property of this source) rather
than routing through vuln-ingest-normalizer.md. `id` is left None on every normalized
finding - FIND-N assignment is the pipeline's job, the same convention
crowdstrike_connector.normalize_alert() already establishes. asset.type is left
"unknown" rather than guessed: a correlated incident can span multiple hosts of
unknown/mixed platform, and normalized-finding-schema.md's asset.type vocabulary has no
honest way to represent "several hosts, mixed OS" as a single value - "unknown" is the
same never-guess default infoblox_connector.py already uses for a comparable gap.
"""
import datetime

import requests

DEFAULT_BASE_URL = None  # no honest default - see module docstring

# Cortex XSIAM's own severity vocabulary is info/low/medium/high/critical - one tier
# ("info") this repo's four-tier scale has no equivalent for, mapped down to "Low"
# (a real, though not officially documented, editorial choice - "informational" is
# closer to "Low" than to being dropped or promoted).
_KNOWN_TIERS = ("Critical", "High", "Medium", "Low")


class CortexXsiamAuthError(RuntimeError):
    pass


def _epoch_ms_to_iso_date(epoch_ms):
    if not epoch_ms:
        return datetime.date.today().isoformat()
    return datetime.datetime.fromtimestamp(epoch_ms / 1000, tz=datetime.timezone.utc).date().isoformat()


class CortexXsiamConnector:
    def __init__(self, api_key, api_key_id, base_url, session=None):
        if not base_url:
            raise ValueError("base_url is required - Cortex XSIAM has no single default API URL, see module docstring")
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key,
            "Content-Type": "application/json",
        })

    def test_connection(self):
        """Cheap, real connectivity/credential check - a get_incidents call capped to
        a single result, the smallest real authenticated call this API offers. Used
        by the dashboard's "Test Connection" action."""
        self.fetch_incidents(search_to=1)
        return {"ok": True}

    def fetch_incidents(self, statuses=None, search_from=0, search_to=100):
        """POST get_incidents with an optional status filter, returns the raw list of
        incident objects (unwraps the reply.incidents envelope)."""
        request_data = {"search_from": search_from, "search_to": search_to}
        if statuses:
            request_data["filters"] = [{"field": "status", "operator": "eq", "value": list(statuses)}]
        resp = self.session.post(
            f"{self.base_url}/public_api/v1/incidents/get_incidents",
            json={"request_data": request_data},
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["reply"]["incidents"]
        except (KeyError, TypeError):
            raise CortexXsiamAuthError(f"Unexpected get_incidents response shape: {data!r}")

    @staticmethod
    def _map_severity(incident):
        severity = incident.get("severity")
        if severity:
            normalized = str(severity).strip().capitalize()
            if normalized == "Info":
                return "Low"
            if normalized in _KNOWN_TIERS:
                return normalized
        return "Medium"

    @staticmethod
    def normalize_incident(incident):
        """Maps one raw Cortex XSIAM incident object into VulnHunter's normalized
        Finding shape (see remediation/schema/normalized-finding-schema.md). See
        module docstring for why cve/cvss/kev/epss are always None, id is always None,
        and asset.type is always "unknown" here."""
        hosts = incident.get("hosts") or []

        return {
            "id": None,
            "source": "cortex-xsiam",
            "source_ref": incident.get("incident_id"),
            "asset": {
                "name": hosts[0] if hosts else incident.get("incident_name"),
                "ip": None,
                "type": "unknown",
                "os": None,
            },
            "title": incident.get("incident_name") or "Cortex XSIAM incident",
            "cve": None,
            "cvss": None,
            "severity": CortexXsiamConnector._map_severity(incident),
            "description": incident.get("description"),
            "recommended_fix": None,
            "remediation_domain": None,
            "first_seen": _epoch_ms_to_iso_date(incident.get("creation_time")),
            "last_seen": _epoch_ms_to_iso_date(incident.get("modification_time") or incident.get("creation_time")),
            "kev": None,
            "epss": None,
        }

    def fetch_and_normalize_incidents(self, statuses=None, search_from=0, search_to=100):
        """Orchestrates fetch_incidents -> normalize_incident, returns the list of
        normalized findings."""
        incidents = self.fetch_incidents(statuses=statuses, search_from=search_from, search_to=search_to)
        return [self.normalize_incident(i) for i in incidents]
