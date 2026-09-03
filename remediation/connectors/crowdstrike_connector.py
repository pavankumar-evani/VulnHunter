"""
Live CrowdStrike Falcon alert connector (XDR/EDR - pull, like Tenable/Armis).

Implements CrowdStrike Falcon's documented OAuth2 + query-then-fetch-entities pattern:
  1. POST {base_url}/oauth2/token          (form fields: client_id, client_secret)
                                            -> {"access_token": "...", "expires_in": N}
     (Authorization: Bearer <access_token> header on every subsequent call)
  2. GET  {base_url}/alerts/queries/alerts/v1   (optional `filter` query param)
                                            -> {"resources": ["<composite_id>", ...]}
  3. POST {base_url}/alerts/entities/alerts/v2  ({"composite_ids": [...]})
                                            -> {"resources": [ {alert}, ... ]}

Reference: https://falconpy.io/ and CrowdStrike Falcon API's Alerts endpoints.

Like the Tenable/Armis/ServiceNow/Jira/Splunk connectors, this was built against
CrowdStrike's publicly documented API contract and has NOT been exercised against a
real Falcon tenant - no credentials were available while building it. Verify field
names against your tenant's current API version. See
remediation/connectors/README.md for what "tested" means here.
"""
import datetime

import requests

from remediation.utils.retry import retry_with_backoff

DEFAULT_BASE_URL = "https://api.crowdstrike.com"

# Falcon alert severities are typically a 1-100 numeric score (severity_name is also
# sometimes present, but its exact vocabulary varies by alert type/product). These
# thresholds are a reasonable-but-arbitrary starting point for mapping onto
# VulnHunter's four-tier Critical/High/Medium/Low scale - they are NOT sourced from
# official CrowdStrike docs, and exact cutoffs vary by alert type in practice. Tune
# against a real tenant before relying on this for triage prioritization.
SEVERITY_CRITICAL_THRESHOLD = 90
SEVERITY_HIGH_THRESHOLD = 70
SEVERITY_MEDIUM_THRESHOLD = 40

_KNOWN_TIERS = ("Critical", "High", "Medium", "Low")

_RETRYABLE_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)


class CrowdStrikeAuthError(RuntimeError):
    pass


class CrowdStrikeConnector:
    def __init__(self, client_id, client_secret, base_url=DEFAULT_BASE_URL, session=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self._access_token = None

    def authenticate(self):
        def _do_post():
            resp = self.session.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_post, retryable_exceptions=_RETRYABLE_EXCEPTIONS)
        try:
            token = data["access_token"]
        except (KeyError, TypeError):
            raise CrowdStrikeAuthError(f"Unexpected auth response shape: {data!r}")
        self._access_token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
        return token

    def _ensure_authenticated(self):
        if not self._access_token:
            self.authenticate()

    def fetch_alert_ids(self, filter_query=None, limit=100):
        """Queries for alert (composite) IDs matching an optional Falcon Query
        Language filter, returning the raw list of opaque composite-id strings."""
        self._ensure_authenticated()
        params = {"limit": limit}
        if filter_query is not None:
            params["filter"] = filter_query

        def _do_get():
            resp = self.session.get(f"{self.base_url}/alerts/queries/alerts/v1", params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()

        return retry_with_backoff(_do_get, retryable_exceptions=_RETRYABLE_EXCEPTIONS).get("resources", [])

    def fetch_alert_details(self, alert_ids):
        """Resolves a list of composite alert IDs (opaque strings combining several
        fields, per Falcon's alert entity ID scheme) into full alert objects."""
        self._ensure_authenticated()

        def _do_post():
            resp = self.session.post(
                f"{self.base_url}/alerts/entities/alerts/v2",
                json={"composite_ids": list(alert_ids)},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        return retry_with_backoff(_do_post, retryable_exceptions=_RETRYABLE_EXCEPTIONS).get("resources", [])

    @staticmethod
    def _map_severity(alert):
        severity_name = alert.get("severity_name")
        if severity_name:
            normalized = str(severity_name).strip().capitalize()
            if normalized in _KNOWN_TIERS:
                return normalized

        severity_num = alert.get("severity")
        if isinstance(severity_num, (int, float)):
            if severity_num >= SEVERITY_CRITICAL_THRESHOLD:
                return "Critical"
            if severity_num >= SEVERITY_HIGH_THRESHOLD:
                return "High"
            if severity_num >= SEVERITY_MEDIUM_THRESHOLD:
                return "Medium"
        return "Low"

    def normalize_alert(self, alert):
        """Maps one raw Falcon alert object into VulnHunter's normalized Finding shape
        (see remediation/schema/normalized-finding-schema.md).

        Falcon EDR alerts are behavioral detections ("process X injected into process
        Y", "suspicious PowerShell encoded command", etc.) - they are not CVE-scoped
        known-vulnerability findings the way Tenable/Armis records are. So cve, cvss,
        kev, and epss are always None here; that's a deliberate, expected property of
        this source, not a gap in the mapping. This connector surfaces EDR *detections*
        as findings, which is a genuinely different kind of signal than a scanner's
        *known-vulnerability* findings, and normalized-finding-schema.md's field notes
        already treat a null cve (and, downstream, null kev/epss) as a first-class case
        rather than an error condition.

        `id` is left None - FIND-N assignment is the normalizer pipeline's job (it
        needs to see every source's output together to number sequentially without
        renumbering existing findings, per normalized-finding-schema.md), and this
        connector has no visibility into that combined list.
        """
        device = alert.get("device", {}) or {}
        platform = device.get("platform_name")
        # Falcon's platform taxonomy has more values than a simple Windows/not-Windows
        # split (macOS, various Linux distros, etc.) - a real implementation would map
        # the full taxonomy. This is a reasonable two-bucket fallback given the
        # asset.type vocabulary VulnHunter currently defines (see
        # normalized-finding-schema.md).
        asset_type = "windows-endpoint" if platform == "Windows" else "unix-server"

        today = datetime.date.today().isoformat()

        return {
            "id": None,
            "source": "crowdstrike",
            "source_ref": alert.get("composite_id"),
            "asset": {
                "name": device.get("hostname"),
                "ip": device.get("local_ip"),
                "type": asset_type,
                "os": device.get("os_version"),
            },
            "title": alert.get("name") or alert.get("display_name"),
            "cve": None,
            "cvss": None,
            "severity": self._map_severity(alert),
            "description": alert.get("description"),
            "recommended_fix": None,
            "remediation_domain": None,
            "first_seen": alert.get("first_behavior") or today,
            "last_seen": alert.get("last_behavior") or today,
            "kev": None,
            "epss": None,
        }

    def fetch_and_normalize_alerts(self, filter_query=None, limit=100):
        """Orchestrates fetch_alert_ids -> fetch_alert_details -> normalize_alert,
        returning the list of normalized findings."""
        alert_ids = self.fetch_alert_ids(filter_query=filter_query, limit=limit)
        if not alert_ids:
            return []
        alerts = self.fetch_alert_details(alert_ids)
        return [self.normalize_alert(a) for a in alerts]
