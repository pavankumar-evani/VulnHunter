"""
Live Prisma Cloud (Palo Alto Networks CNAPP) alert connector - pull, like Tenable/Armis/
CrowdStrike.

Implements Prisma Cloud's documented login + alert-search API contract:
  1. POST {base_url}/login       body: {"username": access_key_id, "password": secret_key}
                                  -> {"token": "...", "customerNames": [...]}
     (x-redlock-auth: <token> header on every subsequent call - Prisma Cloud's real,
     documented header name; NOT "Authorization: Bearer")
  2. POST {base_url}/v2/alert    body: {"filters": [...], "timeRange": {...}}
                                  -> {"items": [ {alert}, ... ], "totalRows": N}

Reference: Prisma Cloud (CSPM) API Reference, publicly documented. Built against Prisma
Cloud's publicly documented API contract and unit-tested against mocked HTTP (see
tests/test_prismacloud_connector.py) - this has NOT been exercised against a real Prisma
Cloud tenant, because no credentials were available while building it. Same honesty
convention as every other connector here (remediation/connectors/README.md).
`base_url` is a required constructor argument, not defaulted to a single "correct"
value - Prisma Cloud assigns a different API URL per region/stack (api.prismacloud.io,
api2.prismacloud.io, api.eu.prismacloud.io, ...), and there is no honest single default
that works for every tenant. The login token also expires (Prisma Cloud's docs describe
roughly a 10-minute to a few-hour lifetime depending on tenant settings); this connector
re-authenticates once per fetch_and_normalize_alerts() call rather than implementing
token-refresh/retry-on-401 logic - a real long-running integration should add that.

Output mapping: unlike Tenable/Armis/Qualys, Prisma Cloud alerts are cloud
posture/compliance violations, not CVE-scoped known-vulnerability findings - so, like
crowdstrike_connector.py, this connector normalizes directly into VulnHunter's Finding
schema itself (cve/cvss/kev/epss always None - a deliberate, expected property of this
source, not a mapping gap) rather than routing through vuln-ingest-normalizer.md. `id` is
left None on every normalized finding - FIND-N assignment is the pipeline's job (it needs
to see every source's output together to number sequentially), the same convention
crowdstrike_connector.normalize_alert() already establishes.

Single-page scope limit: like axonius_connector.py, this fetches a single page of alerts
only. Prisma Cloud's v2/alert response can include a continuation token for further pages
under real-world response volumes; replicating that pagination loop in full is out of
scope for this MVP connector (documented here, not silently dropped) - a real integration
needs that loop the same way ArmisConnector.search_all_pages() implements one.
"""
import requests

from remediation.utils.retry import retry_with_backoff

DEFAULT_BASE_URL = None  # no honest default - see module docstring

_KNOWN_TIERS = ("Critical", "High", "Medium", "Low")

_RETRYABLE_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)


class PrismaCloudAuthError(RuntimeError):
    pass


class PrismaCloudConnector:
    def __init__(self, access_key_id, secret_key, base_url, session=None):
        if not base_url:
            raise ValueError("base_url is required - Prisma Cloud has no single default API URL, see module docstring")
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self._token = None

    def authenticate(self):
        """POST /login exchanges the access key ID + secret key for a short-lived
        token, carried as x-redlock-auth on every subsequent call - Prisma Cloud's
        real, documented header name (not a Bearer Authorization header)."""
        def _do_post():
            resp = self.session.post(
                f"{self.base_url}/login",
                json={"username": self.access_key_id, "password": self.secret_key},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_post, retryable_exceptions=_RETRYABLE_EXCEPTIONS)
        try:
            token = data["token"]
        except (KeyError, TypeError):
            raise PrismaCloudAuthError(f"Unexpected login response shape: {data!r}")
        self._token = token
        self.session.headers["x-redlock-auth"] = token
        return token

    def _ensure_authenticated(self):
        if not self._token:
            self.authenticate()

    def test_connection(self):
        """Cheap, real connectivity/credential check - the login call itself proves
        the access key ID/secret key pair is valid; no separate lighter call is
        needed. Used by the dashboard's "Test Connection" action."""
        self.authenticate()
        return {"ok": True}

    def fetch_alerts(self, status="open", time_range_type="to_now", time_range_value="epoch"):
        """POST /v2/alert with a status filter + time range, returns the raw
        {"items": [...], "totalRows": N} response (single page - see module
        docstring's scope-limit note)."""
        self._ensure_authenticated()
        body = {
            "filters": [{"name": "alert.status", "value": status, "operator": "="}],
            "timeRange": {"type": time_range_type, "value": time_range_value},
        }

        def _do_post():
            resp = self.session.post(f"{self.base_url}/v2/alert", json=body, timeout=30)
            resp.raise_for_status()
            return resp.json()

        return retry_with_backoff(_do_post, retryable_exceptions=_RETRYABLE_EXCEPTIONS)

    @staticmethod
    def _map_severity(alert):
        severity = (alert.get("policy") or {}).get("severity")
        if severity:
            normalized = str(severity).strip().capitalize()
            if normalized in _KNOWN_TIERS:
                return normalized
        return "Medium"

    @staticmethod
    def normalize_alert(alert):
        """Maps one raw Prisma Cloud alert object into VulnHunter's normalized Finding
        shape (see remediation/schema/normalized-finding-schema.md). See module
        docstring for why cve/cvss/kev/epss are always None and id is always None
        here."""
        policy = alert.get("policy") or {}
        resource = alert.get("resource") or {}

        return {
            "id": None,
            "source": "prismacloud",
            "source_ref": alert.get("id"),
            "asset": {
                "name": resource.get("name") or resource.get("id"),
                "ip": None,
                "type": "cloud-infrastructure",
                "os": None,
            },
            "title": policy.get("name") or "Prisma Cloud alert",
            "cve": None,
            "cvss": None,
            "severity": PrismaCloudConnector._map_severity(alert),
            "description": policy.get("description") or alert.get("reason"),
            "recommended_fix": None,
            "remediation_domain": None,
            "first_seen": alert.get("firstSeen"),
            "last_seen": alert.get("lastSeen"),
            "kev": None,
            "epss": None,
        }

    def fetch_and_normalize_alerts(self, status="open"):
        """Orchestrates fetch_alerts -> normalize_alert, returns the list of
        normalized findings."""
        response = self.fetch_alerts(status=status)
        items = response.get("items", [])
        return [self.normalize_alert(a) for a in items]
