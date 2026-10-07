"""
CrowdStrike Falcon lookup connector - READ-ONLY host and detection (alert) lookups through the public Falcon API.

This is a lookup, not an event search: the Hosts and Alerts APIs answer "which sensors match" and "which detections match", so a query is a scope plus a Falcon
Query Language (FQL) filter:
    hosts hostname:'WEB-1'            hosts local_ip:'10.1.2.3'+platform_name:'Windows'
    detections device.hostname:'WEB-1'  detections severity_name:'High'
Implements the documented OAuth2 + query-then-fetch-entities pattern:
  POST <base>/oauth2/token                      (client_id, client_secret) -> access_token
  GET  <base>/devices/queries/devices/v1        ?filter&limit  -> {"resources": [device ids]}
  GET  <base>/devices/entities/devices/v2       ?ids=...       -> {"resources": [device]}
  GET  <base>/alerts/queries/alerts/v2          ?filter&limit  -> {"resources": [composite ids]}
  POST <base>/alerts/entities/alerts/v2         {"composite_ids": [...]}  (a read: it returns the alert records)
Reference: https://falcon.crowdstrike.com/documentation (Hosts, Alerts, FQL); see also remediation/connectors/crowdstrike_connector.py.

Those five calls are the whole allow-list (ALLOWED); any other method or path, for example containment or host-group changes, raises SearchRefused before a request is made.
The API client should hold only Hosts: Read and Alerts: Read.

Built against CrowdStrike's public documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real Falcon tenant.
"""
import re
import time

from remediation.connectors import url_safety
from remediation.hunting import search_base
from remediation.hunting.search_base import SearchError, SearchRefused

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
ALLOWED = {("POST", "/oauth2/token"), ("GET", "/devices/queries/devices/v1"), ("GET", "/devices/entities/devices/v2"), ("GET", "/alerts/queries/alerts/v2"),
           ("POST", "/alerts/entities/alerts/v2")}
_FQL = re.compile(r"^[A-Za-z0-9_.:'\"\[\],+*!<>=~|()\- /@]{1,500}$")
_DEVICE_FIELDS = ("hostname", "local_ip", "external_ip", "platform_name", "os_version", "agent_version", "last_seen", "status", "device_id", "machine_domain", "system_manufacturer")


class FalconSearchConnector(search_base.SearchConnector):
    language = "fql"
    type = "falcon-search"

    def __init__(self, client_id, client_secret, base_url=DEFAULT_BASE_URL, session=None, clock=time.monotonic, sleep=time.sleep):
        if not client_id or not client_secret:
            raise ValueError("A client id and secret are required")
        super().__init__(session or url_safety.safe_session(), clock, sleep)
        self.client_id, self._secret, self.base_url = client_id, client_secret, base_url.rstrip("/")
        self._token = None
        self.secrets = (client_secret,)

    def _call(self, method, path, **kw):
        if (method, path) not in ALLOWED:
            raise SearchRefused(f"{method} {path} is not a read-only lookup Quanta will call")
        if path != "/oauth2/token" and not self._token:
            self._authenticate()
        r = self.session.request(method, f"{self.base_url}{path}", timeout=kw.pop("timeout", 30), **kw)
        if r.status_code == 400:
            raise SearchError("Falcon rejected the filter")
        r.raise_for_status()
        return r.json() or {}

    def _authenticate(self):
        d = self._call("POST", "/oauth2/token", data={"client_id": self.client_id, "client_secret": self._secret})
        self._token = d.get("access_token")
        if not self._token:
            raise SearchError("Falcon did not return an access token")
        self.session.headers["Authorization"] = f"Bearer {self._token}"
        self.secrets = (self._secret, self._token)

    def test_connection(self):
        d = self._call("GET", "/devices/queries/devices/v1", params={"limit": 1})
        return {"reachable": True, "sensors_visible": (d.get("meta") or {}).get("pagination", {}).get("total")}

    def check_query(self, query):
        q = search_base.check_text(query, 600)
        m = re.match(r"^(hosts|detections)\s+(.+)$", q, re.I | re.S)
        if not m:
            raise SearchRefused("A Falcon lookup is written 'hosts <FQL filter>' or 'detections <FQL filter>'")
        if not _FQL.match(m.group(2).strip()):
            raise SearchRefused("The filter holds characters FQL does not need; it was not sent")
        return f"{m.group(1).lower()} {m.group(2).strip()}"

    def _run(self, q, start, end, max_rows, deadline):
        scope, flt = q.split(" ", 1)
        since = search_base.iso(start)
        if scope == "hosts":
            ids = self._call("GET", "/devices/queries/devices/v1", params={"filter": f"({flt})+last_seen:>='{since}'", "limit": max_rows + 1}).get("resources") or []
            total = len(ids)
            rows = []
            if ids:
                res = self._call("GET", "/devices/entities/devices/v2", params={"ids": ids[:max_rows]}).get("resources") or []
                rows = [{k: d.get(k) for k in _DEVICE_FIELDS if d.get(k) is not None} for d in res]
            return rows, None, total > max_rows
        ids = self._call("GET", "/alerts/queries/alerts/v2", params={"filter": f"({flt})+created_timestamp:>='{since}'", "limit": max_rows + 1}).get("resources") or []
        rows = []
        if ids:
            res = self._call("POST", "/alerts/entities/alerts/v2", json={"composite_ids": ids[:max_rows]}).get("resources") or []
            rows = [search_base.flatten({k: a.get(k) for k in ("composite_id", "name", "severity", "severity_name", "tactic", "technique", "status", "created_timestamp", "device", "description") if a.get(k) is not None}) for a in res]
        return rows, None, len(ids) > max_rows
