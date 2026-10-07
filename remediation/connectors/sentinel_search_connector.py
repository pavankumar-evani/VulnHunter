"""
Microsoft Sentinel search connector - runs a READ-ONLY KQL query against a Log Analytics workspace (the data store behind Sentinel).

Implements the documented Log Analytics query API:
  POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token   (client credentials; scope https://api.loganalytics.io/.default) -> access_token
  POST <base>/v1/workspaces/<workspace id>/query   {"query": "...", "timespan": "<start ISO>/<end ISO>"}   Authorization: Bearer <token>   Prefer: wait=<seconds>
       -> {"tables": [{"name": "PrimaryResult", "columns": [{"name", "type"}], "rows": [[...]]}]}
Reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format

Deliberately narrow: the only data endpoint is the query endpoint (fixed in code); the app registration should hold only the Log Analytics Reader role.
Management commands (a leading '.'), `set` statements, and the plugins that reach out or run external code (externaldata, http_request, sql_request, ...) are
refused before anything is sent; the result is capped with `| take N`, and the call has a deadline (Log Analytics has no cancel call, so a slow query is
abandoned by the client timeout and ended by the service's own query limit).

Built against Microsoft's public documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real workspace or tenant.
"""
import re
import time

from remediation.connectors import url_safety
from remediation.hunting import search_base
from remediation.hunting.search_base import SearchError, SearchRefused

DEFAULT_BASE_URL = "https://api.loganalytics.azure.com"
LOGIN_URL = "https://login.microsoftonline.com"
SCOPE = "https://api.loganalytics.io/.default"
_FORBIDDEN = ("externaldata", "http_request", "http_request_post", "sql_request", "cosmosdb_sql_request", "mysql_request", "postgresql_request", "ingest", "invoke")
_WS = re.compile(r"^[0-9a-fA-F-]{36}$")


class SentinelSearchConnector(search_base.SearchConnector):
    language = "kql"
    type = "sentinel-search"

    def __init__(self, workspace_id, tenant_id=None, client_id=None, client_secret=None, access_token=None, base_url=DEFAULT_BASE_URL, login_url=LOGIN_URL,
                 session=None, clock=time.monotonic, sleep=time.sleep):
        if not _WS.match(str(workspace_id or "")):
            raise ValueError("The Log Analytics workspace id must be a GUID")
        if not access_token and not (tenant_id and client_id and client_secret):
            raise ValueError("Give a tenant id, client id and client secret (or a ready access token)")
        super().__init__(session or url_safety.safe_session(), clock, sleep)
        self.workspace_id, self.tenant_id, self.client_id = workspace_id, tenant_id, client_id
        self.base_url, self.login_url = base_url.rstrip("/"), login_url.rstrip("/")
        self._client_secret, self._token = client_secret, access_token
        self.secrets = (client_secret, access_token)

    def _auth(self):
        if not self._token:
            r = self.session.post(f"{self.login_url}/{self.tenant_id}/oauth2/v2.0/token", data={"grant_type": "client_credentials", "client_id": self.client_id,
                                                                                                 "client_secret": self._client_secret, "scope": SCOPE}, timeout=30)
            r.raise_for_status()
            self._token = (r.json() or {}).get("access_token")
            if not self._token:
                raise SearchError("Microsoft Entra did not return an access token")
            self.secrets = (self._client_secret, self._token)
        return {"Authorization": f"Bearer {self._token}"}

    def check_query(self, query):
        q = search_base.check_text(query).rstrip("; \n\t")
        if re.search(r"(^|[;\n])\s*\.", q):
            raise SearchRefused("Management commands (a leading '.') are not allowed")
        if re.search(r"(^|;)\s*set\s", q, re.I):
            raise SearchRefused("`set` statements are not allowed")
        search_base.refuse_words(q, _FORBIDDEN, "operator")
        return q

    def _query(self, q, timespan, deadline):
        headers = {**self._auth(), "Prefer": f"wait={int(deadline)}"}
        try:
            r = self.session.post(f"{self.base_url}/v1/workspaces/{self.workspace_id}/query", json={"query": q, "timespan": timespan}, headers=headers, timeout=deadline + 10)
        except Exception as exc:  # noqa: BLE001 - a timeout is reported as the slow-search case, anything else by map_error
            import requests
            if isinstance(exc, requests.Timeout):
                raise SearchError(f"The query did not finish within {deadline} seconds and was abandoned") from None
            raise
        if r.status_code == 400:
            code = ((r.json() or {}).get("error") or {}).get("code") if hasattr(r, "json") else None
            raise SearchError(f"Log Analytics rejected the query ({code or 'bad request'})")
        r.raise_for_status()
        return r.json() or {}

    def test_connection(self):
        data = self._query("print ok=1", "PT5M", 30)
        return {"workspace": self.workspace_id, "reachable": bool((data.get("tables") or [{}])[0].get("rows"))}

    def _run(self, q, start, end, max_rows, deadline):
        data = self._query(f"{q}\n| take {max_rows + 1}", f"{search_base.iso(start)}/{search_base.iso(end)}", deadline)
        tables = data.get("tables") or []
        t = next((x for x in tables if x.get("name") == "PrimaryResult"), tables[0] if tables else {})
        cols = [c.get("name") for c in t.get("columns") or []]
        rows = [dict(zip(cols, r)) for r in t.get("rows") or []]
        return rows[:max_rows], None, len(rows) > max_rows
