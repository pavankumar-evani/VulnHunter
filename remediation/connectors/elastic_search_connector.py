"""
Elastic search connector - runs a READ-ONLY EQL or ES|QL query against Elasticsearch.

Implements the documented search APIs:
  EQL    POST <base>/<index pattern>/_eql/search   {"query", "size", "filter": {"range": {"@timestamp": ...}}, "wait_for_completion_timeout"}
         -> {"is_running", "id", "hits": {"total": {"value"}, "events": [{"_source": {...}}]}}      (a still-running search is cancelled with DELETE /_eql/search/<id>)
  ES|QL  POST <base>/_query?format=json   {"query": "FROM ... | ...", "filter": {"range": ...}}  -> {"columns": [{"name", "type"}], "values": [[...]]}
  Info   GET  <base>/                      (test_connection)
  Auth:  `Authorization: ApiKey <base64 id:key>` or `Bearer <token>` or HTTP Basic.
Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-apis.html and .../esql-query-api.html

Which language the connection takes is a setting (`language`: eql or esql). Only these paths are reachable, so there is no way to index, delete or administer anything;
the account should hold read access to the indexes you hunt in and nothing else. ES|QL is limited to FROM / ROW-free queries and an allow-list of read commands;
the row count is capped (`| LIMIT n` is appended to ES|QL, `size` is sent for EQL).

Built against Elastic's public documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real cluster.
"""
import re
import time

import requests

from remediation.connectors import url_safety
from remediation.hunting import search_base
from remediation.hunting.search_base import SearchError, SearchRefused

_INDEX = re.compile(r"^[A-Za-z0-9_.*,\-:]{1,200}$")
_ESQL_OK = {"where", "stats", "keep", "drop", "sort", "limit", "eval", "rename", "dissect", "grok", "mv_expand", "dedup", "lookup", "inlinestats"}
_EQL_START = re.compile(r"^\s*(\w[\w.-]*\s+where\b|any\s+where\b|sequence\b|sample\b)", re.I)


class ElasticSearchConnector(search_base.SearchConnector):
    type = "elastic-search"

    def __init__(self, base_url, api_key=None, token=None, username=None, password=None, language="esql", index="logs-*,winlogbeat-*,filebeat-*", verify_tls=True,
                 session=None, clock=time.monotonic, sleep=time.sleep):
        if language not in ("eql", "esql"):
            raise ValueError("language must be eql or esql")
        if not (api_key or token or (username and password)):
            raise ValueError("Give an API key, a bearer token, or a username and password")
        if not _INDEX.match(index or ""):
            raise ValueError("The index pattern may hold only letters, digits and . _ - * , :")
        super().__init__(session or url_safety.safe_session(), clock, sleep)
        self.language, self.index, self.base_url = language, index, base_url.rstrip("/")
        self.session.verify = bool(verify_tls)
        if api_key:
            self.session.headers["Authorization"] = f"ApiKey {api_key}"
        elif token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:
            self.session.auth = (username, password)
        self.secrets = (api_key, token, password)

    def test_connection(self):
        r = self.session.get(f"{self.base_url}/", timeout=20)
        r.raise_for_status()
        d = r.json() or {}
        return {"cluster": d.get("cluster_name"), "version": (d.get("version") or {}).get("number"), "language": self.language}

    def check_query(self, query):
        q = search_base.check_text(query)
        if self.language == "eql":
            if not _EQL_START.match(q):
                raise SearchRefused("An EQL query must start with an event category and 'where' (for example: any where ...), or 'sequence'")
            return q
        if not re.match(r"^\s*from\s+[A-Za-z0-9_.*,\-:]+", q, re.I):
            raise SearchRefused("An ES|QL query must start with FROM <index>")
        for seg in re.sub(r'"(?:\\.|[^"\\])*"', '""', q).split("|")[1:]:
            cmd = re.match(r"\s*([A-Za-z_]+)", seg)
            if not cmd or cmd.group(1).lower() not in _ESQL_OK:
                raise SearchRefused(f"The ES|QL command '{cmd.group(1) if cmd else seg.strip()[:20]}' is not allowed")
        return q

    @staticmethod
    def _range(start, end):
        return {"range": {"@timestamp": {"gte": search_base.iso(start), "lte": search_base.iso(end)}}}

    def _post(self, url, body, deadline, params=None):
        try:
            r = self.session.post(url, json=body, params=params, timeout=deadline + 10)
        except requests.Timeout:
            raise SearchError(f"The search did not finish within {deadline} seconds and was abandoned") from None
        if r.status_code == 400:
            raise SearchError("Elasticsearch rejected the query")
        r.raise_for_status()
        return r.json() or {}

    def _run(self, q, start, end, max_rows, deadline):
        if self.language == "eql":
            d = self._post(f"{self.base_url}/{self.index}/_eql/search", {"query": q, "size": max_rows, "filter": self._range(start, end), "keep_on_completion": False,
                                                                       "wait_for_completion_timeout": f"{int(deadline)}s"}, deadline)
            if d.get("is_running"):
                if d.get("id"):
                    try:
                        self.session.delete(f"{self.base_url}/_eql/search/{d['id']}", timeout=15)
                    except requests.RequestException:
                        pass
                raise SearchError(f"The search did not finish within {deadline} seconds and was cancelled")
            hits = d.get("hits") or {}
            events = hits.get("events") or hits.get("sequences") or []
            rows = [search_base.flatten(e.get("_source") or e) for e in events if isinstance(e, dict)]
            total = (hits.get("total") or {}).get("value")
            return rows[:max_rows], total, False
        d = self._post(f"{self.base_url}/_query", {"query": f"{q}\n| LIMIT {max_rows + 1}", "filter": self._range(start, end)}, deadline, params={"format": "json"})
        cols = [c.get("name") for c in d.get("columns") or []]
        rows = [dict(zip(cols, r)) for r in d.get("values") or []]
        return rows[:max_rows], None, len(rows) > max_rows
