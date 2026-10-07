"""
Splunk search connector - runs a READ-ONLY search in the customer's Splunk and returns a count and a small sample.

Implements Splunk's documented REST search flow:
  POST   <base>/services/search/jobs            (search, earliest_time, latest_time, output_mode=json) -> {"sid": "..."}
  GET    <base>/services/search/jobs/<sid>      (output_mode=json) -> entry[0].content.isDone / dispatchState / resultCount
  GET    <base>/services/search/jobs/<sid>/results (output_mode=json, count=N) -> {"results": [...]}
  Auth:  `Authorization: Bearer <token>` (a Splunk authentication token) or HTTP Basic.

Reference: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch

This is the other direction from splunk_connector.py (which pushes events in through HEC): here Quanta asks Splunk a question.
It is for hunting and triage evidence, and it is deliberately narrow:
  - only a query that starts with `search` is accepted, and any pipe into a command that writes, deletes, runs code or reaches out
    (delete, outputlookup, outputcsv, collect, sendemail, script, run, rest, map, ...) is refused before anything is sent;
  - the number of rows returned is capped and the call has a deadline (the search is cancelled if it overruns);
  - rows come back truncated to a short sample; the full result stays in Splunk.

Built against Splunk's public REST documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real
Splunk instance. See remediation/connectors/README.md for what "tested" means here.
"""
import re
import time

import requests

from remediation.connectors import url_safety
from remediation.hunting import search_base
from remediation.hunting.search_base import DEFAULT_DEADLINE_SECONDS, DEFAULT_MAX_ROWS, HARD_MAX_ROWS, SearchError as SiemSearchError, SearchRefused  # noqa: F401 - names kept for older callers
_FORBIDDEN = ("delete", "outputlookup", "outputcsv", "collect", "mcollect", "sendemail", "sendalert", "script", "run", "rest", "map", "dbxquery",
              "tscollect", "outputtext", "audit", "loadjob", "savedsearch", "inputlookup", "fit", "apply", "crawl")


def check_query(query):
    q = (query or "").strip()
    if not q.lower().startswith("search "):
        raise SearchRefused("Only a query that starts with 'search' can be run")
    if len(q) > 6000:
        raise SearchRefused("The query is too long")
    if "`" in q:
        raise SearchRefused("Macros are not allowed")
    for seg in q.split("|")[1:]:
        cmd = re.match(r"\s*([A-Za-z_]+)", seg)
        if cmd and cmd.group(1).lower() in _FORBIDDEN:
            raise SearchRefused(f"The command '{cmd.group(1)}' is not allowed")
    return q


_clip = search_base.clip_row


class SplunkSearchConnector(search_base.SearchConnector):
    """The Splunk implementation of search_base.SearchConnector (language splunk-spl). Splunk takes relative times such as -24h natively, so `earliest` and
    `latest` are passed through as given."""
    language = "splunk-spl"
    type = "splunk-search"

    def __init__(self, base_url, token=None, username=None, password=None, verify_tls=True, session=None, clock=time.monotonic, sleep=time.sleep):
        if not token and not (username and password):
            raise ValueError("A Splunk token, or a username and password, is required")
        self.secrets = (token, password)
        self.base_url = base_url.rstrip("/")
        self.session = session or url_safety.safe_session()
        self.session.verify = bool(verify_tls)
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:
            self.session.auth = (username, password)
        self._clock, self._sleep = clock, sleep

    def check_query(self, query):
        return check_query(query)

    def test_connection(self):
        resp = self.session.get(f"{self.base_url}/services/server/info", params={"output_mode": "json"}, timeout=20)
        resp.raise_for_status()
        entry = (resp.json().get("entry") or [{}])[0].get("content", {})
        return {"server": entry.get("serverName"), "version": entry.get("version")}

    def search(self, query, earliest="-24h", latest="now", max_rows=DEFAULT_MAX_ROWS, deadline=DEFAULT_DEADLINE_SECONDS):
        """Runs the search and returns the common envelope {rows, count, truncated, took_ms, query_language} plus the Splunk `sid`. Raises SearchRefused or SiemSearchError."""
        q = check_query(query)
        max_rows = max(1, min(int(max_rows), HARD_MAX_ROWS))
        start = self._clock()
        resp = self.session.post(f"{self.base_url}/services/search/jobs", data={"search": q, "earliest_time": earliest, "latest_time": latest,
                                                                              "output_mode": "json", "exec_mode": "normal", "max_count": 10000}, timeout=30)
        resp.raise_for_status()
        sid = resp.json().get("sid")
        if not sid:
            raise SiemSearchError("Splunk did not return a search id")
        while True:
            st = self.session.get(f"{self.base_url}/services/search/jobs/{sid}", params={"output_mode": "json"}, timeout=30)
            st.raise_for_status()
            content = (st.json().get("entry") or [{}])[0].get("content", {})
            if content.get("dispatchState") == "FAILED":
                raise SiemSearchError("Splunk reported the search failed")
            if content.get("isDone"):
                break
            if self._clock() - start > deadline:
                try:
                    self.session.post(f"{self.base_url}/services/search/jobs/{sid}/control", data={"action": "cancel"}, timeout=15)
                except requests.RequestException:
                    pass
                raise SiemSearchError(f"The search did not finish within {deadline} seconds and was cancelled")
            self._sleep(1.0)
        count = int(content.get("resultCount") or 0)
        rows = []
        if count:
            r = self.session.get(f"{self.base_url}/services/search/jobs/{sid}/results", params={"output_mode": "json", "count": max_rows}, timeout=60)
            r.raise_for_status()
            rows = [_clip(x) for x in (r.json().get("results") or [])][:max_rows]
        return search_base.envelope(rows, self.language, (self._clock() - start) * 1000, count=count, truncated=count > len(rows), sid=sid)
