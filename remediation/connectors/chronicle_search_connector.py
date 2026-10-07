"""
Google SecOps (Chronicle) search connector - runs a READ-ONLY UDM search.

Calls the Chronicle API's UDM search view method:
  POST <base>/v1alpha/<instance resource>/legacy:legacyFetchUdmSearchView
       {"query": "<UDM search>", "timeRange": {"startTime": "<ISO>", "endTime": "<ISO>"}, "limit": N}     Authorization: Bearer <OAuth2 access token>
       -> events under "events" (each wrapping a UDM event), tolerated under "results" or "udmEvents" too.
Reference: https://cloud.google.com/chronicle/docs/reference/rest (projects.locations.instances.legacy)

Honest limits:
  * The request and response field names above come from the public reference, which is thin for this method; the path is one constant (SEARCH_PATH) and the
    response reader is tolerant. Check both against your tenant before relying on it.
  * Quanta takes a ready OAuth2 access token (for example one your own token broker issues for a service account holding only search permission). It does
    not hold a service-account private key or mint tokens itself.
  * `query` is a UDM search, not a YARA-L rule: Quanta never creates or edits a rule, a reference list or a feed. Only the one search path is reachable.
Slow searches are abandoned by the client timeout; the search API has no job to cancel.

Built against public documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real Google SecOps tenant.
"""
import re
import time

import requests

from remediation.connectors import url_safety
from remediation.hunting import search_base
from remediation.hunting.search_base import SearchError, SearchRefused

SEARCH_PATH = "legacy:legacyFetchUdmSearchView"
_INSTANCE = re.compile(r"^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/instances/[A-Za-z0-9_-]+$")


class ChronicleSearchConnector(search_base.SearchConnector):
    language = "udm"
    type = "chronicle-search"

    def __init__(self, base_url, instance, access_token, session=None, clock=time.monotonic, sleep=time.sleep):
        if not _INSTANCE.match(str(instance or "")):
            raise ValueError("The instance must look like projects/<project>/locations/<location>/instances/<instance id>")
        if not access_token:
            raise ValueError("An OAuth2 access token is required")
        super().__init__(session or url_safety.safe_session(), clock, sleep)
        self.base_url, self.instance = base_url.rstrip("/"), instance
        self.session.headers["Authorization"] = f"Bearer {access_token}"
        self.secrets = (access_token,)

    def check_query(self, query):
        q = search_base.check_text(query)
        if re.match(r"^\s*(rule\s+\w+\s*\{|events:|meta:)", q, re.I) or re.search(r"\bmeta:\s|\bcondition:\s", q):
            raise SearchRefused("A YARA-L rule is not a search; Quanta never creates or runs rules")
        return q

    def _post(self, body, deadline):
        try:
            r = self.session.post(f"{self.base_url}/v1alpha/{self.instance}/{SEARCH_PATH}", json=body, timeout=deadline + 10)
        except requests.Timeout:
            raise SearchError(f"The search did not finish within {deadline} seconds and was abandoned") from None
        if r.status_code == 400:
            raise SearchError("Google SecOps rejected the UDM query")
        r.raise_for_status()
        return r.json() or {}

    def test_connection(self):
        now = search_base.parse_time("now")
        data = self._post({"query": 'metadata.event_type = "NETWORK_CONNECTION"', "timeRange": {"startTime": search_base.iso(search_base.parse_time("-5m", now)),
                                                                                              "endTime": search_base.iso(now)}, "limit": 1}, 30)
        return {"instance": self.instance, "reachable": isinstance(data, dict)}

    def _run(self, q, start, end, max_rows, deadline):
        data = self._post({"query": q, "timeRange": {"startTime": search_base.iso(start), "endTime": search_base.iso(end)}, "limit": max_rows + 1}, deadline)
        events = data.get("events") or data.get("results") or data.get("udmEvents") or []
        rows = [search_base.flatten((e.get("event") or e.get("udm") or e) if isinstance(e, dict) else {"value": e}) for e in events]
        return rows[:max_rows], None, len(rows) > max_rows
