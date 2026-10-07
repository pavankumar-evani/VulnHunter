"""
The one interface every read-only SIEM / EDR search connection implements, so a hunt, an alert investigation or a playbook runs the same way whichever
product the customer has: Splunk, Microsoft Sentinel, Google SecOps (Chronicle), Elastic or CrowdStrike Falcon.

    connector.test_connection()                                  -> a small dict (server name, version, ...)
    connector.search(query, earliest, latest, max_rows, deadline) -> {rows, count, truncated, took_ms, query_language, ...}

Rules every implementation keeps (and the tests check for each one):
  * READ ONLY. A query is checked before anything is sent and a write, administrative or code-running construct is refused (SearchRefused). Each connector
    also fixes the endpoints it will call in code; there is no way to pass it another path.
  * BOUNDED. At most HARD_MAX_ROWS rows come back (the full count stays in the SIEM when the product reports it), every row is clipped, and the call has a
    deadline; a slow search is cancelled where the product has a cancel call and abandoned (client timeout) where it does not. The `truncated` flag says rows were left out.
  * NO SECRETS IN ERRORS. Errors are mapped to a short message by map_error(); the credentials, tokens and response bodies are never put in one, and
    nothing here logs a request.
  * The caller (a confirm-gated route) decides WHEN to search; a connector never searches on its own.

`count` is the full result count when the product reports one (Splunk does) and otherwise the number of rows received (a lower bound when `truncated` is true).
"""
import datetime
import re
import time

import requests

DEFAULT_MAX_ROWS = 25
HARD_MAX_ROWS = 100
DEFAULT_DEADLINE_SECONDS = 90
MAX_QUERY_CHARS = 6000

_REL = re.compile(r"^-(\d{1,4})([mhdw])$")
_UNIT = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


class SearchRefused(ValueError):
    """The query is not one Quanta will send."""


class SearchError(RuntimeError):
    """The search could not be completed (a failed or timed-out call). The message never carries a credential."""


def parse_time(value, now=None, default_now=True):
    """'now', a relative '-24h' / '-7d' / '-30m' / '-2w', an ISO-8601 string or a datetime -> an aware UTC datetime."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if value in (None, "", "now"):
        if value is None and not default_now:
            return None
        return now
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    m = _REL.match(str(value).strip())
    if m:
        return now - datetime.timedelta(seconds=int(m.group(1)) * _UNIT[m.group(2)])
    try:
        d = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SearchRefused(f"Cannot read the time {value!r}; use -24h, -7d, -30m or an ISO-8601 time") from exc
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def iso(d):
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clamp_rows(max_rows):
    return max(1, min(int(max_rows or DEFAULT_MAX_ROWS), HARD_MAX_ROWS))


def clip_row(row):
    """A short, flat sample of one result row: at most 30 fields, values as text of at most 300 characters, internal fields (leading '_') dropped except _time and _raw."""
    out = {}
    for k, v in list(row.items())[:30]:
        if str(k).startswith("_") and k not in ("_time", "_raw"):
            continue
        s = v if isinstance(v, str) else str(v)
        out[str(k)] = s if len(s) <= 300 else s[:297] + "..."
    return out


def flatten(obj, prefix="", depth=0, out=None):
    """Nested JSON -> {'a.b.c': value}, lists joined, so a UDM event or an Elastic hit becomes a flat row."""
    out = {} if out is None else out
    if isinstance(obj, dict) and depth < 6:
        for k, v in obj.items():
            flatten(v, f"{prefix}{k}.", depth + 1, out)
    elif isinstance(obj, list) and obj and all(not isinstance(x, (dict, list)) for x in obj):
        out[prefix[:-1]] = ", ".join(str(x) for x in obj[:10])
    elif isinstance(obj, list):
        for i, x in enumerate(obj[:5]):
            flatten(x, f"{prefix}{i}.", depth + 1, out)
    else:
        out[prefix[:-1]] = obj
    return out


def envelope(rows, language, took_ms, count=None, truncated=False, **extra):
    rows = list(rows)
    return {"rows": rows, "count": len(rows) if count is None else int(count), "truncated": bool(truncated), "took_ms": int(took_ms), "query_language": language, **extra}


def map_error(exc, secrets=()):
    """A short message for a failed call, safe to store and show: the HTTP status and the product's own one-line reason, never a body dump or a credential."""
    if isinstance(exc, requests.Timeout):
        msg = "the request timed out"
    elif isinstance(exc, requests.ConnectionError):
        msg = "the service could not be reached"
    elif isinstance(exc, requests.HTTPError):
        code = getattr(getattr(exc, "response", None), "status_code", None)
        meaning = {400: "the query was rejected", 401: "authentication failed", 403: "the account may not run this search", 404: "the endpoint or index was not found",
                   408: "the request timed out", 429: "rate limited", 500: "the service reported an error", 502: "bad gateway", 503: "the service is unavailable"}.get(code, "the call failed")
        msg = f"HTTP {code}: {meaning}"
    else:
        msg = f"{type(exc).__name__}: {str(exc)[:160]}"
    for s in secrets:
        if s and len(str(s)) > 3:
            msg = msg.replace(str(s), "***")
    return msg


class SearchConnector:
    """Base class. A subclass sets `language`, `type` and implements test_connection(), check_query() and _run(); search() is the same for all of them."""
    language = None       # the query language this connection takes: splunk-spl, kql, eql, esql, udm, fql
    type = None           # the connection type in remediation/connections/registry.py
    secrets = ()          # values never to appear in an error

    def __init__(self, session=None, clock=time.monotonic, sleep=time.sleep):
        self.session = session
        self._clock, self._sleep = clock, sleep

    def test_connection(self):
        raise NotImplementedError

    def check_query(self, query):
        raise NotImplementedError

    def _run(self, query, start, end, max_rows, deadline):
        """-> (rows, total or None, truncated). Rows are raw dicts; the base clips them."""
        raise NotImplementedError

    def search(self, query, earliest="-24h", latest="now", max_rows=DEFAULT_MAX_ROWS, deadline=DEFAULT_DEADLINE_SECONDS):
        q = self.check_query(query)
        max_rows = clamp_rows(max_rows)
        now = datetime.datetime.now(datetime.timezone.utc)
        start, end = parse_time(earliest, now), parse_time(latest, now)
        if start >= end:
            raise SearchRefused("The search window is empty (earliest is not before latest)")
        t0 = self._clock()
        try:
            rows, total, truncated = self._run(q, start, end, max_rows, deadline)
        except (SearchRefused, SearchError):
            raise
        except requests.RequestException as exc:
            raise SearchError(map_error(exc, self.secrets)) from None
        rows = [clip_row(r) for r in rows][:max_rows]
        return envelope(rows, self.language, (self._clock() - t0) * 1000, count=total, truncated=truncated or (total is not None and total > len(rows)))


def check_text(query, max_chars=MAX_QUERY_CHARS):
    q = (query or "").strip()
    if not q:
        raise SearchRefused("The query is empty")
    if len(q) > max_chars:
        raise SearchRefused("The query is too long")
    return q


def refuse_words(query, words, what="command"):
    """Refuses the query when any of `words` appears as a whole word outside a quoted string."""
    stripped = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', query)
    for w in words:
        if re.search(rf"(?<![\w.]){re.escape(w)}(?![\w])", stripped, re.I):
            raise SearchRefused(f"The {what} '{w}' is not allowed")


class Runner:
    """Adapts a search connection to the `run(query, earliest, max_rows)` callable the investigation, follow-up, SOAR and playbook code takes, and tells that code which
    language to write its queries in (`.language`). A plain function without `.language` is treated as Splunk SPL, which is what every caller wrote before."""
    def __init__(self, conn, max_rows=10):
        self.conn, self.max_rows = conn, max_rows
        self.language = getattr(conn, "language", None) or "splunk-spl"

    def __call__(self, query, earliest="-24h", max_rows=None):
        return self.conn.search(query, earliest=earliest, max_rows=max_rows or self.max_rows)


SIGHTING = {
    "splunk-spl": 'search ("{v}") | stats count, dc(host) as hosts',
    "kql": 'search "{v}" | summarize count = count(), hosts = dcount(Computer)',
    "esql": 'FROM logs-* | WHERE QSTR("\\"{v}\\"") | STATS count = COUNT(*), hosts = COUNT_DISTINCT(host.name)',
}


def sighting_query(language, value):
    """The "where else was this value seen" search in `language`, or None when that language has no free-text search (EQL, UDM and FQL need a field). `value` must already be safe text."""
    t = SIGHTING.get(language)
    return t.replace("{v}", value) if t else None
