"""
Anthropic coordinated-vulnerability-disclosure (CVD) feed connector.

Reads ONLY the public page https://red.anthropic.com/2026/cvd/ and its published machine-readable payload
(https://red.anthropic.com/2026/cvd/payload.json). Nothing unofficial or leaked is ever read. The page describes a disclosure ledger whose entries
reveal progressively (a hash commitment first, then status and severity, then project, bug class and CVE/GHSA ids once the disclosure window closes),
so many records legitimately carry little more than an id and a state; they are stored as such and never guessed at.

Honest limits: the payload schema is NOT documented. When this was written, payload.json could not be retrieved (the fetch tool returned the site
index instead), so the parser is built against an ASSUMED shape and made deliberately tolerant: it accepts a top-level list or an object holding the
list under one of several plausible keys, and reads each field from several plausible names. Missing fields become empty values, never errors. It is
unit-tested against a hand-rolled fake session and has never been run against the live site. Verify the field mapping (`FIELD_ALIASES`) against a real
payload before relying on it.
"""
import hashlib
import re

from remediation.connectors import url_safety

DEFAULT_URL = "https://red.anthropic.com/2026/cvd/payload.json"
PAGE_URL = "https://red.anthropic.com/2026/cvd/"
SOURCE = "anthropic-cvd"
MAX_RECORDS = 20000

_LIST_KEYS = ("entries", "ledger", "disclosures", "advisories", "vulnerabilities", "records", "items", "findings", "data")
FIELD_ALIASES = {
    "id": ("id", "advisory_id", "disclosure_id", "commitment", "hash", "sha3_512", "ledger_id"),
    "title": ("title", "name", "summary", "bug_class", "bugClass", "class"),
    "cves": ("cves", "cve", "cve_ids", "cve_id", "identifiers", "ids", "aliases"),
    "vendor": ("vendor", "organization", "org", "maintainer"),
    "product": ("project", "product", "package", "software", "repo", "repository"),
    "severity": ("severity", "final_severity", "maintainer_severity", "external_severity", "claude_severity"),
    "published": ("published", "published_at", "disclosed_at", "disclosure_date", "disclosed", "date", "reported_at", "committed_at"),
    "state": ("state", "status", "disclosure_state", "stage"),
    "url": ("url", "link", "advisory_url", "reference"),
}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low", "info": "Low", "informational": "Low"}
_ORDER = ["Critical", "High", "Medium", "Low"]


class CvdFeedError(RuntimeError):
    pass


def _first(rec, key):
    for name in FIELD_ALIASES[key]:
        v = rec.get(name)
        if v not in (None, "", [], {}):
            return v
    return None


def _text(v):
    if isinstance(v, (list, tuple)):
        v = ", ".join(str(x) for x in v if x not in (None, ""))
    elif isinstance(v, dict):
        v = v.get("name") or v.get("title") or ""
    return str(v).strip() if v is not None else ""


def _severity(v):
    """Most severe label stated, from a string, a number (CVSS-like), a list or a {assessor: label} dict; '' when none is given."""
    items = list(v.values()) if isinstance(v, dict) else v if isinstance(v, (list, tuple)) else [v]
    found = []
    for s in items:
        if isinstance(s, bool):
            continue
        if isinstance(s, (int, float)):
            found.append("Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low")
        elif isinstance(s, str) and s.strip().lower() in _SEV:
            found.append(_SEV[s.strip().lower()])
    return min(found, key=_ORDER.index) if found else ""


def _cves(v):
    blob = " ".join(_text(x) for x in v) if isinstance(v, (list, tuple)) else _text(v)
    return sorted({m.upper() for m in _CVE.findall(blob)})


def parse(payload):
    """payload (parsed JSON) -> [advisory dict]. Tolerant: an unknown shape gives [], an unusable record is skipped, a missing field is ''."""
    rows = None
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for k in _LIST_KEYS:
            if isinstance(payload.get(k), list):
                rows = payload[k]
                break
        if rows is None and payload and all(isinstance(v, dict) for v in payload.values()):  # {id: {...}} mapping
            rows = [dict(v, id=v.get("id") or k) for k, v in payload.items()]
    out, seen = [], set()
    for rec in (rows or [])[:MAX_RECORDS]:
        if not isinstance(rec, dict):
            continue
        cves = _cves(_first(rec, "cves"))
        product = _text(_first(rec, "product"))
        aid = _text(_first(rec, "id"))
        if not aid:
            if not (cves or product):
                continue
            aid = "anon-" + hashlib.sha256(f"{cves}|{product}|{_text(_first(rec, 'published'))}".encode()).hexdigest()[:16]
        if aid in seen:
            continue
        seen.add(aid)
        out.append({"source": SOURCE, "id": aid, "title": _text(_first(rec, "title")) or (cves[0] if cves else ""), "cves": cves, "vendor": _text(_first(rec, "vendor")),
                    "product": product, "severity": _severity(_first(rec, "severity")), "published": _text(_first(rec, "published"))[:10],
                    "state": (_text(_first(rec, "state")) or "committed").lower(), "url": _text(_first(rec, "url")) or PAGE_URL})
    return out


class CvdFeedConnector:
    def __init__(self, url=DEFAULT_URL, session=None):
        if not str(url).lower().startswith("https://"):
            raise url_safety.UnsafeTargetError("The CVD feed must be fetched over https.")
        if url != DEFAULT_URL:
            url_safety.assert_safe_target(url)
        self.url = url
        self.session = session or url_safety.safe_session()

    def _get(self):
        r = self.session.get(self.url, timeout=30, headers={"Accept": "application/json"})
        if r.status_code >= 400:
            raise CvdFeedError(f"The CVD feed answered {r.status_code}")
        try:
            return r.json()
        except ValueError as exc:
            raise CvdFeedError("The CVD feed did not return JSON") from exc

    def test_connection(self):
        """The payload is the only endpoint, so the cheapest real call is the same GET. True if it answers with JSON."""
        self._get()
        return True

    def fetch(self):
        return parse(self._get())
