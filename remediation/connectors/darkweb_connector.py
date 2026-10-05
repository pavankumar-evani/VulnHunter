"""
Dark-web exposure connectors: public ransomware leak-site feeds and credential-exposure lookups.

Quanta never touches the Tor network and never fetches a leak site or marketplace itself. It reads two kinds of clearnet service:

  Ransomware leak-site feeds (free, no key, nothing about you is sent): a list of organisations that ransomware groups have posted.
    ransomware.live  GET https://api.ransomware.live/v2/recentvictims   -> [{victim, group, discovered, published, country, website, post_url, ...}]
    ransomwatch      GET https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json -> [{post_title, group_name, discovered}]
  The whole list is fetched and matched against YOUR watch terms locally (watch.py); the terms never leave Quanta.

  Credential-exposure lookups (need your own account and key; only your own domain is sent):
    IntelligenceX   POST https://2.intelx.io/intelligent/search  {term, maxresults, media, sort, terminate}  header x-key   then
                    GET  https://2.intelx.io/intelligent/search/result?id=<id>&limit=<n>   -> {records: [{name, date, bucket, ...}], status}
    DeHashed        POST https://api.dehashed.com/v2/search  {query: "domain:example.com", page, size}  header Dehashed-Api-Key   -> {entries: [...], total}
    LeakCheck       GET  https://leakcheck.io/api/v2/query/<domain>?type=domain  header X-API-Key   -> {success, found, result: [...]}  (domain search is a paid-plan feature)
    Snusbase        POST https://api.snusbase.com/data/search  {terms: [domain], types: ["_domain"], wildcard: false}  header Auth   -> {size, results: {<database>: [...]}}

What is kept from a credential answer: how many records, which breach or database name, its date, and a masked identifier (first character and the domain).
Passwords, hashes and any other secret field are dropped here, in this module, before anything is returned, so they cannot reach the database or a log.

Built against the services' public documentation and unit-tested against hand-rolled fakes. None has been run against a real account; field names are read
defensively and a changed answer gives an empty result with a note, not an error that hides what happened.
"""
import re

import requests

TIMEOUT = 25
MAX_RECORDS = 200


class DarkWebError(RuntimeError):
    pass


def mask_identifier(value):
    """a.person@example.com -> a***@example.com ; anything else -> first character and stars."""
    v = str(value or "").strip()
    if not v:
        return ""
    if "@" in v:
        local, _, dom = v.partition("@")
        return f"{local[:1]}***@{dom}"
    return v[:1] + "***"


def _get_json(session, method, url, **kw):
    try:
        r = session.request(method, url, timeout=TIMEOUT, **kw)
    except requests.RequestException as exc:
        raise DarkWebError(f"Could not reach {url.split('/')[2]}: {exc.__class__.__name__}") from exc
    if r.status_code in (401, 403):
        raise DarkWebError("The service rejected the key (check it and your plan)")
    if r.status_code == 429:
        raise DarkWebError("The service is rate limiting this key; try later")
    if r.status_code >= 400:
        raise DarkWebError(f"The service answered HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as exc:
        raise DarkWebError("The service did not return JSON") from exc


# ---------------------------------------------------------------- ransomware leak-site feeds
class RansomwareLive:
    name = "ransomware.live"
    URL = "https://api.ransomware.live/v2/recentvictims"

    def __init__(self, session=None):
        self.session = session or requests.Session()

    def fetch(self):
        data = _get_json(self.session, "GET", self.URL)
        out = []
        for p in data if isinstance(data, list) else []:
            if not isinstance(p, dict):
                continue
            out.append({"feed": self.name, "victim": str(p.get("victim") or p.get("post_title") or "")[:300], "group": str(p.get("group") or p.get("group_name") or "")[:80],
                        "discovered": str(p.get("discovered") or p.get("published") or "")[:40], "website": str(p.get("website") or p.get("domain") or "")[:200],
                        "country": str(p.get("country") or "")[:8], "post_url": str(p.get("post_url") or p.get("permalink") or "")[:400]})
        return out


class Ransomwatch(RansomwareLive):
    name = "ransomwatch"
    URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

    def fetch(self):
        data = _get_json(self.session, "GET", self.URL)
        out = []
        for p in data if isinstance(data, list) else []:
            if isinstance(p, dict):
                out.append({"feed": self.name, "victim": str(p.get("post_title") or "")[:300], "group": str(p.get("group_name") or "")[:80],
                            "discovered": str(p.get("discovered") or "")[:40], "website": "", "country": "", "post_url": ""})
        return out[-3000:]


FEEDS = {"ransomware-live": RansomwareLive, "ransomwatch": Ransomwatch}


# ---------------------------------------------------------------- credential exposure
def _summary(source, total, records, note=""):
    return {"source": source, "total": int(total), "records": records[:MAX_RECORDS], "note": note}


class IntelX:
    name = "intelx"
    HOST = "https://2.intelx.io"

    def __init__(self, api_key, host=None, session=None):
        self.key, self.host, self.session = api_key, (host or self.HOST).rstrip("/"), session or requests.Session()

    def _h(self):
        return {"x-key": self.key}

    def test_connection(self):
        d = _get_json(self.session, "GET", f"{self.host}/authenticate/info", headers=self._h())
        return {"ok": True, "message": "IntelligenceX key accepted" + (f" ({d.get('buckets') and len(d['buckets'])} data buckets)" if isinstance(d, dict) and d.get("buckets") else "")}

    def lookup_domain(self, domain, limit=100):
        s = _get_json(self.session, "POST", f"{self.host}/intelligent/search", headers=self._h(),
                      json={"term": domain, "maxresults": limit, "media": 0, "sort": 4, "terminate": []})
        sid = (s or {}).get("id")
        if not sid:
            return _summary(self.name, 0, [], "The search was not accepted (status " + str((s or {}).get("status")) + ")")
        r = _get_json(self.session, "GET", f"{self.host}/intelligent/search/result", headers=self._h(), params={"id": sid, "limit": limit})
        recs = [{"identifier": mask_identifier(x.get("name")), "source": str(x.get("bucket") or "")[:80], "date": str(x.get("date") or "")[:20]} for x in (r or {}).get("records") or []]
        return _summary(self.name, len(recs), recs)


class DeHashed:
    name = "dehashed"
    URL = "https://api.dehashed.com/v2/search"

    def __init__(self, api_key, session=None):
        self.key, self.session = api_key, session or requests.Session()

    def test_connection(self):
        d = _get_json(self.session, "POST", self.URL, headers={"Dehashed-Api-Key": self.key}, json={"query": "domain:example.invalid", "page": 1, "size": 1})
        return {"ok": True, "message": "DeHashed key accepted" + (f" (balance {d['balance']})" if isinstance(d, dict) and d.get("balance") is not None else "")}

    def lookup_domain(self, domain, limit=100):
        d = _get_json(self.session, "POST", self.URL, headers={"Dehashed-Api-Key": self.key}, json={"query": f"domain:{domain}", "page": 1, "size": min(limit, 10000)})
        entries = (d or {}).get("entries") or []
        recs = []
        for e in entries:  # only these fields are read; password, hashed_password and the rest are never touched
            recs.append({"identifier": mask_identifier(e.get("email") or e.get("username")), "source": str(e.get("database_name") or "")[:80], "date": ""})
        return _summary(self.name, (d or {}).get("total") or len(entries), recs)


class LeakCheck:
    name = "leakcheck"
    BASE = "https://leakcheck.io/api/v2"

    def __init__(self, api_key, session=None):
        self.key, self.session = api_key, session or requests.Session()

    def test_connection(self):
        d = _get_json(self.session, "GET", f"{self.BASE}/query/example.invalid", headers={"X-API-Key": self.key}, params={"type": "domain", "limit": 1})
        return {"ok": True, "message": "LeakCheck key accepted" + (f" (quota {d['quota']})" if isinstance(d, dict) and d.get("quota") is not None else "")}

    def lookup_domain(self, domain, limit=100):
        d = _get_json(self.session, "GET", f"{self.BASE}/query/{domain}", headers={"X-API-Key": self.key}, params={"type": "domain", "limit": limit})
        res = (d or {}).get("result") or []
        recs = []
        for e in res:
            src = e.get("source") if isinstance(e.get("source"), dict) else {}
            recs.append({"identifier": mask_identifier(e.get("email") or e.get("username")), "source": str(src.get("name") or "")[:80], "date": str(src.get("breach_date") or "")[:20]})
        return _summary(self.name, (d or {}).get("found") or len(recs), recs, "" if (d or {}).get("success", True) else str((d or {}).get("error") or "The query failed"))


class Snusbase:
    name = "snusbase"
    URL = "https://api.snusbase.com/data/search"

    def __init__(self, api_key, session=None):
        self.key, self.session = api_key, session or requests.Session()

    def test_connection(self):
        d = _get_json(self.session, "GET", "https://api.snusbase.com/data/stats", headers={"Auth": self.key})
        return {"ok": True, "message": "Snusbase key accepted" + (f" ({d['rows']:,} rows indexed)" if isinstance(d, dict) and isinstance(d.get("rows"), int) else "")}

    def lookup_domain(self, domain, limit=100):
        d = _get_json(self.session, "POST", self.URL, headers={"Auth": self.key}, json={"terms": [domain], "types": ["_domain"], "wildcard": False})
        recs = []
        for db, rows in ((d or {}).get("results") or {}).items():
            for e in rows if isinstance(rows, list) else []:
                recs.append({"identifier": mask_identifier(e.get("email") or e.get("username")), "source": str(db)[:80], "date": ""})
        return _summary(self.name, (d or {}).get("size") or len(recs), recs)


LOOKUPS = {"intelx": IntelX, "dehashed": DeHashed, "leakcheck": LeakCheck, "snusbase": Snusbase}
