"""
TAXII 2.1 collection poller - READ-ONLY, for credentialed threat-intelligence platforms (MISP, OpenCTI, Anomali, ThreatConnect and any TAXII 2.1 server).

Implements the documented TAXII 2.1 client calls (OASIS TAXII 2.1, section 5):
  GET <api root>/                                          -> api root information (test_connection)
  GET <api root>/collections/                              -> {"collections": [{"id", "title", "can_read", ...}]}
  GET <api root>/collections/<id>/objects/?added_after=<ts>&match[type]=report&limit=N[&next=<cursor>]
        -> {"more": bool, "next": "...", "objects": [STIX 2.1 objects]}
  Headers: Accept: application/taxii+json;version=2.1; auth is HTTP Basic or `Authorization: Bearer <token>` (or an API-key header for platforms that use one).
This client issues GET requests only; there is no call that adds, changes or deletes an object, a collection or a subscription (a non-GET raises).

Each STIX `report` object becomes one item whose content is a small STIX bundle holding the report and the objects it references that arrived in the same poll
(indicators, threat actors, intrusion sets, attack patterns, vulnerabilities), so the existing extractor (remediation/hunting/intel.py) reads indicators, CVEs, ATT&CK
techniques and actors from it. The `added_after` cursor (the server's X-TAXII-Date-Added-Last, else the newest `added` date seen) is kept per source so each poll
asks only for what is new. Pages are followed up to MAX_PAGES and objects capped at MAX_OBJECTS per poll.

Built against the public TAXII 2.1 and STIX 2.1 specifications and unit-tested against a hand-rolled fake session. It has NOT been exercised against a real TAXII
server; platforms differ in what they put in a `report`'s object_refs.
"""
import json
import uuid

import requests

from remediation.connectors import url_safety

ACCEPT = "application/taxii+json;version=2.1"
MAX_PAGES = 5
MAX_OBJECTS = 2000
PAGE_LIMIT = 200
_CONTEXT_TYPES = {"indicator", "threat-actor", "intrusion-set", "attack-pattern", "vulnerability", "malware", "campaign", "identity", "tool"}


class TaxiiError(RuntimeError):
    pass


class TaxiiConnector:
    def __init__(self, api_root, username=None, password=None, token=None, api_key=None, api_key_header="X-API-Key", verify_tls=True, session=None, timeout=30):
        if not str(api_root or "").lower().startswith(("https://", "http://")):
            raise ValueError("The TAXII API root must be a URL")
        try:
            url_safety.assert_safe_target(api_root)
        except url_safety.UnsafeTargetError as exc:
            raise ValueError(str(exc)) from exc
        self.root, self.timeout = api_root.rstrip("/"), timeout
        self.session = session or url_safety.safe_session()
        self.session.verify = bool(verify_tls)
        self.session.headers["Accept"] = ACCEPT
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif api_key:
            self.session.headers[api_key_header] = api_key
        elif username and password:
            self.session.auth = (username, password)
        self._secrets = (token, api_key, password)

    def _get(self, path, params=None):
        try:
            r = self.session.request("GET", f"{self.root}{path}", params=params, timeout=self.timeout)
            r.raise_for_status()
            return r.json() or {}, r
        except requests.HTTPError as exc:
            code = getattr(exc.response, "status_code", None)
            raise TaxiiError({401: "authentication failed", 403: "the account may not read this collection", 404: "the API root or collection was not found"}.get(code, f"HTTP {code}")) from None
        except requests.RequestException as exc:
            raise TaxiiError(f"the server could not be reached ({type(exc).__name__})") from None
        except ValueError:
            raise TaxiiError("the server did not return JSON") from None

    def test_connection(self):
        d, _ = self._get("/")
        return {"title": d.get("title"), "versions": d.get("versions"), "max_content_length": d.get("max_content_length")}

    def collections(self):
        d, _ = self._get("/collections/")
        return [{"id": c.get("id"), "title": c.get("title"), "can_read": c.get("can_read", True)} for c in d.get("collections") or []]

    def poll(self, collection_id, added_after=None, limit=PAGE_LIMIT):
        """-> {items: [{external_id, title, url, published_at, content}], added_after (the cursor to store), objects_seen, pages}."""
        params = {"match[type]": "report,indicator,threat-actor,intrusion-set,attack-pattern,vulnerability,malware,campaign", "limit": int(limit)}
        if added_after:
            params["added_after"] = added_after
        objects, last_added, pages = [], None, 0
        while pages < MAX_PAGES and len(objects) < MAX_OBJECTS:
            d, resp = self._get(f"/collections/{collection_id}/objects/", params)
            pages += 1
            objects.extend(o for o in d.get("objects") or [] if isinstance(o, dict))
            last_added = (resp.headers or {}).get("X-TAXII-Date-Added-Last") or last_added
            if not d.get("more") or not d.get("next"):
                break
            params = {**params, "next": d["next"]}
        by_id = {o.get("id"): o for o in objects if o.get("id")}
        items = []
        for o in objects:
            if o.get("type") != "report":
                continue
            refs = [by_id[r] for r in o.get("object_refs") or [] if r in by_id and by_id[r].get("type") in _CONTEXT_TYPES][:200]
            bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [o, *refs]}
            items.append({"external_id": f"{o.get('id')}@{o.get('modified') or o.get('created') or ''}", "title": str(o.get("name") or o.get("id"))[:200],
                          "url": next((x.get("url") for x in o.get("external_references") or [] if x.get("url")), ""), "published_at": _stix_ts(o.get("published") or o.get("created")),
                          "content": json.dumps(bundle)})
        return {"items": items, "added_after": last_added or params.get("added_after"), "objects_seen": len(objects), "pages": pages}


def _stix_ts(v):
    if not v:
        return None
    s = str(v).replace("Z", "+00:00")
    try:
        import datetime
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    import datetime as _dt
    d = d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
