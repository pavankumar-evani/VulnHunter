"""
Report feed reader - reads threat-intelligence REPORT feeds (vendor blogs, CISA advisories, any feed URL an administrator adds): RSS 2.0, Atom 1.0 and
JSON (JSON Feed 1.x, or a plain list / {"reports": [...]} of objects with a title and text).

What it does and does not do:
  * https only, and the address goes through the SSRF guard (url_safety) at construction and on every redirect hop (safe_session); a feed on a loopback,
    link-local or cloud-metadata address is refused. Nothing is sent but a GET (with If-None-Match / If-Modified-Since when the previous poll gave an ETag or
    Last-Modified, so an unchanged feed costs one cheap 304).
  * The body is capped (DEFAULT_MAX_BYTES), read as a stream, and a feed that exceeds it is refused rather than truncated. XML with a DOCTYPE or ENTITY
    declaration is refused (it is never needed for a feed, and is the way entity-expansion attacks arrive).
  * Items come back as {external_id, title, url, published_at, content}. `content` is the item's own text with markup stripped; the connector does NOT follow the
    item's link to fetch the full article, so a feed that publishes only a teaser gives Quanta only the teaser to extract indicators from (the analyst can paste
    the full report on the Intel tab).
  * Credentialed platforms are the TAXII connector's job (taxii_connector.py), not this one: this reader sends no credentials.

Built against the public RSS 2.0, Atom (RFC 4287) and JSON Feed specifications and unit-tested against a hand-rolled fake session. It has NOT been run against a
live vendor feed.
"""
import datetime
import email.utils
import hashlib
import html
import json
import re
import xml.etree.ElementTree as ET

from remediation.connectors import url_safety

DEFAULT_MAX_BYTES = 2_000_000
DEFAULT_MAX_ITEMS = 50
USER_AGENT = "Quanta-report-watcher/1 (+read-only)"
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_ATOM = "{http://www.w3.org/2005/Atom}"
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}"


class FeedError(RuntimeError):
    pass


def strip_markup(text):
    return _WS.sub(" ", html.unescape(_TAG.sub(" ", text or ""))).strip()


def _iso(value):
    """Any common feed date -> 'YYYY-MM-DDTHH:MM:SSZ', or None."""
    if not value:
        return None
    value = str(value).strip()
    d = None
    try:
        d = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        d = None
    if d is None:
        try:
            d = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ext_id(*parts):
    return hashlib.sha256("|".join(p or "" for p in parts).encode("utf-8", "replace")).hexdigest()[:32]


def _text(el, *names):
    for n in names:
        found = el.find(n)
        if found is not None and (found.text or len(found)):
            return "".join(found.itertext()).strip() if len(found) else (found.text or "").strip()
    return ""


def parse_xml(raw):
    if b"<!doctype" in raw[:20000].lower() or b"<!entity" in raw[:20000].lower():
        raise FeedError("The feed declares a DOCTYPE or ENTITY, which a feed never needs; it was refused")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise FeedError(f"The feed is not valid XML ({str(exc)[:80]})") from None
    items = []
    if root.tag == f"{_ATOM}feed":
        for e in root.findall(f"{_ATOM}entry"):
            link = ""
            for l in e.findall(f"{_ATOM}link"):
                if l.get("rel") in (None, "alternate"):
                    link = l.get("href") or ""
                    break
            title = _text(e, f"{_ATOM}title")
            body = strip_markup(_text(e, f"{_ATOM}content", f"{_ATOM}summary"))
            eid = _text(e, f"{_ATOM}id") or link or title
            items.append({"external_id": eid[:300], "title": strip_markup(title), "url": link, "published_at": _iso(_text(e, f"{_ATOM}published", f"{_ATOM}updated")), "content": body})
        return "atom", items
    if root.tag in ("rss", "channel") or root.tag.endswith("RDF"):
        nodes = root.findall(".//item")
        for e in nodes:
            title, link = _text(e, "title"), _text(e, "link")
            body = strip_markup(_text(e, f"{_CONTENT}encoded") or _text(e, "description"))
            guid = _text(e, "guid") or link or title
            date = _text(e, "pubDate", "{http://purl.org/dc/elements/1.1/}date")
            items.append({"external_id": guid[:300], "title": strip_markup(title), "url": link, "published_at": _iso(date), "content": body})
        return "rss", items
    raise FeedError("The document is not an RSS or Atom feed")


def parse_json(raw):
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise FeedError("The feed is not valid JSON") from None
    if isinstance(doc, dict):
        rows = doc.get("items") or doc.get("reports") or doc.get("entries") or doc.get("data")
        fmt = "jsonfeed" if "items" in doc else "json"
    else:
        rows, fmt = doc, "json"
    if not isinstance(rows, list):
        raise FeedError("The JSON has no list of items or reports")
    items = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        title = str(r.get("title") or r.get("name") or "")
        body = strip_markup(str(r.get("content_text") or r.get("content_html") or r.get("content") or r.get("summary") or r.get("description") or ""))
        url = str(r.get("url") or r.get("link") or r.get("external_url") or "")
        eid = str(r.get("id") or r.get("guid") or url or _ext_id(title, body))
        items.append({"external_id": eid[:300], "title": strip_markup(title), "url": url, "published_at": _iso(r.get("date_published") or r.get("published") or r.get("date") or r.get("pubDate") or r.get("created")),
                      "content": body})
    return fmt, items


class ReportFeedConnector:
    def __init__(self, url, session=None, max_bytes=DEFAULT_MAX_BYTES, max_items=DEFAULT_MAX_ITEMS, timeout=20):
        if not str(url or "").lower().startswith("https://"):
            raise ValueError("A report feed address must start with https://")
        try:
            url_safety.assert_safe_target(url)
        except url_safety.UnsafeTargetError as exc:
            raise ValueError(str(exc)) from exc
        self.url, self.max_bytes, self.max_items, self.timeout = url, int(max_bytes), int(max_items), timeout
        self.session = session or url_safety.safe_session()

    def _get(self, headers):
        resp = self.session.get(self.url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/feed+json, application/json, application/xml;q=0.9, */*;q=0.5", **headers},
                                timeout=self.timeout, stream=True)
        try:
            if resp.status_code == 304:
                return resp, b""
            resp.raise_for_status()
            declared = int((resp.headers or {}).get("Content-Length") or 0)
            if declared > self.max_bytes:
                raise FeedError(f"The feed is {declared} bytes, over the {self.max_bytes}-byte limit")
            buf = bytearray()
            for chunk in resp.iter_content(65536):
                buf.extend(chunk)
                if len(buf) > self.max_bytes:
                    raise FeedError(f"The feed is larger than the {self.max_bytes}-byte limit")
            return resp, bytes(buf)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()

    def fetch(self, etag=None, last_modified=None):
        """-> {status: ok|not-modified, format, items (newest first, at most max_items), etag, last_modified}. Raises FeedError or requests errors."""
        cond = {}
        if etag:
            cond["If-None-Match"] = etag
        if last_modified:
            cond["If-Modified-Since"] = last_modified
        resp, raw = self._get(cond)
        if resp.status_code == 304:
            return {"status": "not-modified", "format": None, "items": [], "etag": etag, "last_modified": last_modified}
        h = resp.headers or {}
        stripped = raw.lstrip()
        fmt, items = parse_json(raw) if stripped[:1] in (b"{", b"[") else parse_xml(raw)
        items.sort(key=lambda i: i["published_at"] or "", reverse=True)
        return {"status": "ok", "format": fmt, "items": items[: self.max_items], "etag": h.get("ETag"), "last_modified": h.get("Last-Modified")}

    def test_connection(self):
        r = self.fetch()
        return {"format": r["format"], "items": len(r["items"]), "newest": (r["items"][0]["title"][:120] if r["items"] else None)}
