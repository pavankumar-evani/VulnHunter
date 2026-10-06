"""
ReplaySession: a stand-in for `requests.Session` that answers from recorded vendor-format responses.

Every pull connector takes `session=` (see remediation/connectors/*). Handing it a ReplaySession means
the connector's REAL code runs unchanged - building URLs, sending headers, paging, parsing the vendor's
JSON or XML - and only the transport is replaced. Connecting a real account later changes nothing but
the session.

Contract for a renderer author (remediation/simulation/renderers.py):
  * Build routes: a list of (method, url_regex, handler). `method` is "GET"/"POST"/... or "*" for any.
    `url_regex` is matched with re.search against the URL WITHOUT its query string (anchor it with `$`).
  * handler(req) -> (status, headers, body). `body` may be bytes, str, or a dict/list (sent as JSON
    with a JSON content type). `headers` may be None or {}.
  * `req` is a RequestInfo: .method .url (full, with the query) .path_url (without query) .params
    (query parameters as a dict of str; the first value wins) .json (the parsed JSON body or None)
    .data (the raw body as str or None) .headers (the request headers, session defaults included)
    .match (the regex match, so named groups give path variables) .auth (the session auth).
  * Honour the paging parameters the connector sends (offset/limit/cursor/id_min ...) so multi-page
    code paths really run. Keep page sizes small in the renderer for that reason.
  * An unmatched request raises UnmatchedRequestError naming the method and URL. It never answers 200.
  * `.served` lists every request answered (method, url, params, status), for tests.

The session returns real `requests.Response` objects, so .json(), .text, .content, .raise_for_status(),
.iter_content() and .status_code behave exactly as they do against a live server.
"""
import io
import json as jsonlib
import re
from urllib.parse import parse_qsl, urlsplit

import requests
from requests.structures import CaseInsensitiveDict


class UnmatchedRequestError(RuntimeError):
    """No route in the replay session matches the request: the connector asked for something the simulation does not model."""


class RequestInfo:
    def __init__(self, method, url, path_url, params, json, data, headers, match, auth):
        self.method = method
        self.url = url
        self.path_url = path_url
        self.params = params
        self.json = json
        self.data = data
        self.headers = headers
        self.match = match
        self.auth = auth


class ReplaySession:
    def __init__(self, routes=None, base_headers=None):
        self.routes = [(m.upper(), re.compile(rx), h) for m, rx, h in (routes or [])]
        self.headers = CaseInsensitiveDict(base_headers or {})
        self.auth = None
        self.verify = True
        self.proxies = {}
        self.cert = None
        self.cookies = requests.cookies.RequestsCookieJar()
        self.served = []
        self.closed = False

    def add_route(self, method, url_regex, handler):
        self.routes.append((method.upper(), re.compile(url_regex), handler))

    # -- requests.Session surface -------------------------------------------------
    def mount(self, prefix, adapter):  # a no-op: there is no transport to configure
        return None

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, data=None, json=None, **kw):
        return self.request("POST", url, data=data, json=json, **kw)

    def put(self, url, data=None, **kw):
        return self.request("PUT", url, data=data, **kw)

    def patch(self, url, data=None, **kw):
        return self.request("PATCH", url, data=data, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def request(self, method, url, params=None, data=None, headers=None, json=None, auth=None, **_ignored):
        merged = CaseInsensitiveDict(self.headers)
        merged.update(headers or {})
        prepared = requests.Request(method.upper(), url, params=params, data=data, json=json, headers=merged).prepare()
        parts = urlsplit(prepared.url)
        path_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        query = {}
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            query.setdefault(k, v)
        body = prepared.body
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        parsed_json = None
        if json is not None:
            parsed_json = jsonlib.loads(body) if body else None
        for m, rx, handler in self.routes:
            if m not in ("*", method.upper()):
                continue
            match = rx.search(path_url)
            if not match:
                continue
            info = RequestInfo(method.upper(), prepared.url, path_url, query, parsed_json, body, dict(prepared.headers), match, auth or self.auth)
            status, resp_headers, payload = handler(info)
            self.served.append({"method": method.upper(), "url": prepared.url, "path_url": path_url, "params": query, "json": parsed_json, "status": status})
            return self._response(status, resp_headers, payload, prepared)
        raise UnmatchedRequestError(f"ReplaySession has no route for {method.upper()} {prepared.url}")

    @staticmethod
    def _response(status, headers, payload, prepared):
        resp = requests.Response()
        resp.status_code = int(status)
        resp.headers = CaseInsensitiveDict(headers or {})
        if isinstance(payload, (dict, list)):
            content = jsonlib.dumps(payload).encode("utf-8")
            resp.headers.setdefault("Content-Type", "application/json")
        elif isinstance(payload, str):
            content = payload.encode("utf-8")
        else:
            content = payload or b""
        resp._content = content
        resp._content_consumed = True
        resp.raw = io.BytesIO(content)
        resp.url = prepared.url
        resp.encoding = "utf-8"
        resp.reason = {200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                       404: "Not Found", 429: "Too Many Requests", 500: "Internal Server Error"}.get(resp.status_code, "")
        resp.request = prepared
        return resp
