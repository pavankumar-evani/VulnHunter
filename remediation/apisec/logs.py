"""
Access-log and traffic-record intake: turns what a gateway, load balancer, WAF or proxy already logs into normalised request records.

Quanta does not sit on the network and cannot sniff traffic. This module reads exports and pushed records instead. Accepted shapes:
  * JSON lines or a JSON array of objects (API gateway access logs, WAF logs, proxy logs, a log shipper's output);
  * the common / combined log format (nginx, Apache);
  * CSV with a header row.
Field names are matched through aliases (httpMethod, resourcePath, statusCode, ...), listed in ALIASES. Time units: `latency_ms`, `duration_ms`, `responseLatency` and
`response_time_ms` are milliseconds; `request_time` and `upstream_response_time` are seconds (nginx); a bare `latency`, `duration` or `responseTime` is assumed to be milliseconds.

What is kept: method, a path template (identifiers removed), status, timing, byte counts, a caller identity, the client address, and the NAMES of query parameters,
request fields and response fields. What is never kept: the query-string values, request or response bodies, header values, or a token. A bearer token that is sent
as a field is decoded in memory for its signing algorithm and lifetime and then discarded. Not verified against a live gateway: built against the formats' public
documentation and tested with sample lines.
"""
import base64
import csv
import datetime
import io
import json
import re

from remediation.apisec import classify, paths

ALIASES = {
    "method": ("method", "httpmethod", "http_method", "request_method", "verb", "cs-method", "req_method"),
    "path": ("path", "uri", "url", "request_uri", "request_url", "resourcepath", "route", "endpoint", "cs-uri-stem", "target", "http_path", "requestpath"),
    "request": ("request", "request_line"),
    "host": ("host", "hostname", "http_host", "domainname", "domain", "server_name", "authority", "cs-host", "service"),
    "status": ("status", "status_code", "statuscode", "response_code", "responsecode", "sc-status", "http_status", "code"),
    "latency_ms": ("latency_ms", "duration_ms", "response_time_ms", "responselatency", "latencyms", "elapsed_ms", "upstream_latency_ms"),
    "latency_s": ("request_time", "upstream_response_time", "latency_s", "duration_s", "time_taken_s"),
    "latency_any": ("latency", "duration", "responsetime", "response_time", "elapsed", "time_taken"),
    "bytes_out": ("bytes_out", "response_bytes", "bytes_sent", "body_bytes_sent", "responselength", "response_size", "sc-bytes", "resp_bytes", "bytes", "size"),
    "bytes_in": ("bytes_in", "request_bytes", "request_length", "request_size", "cs-bytes", "req_bytes", "bytes_received"),
    "actor": ("actor", "user", "user_id", "userid", "username", "principal", "sub", "identity", "client_id", "clientid", "caller", "account", "remote_user", "api_key_id"),
    "client_ip": ("client_ip", "clientip", "remote_addr", "remote_ip", "source_ip", "sourceip", "src_ip", "ip", "c-ip", "x_forwarded_for", "true_client_ip", "forwarded_for"),
    "ts": ("ts", "timestamp", "time", "@timestamp", "time_local", "requesttime", "requesttimeepoch", "date", "datetime", "time_iso8601"),
    "auth": ("auth", "auth_type", "authtype", "auth_scheme", "authentication", "authorizer_type", "auth_method"),
    "authorization": ("authorization", "http_authorization", "authorization_header", "bearer"),
    "scheme": ("scheme", "protocol_scheme", "request_scheme", "x_forwarded_proto", "forwarded_proto"),
    "response_fields": ("response_fields", "response_keys", "response_attributes"),
    "request_fields": ("request_fields", "request_keys", "request_attributes"),
    "event": ("security_event", "threat", "waf_event", "attack", "blocked"),
    "waf_action": ("waf_action", "action", "waf_decision", "terminating_rule_action"),
    "rule": ("rule_triggered", "waf_rule", "rule_id", "terminating_rule_id", "signature"),
    "jwt_alg": ("jwt_alg", "token_alg"),
    "jwt_exp": ("jwt_exp", "token_exp"),
    "jwt_iat": ("jwt_iat", "token_iat"),
    "sample": ("response_sample", "response_body_sample", "sample"),
    "dest_exposure": ("dest_exposure", "destination_exposure", "upstream_exposure"),
    "source_service": ("source_service", "caller_service", "client_service", "from_service"),
}
_REV = {}
for _k, _names in ALIASES.items():
    for _n in _names:
        _REV.setdefault(_n, _k)

_CLF = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?')
_REQLINE = re.compile(r"^([A-Za-z]{3,10})\s+(\S+)")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
AUTH_NAMES = {"none": "none", "anonymous": "none", "unauthenticated": "none", "": "none", "-": "none", "bearer": "bearer", "jwt": "bearer", "oauth2": "oauth2", "oauth": "oauth2", "oidc": "oauth2",
              "basic": "basic", "api-key": "api-key", "apikey": "api-key", "api_key": "api-key", "key": "api-key", "cookie": "cookie", "session": "cookie", "mtls": "mtls", "cert": "mtls",
              "iam": "iam", "sigv4": "iam", "aws_iam": "iam", "custom": "custom", "lambda": "custom"}


class LogError(ValueError):
    pass


def _key(name):
    return re.sub(r"[^a-z0-9_@\-]", "", str(name).strip().lower().replace(" ", "_"))


def _num(v):
    try:
        if v in (None, "", "-"):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_time(v):
    if v in (None, "", "-"):
        return None
    try:
        n = float(v)
        if n > 1e11:
            n /= 1000.0
        return datetime.datetime.fromtimestamp(n, datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    s = str(v).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            d = datetime.datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _b64(seg):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8"))


def jwt_posture(token):
    """What a JWT's own header and claims say about it, decoded WITHOUT verification and discarded. None when it is not a JWT."""
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        return None
    try:
        head, claims = _b64(parts[0]), _b64(parts[1])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(head, dict) or not isinstance(claims, dict):
        return None
    exp, iat = _num(claims.get("exp")), _num(claims.get("iat"))
    life = round((exp - iat) / 3600.0, 2) if exp is not None and iat is not None and exp >= iat else None
    return {"alg": str(head.get("alg", "")).lower() or None, "has_exp": exp is not None, "has_iat": iat is not None, "lifetime_hours": life,
            "key_url_header": any(h in head for h in ("jku", "x5u", "jwk")), "has_kid": "kid" in head, "has_aud": "aud" in claims, "has_iss": "iss" in claims}


def _auth_from(raw, fields):
    """(auth label or None, jwt posture or None). None means the log does not say; 'none' is only returned on explicit evidence."""
    jwt = None
    if fields.get("jwt_alg"):
        jwt = {"alg": str(fields["jwt_alg"]).lower(), "has_exp": _num(fields.get("jwt_exp")) is not None, "has_iat": _num(fields.get("jwt_iat")) is not None, "lifetime_hours": None,
               "key_url_header": False, "has_kid": False, "has_aud": False, "has_iss": False}
        e, i = _num(fields.get("jwt_exp")), _num(fields.get("jwt_iat"))
        if e is not None and i is not None and e >= i:
            jwt["lifetime_hours"] = round((e - i) / 3600.0, 2)
    label = None
    if "auth" in fields:
        v = str(fields["auth"]).strip().lower()
        label = AUTH_NAMES.get(v, v[:24] or "none")
    if "authorization" in fields:
        header = str(fields["authorization"]).strip()
        scheme, _, rest = header.partition(" ")
        low = scheme.lower()
        if not header or header == "-":
            label = label or "none"
        elif low == "bearer" or header.count(".") == 2:
            label = "bearer"
            jwt = jwt or jwt_posture(rest if low == "bearer" else header)
        elif low == "basic":
            label = "basic"
        else:
            label = label or AUTH_NAMES.get(low, low[:24])
    return label, jwt


def _split_request(v):
    m = _REQLINE.match(str(v or "").strip())
    return (m.group(1).upper(), m.group(2)) if m else (None, None)


def normalise(raw, default_host=None):
    """One raw record (dict) -> the normalised request record. Raises LogError when it cannot be a request."""
    if not isinstance(raw, dict):
        raise LogError("not an object")
    fields = {}
    for k, v in raw.items():
        canon = _REV.get(_key(k))
        if canon and canon not in fields and v is not None:
            fields[canon] = v
    method, target = str(fields.get("method") or "").strip().upper(), fields.get("path")
    if not target and fields.get("request"):
        m, target = _split_request(fields["request"])
        method = method or m
    if not method or method not in _METHODS:
        if fields.get("request"):
            method = _split_request(fields["request"])[0] or method
    if method not in _METHODS:
        raise LogError("no HTTP method")
    if not target:
        raise LogError("no path")
    target = str(target)
    host = str(fields.get("host") or "").strip() or None
    if "://" in target:
        from urllib.parse import urlsplit
        u = urlsplit(target)
        host = host or u.hostname
        target = (u.path or "/") + (("?" + u.query) if u.query else "")
    path, qnames = paths.split_url(target)
    status = _num(fields.get("status"))
    status = int(status) if status is not None and 100 <= status <= 599 else None
    lat = _num(fields.get("latency_ms"))
    if lat is None and _num(fields.get("latency_s")) is not None:
        lat = _num(fields["latency_s"]) * 1000.0
    if lat is None:
        lat = _num(fields.get("latency_any"))
    if lat is not None and lat < 0:
        lat = None
    auth, jwt = _auth_from(raw, fields)
    ip = str(fields.get("client_ip") or "").split(",")[0].strip() or None
    actor = str(fields.get("actor") or "").strip()
    actor = None if actor in ("", "-", "null", "None", "anonymous") else actor[:200]
    scheme = str(fields.get("scheme") or "").lower().split(",")[0].strip() or None
    wafa = str(fields.get("waf_action") or "").strip().lower()
    event = bool(fields.get("event") not in (None, "", False, 0, "0", "false", "False", "-")) or wafa in ("block", "blocked", "count", "deny", "challenge", "captcha") or bool(fields.get("rule"))

    detected, sample_names = {}, []
    if isinstance(fields.get("sample"), (dict, list)):
        detected, sample_names = classify.detect_sample(fields["sample"])  # classified in memory; the values are dropped here

    def names(v):
        if isinstance(v, str):
            v = [x.strip() for x in v.split(",")]
        return [str(x)[:80] for x in (v or []) if str(x).strip()][:100] if isinstance(v, (list, tuple, set)) else []
    return {"method": method, "path": paths.normalise_path(path), "query_params": qnames[:30], "host": (host or default_host or "").lower() or None, "status": status,
            "latency_ms": lat, "bytes_in": int(_num(fields.get("bytes_in")) or 0), "bytes_out": int(_num(fields.get("bytes_out")) or 0), "actor": actor, "client_ip": ip,
            "auth": auth, "jwt": jwt, "ts": parse_time(fields.get("ts")), "scheme": scheme if scheme in ("http", "https") else None,
            "response_fields": sorted(set(names(fields.get("response_fields")) + sample_names))[:200], "detected": detected, "request_fields": names(fields.get("request_fields")), "security_event": event,
            "rule": str(fields.get("rule") or "")[:80] or None, "dest_exposure": str(fields.get("dest_exposure") or "").lower() or None,
            "source_service": str(fields.get("source_service") or "").strip()[:120] or None}


def _clf(line):
    m = _CLF.match(line)
    if not m:
        raise LogError("not a recognised log line")
    ip, user, ts, request, status, size = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
    return {"client_ip": ip, "remote_user": None if user == "-" else user, "ts": ts, "request": request, "status": status, "bytes_out": None if size == "-" else size}


def detect_format(text):
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("["):
        return "json"
    if first.startswith("{"):
        if text.lstrip().startswith("{") and chr(10) not in text.strip():
            try:
                doc = json.loads(text)
                if isinstance(doc, dict) and any(isinstance(doc.get(k), list) for k in ("records", "items", "logs")):
                    return "json"
            except ValueError:
                pass
        return "jsonl"
    if _CLF.match(first):
        return "clf"
    return "csv"


def parse(data, fmt=None, default_host=None, max_records=500000):
    """-> (records, stats) where stats = {format, read, skipped, reasons}. Raises LogError for an empty or unreadable input."""
    text = data.decode("utf-8-sig", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    if not text.strip():
        raise LogError("The upload is empty")
    fmt = fmt or detect_format(text)
    if fmt not in ("json", "jsonl", "clf", "csv"):
        raise LogError("format must be json, jsonl, clf or csv")
    stats = {"format": fmt, "read": 0, "skipped": 0, "reasons": {}}
    out = []

    def add(raw):
        stats["read"] += 1
        try:
            out.append(normalise(raw, default_host))
        except LogError as exc:
            stats["skipped"] += 1
            stats["reasons"][str(exc)] = stats["reasons"].get(str(exc), 0) + 1

    if fmt == "json":
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise LogError(f"Not valid JSON: {str(exc)[:100]}") from exc
        if isinstance(doc, dict):
            doc = doc.get("records") or doc.get("items") or doc.get("logs") or [doc]
        for raw in doc:
            if len(out) + stats["skipped"] >= max_records:
                break
            add(raw)
    elif fmt == "jsonl":
        for line in text.splitlines():
            if not line.strip():
                continue
            if len(out) + stats["skipped"] >= max_records:
                break
            try:
                add(json.loads(line))
            except ValueError:
                stats["read"] += 1
                stats["skipped"] += 1
                stats["reasons"]["not valid JSON"] = stats["reasons"].get("not valid JSON", 0) + 1
    elif fmt == "clf":
        for line in text.splitlines():
            if not line.strip():
                continue
            if len(out) + stats["skipped"] >= max_records:
                break
            try:
                add(_clf(line.strip()))
            except LogError as exc:
                stats["read"] += 1
                stats["skipped"] += 1
                stats["reasons"][str(exc)] = stats["reasons"].get(str(exc), 0) + 1
    else:
        for row in csv.DictReader(io.StringIO(text)):
            if len(out) + stats["skipped"] >= max_records:
                break
            add(row)
    if not out:
        raise LogError("No request records could be read" + (f" ({', '.join(f'{k}: {v}' for k, v in list(stats['reasons'].items())[:3])})" if stats["reasons"] else ""))
    return out, stats
