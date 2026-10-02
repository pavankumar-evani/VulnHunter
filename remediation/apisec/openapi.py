"""
Reads an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML) into the endpoints it documents.

Only what the document says is reported. An operation with no `security` anywhere is `unspecified` (the spec is silent), which is different from an operation
that explicitly sets `security: []` (declared open). Response and request field names are collected from the schemas (references followed, cycles and depth
bounded) so the documented data can be compared with the data actually observed in traffic.
"""
import json
import re
from urllib.parse import urlsplit

import yaml

from remediation.apisec import paths

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
MAX_BYTES = 5 * 1024 * 1024
MAX_ENDPOINTS = 5000
_ALIAS = re.compile(r"(?m)[\s:\[,\-]\*[A-Za-z0-9_-]+")


class SpecError(ValueError):
    pass


def parse_text(text):
    if not isinstance(text, str):
        text = text.decode("utf-8", "replace")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise SpecError("A specification may be at most 5 MB")
    stripped = text.lstrip("\ufeff \t\r\n")
    try:
        if stripped[:1] in ("{", "["):
            doc = json.loads(stripped)
        else:
            if len(_ALIAS.findall(stripped)) > 100:
                raise SpecError("The YAML uses an unreasonable number of aliases")
            doc = yaml.safe_load(stripped)
    except (ValueError, yaml.YAMLError) as exc:
        if isinstance(exc, SpecError):
            raise
        raise SpecError(f"Not valid JSON or YAML: {str(exc)[:120]}") from exc
    if not isinstance(doc, dict) or not (doc.get("openapi") or doc.get("swagger")) or not isinstance(doc.get("paths"), dict):
        raise SpecError("Not an OpenAPI or Swagger document (needs an 'openapi' or 'swagger' version and a 'paths' object)")
    return doc


def _ref(doc, node, depth=0):
    while isinstance(node, dict) and "$ref" in node and depth < 8:
        ref = str(node["$ref"])
        if not ref.startswith("#/"):
            return {}
        cur = doc
        for part in ref[2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(cur, dict) else None
        node, depth = cur, depth + 1
    return node if isinstance(node, dict) else {}


def _fields(doc, schema, seen=None, depth=0, out=None):
    out = set() if out is None else out
    seen = seen or set()
    if depth > 6 or len(out) > 300 or not isinstance(schema, dict):
        return out
    if "$ref" in schema:
        if schema["$ref"] in seen:
            return out
        seen = seen | {schema["$ref"]}
        schema = _ref(doc, schema)
    for sub in list(schema.get("allOf") or []) + list(schema.get("oneOf") or []) + list(schema.get("anyOf") or []):
        _fields(doc, sub, seen, depth + 1, out)
    if isinstance(schema.get("items"), dict):
        _fields(doc, schema["items"], seen, depth + 1, out)
    for name, sub in (schema.get("properties") or {}).items():
        out.add(str(name))
        _fields(doc, sub if isinstance(sub, dict) else {}, seen, depth + 1, out)
    return out


def _scheme_label(sch):
    t = str(sch.get("type", "")).lower()
    if t == "http":
        return {"bearer": "bearer", "basic": "basic"}.get(str(sch.get("scheme", "")).lower(), "http-" + str(sch.get("scheme", "")).lower())
    return {"apikey": "api-key", "oauth2": "oauth2", "openidconnect": "oidc", "mutualtls": "mtls", "basic": "basic"}.get(t, t or "unknown")


def _auth(doc, op, schemes):
    """('none' | 'unspecified' | 'declared', [labels])"""
    sec = op.get("security", doc.get("security"))
    if sec is None:
        return "unspecified", []
    if sec == []:
        return "none", []
    labels, optional = [], False
    for req in sec:
        if req == {}:
            optional = True
        elif isinstance(req, dict):
            for name in req:
                lab = _scheme_label(schemes[name]) if name in schemes else "unknown"
                if lab not in labels:
                    labels.append(lab)
    if not labels:
        return "none", []
    return "declared", labels + (["optional"] if optional else [])


def parse(text):
    doc = parse_text(text)
    v3 = bool(doc.get("openapi"))
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    servers = []
    if v3:
        servers = [str(s.get("url", "")) for s in doc.get("servers") or [] if isinstance(s, dict)]
    else:
        host = doc.get("host")
        for sch in doc.get("schemes") or ["https"]:
            if host:
                servers.append(f"{sch}://{host}{doc.get('basePath', '')}")
    hosts = sorted({urlsplit(s).hostname for s in servers if "://" in s and urlsplit(s).hostname})
    base_paths = sorted({urlsplit(s).path.rstrip("/") for s in servers if "://" in s} - {""})
    schemes = ((doc.get("components") or {}).get("securitySchemes") if v3 else doc.get("securityDefinitions")) or {}
    schemes = {k: _ref(doc, v) for k, v in schemes.items()}
    plain_http = [s for s in servers if s.lower().startswith("http://")]
    prefix = base_paths[0] if len(base_paths) == 1 else ""
    endpoints = []
    for raw_path, item in doc["paths"].items():
        item = _ref(doc, item)
        if not str(raw_path).startswith("/"):
            continue
        full = paths.normalise_path(prefix + raw_path) if prefix else paths.normalise_path(raw_path)
        shared = [_ref(doc, p) for p in item.get("parameters") or []]
        for m in METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = shared + [_ref(doc, p) for p in op.get("parameters") or []]
            where = {"path": [], "query": [], "header": [], "cookie": []}
            req_fields, resp_fields = set(), set()
            for p in params:
                loc = p.get("in")
                if loc in where and p.get("name"):
                    where[loc].append(str(p["name"]))
                if loc == "body":
                    _fields(doc, p.get("schema") or {}, out=req_fields)
            if v3:
                body = _ref(doc, op.get("requestBody"))
                for mt in (body.get("content") or {}).values():
                    _fields(doc, (mt or {}).get("schema") or {}, out=req_fields)
                for resp in (op.get("responses") or {}).values():
                    for mt in (_ref(doc, resp).get("content") or {}).values():
                        _fields(doc, (mt or {}).get("schema") or {}, out=resp_fields)
            else:
                for resp in (op.get("responses") or {}).values():
                    _fields(doc, _ref(doc, resp).get("schema") or {}, out=resp_fields)
            state, labels = _auth(doc, op, schemes)
            endpoints.append({"method": m.upper(), "path": full, "key": paths.key_of(full), "summary": str(op.get("summary") or op.get("operationId") or "")[:200],
                              "deprecated": bool(op.get("deprecated")), "auth_state": state, "auth": labels, "params": where, "request_fields": sorted(req_fields)[:200],
                              "response_fields": sorted(resp_fields)[:200], "tags": [str(t) for t in op.get("tags") or []][:5],
                              "exposure_hint": str(op.get("x-exposure") or item.get("x-exposure") or "").lower() or None})
            if len(endpoints) > MAX_ENDPOINTS:
                raise SpecError(f"A specification may document at most {MAX_ENDPOINTS} operations")
    if not endpoints:
        raise SpecError("The document describes no operations")
    return {"title": str(info.get("title") or "")[:200], "version": str(info.get("version") or "")[:60], "openapi": str(doc.get("openapi") or doc.get("swagger")),
            "servers": servers, "hosts": hosts, "base_paths": base_paths, "plain_http_servers": plain_http,
            "security_schemes": {k: _scheme_label(v) for k, v in schemes.items()}, "endpoints": endpoints}
