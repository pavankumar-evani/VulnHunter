"""
Turning concrete request paths into endpoint templates, and matching them to a specification's templates.

An endpoint is identified by (service, method, path key). The path key replaces every identifier segment with `{}` so `/users/123/orders`, `/users/{id}/orders`
and `/users/{userId}/orders` are one endpoint. A segment is treated as an identifier when it is all digits, a UUID, a long hexadecimal or base-64 style token,
or contains digits mixed with letters at a length no word has. The heuristic is deliberately conservative: when a specification names the real template, the
observed path is matched to it instead (a literal segment such as `me` against a `{id}` parameter matches the parameter).
"""
import re
from urllib.parse import parse_qsl, urlsplit

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_-]{16,}$")
_PARAM = re.compile(r"^\{[^{}]*\}$")
_COLON = re.compile(r"^:[A-Za-z_][A-Za-z0-9_]*$")


def is_identifier(segment):
    s = segment.strip()
    if not s:
        return False
    return bool(s.isdigit() or _UUID.match(s) or _HEX.match(s) or _TOKEN.match(s))


def split_url(raw):
    """(path, query-parameter names) from a path, a path with a query, or a full URL."""
    raw = (raw or "").strip()
    parts = urlsplit(raw if "://" in raw else "//x" + raw if not raw.startswith("/") else raw)
    path = parts.path or "/"
    names = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    return path, names


def normalise_path(path):
    path = re.sub(r"/{2,}", "/", path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path if path.startswith("/") else "/" + path


def key_of(path):
    """The comparison key: every parameter or identifier segment becomes {}."""
    segs = [s for s in normalise_path(path).split("/")[1:]]
    return "/" + "/".join("{}" if (_PARAM.match(s) or _COLON.match(s) or is_identifier(s)) else s for s in segs) if segs != [""] else "/"


def template_of(path):
    """A readable template for an observed path: identifiers become {id}."""
    segs = normalise_path(path).split("/")[1:]
    if segs == [""]:
        return "/"
    return "/" + "/".join("{id}" if is_identifier(s) else s for s in segs)


def match_spec(path, spec_keys):
    """The spec key an observed concrete path belongs to, or None. Prefers the template with the most literal segments."""
    segs = normalise_path(path).split("/")[1:]
    best, best_lit = None, -1
    for k in spec_keys:
        ks = k.split("/")[1:]
        if len(ks) != len(segs):
            continue
        if all(a == "{}" or a == b for a, b in zip(ks, segs)):
            lit = sum(1 for a in ks if a != "{}")
            if lit > best_lit:
                best, best_lit = k, lit
    return best


def resolve(path, spec_keys=()):
    """(path key, object ids in the path) for an observed path."""
    path = normalise_path(path)
    segs = path.split("/")[1:]
    heuristic = key_of(path)
    spec_keys = set(spec_keys)
    chosen = heuristic if heuristic in spec_keys else (match_spec(path, spec_keys) or heuristic)
    ids = [s for s, k in zip(segs, chosen.split("/")[1:]) if k == "{}" and s]
    return chosen, ids


_ID_NAME = re.compile(r"^(id|uuid|guid)$|_id$", re.I)
_CAMEL_ID = re.compile(r"[a-z]Id$")


def has_object_id(key, params=()):
    """Does the endpoint address a single object: an identifier segment in the path, or an id-like parameter name?"""
    return "{}" in key.split("/") or any((_ID_NAME.search(str(p)) or _CAMEL_ID.search(str(p))) and len(str(p)) > 1 for p in params)
