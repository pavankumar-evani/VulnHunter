"""
Sensitive-data detection and your own classification framework.

Two separate questions, deliberately kept apart:
  1. WHAT KIND of data is this field or value? Answered by explicit detectors in api_security.yaml (email, payment card, national identifier, ...). A field is
     matched on its whole name or on one whole word of its name (camelCase, snake_case and kebab-case are split); a sampled value is matched by a regular
     expression, and a card number must also pass the Luhn checksum. Values are classified in memory and never stored.
  2. HOW SENSITIVE is that kind of data HERE? Answered only by your own classification framework: classes you import (name, priority where 1 is the most
     sensitive, the detectors that belong to the class, and any field-name patterns of your own such as a loyalty-programme id). Quanta ships no framework. A
     detector that maps to none of your classes is reported as "unclassified": never assumed sensitive and never assumed harmless.
"""
import csv
import io
import json
import re

from remediation.apisec import config

_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def tokens(name):
    return [t.lower() for t in _SPLIT.split(str(name)) if t]


def compact(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def luhn_ok(digits):
    d = [int(c) for c in re.sub(r"\D", "", str(digits))]
    if not 12 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detectors():
    return config.load().get("detectors") or []


def _index():
    exact, word = {}, {}
    for d in detectors():
        for f in d.get("fields") or []:
            exact.setdefault(compact(f), set()).add(d["id"])
            if len(tokens(f)) == 1:
                word.setdefault(tokens(f)[0], set()).add(d["id"])
    return exact, word


def detect_fields(names):
    """{detector id: [field names]} for a list of field names. An exact name wins over a word of it (ip_address is an IP, not a postal address)."""
    exact, word = _index()
    found = {}
    for n in names or []:
        ids = exact.get(compact(n))
        if not ids:
            ids = set()
            for t in tokens(n):
                ids |= word.get(t, set())
        for i in ids:
            found.setdefault(i, []).append(str(n))
    return found


def detect_value(value):
    out = set()
    if not isinstance(value, str) or not value or len(value) > 200:
        return out
    for d in detectors():
        rx = d.get("value")
        if rx and re.search(rx, value):
            if d.get("luhn") and not luhn_ok(value):
                continue
            out.add(d["id"])
    return out


def detect_sample(sample, depth=0):
    """({detector id: count}, [field names]) from a sampled payload (a dict or list). The values are classified in memory and dropped."""
    counts, names = {}, set()

    def walk(node, d):
        if d > 5:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                names.add(str(k)[:80])
                if isinstance(v, (dict, list)):
                    walk(v, d + 1)
                else:
                    for i in detect_value(v if isinstance(v, str) else str(v)):
                        counts[i] = counts.get(i, 0) + 1
        elif isinstance(node, list):
            for v in node[:50]:
                walk(v, d + 1)
    walk(sample, depth)
    return counts, sorted(names)[:200]


# ---------------------------------------------------------------- your framework
def parse_framework(text, fmt=None):
    """Classes from JSON ({"classes": [...]} or a list) or CSV (name,priority,description,detectors,field_patterns; lists separated by ;). Raises ValueError."""
    text = (text.decode("utf-8-sig", "replace") if isinstance(text, (bytes, bytearray)) else str(text)).strip()
    if not text:
        raise ValueError("The framework is empty")
    fmt = fmt or ("json" if text[:1] in "[{" else "csv")
    if fmt == "json":
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"Not valid JSON: {str(exc)[:100]}") from exc
        rows = doc.get("classes") if isinstance(doc, dict) else doc
        if not isinstance(rows, list):
            raise ValueError("Expected a list of classes, or an object with a 'classes' list")
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
    known = {d["id"] for d in detectors()}
    out, seen = [], set()
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict):
            raise ValueError(f"Class {i}: expected an object")
        r = {str(k).strip().lower(): v for k, v in r.items()}
        name = str(r.get("name") or "").strip()
        if not name or len(name) > 80:
            raise ValueError(f"Class {i}: a name of 1 to 80 characters is required")
        if name.lower() in seen:
            raise ValueError(f"Class '{name}' appears twice")
        seen.add(name.lower())
        try:
            prio = int(str(r.get("priority")).strip())
        except (TypeError, ValueError):
            raise ValueError(f"Class '{name}': priority must be a whole number (1 is the most sensitive)") from None
        if not 1 <= prio <= 99:
            raise ValueError(f"Class '{name}': priority must be between 1 and 99")

        def lst(v):
            if isinstance(v, str):
                v = [x for x in re.split(r"[;|]", v)]
            return [str(x).strip() for x in (v or []) if str(x).strip()]
        dets = [d.lower() for d in lst(r.get("detectors"))]
        bad = [d for d in dets if d not in known]
        if bad:
            raise ValueError(f"Class '{name}': unknown detector(s) {', '.join(bad)}; known: {', '.join(sorted(known))}")
        pats = [compact(p) for p in lst(r.get("field_patterns"))][:30]
        if any(not p or len(p) > 80 for p in pats):
            raise ValueError(f"Class '{name}': field patterns must be 1 to 80 letters or digits")
        out.append({"name": name, "priority": prio, "description": str(r.get("description") or "")[:300] or None, "detectors": sorted(set(dets)), "field_patterns": sorted(set(pats))})
    if not out:
        raise ValueError("The framework has no classes")
    return out


def class_of(detector_id, fields, classes):
    """The most sensitive of your classes (lowest priority number) that a detector or any of its fields belongs to, or None."""
    best = None
    for c in classes:
        hit = detector_id in c["detectors"] or any(p in compact(f) for f in fields or [] for p in c["field_patterns"])
        if hit and (best is None or c["priority"] < best["priority"]):
            best = c
    return best


def pattern_hits(names, classes):
    """{class name: [field names]} for fields that match a class's own field patterns (data kinds only you know about)."""
    out = {}
    for c in classes:
        for n in names or []:
            if any(p in compact(n) for p in c["field_patterns"]):
                out.setdefault(c["name"], []).append(str(n))
    return out


def assess_data(observed, names, classes):
    """What an endpoint's observed data means under your framework.
    observed: {detector id: count or fields}; names: all response field names. Returns {classes: [{name, priority, via}], unclassified: [detector ids], top_priority}."""
    by_class, unclassified = {}, []
    fields = detect_fields(names)
    for det in set(observed or {}) | set(fields):
        c = class_of(det, fields.get(det, []), classes)
        if c:
            by_class.setdefault(c["name"], {"name": c["name"], "priority": c["priority"], "via": []})["via"].append(det)
        else:
            unclassified.append(det)
    for cname, flds in pattern_hits(names, classes).items():
        c = next(x for x in classes if x["name"] == cname)
        by_class.setdefault(cname, {"name": cname, "priority": c["priority"], "via": []})["via"].append("field:" + ",".join(sorted(set(flds))[:3]))
    cls = sorted(by_class.values(), key=lambda x: (x["priority"], x["name"]))
    return {"classes": cls, "unclassified": sorted(unclassified), "top_priority": cls[0]["priority"] if cls else None}
