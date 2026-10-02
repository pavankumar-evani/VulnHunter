"""
Maps OCSF (Open Cybersecurity Schema Framework) Detection Finding events to Quanta alerts, and pulls the entities out of any alert.

Supported input: OCSF Detection Finding (class_uid 2004) as JSON, one event or a list, which is what an OCSF-emitting SIEM, XDR or
security lake produces. Only the fields Quanta uses are read; everything else is ignored, so a newer schema version still maps.

  external_id   finding_info.uid (falls back to metadata.uid)
  title         finding_info.title
  severity      severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal (shown as Critical); 0 and unknown become Medium
  rule_name     finding_info.analytic.name
  technique     the first finding_info.attacks[].technique.uid (an ATT&CK id)
  asset         resources[0].name, else device.hostname / device.name, else evidences[0].device.hostname
  occurred_at   time (epoch milliseconds) or finding_info.created_time
  entities      host, user, ips, domains, hashes, urls from device, user, src_endpoint / dst_endpoint, file hashes and url fields

This is a subset mapping written from the public schema (https://schema.ocsf.io), not a full validator, and it has not been run against
a live OCSF producer.
"""
import datetime
import ipaddress
import re

SEVERITY = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Critical"}
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|co|us|uk|de|su|cc|tk|ml|ga|cf|gq|online|site|club)\b", re.I)


def empty_entities():
    return {"host": None, "user": None, "ips": [], "domains": [], "hashes": [], "urls": []}


def _add(lst, v):
    if v and v not in lst:
        lst.append(v)


def scan_text(text, ent=None):
    """Adds the indicators found in free text to an entities dict."""
    ent = ent or empty_entities()
    text = text or ""
    for u in _URL.findall(text):
        _add(ent["urls"], u.rstrip(".,;"))
    for m in _IPV4.findall(text):
        try:
            _add(ent["ips"], str(ipaddress.ip_address(m)))
        except ValueError:
            pass
    for h in _HASH.findall(text):
        _add(ent["hashes"], h.lower())
    stripped = _URL.sub(" ", text)
    for d in _DOMAIN.findall(stripped):
        _add(ent["domains"], d.lower())
    return ent


def _first(*vals):
    for v in vals:
        if v:
            return v
    return None


def _endpoint(ep, ent):
    if isinstance(ep, dict):
        _add(ent["ips"], ep.get("ip"))
        if ep.get("hostname") and not ent["host"]:
            ent["host"] = ep["hostname"]


def map_detection_finding(ev):
    """One OCSF event -> an alert dict for hunting.store.receive_alert, or raises ValueError."""
    if not isinstance(ev, dict):
        raise ValueError("An OCSF event must be a JSON object")
    fi = ev.get("finding_info") or {}
    uid = _first(fi.get("uid"), (ev.get("metadata") or {}).get("uid"))
    title = _first(fi.get("title"), ev.get("message"))
    if not uid or not title:
        raise ValueError("The event has no finding_info.uid and finding_info.title")
    sev_id = ev.get("severity_id")
    severity = SEVERITY.get(sev_id) if isinstance(sev_id, int) else None
    severity = severity or (ev.get("severity") if ev.get("severity") in SEVERITY.values() else "Medium")
    attacks = fi.get("attacks") or []
    technique = None
    for a in attacks:
        uid_t = ((a or {}).get("technique") or {}).get("uid")
        if uid_t:
            technique = str(uid_t).upper()
            break
    ent = empty_entities()
    device = ev.get("device") or {}
    ent["host"] = _first(device.get("hostname"), device.get("name"))
    _add(ent["ips"], device.get("ip"))
    for ev_item in ev.get("evidences") or []:
        d = (ev_item or {}).get("device") or {}
        ent["host"] = ent["host"] or _first(d.get("hostname"), d.get("name"))
        _endpoint((ev_item or {}).get("src_endpoint"), ent)
        _endpoint((ev_item or {}).get("dst_endpoint"), ent)
        f = (ev_item or {}).get("file") or {}
        for h in f.get("hashes") or []:
            _add(ent["hashes"], str((h or {}).get("value", "")).lower())
        u = (ev_item or {}).get("url") or {}
        _add(ent["urls"], u.get("url_string"))
        _add(ent["domains"], (ev_item or {}).get("query", {}).get("hostname") if isinstance((ev_item or {}).get("query"), dict) else None)
    _endpoint(ev.get("src_endpoint"), ent)
    _endpoint(ev.get("dst_endpoint"), ent)
    user = ev.get("user") or {}
    ent["user"] = _first(user.get("name"), user.get("uid"), ((ev.get("actor") or {}).get("user") or {}).get("name"))
    resources = ev.get("resources") or []
    asset = _first((resources[0] or {}).get("name") if resources else None, ent["host"])
    t = ev.get("time")
    occurred = None
    if isinstance(t, (int, float)):
        occurred = datetime.datetime.fromtimestamp(t / 1000 if t > 1e11 else t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(fi.get("created_time"), (int, float)):
        ct = fi["created_time"]
        occurred = datetime.datetime.fromtimestamp(ct / 1000 if ct > 1e11 else ct, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    desc = _first(fi.get("desc"), ev.get("message")) or ""
    scan_text(desc, ent)
    return {"external_id": str(uid), "title": str(title), "severity": severity, "asset": asset, "technique": technique, "detail": desc,
            "occurred_at": occurred, "rule_name": _first((fi.get("analytic") or {}).get("name"), (fi.get("analytic") or {}).get("uid")), "entities": ent}
