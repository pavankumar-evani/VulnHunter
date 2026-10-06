"""
Firewall rules in one shape, and parsers that read them from what firewalls actually export.

A normalised rule:
  device, key (stable id on the device), position (order; first match wins), name, action ('allow' or 'deny'), enabled, log,
  src_zones / dst_zones, sources / destinations (lists: 'any', an address or CIDR, or an object name), services (list of 'tcp/443', 'udp/53',
  'tcp/1000-2000', 'any', or an application name), hits (int or None when the device did not say), last_hit, created, modified,
  owner, comment, expires.

Parsers: a generic CSV (column names matched case-insensitively against the aliases below, which cover common Palo Alto and FortiGate CSV
exports), JSON (a list of rules already in this shape), PAN-OS configuration XML (rulebase security rules) and FortiGate `config firewall policy`
text. They are written from the vendors' documented formats and tested against hand-written samples; none has been run against a real export,
and address or service OBJECTS are kept by name rather than resolved, because an export of rules alone does not contain them.
"""
import csv
import io
import ipaddress
import json
import re
from remediation.utils import safe_xml

ALIASES = {
    "name": ("name", "rule name", "rule", "policy name", "policy"),
    "key": ("id", "rule id", "policy id", "uuid", "key", "no.", "no", "seq"),
    "action": ("action", "rule action"),
    "enabled": ("enabled", "status", "disabled"),
    "log": ("log", "logging", "log at session end", "logtraffic", "log end"),
    "src_zones": ("source zone", "from zone", "from", "srcintf", "source interface", "src zone"),
    "dst_zones": ("destination zone", "to zone", "to", "dstintf", "destination interface", "dst zone"),
    "sources": ("source", "source address", "src", "srcaddr", "source addresses", "src address"),
    "destinations": ("destination", "destination address", "dst", "dstaddr", "destination addresses", "dst address"),
    "services": ("service", "services", "application", "ports", "port"),
    "hits": ("hit count", "hits", "rule usage hit count", "hit_count"),
    "last_hit": ("last hit", "last hit date", "last used", "last_hit"),
    "created": ("created", "creation date", "created date"),
    "modified": ("modified", "last modified", "last changed", "modified date"),
    "owner": ("owner", "rule owner", "tags", "tag", "contact"),
    "comment": ("comment", "comments", "description", "note", "notes"),
    "expires": ("expires", "expiry", "expiration", "schedule end", "valid until"),
}
WELL_KNOWN = {"ssh": "tcp/22", "telnet": "tcp/23", "ftp": "tcp/21", "smtp": "tcp/25", "dns": "udp/53", "http": "tcp/80", "https": "tcp/443", "pop3": "tcp/110", "imap": "tcp/143",
              "smb": "tcp/445", "rdp": "tcp/3389", "ms-rdp": "tcp/3389", "mysql": "tcp/3306", "mssql": "tcp/1433", "postgres": "tcp/5432", "postgresql": "tcp/5432", "ntp": "udp/123",
              "snmp": "udp/161", "ldap": "tcp/389", "ldaps": "tcp/636", "tftp": "udp/69", "vnc": "tcp/5900", "winrm": "tcp/5985", "radius": "udp/1812", "syslog": "udp/514",
              "all": "any", "all_tcp": "tcp/1-65535", "all_udp": "udp/1-65535", "any": "any", "application-default": "app-default"}


class RuleFormatError(ValueError):
    pass


def _truthy(v, default=None):
    if v is None or v == "":
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "enabled", "on", "enable", "all", "utm")


def _split(v):
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in re.split(r"[;,|\n]+|\s{2,}", str(v or "")) if x.strip()]


def norm_service(tok):
    t = tok.strip().lower()
    if t in WELL_KNOWN:
        return WELL_KNOWN[t]
    m = re.fullmatch(r"(tcp|udp)[/_:-]?(\d+)(?:-(\d+))?", t)
    if m:
        return f"{m.group(1)}/{m.group(2)}" + (f"-{m.group(3)}" if m.group(3) else "")
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", t)
    if m:
        return f"tcp/{m.group(1)}" + (f"-{m.group(2)}" if m.group(2) else "")
    return t


def norm_address(tok):
    t = tok.strip()
    if t.lower() in ("any", "all", "0.0.0.0/0", "::/0", "internet"):
        return "any"
    try:
        return str(ipaddress.ip_network(t, strict=False)) if "/" in t else str(ipaddress.ip_address(t)) + "/32" if ":" not in t else str(ipaddress.ip_address(t)) + "/128"
    except ValueError:
        return t


def _date(v):
    s = str(v or "").strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return m.group(0)
    m = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", s)
    return f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}" if m else None


def make_rule(device, position, raw):
    action = str(raw.get("action") or "").strip().lower()
    action = "allow" if action in ("allow", "accept", "permit", "pass") else "deny" if action in ("deny", "drop", "reject", "block", "discard", "reset", "reset-both", "reset-client", "reset-server") else None
    if action is None:
        raise RuleFormatError(f"Rule {raw.get('name') or position}: the action '{raw.get('action')}' is not allow or deny")
    enabled = raw.get("enabled")
    if isinstance(enabled, str) and enabled.strip().lower() in ("disabled", "disable", "no", "false", "0"):
        enabled = False
    hits = raw.get("hits")
    try:
        hits = int(str(hits).replace(",", "")) if hits not in (None, "", "N/A", "n/a", "-") else None
    except ValueError:
        hits = None
    return {"device": device, "key": str(raw.get("key") or raw.get("name") or position), "position": position, "name": str(raw.get("name") or f"rule-{position}")[:200], "action": action,
            "enabled": _truthy(enabled, True) if not isinstance(enabled, bool) else enabled, "log": _truthy(raw.get("log"), False) if not isinstance(raw.get("log"), bool) else raw["log"],
            "src_zones": [z.lower() for z in _split(raw.get("src_zones"))] or ["any"], "dst_zones": [z.lower() for z in _split(raw.get("dst_zones"))] or ["any"],
            "sources": sorted({norm_address(a) for a in _split(raw.get("sources"))} or {"any"}), "destinations": sorted({norm_address(a) for a in _split(raw.get("destinations"))} or {"any"}),
            "services": sorted({norm_service(s) for s in _split(raw.get("services"))} or {"any"}), "hits": hits, "last_hit": _date(raw.get("last_hit")), "created": _date(raw.get("created")),
            "modified": _date(raw.get("modified")), "owner": (str(raw.get("owner") or "").strip() or None), "comment": (str(raw.get("comment") or "").strip()[:300] or None), "expires": _date(raw.get("expires"))}


def from_csv(text, device):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise RuleFormatError("The CSV has no header row")
    cols = {}
    for field, names in ALIASES.items():
        for h in reader.fieldnames:
            if (h or "").strip().lower() in names:
                cols.setdefault(field, h)
    for need in ("action",):
        if need not in cols:
            raise RuleFormatError(f"No column for '{need}' was recognised. Columns seen: {', '.join(h for h in reader.fieldnames if h)}")
    rules = []
    for i, row in enumerate(reader, 1):
        raw = {f: row.get(h) for f, h in cols.items()}
        if "enabled" in cols and cols["enabled"].strip().lower() in ("disabled",):
            raw["enabled"] = "false" if _truthy(row.get(cols["enabled"]), False) else "true"
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue
        rules.append(make_rule(device, i, raw))
    if not rules:
        raise RuleFormatError("The CSV has no rules")
    return rules


def from_json(text, device):
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise RuleFormatError(f"Not valid JSON: {exc}") from exc
    items = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise RuleFormatError("Expected a list of rules, or an object with a 'rules' list")
    return [make_rule(device, i, r) for i, r in enumerate(items, 1)]


def from_panos_xml(text, device):
    try:
        root = safe_xml.fromstring(text)
    except safe_xml.UnsafeXml as exc:
        raise RuleFormatError(str(exc)) from exc
    except safe_xml.ParseError as exc:
        raise RuleFormatError(f"Not valid XML: {exc}") from exc
    entries = root.findall(".//security/rules/entry") or root.findall(".//rules/entry")
    if not entries:
        raise RuleFormatError("No <security><rules><entry> elements found; this does not look like a PAN-OS security rulebase")
    members = lambda e, tag: [m.text for m in e.findall(f"{tag}/member") if m.text]  # noqa: E731
    rules = []
    for i, e in enumerate(entries, 1):
        text_of = lambda tag: (e.findtext(tag) or "").strip()  # noqa: E731
        rules.append(make_rule(device, i, {
            "name": e.get("name"), "action": text_of("action") or "deny", "enabled": "false" if text_of("disabled") == "yes" else "true",
            "log": "yes" if text_of("log-end") != "no" and text_of("log-end") else "no", "src_zones": members(e, "from"), "dst_zones": members(e, "to"), "sources": members(e, "source"),
            "destinations": members(e, "destination"), "services": members(e, "service") + members(e, "application") if members(e, "service") != ["application-default"] else members(e, "application"),
            "comment": text_of("description"), "owner": ", ".join(members(e, "tag")) or None}))
    return rules


def from_fortigate(text, device):
    m = re.search(r"config firewall policy\s*(.*?)\n\s*end\b", text, re.S)
    if not m:
        raise RuleFormatError("No 'config firewall policy' block found")
    rules, pos = [], 0
    for em in re.finditer(r"edit\s+(\S+)\s*(.*?)\n\s*next\b", m.group(1), re.S):
        pos += 1
        raw = {"key": em.group(1)}
        for sm in re.finditer(r"set\s+(\S+)\s+(.+)", em.group(2)):
            raw[sm.group(1)] = re.findall(r'"([^"]*)"|(\S+)', sm.group(2).strip())
            raw[sm.group(1)] = [a or b for a, b in raw[sm.group(1)]]
        g = lambda k: raw.get(k, [])  # noqa: E731
        rules.append(make_rule(device, pos, {
            "key": raw["key"], "name": (g("name") or [f"policy-{raw['key']}"])[0], "action": (g("action") or ["deny"])[0], "enabled": "false" if (g("status") or ["enable"])[0] == "disable" else "true",
            "log": "yes" if (g("logtraffic") or ["utm"])[0] in ("all", "utm") else "no", "src_zones": g("srcintf"), "dst_zones": g("dstintf"), "sources": g("srcaddr"), "destinations": g("dstaddr"),
            "services": g("service"), "comment": " ".join(g("comments")), "expires": None}))
    if not rules:
        raise RuleFormatError("The firewall policy block has no policies")
    return rules


def detect_and_parse(text, device, fmt=None):
    fmt = (fmt or "").lower() or ("xml" if text.lstrip().startswith("<") else "json" if text.lstrip()[:1] in "[{" else "fortigate" if "config firewall policy" in text else "csv")
    if fmt in ("xml", "panos"):
        return from_panos_xml(text, device), "panos"
    if fmt == "json":
        return from_json(text, device), "json"
    if fmt in ("fortigate", "fortios"):
        return from_fortigate(text, device), "fortigate"
    if fmt == "csv":
        return from_csv(text, device), "csv"
    raise RuleFormatError("format must be csv, json, panos or fortigate")
