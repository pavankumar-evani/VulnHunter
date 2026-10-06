"""
Readers for the output of the open-source discovery tools Quanta can take in for external attack surface management.

Quanta never scans and never talks to a target. A person who is authorised to test their own infrastructure runs these tools; this module only reads
what they wrote. Built against the tools' public documentation of their JSON output; never run against live output at scale. Each reader is tolerant
(a missing field is simply absent, a malformed line is counted and skipped), refuses an unknown tool with a clear error, and enforces size limits.

  subfinder -oJ      {"host": "...", "input": "example.com", "source": ["crtsh", ...]}
  dnsx -json         {"host": "...", "a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": [], "status_code": "NOERROR"}
  httpx -json        {"url", "input", "host" (the address), "title", "status_code", "tech": [], "webserver", "cdn", "a": [], "cname": [], "tls": {...}}
  naabu -json        {"ip": "...", "host": "...", "port": 443, "protocol": "tcp"}
  nuclei -jsonl      {"template-id", "info": {"name", "severity", "tags", "classification": {"cve-id": []}}, "host", "matched-at", "type"}
  seeds (CSV)        "domain,example.com" and "cidr,203.0.113.0/24" lines (or bare values): what you declare as YOURS. Declaring scope is an administrator's act.

parse(tool, text) returns {"tool", "observations": [...], "skipped", "errors": [first few messages]}. Observations are plain dicts with a "type".
"""
import csv
import datetime
import io
import ipaddress
import json
import re
from urllib.parse import urlsplit

TOOLS = ("subfinder", "dnsx", "httpx", "naabu", "nuclei", "seeds")
MAX_BYTES = 50_000_000
MAX_RECORDS = 200_000
MAX_ERRORS_KEPT = 10
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_NUCLEI_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}


class ParseError(ValueError):
    """The input cannot be used at all (unknown tool, too large, nothing readable). A single bad line is skipped, not raised."""


# ---------------------------------------------------------------- small helpers
def norm_host(value):
    """A host name or IP address in canonical lower case, or None when it is neither."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower().rstrip(".")
    if v.startswith("*."):
        v = v[2:]
    if not v:
        return None
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    return v if _HOST.match(v) else None


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _ips(values):
    out = []
    for v in values if isinstance(values, list) else [values]:
        h = norm_host(v) if isinstance(v, str) else None
        if h and is_ip(h) and h not in out:
            out.append(h)
    return out[:20]


def _names(values):
    out = []
    for v in values if isinstance(values, list) else [values]:
        h = norm_host(v) if isinstance(v, str) else None
        if h and not is_ip(h) and h not in out:
            out.append(h)
    return out[:20]


def _str(v, n=300):
    return str(v).strip()[:n] if v not in (None, "") else ""


def _int(v):
    try:
        i = int(v)
    except (TypeError, ValueError):
        return None
    return i if 0 < i < 65536 else None


def _strlist(v, n=30, size=80):
    if isinstance(v, str):
        v = [x for x in re.split(r"[,;]", v)]
    return [_str(x, size) for x in v if _str(x, size)][:n] if isinstance(v, list) else []


def host_of_target(target):
    """(host, port) from 'https://a.example:8443/x', 'a.example:22' or a bare host. host is None when it is not a name or IP."""
    t = _str(target, 600)
    if not t:
        return None, None
    if "://" not in t:
        t = "//" + t
    try:
        u = urlsplit(t)
        port = u.port
    except ValueError:
        return None, None
    scheme = urlsplit(target).scheme if "://" in str(target) else ""
    if port is None and scheme in ("http", "https"):
        port = 443 if scheme == "https" else 80
    return norm_host(u.hostname or ""), port


def _date(v):
    """YYYY-MM-DD from the shapes httpx writes (RFC 3339, 'YYYY-MM-DD HH:MM:SS', plain date), or None."""
    s = _str(v, 40)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if not m:
        return None
    try:
        return datetime.date(int(m[1]), int(m[2]), int(m[3])).isoformat()
    except ValueError:
        return None


def product_version(text):
    """('nginx', '1.18.0') from 'nginx/1.18.0 (Ubuntu)' or 'PHP:7.4.3'; (name, None) when the text carries no version. Never guesses a version."""
    s = _str(text, 120)
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 ._+-]*?)\s*[:/ ]\s*v?(\d+(?:\.\d+){0,3})(?![\w.])", s)
    name, ver = (m.group(1), m.group(2)) if m else (re.sub(r"\s*\(.*$", "", s), None)
    key = re.sub(r"[^a-z0-9+.-]+", "-", name.lower()).strip("-")
    key = {"apache-http-server": "apache", "apache-httpd": "apache", "microsoft-iis": "microsoft-iis", "iis": "microsoft-iis", "jquery-ui": "jquery-ui"}.get(key, key)
    return key, ver


# ---------------------------------------------------------------- reading records
def _records(text, max_records):
    if not isinstance(text, str):
        raise ParseError("The input must be text")
    if len(text) > MAX_BYTES:
        raise ParseError(f"The input is too large (limit {MAX_BYTES // 1_000_000} MB). Split it into several imports.")
    text = text.lstrip("﻿").strip()
    if not text:
        raise ParseError("The input is empty")
    recs, bad = [], 0
    if text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ParseError(f"The input looks like a JSON array but is not valid JSON: {exc}") from exc
        items = data if isinstance(data, list) else []
        for it in items:
            if isinstance(it, dict):
                recs.append(it)
            else:
                bad += 1
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(obj, dict):
                recs.append(obj)
            else:
                bad += 1
            if len(recs) > max_records:
                break
    if len(recs) > max_records:
        raise ParseError(f"Too many records (limit {max_records:,} per import). Split the file.")
    return recs, bad


# ---------------------------------------------------------------- one reader per tool
def _subfinder(r):
    host = norm_host(r.get("host") or "")
    if not host or is_ip(host):
        return None
    src = r.get("source")
    return {"type": "host", "host": host, "found_by": _strlist(src if isinstance(src, (list, str)) else [], 10, 40), "input": norm_host(r.get("input") or "")}


def _dnsx(r):
    host = norm_host(r.get("host") or "")
    if not host or is_ip(host):
        return None
    return {"type": "dns", "host": host, "a": _ips(r.get("a") or []), "aaaa": _ips(r.get("aaaa") or []), "cname": _names(r.get("cname") or []), "mx": _names(r.get("mx") or []),
            "ns": _names(r.get("ns") or []), "txt_count": len(r.get("txt") or []) if isinstance(r.get("txt"), list) else 0, "status": _str(r.get("status_code"), 30).upper() or None}


def _tls(t):
    if not isinstance(t, dict):
        return None
    out = {"not_after": _date(t.get("not_after")), "not_before": _date(t.get("not_before")), "subject_cn": _str(t.get("subject_cn"), 200) or None, "issuer_cn": _str(t.get("issuer_cn"), 200) or None,
           "self_signed": bool(t.get("self_signed")) if "self_signed" in t else None, "expired": bool(t.get("expired")) if "expired" in t else None,
           "mismatched": bool(t.get("mismatched")) if "mismatched" in t else None, "untrusted": bool(t.get("untrusted")) if "untrusted" in t else None,
           "names": _strlist(t.get("subject_an") or [], 10, 200), "version": _str(t.get("tls_version"), 20) or None}
    fp = t.get("fingerprint_hash")
    out["fingerprint"] = _str(fp.get("sha256"), 100) if isinstance(fp, dict) and fp.get("sha256") else None
    return out if any(v not in (None, [], "") for v in out.values()) else None


def _httpx(r):
    url = _str(r.get("url"), 600)
    host_in, port = host_of_target(r.get("input") or "")
    uhost, uport = host_of_target(url)
    host = host_in or uhost
    if not url or not host:
        return None
    ip = None
    for cand in (r.get("host"), *(r.get("a") or [])):
        if isinstance(cand, str) and is_ip(norm_host(cand) or ""):
            ip = norm_host(cand)
            break
    # the original input is the better name; an IP input stays an IP
    return {"type": "web", "url": url.split("#")[0], "host": host, "ip": ip, "port": _int(r.get("port")) or uport or port, "scheme": _str(r.get("scheme"), 10).lower() or urlsplit(url).scheme.lower(),
            "title": _str(r.get("title"), 200), "status_code": _int(r.get("status_code")) if r.get("status_code") is not None else None,
            "tech": _strlist(r.get("tech") or r.get("technologies") or [], 30, 80), "webserver": _str(r.get("webserver"), 100), "cdn": _str(r.get("cdn_name") or (r.get("cdn") if isinstance(r.get("cdn"), str) else ""), 60),
            "cname": _names(r.get("cname") or []), "a": _ips(r.get("a") or []), "tls": _tls(r.get("tls")) if r.get("tls") else None}


def _naabu(r):
    ip = norm_host(r.get("ip") or "")
    host = norm_host(r.get("host") or "")
    port = _int(r.get("port"))
    ip = ip if ip and is_ip(ip) else (host if host and is_ip(host) else None)
    if port is None or not (ip or host):
        return None
    return {"type": "port", "ip": ip, "host": host if host and not is_ip(host) else None, "port": port, "protocol": (_str(r.get("protocol"), 6).lower() or "tcp")}


def _nuclei(r):
    info = r.get("info") if isinstance(r.get("info"), dict) else {}
    tid = _str(r.get("template-id") or r.get("templateID") or r.get("template_id"), 200)
    sev = _NUCLEI_SEV.get(_str(info.get("severity"), 20).lower())
    matched = _str(r.get("matched-at") or r.get("matched"), 600)
    host_t, port = host_of_target(matched or r.get("host") or "")
    host_h, _ = host_of_target(r.get("host") or "")
    host = host_t or host_h
    if not tid or not host or not sev:
        return None
    cls = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    raw = cls.get("cve-id") or cls.get("cve_id") or cls.get("cve") or []
    cves = sorted({str(c).strip().upper() for c in (raw if isinstance(raw, list) else [raw]) if _CVE.match(str(c).strip())})[:10]
    cvss = cls.get("cvss-score") or cls.get("cvss_score")
    try:
        cvss = round(float(cvss), 1) if cvss not in (None, "") and 0 <= float(cvss) <= 10 else None
    except (TypeError, ValueError):
        cvss = None
    refs = info.get("reference")
    return {"type": "vuln", "template_id": tid, "name": _str(info.get("name"), 200) or tid, "severity": sev, "tags": _strlist(info.get("tags") or [], 15, 40), "host": host, "port": port,
            "matched_at": matched or host, "ip": norm_host(r.get("ip") or "") if r.get("ip") else None, "check_type": _str(r.get("type"), 20), "cves": cves, "cvss": cvss,
            "description": _str(info.get("description"), 600), "references": _strlist(refs if isinstance(refs, list) else ([refs] if refs else []), 5, 300), "matcher": _str(r.get("matcher-name"), 80),
            "timestamp": _str(r.get("timestamp"), 40)}


_READERS = {"subfinder": _subfinder, "dnsx": _dnsx, "httpx": _httpx, "naabu": _naabu, "nuclei": _nuclei}


def parse_cidr(value):
    """A declared range as a canonical string; refuses a range so wide it is almost certainly a typo (shorter than /8, or /32 for IPv6)."""
    try:
        net = ipaddress.ip_network(_str(value, 60), strict=False)
    except ValueError as exc:
        raise ParseError(f"{value!r} is not an IP range") from exc
    if net.version == 4 and net.prefixlen < 8 or net.version == 6 and net.prefixlen < 32:
        raise ParseError(f"{value!r} is too wide to be a declared scope (shortest allowed: /8 for IPv4, /32 for IPv6)")
    return str(net)


def _seeds(text):
    out, bad, errors = [], 0, []
    for row in csv.reader(io.StringIO(text.lstrip("﻿"))):
        cells = [c.strip() for c in row if c.strip()]
        if not cells or cells[0].startswith("#"):
            continue
        if len(cells) == 1:
            kind, value = None, cells[0]
        else:
            kind, value = cells[0].lower(), cells[1]
        if kind in ("type", "kind") and value.lower() == "value":
            continue
        try:
            if kind in (None, "cidr", "range", "ip", "network") and (kind or re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", value)):
                out.append({"type": "seed", "seed_kind": "cidr", "value": parse_cidr(value)})
            elif kind in (None, "domain", "host", "fqdn"):
                h = norm_host(value)
                if not h or is_ip(h):
                    raise ParseError(f"{value!r} is not a domain name")
                out.append({"type": "seed", "seed_kind": "domain", "value": h})
            else:
                raise ParseError(f"Unknown seed type {kind!r} (use domain or cidr)")
        except ParseError as exc:
            bad += 1
            if len(errors) < MAX_ERRORS_KEPT:
                errors.append(str(exc))
        if len(out) > MAX_RECORDS:
            raise ParseError(f"Too many seed rows (limit {MAX_RECORDS:,})")
    return out, bad, errors


def parse(tool, text, max_records=MAX_RECORDS):
    tool = (tool or "").strip().lower()
    if tool not in TOOLS:
        raise ParseError(f"Unknown tool {tool!r}. Quanta reads the output of: {', '.join(TOOLS)}")
    if not isinstance(text, str):
        raise ParseError("The input must be text")
    if len(text) > MAX_BYTES:
        raise ParseError(f"The input is too large (limit {MAX_BYTES // 1_000_000} MB). Split it into several imports.")
    if tool == "seeds":
        obs, bad, errors = _seeds(text)
        if not obs:
            raise ParseError("No usable seed rows" + (f": {errors[0]}" if errors else ""))
        return {"tool": tool, "observations": obs, "skipped": bad, "errors": errors}
    recs, bad = _records(text, max_records)
    reader, obs, errors = _READERS[tool], [], []
    for r in recs:
        try:
            o = reader(r)
        except Exception:  # noqa: BLE001 - one odd record never rejects the file
            o = None
        if o is None:
            bad += 1
            if len(errors) < MAX_ERRORS_KEPT:
                errors.append(f"A {tool} record without the fields Quanta needs was skipped")
        else:
            obs.append(o)
    if not obs:
        raise ParseError(f"No {tool} records could be read" + (". Is this the output of a different tool, or not JSON output (-json / -jsonl)?" if recs or bad else ""))
    return {"tool": tool, "observations": obs, "skipped": bad, "errors": errors}


# ---------------------------------------------------------------- how to feed it
EXAMPLES = [
    {"tool": "subfinder", "what": "Subdomains of a domain you own (passive sources only).", "command": "subfinder -d example.com -silent -oJ -o subfinder.json", "complete": "A full run for the domain can be a complete import for it."},
    {"tool": "dnsx", "what": "What each name resolves to, including CNAMEs.", "command": "dnsx -l hosts.txt -a -aaaa -cname -resp -json -o dnsx.json", "complete": "Feeds the takeover check."},
    {"tool": "httpx", "what": "Which names answer on the web, with title, technologies and TLS certificate.", "command": "httpx -l hosts.txt -title -tech-detect -web-server -tls-grab -cdn -json -o httpx.json", "complete": "Feeds titles, versions and certificate expiry."},
    {"tool": "naabu", "what": "Open ports on addresses you own.", "command": "naabu -list ips.txt -top-ports 100 -json -o naabu.json", "complete": "Only ports you scanned are known; an unscanned port is unknown, not closed."},
    {"tool": "nuclei", "what": "Known-issue checks against your own web endpoints.", "command": "nuclei -l urls.txt -severity low,medium,high,critical -jsonl -o nuclei.jsonl", "complete": "Each result becomes a finding, with its CVE when the template names one."},
    {"tool": "seeds", "what": "Your declared scope (administrator only): one row per domain or range.", "command": "printf 'type,value\\ndomain,example.com\\ncidr,203.0.113.0/24\\n' > seeds.csv", "complete": "Anything outside the scope is recorded but flagged, never silently included."},
]
POST_EXAMPLE = ("curl -sS -X POST 'https://quanta.example/api/ingest/asm?tool=httpx&complete=false' -H \"Authorization: Bearer $QUANTA_API_KEY\" "
                "--data-binary @httpx.json   # key scope asm:write; add &publish=true to refresh the queue findings")
SAFETY = ("Quanta does not scan and does not contact any target. Run these tools yourself, only against domains and address ranges you own or are authorised in writing to test; "
          "scanning systems without authorisation can be illegal and can disrupt services. Quanta reads what the tools wrote.")
