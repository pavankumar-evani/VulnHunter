"""
Threat-intelligence intake: turn a report into the facts a hunt needs, and say how much it matters to this environment.

Accepts plain text (an advisory, a blog post, a PDF's extracted text) or a STIX 2.1 bundle (JSON). It extracts, with explicit patterns and no
model: CVE ids, ATT&CK technique ids, indicators (public IPs, domains, hashes, URLs) and threat-actor names (STIX threat-actor / intrusion-set
objects, or the usual APT / FIN / UNC / TA names in text).

Relevance to this environment is a score out of 100 with the reasons listed:
  +40 a CVE in the report is open on an asset in the estate        (+10 more if one of them is on CISA's KEV list)
  +25 a technique in the report is tagged on the estate's open findings
  +15 a technique in the report has hunt queries in the library
  +10 the report names an indicator type we can sweep (IP, domain, hash)
Priority: >= 60 high, >= 30 medium, else low. A report that matches nothing in your estate is low priority, not discarded; the facts are
still extracted so a person can decide.

The proposed hunt is built the same way as the exposure-driven ones (generate.py): the hosts are those carrying the report's CVEs, the queries
come from the library for the report's techniques, and one more query sweeps the indicators.
"""
import hashlib
import ipaddress
import json
import re

from remediation.hunting import generate, ocsf

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ACTOR = re.compile(r"\b(?:APT\s?\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA\d{3}|Storm-\d{4}|Lazarus Group|Sandworm|Cozy Bear|Fancy Bear|Scattered Spider)\b", re.I)
_STIX_VALUE = re.compile(r"\[(?P<kind>ipv4-addr|ipv6-addr|domain-name|url|file:hashes\.[^\s=]+)(?::value)?\s*=\s*'(?P<v>[^']+)'\]")
_STIX_PATTERN = re.compile(r"(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes\.'?[A-Za-z0-9-]+'?)\s*=\s*'([^']+)'")


def _public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _norm_actor(a):
    return re.sub(r"\s+", "", a.upper()) if re.match(r"(?i)^(apt|fin|unc|ta)", a) else a.title()


def extract(content):
    """Returns {title, cves, techniques, actors, ips, domains, hashes, urls, format}. `content` is text or a JSON string/dict (STIX)."""
    doc = None
    if isinstance(content, dict):
        doc = content
    elif isinstance(content, str) and content.lstrip().startswith("{"):
        try:
            doc = json.loads(content)
        except ValueError:
            doc = None
    out = {"title": None, "cves": [], "techniques": [], "actors": [], "ips": [], "domains": [], "hashes": [], "urls": [], "format": "text"}

    def add(key, v):
        if v and v not in out[key]:
            out[key].append(v)

    texts = []
    if doc and doc.get("type") == "bundle" and isinstance(doc.get("objects"), list):
        out["format"] = "stix"
        for o in doc["objects"]:
            t = o.get("type")
            if t == "report" and not out["title"]:
                out["title"] = o.get("name")
            if t in ("threat-actor", "intrusion-set", "campaign") and o.get("name"):
                add("actors", _norm_actor(o["name"]))
            if t == "vulnerability":
                for ref in o.get("external_references") or []:
                    if ref.get("external_id"):
                        add("cves", ref["external_id"].upper()) if _CVE.match(ref["external_id"]) else None
                if _CVE.match(o.get("name", "")):
                    add("cves", o["name"].upper())
            if t == "attack-pattern":
                for ref in o.get("external_references") or []:
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        add("techniques", ref["external_id"].upper())
            if t == "indicator" and o.get("pattern"):
                for kind, v in _STIX_PATTERN.findall(o["pattern"]):
                    k = kind.lower()
                    if k.startswith("ipv"):
                        add("ips", v) if _public_ip(v) else None
                    elif k.startswith("domain"):
                        add("domains", v.lower())
                    elif k.startswith("url"):
                        add("urls", v)
                    elif k.startswith("file"):
                        add("hashes", v.lower())
            for k in ("name", "description"):
                if isinstance(o.get(k), str):
                    texts.append(o[k])
    else:
        texts.append(content if isinstance(content, str) else json.dumps(content))
    blob = "\n".join(texts)
    for c in _CVE.findall(blob):
        add("cves", c.upper())
    for t in _TECH.findall(blob):
        add("techniques", t)
    for a in _ACTOR.findall(blob):
        add("actors", _norm_actor(a))
    ent = ocsf.scan_text(blob)
    for ip in ent["ips"]:
        add("ips", ip) if _public_ip(ip) else None
    for d in ent["domains"]:
        add("domains", d)
    for h in ent["hashes"]:
        add("hashes", h)
    for u in ent["urls"]:
        add("urls", u)
    if not out["title"]:
        first = next((ln.strip() for ln in blob.splitlines() if ln.strip()), "Threat intelligence report")
        out["title"] = first[:160]
    out["cves"] = out["cves"][:200]
    out["techniques"] = sorted(set(out["techniques"]))[:100]
    return out


def content_hash(content):
    raw = content if isinstance(content, str) else json.dumps(content, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def relevance(ex, findings):
    """(score 0-100, priority, reasons, matches) for an extracted report against the estate's findings."""
    open_f = [f for f in findings if f.get("status") not in ("resolved", "closed") and not (f.get("exception") or {}).get("active")]
    by_cve = {}
    for f in open_f:
        if f.get("cve"):
            by_cve.setdefault(f["cve"].upper(), []).append(f)
    hit_cves = [c for c in ex["cves"] if c in by_cve]
    hit_kev = [c for c in hit_cves if any((f.get("kev") or {}).get("listed") for f in by_cve[c])]
    estate_t = {t["technique_id"] for f in open_f for t in f.get("attack_techniques") or []}
    parents = {t.split(".")[0] for t in ex["techniques"]}
    hit_t = sorted(parents & estate_t)
    lib = generate.library()
    in_lib = sorted(parents & set(lib))
    score, reasons = 0, []
    if hit_cves:
        score += 40
        reasons.append(f"{len(hit_cves)} CVE(s) in the report are open in your estate: {', '.join(hit_cves[:5])}")
    if hit_kev:
        score += 10
        reasons.append(f"{len(hit_kev)} of them are on CISA's KEV list")
    if hit_t:
        score += 25
        reasons.append(f"Technique(s) {', '.join(hit_t)} are tagged on your open findings")
    if in_lib:
        score += 15
        reasons.append(f"Hunt queries exist for {', '.join(in_lib)}")
    if ex["ips"] or ex["domains"] or ex["hashes"]:
        score += 10
        reasons.append("The report has indicators that can be swept")
    if not reasons:
        reasons.append("Nothing in the report matches your open findings or the hunt library")
    hosts = sorted({(f.get("asset") or {}).get("name") for c in hit_cves for f in by_cve[c] if (f.get("asset") or {}).get("name")})
    prio = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return score, prio, reasons, {"cves": hit_cves, "kev": hit_kev, "estate_techniques": hit_t, "hosts": hosts, "library_techniques": in_lib}


def ioc_selection(ex):
    """A Sigma-style selection that sweeps the report's indicators, or None. Field names are Sigma's; map them to your data model."""
    sel = {}
    if ex["ips"]:
        sel["DestinationIp"] = ex["ips"][:100]
    if ex["domains"]:
        sel["QueryName|endswith"] = ex["domains"][:100]
    if ex["hashes"]:
        sel["Hashes|contains"] = ex["hashes"][:100]
    return sel or None


def propose_hunt(ex, rel, hosts, index=None):
    """The hunt for a report: hypothesis, techniques, hosts, data sources, queries."""
    from remediation.hunting import translate
    lib = generate.library()
    tids = sorted({t.split(".")[0] for t in ex["techniques"]})
    queries = generate.build_queries([t for t in tids if t in lib], hosts, lib, index)
    sel = ioc_selection(ex)
    if sel:
        queries.append({"technique": "IOC", "name": "Sweep the report's indicators", "language": "splunk-spl", "query": translate.to_spl(sel, hosts, index), "result": None, "notes": ""})
    actors = ", ".join(ex["actors"][:3]) or "the actor in the report"
    why = "; ".join(rel[2][:2])
    hyp = (f"{ex['title']}: {actors} may be active against this environment. {why}. "
           "Look for the techniques and indicators the report describes, and for activity on the affected hosts after any successful exploitation.")
    return {"title": f"Hunt: {ex['title'][:120]}", "hypothesis": hyp, "source": "intel", "techniques": [{"technique_id": t, "technique_name": (lib.get(t) or {}).get("hunt", t)} for t in tids],
            "assets": hosts, "data_sources": generate.data_sources(tids, lib), "queries": queries,
            "notes": ("" if queries else "No queries could be generated (no library entry for the techniques and no indicators); write them for your data model.")}
