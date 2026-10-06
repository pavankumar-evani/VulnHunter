"""
Findings from the external attack surface, raised by explicit rules from what was IMPORTED. Nothing here scans or contacts a target.

Rules (policy in remediation/config/asm_policy.yaml; every finding carries evidence, how fresh that evidence is, and the exact next step):
  ASM-NUCLEI  a nuclei result (its CVE ids go on the finding so KEV and EPSS enrichment works; 'info' results are counted, not raised, unless the policy says so);
  ASM-PORT    a risky service reachable from outside (RDP, SMB, Telnet, databases, management APIs; SSH is judged separately);
  ASM-TLS     an expired, near-expiry, self-signed or mismatched certificate, as reported by httpx;
  ASM-TAKEOVER  a CNAME to a provider that allows claiming names, whose target no longer answers: a NAME MATCH that says "looks like", a person confirms;
  ASM-MGMT    a page whose title or address looks like an administration interface (a word match, confirmed by a person);
  ASM-TECH    a detected product whose reported version is below YOUR minimum (only where a version was reported; a version is never guessed);
  ASM-SHADOW  an in-scope name or address seen from outside that is absent from the asset inventory (skipped, and reported as a gap, when there is no inventory).

Only in-scope, active assets raise findings: an out-of-scope or disappeared asset never does. A rule with no data to judge raises nothing, and the gaps list says which
data is missing, so an empty result is never presented as a clean one.
"""
import datetime
import re
from pathlib import Path

import yaml

from remediation.asm import parsers

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "asm_policy.yaml"
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
NUCLEI_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
RULES = {
    "ASM-NUCLEI": "Known-issue check matched", "ASM-PORT": "Risky service exposed", "ASM-TLS": "Certificate problem", "ASM-TAKEOVER": "Possible subdomain takeover",
    "ASM-MGMT": "Management interface exposed", "ASM-TECH": "Outdated technology", "ASM-SHADOW": "Unknown external asset",
}
SCAN_TYPE = {"ASM-NUCLEI": "dast", "ASM-PORT": "infra-vm", "ASM-TLS": "cert-mgmt", "ASM-TAKEOVER": "dast", "ASM-MGMT": "dast", "ASM-TECH": "dast", "ASM-SHADOW": "infra-vm"}


def policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        p = yaml.safe_load(fh) or {}
    p.setdefault("risky_ports", {})
    p["risky_ports"] = {int(k): v for k, v in p["risky_ports"].items()}
    return p


def _vtuple(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])
    except ValueError:
        return ()


def _age(ts, now):
    try:
        d = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        return max(0, (now - d).days)
    except (TypeError, ValueError):
        return None


def _name(a):
    d = a["data"]
    if a["kind"] in ("url", "service"):
        host = d.get("host") or a["value"]
        names = [h for h in d.get("hosts") or [] if not parsers.is_ip(h)]
        return names[0] if parsers.is_ip(host) and names else host
    return a["value"]


def _ip(a):
    if a["kind"] == "ip":
        return a["value"]
    d = a["data"]
    if d.get("host") and parsers.is_ip(d["host"]):
        return d["host"]
    return (d.get("ips") or [None])[0]


def _fresh(a, now):
    age = _age(a["last_seen"], now)
    return f"Last observed {a['last_seen'][:10]}" + (f" ({age} days ago)" if age is not None else "") + f" by {', '.join(a['sources']) or 'an import'}."


def evaluate(assets, known=None, pol=None, now=None):
    """-> {"findings": [...], "gaps": [...], "skipped_info": n, "capped": [...]}. `assets` are store.all_assets() rows; `known` is a set of lower-case names and
    addresses from the asset inventory (None or empty: the shadow rule cannot judge and says so)."""
    pol = pol or policy()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    live = [a for a in assets if a["in_scope"] and a["status"] == "active"]
    out, gaps = [], []
    skipped_info = 0
    by_tool = {t: any(t in a["sources"] for a in live) for t in ("httpx", "naabu", "nuclei", "dnsx", "subfinder")}
    web_hosts = set()
    for a in live:
        if a["kind"] == "url":
            web_hosts.update({_name(a).lower(), *[i.lower() for i in a["data"].get("ips") or []], *[h.lower() for h in a["data"].get("hosts") or []]})

    def add(rule, sev, a, title, evidence, step, key, cve=None, cvss=None, url=None, asset_type=None):
        out.append({"rule": rule, "rule_title": RULES[rule], "severity": sev, "title": title, "asset": _name(a), "ip": _ip(a), "asset_key": a["key"], "evidence": evidence, "next_step": step,
                    "fresh": _fresh(a, now), "last_seen": a["last_seen"], "key": key, "cve": cve, "cvss": cvss, "url": url, "asset_type": asset_type, "scan_type": SCAN_TYPE[rule],
                    "first_seen": a["first_seen"]})

    # nuclei
    for a in live:
        for v in a["data"].get("vulns") or []:
            sev = NUCLEI_SEV.get(v["severity"])
            if not sev:
                if pol.get("nuclei", {}).get("include_info"):
                    sev = "Low"
                else:
                    skipped_info += 1
                    continue
            cves = v.get("cves") or []
            ev = [f"Template {v['template_id']} matched at {v['matched_at']}" + (f" (matcher {v['matcher']})" if v.get("matcher") else "") + ".", v.get("description") or ""]
            if len(cves) > 1:
                ev.append("Also names " + ", ".join(cves[1:]) + ".")
            if v.get("references"):
                ev.append("Reference: " + v["references"][0])
            add("ASM-NUCLEI", sev, a, f"{v['name']} on {_name(a)}", " ".join(e for e in ev if e),
                f"Open {v['matched_at']} and confirm the issue from a machine you are authorised to test from"
                + (f"; if it is real, patch or remove the affected component and look up {cves[0]} for the fixed version." if cves else "; if it is real, follow the template's reference to fix or remove the exposure."),
                f"{a['key']}|{v['template_id']}|{v.get('matcher') or ''}|{v['matched_at'][:120]}", cve=cves[0] if cves else None, cvss=v.get("cvss"), url=v["matched_at"])
    # risky ports
    rp, ssh = pol["risky_ports"], pol.get("ssh") or {}
    ssh_ports = set(ssh.get("ports") or [22])
    seen_ports = set()
    for a in live:
        if a["kind"] != "service":
            continue
        port, proto = a["data"].get("port"), a["data"].get("protocol") or "tcp"
        if port is None:
            continue
        host = _name(a)
        src = f"Seen by {', '.join(a['sources'])}."
        if port in ssh_ports:
            on_web = host.lower() in web_hosts or (_ip(a) or "").lower() in web_hosts
            sev = ssh.get("severity_on_web_host", "Medium") if on_web else ssh.get("severity_otherwise", "Low")
            add("ASM-PORT", sev, a, f"SSH reachable from the internet on {host}", f"{host}:{port}/{proto} answers from outside. " + ("The same host also serves a website. " if on_web else "") + src,
                "Confirm SSH needs to be public. If not, restrict it to a VPN, bastion or allow-listed addresses at the firewall; if it does, require keys, disable passwords and enable rate limiting.",
                f"{a['key']}|ssh")
        elif port in rp and (host, port) not in seen_ports:
            seen_ports.add((host, port))
            r = rp[port]
            add("ASM-PORT", r.get("severity", "Medium"), a, f"{r['name']} exposed on {host}", f"{host}:{port}/{proto} ({r['name']}, {r.get('category', 'other')}) answers from outside. {src}",
                f"Confirm whether {r['name']} must be reachable from the internet. If not, block port {port} at the perimeter or move it behind a VPN; if it must, restrict source addresses and require strong authentication.",
                f"{a['key']}|risky")
    # TLS
    today = now.date()
    for a in live:
        tls = a["data"].get("tls") if a["kind"] == "url" else None
        if not tls:
            continue
        host = _name(a)
        na = tls.get("not_after")
        days = None
        if na:
            try:
                days = (datetime.date.fromisoformat(na) - today).days
            except ValueError:
                pass
        t = pol.get("tls") or {}
        issues = []
        if tls.get("expired") or (days is not None and days < 0):
            issues.append(("expired", t.get("expired_severity", "Medium"), f"The certificate on {host} expired" + (f" on {na}." if na else "."), "Renew and install the certificate, then confirm the new expiry date."))
        elif days is not None and days <= t.get("warn_days", 30):
            issues.append(("expiring", t.get("near_expiry_severity", "Low"), f"The certificate on {host} expires in {days} days ({na}).", "Renew the certificate before it expires and confirm automated renewal is working."))
        if tls.get("self_signed"):
            issues.append(("self-signed", t.get("self_signed_severity", "Medium"), f"{host} presents a self-signed certificate.", "Replace it with a certificate from a trusted authority, or take the service off the internet."))
        if tls.get("mismatched"):
            issues.append(("mismatch", t.get("mismatch_severity", "Medium"), f"The certificate on {host} does not name this host" + (f" (subject {tls['subject_cn']})." if tls.get("subject_cn") else "."),
                           "Issue a certificate that names this host, or point the name at the right service."))
        for kind, sev, ev, step in issues:
            add("ASM-TLS", sev, a, f"Certificate {kind} on {host}", f"{ev} Issuer: {tls.get('issuer_cn') or 'not reported'}.", step, f"{a['key']}|tls-{kind}", url=a["value"], asset_type="certificate")
    if not by_tool["httpx"]:
        gaps.append("No httpx output has been imported, so certificate, management-interface and software-version rules had nothing to judge.")
    if not by_tool["naabu"]:
        gaps.append("No naabu (port scan) output has been imported, so exposed-service rules had nothing to judge. A port that was never scanned is unknown, not closed.")
    if not by_tool["nuclei"]:
        gaps.append("No nuclei output has been imported, so no known-issue checks were judged.")
    # takeover (name match)
    prov = pol.get("takeover_providers") or []
    codes = {}
    for a in live:
        if a["kind"] == "url":
            codes.setdefault(_name(a).lower(), set()).add(a["data"].get("status_code"))
    for a in live:
        if a["kind"] not in ("subdomain", "domain"):
            continue
        d = a["data"]
        for cn in d.get("cname") or []:
            p = next((p for p in prov if cn == p["suffix"] or cn.endswith("." + p["suffix"]) or cn.endswith(p["suffix"] + ".")), None)
            if not p:
                continue
            unresolved = d.get("dns_status") == "NXDOMAIN" or (d.get("dns_status") is not None and not d.get("ips"))
            err = 404 in codes.get(a["value"], set())
            if not (unresolved or err):
                continue
            sev = pol.get("takeover_severity_unresolved", "High") if unresolved else pol.get("takeover_severity_http_error", "Medium")
            add("ASM-TAKEOVER", sev, a, f"{a['value']} may be open to subdomain takeover ({p['name']})",
                f"{a['value']} is a CNAME to {cn}, a {p['name']} name, and "
                + ("it no longer resolves (NXDOMAIN or no address)." if unresolved else "the site answers HTTP 404.")
                + " This is a name match against known providers, not proof: the provider's page for that name must be checked.",
                f"Either delete the DNS record for {a['value']} (the safe default if it is unused) or recreate the resource at {p['name']} so it is yours again. Then confirm the name no longer points at an unclaimed target.",
                f"{a['key']}|{cn}")
    # management interfaces
    words = [w.lower() for w in pol.get("management_words") or []]
    for a in live:
        if a["kind"] != "url":
            continue
        title = (a["data"].get("title") or "").lower()
        hit = next((w for w in words if w in title or w in a["value"].lower()), None)
        if hit:
            add("ASM-MGMT", pol.get("management_severity", "Medium"), a, f"Possible management interface at {a['value']}",
                f"The page title \"{a['data'].get('title') or ''}\" matches the word '{hit}'. A word match, not a login test. HTTP {a['data'].get('status_code') or 'unknown'}.",
                "Confirm what this page is. If it is an administration interface, remove it from the internet or restrict it to a VPN or allow-listed addresses and require multi-factor authentication.",
                f"{a['key']}|mgmt", url=a["value"])
    # outdated technologies, only where a version is reported
    mins = pol.get("technology_minimums") or {}
    for a in live:
        if a["kind"] != "url":
            continue
        seen = set()
        for t in a["technologies"]:
            prod, ver = parsers.product_version(t)
            m = mins.get(prod)
            if not (m and ver) or prod in seen:
                continue
            if _vtuple(ver) and _vtuple(ver) < _vtuple(m["minimum"]):
                seen.add(prod)
                add("ASM-TECH", m.get("severity", "Low"), a, f"{prod} {ver} on {_name(a)} is below your minimum {m['minimum']}",
                    f"The import reported {t!r}. Your policy sets {m['minimum']} as the minimum for {prod}. This compares versions against your own list; it is not a lookup of known vulnerabilities (the nuclei and scanner findings do that), "
                    "and a vendor may have back-ported fixes to an older version number.", f"Check the installed {prod} version on {_name(a)}; if it is really {ver}, schedule an upgrade to {m['minimum']} or later, or record why not.",
                    f"{a['key']}|tech|{prod}", url=a["value"])
    # shadow assets
    sh = pol.get("shadow") or {}
    if sh.get("enabled", True):
        if not known:
            gaps.append("There is no asset inventory to compare against (no assets with findings, no CMDB import, no recorded owners), so unknown external assets could not be judged.")
        else:
            exposed = {x.lower() for a in live if a["kind"] in ("url", "service") for x in [_name(a), *(a["data"].get("hosts") or []), *(a["data"].get("ips") or [])] if x}
            for a in live:
                if a["kind"] not in ("subdomain", "ip"):
                    continue
                names = {a["value"].lower(), *[i.lower() for i in a["data"].get("ips") or []], *[h.lower() for h in a["data"].get("hosts") or []]}
                if a["kind"] == "ip" and any(not parsers.is_ip(h) for h in names):
                    continue  # judged through its host name
                if names & known:
                    continue
                is_exposed = bool(names & exposed)
                add("ASM-SHADOW", sh.get("severity_with_exposure", "Medium") if is_exposed else sh.get("severity_otherwise", "Low"), a, f"{a['value']} is visible from the internet but not in the asset inventory",
                    f"{a['value']} was seen by {', '.join(a['sources'])}" + (" and serves traffic" if is_exposed else "") + ". Nothing in the asset inventory matches its name or address. Absence from the inventory is what this checks; "
                    "it may be a gap in the inventory rather than a rogue system.", "Find the owner. If it is yours, add it to the inventory with an owner and a team; if it is not, report it to your security team and, for a third party's system, to that party.",
                    f"{a['key']}|shadow")
    # cap per rule
    cap = int(pol.get("max_findings_per_rule", 500))
    capped, kept, per = [], [], {}
    out.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["rule"], f["asset"], f["key"]))
    for f in out:
        per[f["rule"]] = per.get(f["rule"], 0) + 1
        if per[f["rule"]] <= cap:
            kept.append(f)
    capped = [f"{r}: {n} raised, {cap} kept (highest severity first)" for r, n in per.items() if n > cap]
    return {"findings": kept, "gaps": gaps, "skipped_info": skipped_info, "capped": capped}


def to_queue_items(findings):
    """The findings in the shape the ingest API takes (source 'asm')."""
    items = []
    for f in findings:
        item = {"title": f["title"][:300], "severity": f["severity"], "asset": {"name": f["asset"], "ip": f["ip"]}, "source_ref": f"{f['rule']}:{f['key']}"[:300],
                "description": f"{f['evidence']} {f['fresh']} External attack surface data comes from imported tool output; Quanta did not scan.", "recommended_fix": f["next_step"], "scan_type": f["scan_type"],
                "rule_id": f["rule"], "tool": "quanta-asm", "first_seen": f["first_seen"][:10], "last_seen": f["last_seen"][:10]}
        if f.get("asset_type"):
            item["asset"]["type"] = f["asset_type"]
        if f.get("cve"):
            item["cve"] = f["cve"]
        if f.get("cvss") is not None:
            item["cvss"] = f["cvss"]
        if f.get("url"):
            item["location"] = {"url": f["url"]}
        items.append(item)
    return items


def known_assets(findings, ownership=None):
    """Lower-case names and addresses the asset inventory already knows: assets in other sources' findings, plus every asset with a recorded owner."""
    known = set()
    for f in findings or []:
        if f.get("source") == "asm":
            continue
        a = f.get("asset") or {}
        for k in ("name", "hostname", "ip"):
            if a.get(k):
                known.add(str(a[k]).lower())
        for x in a.get("ips") or []:
            known.add(str(x).lower())
    for k, v in (ownership or {}).items():
        known.add(str(k).lower())
        if isinstance(v, dict) and v.get("ip"):
            known.add(str(v["ip"]).lower())
    return known
