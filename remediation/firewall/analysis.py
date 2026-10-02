"""
What is wrong with a firewall ruleset, which ports it exposes, and whether a requested change is already allowed, blocked or needs a new rule.

Rules are checked in order (first match wins), so a rule can be useless (shadowed or redundant) because an earlier one already decides the same traffic.

Findings (id, default severity):
  FW001 Critical  allows any source to any destination on any service
  FW002 Critical  allows the internet to reach a management, remote-access or database port
  FW003 High      allows the internet to reach a destination on any service
  FW004 Medium    allows any service between specific hosts (the service should be named)
  FW005 Medium    allows any destination from specific sources (the destination should be named)
  FW006 Medium    allows a clear-text protocol (FTP, Telnet, TFTP, ...)
  FW007 Medium    an allow rule that does not log
  FW008 Medium    an allow rule that has not been hit for a long time (only when the device reports hits)
  FW009 Low       a disabled rule left in place for a long time
  FW010 Medium    shadowed: an earlier rule already decides this traffic differently, so this rule never applies
  FW011 Low       redundant or duplicate: an earlier rule already decides this traffic the same way
  FW012 Medium    an allow rule with no owner, so nobody can recertify it
  FW013 Medium    an enabled rule whose expiry date has passed
"Internet-facing" means an enabled allow rule with source 'any' whose source zone is any, or has a name like untrust, wan, internet, outside or external.
This is name matching; if your zones are named differently, add the words to `internet_zone_words` in firewall_policy.yaml.

Containment is exact for addresses and port ranges written as addresses, CIDRs, ports and ranges. An address or service OBJECT name is compared by
name only, because a rule export does not contain what the object holds; two different objects that hold the same addresses are not seen as equal.
"""
import datetime
import ipaddress
import re
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "firewall_policy.yaml"
SEVERITY = {"FW001": "Critical", "FW002": "Critical", "FW003": "High", "FW004": "Medium", "FW005": "Medium", "FW006": "Medium", "FW007": "Medium", "FW008": "Medium",
            "FW009": "Low", "FW010": "Medium", "FW011": "Low", "FW012": "Medium", "FW013": "Medium"}
WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
DEFAULT_INTERNET_WORDS = ("untrust", "wan", "internet", "outside", "external", "public")


def policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _today(today):
    return today or datetime.date.today()


def _days_ago(d, today):
    try:
        return (today - datetime.date.fromisoformat(d)).days
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- containment
def _net(tok):
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


def addr_covers(outer, inner):
    """Does the address list `outer` cover every address in `inner`?"""
    if "any" in outer:
        return True
    if "any" in inner:
        return False
    for tok in inner:
        n = _net(tok)
        if not any(tok == o or (n is not None and _net(o) is not None and n.version == _net(o).version and n.subnet_of(_net(o))) for o in outer):
            return False
    return True


def _svc(tok):
    m = re.fullmatch(r"(tcp|udp)/(\d+)(?:-(\d+))?", tok)
    return (m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))) if m else None


def service_covers(outer, inner):
    if "any" in outer:
        return True
    if "any" in inner:
        return False
    for tok in inner:
        s = _svc(tok)
        ok = False
        for o in outer:
            r = _svc(o)
            if tok == o or (s and r and s[0] == r[0] and r[1] <= s[1] and s[2] <= r[2]):
                ok = True
                break
        if not ok:
            return False
    return True


def zone_covers(outer, inner):
    return "any" in outer or (all(z in outer for z in inner) and "any" not in inner)


def covers(a, b):
    """Rule a (earlier) decides everything rule b matches."""
    return (a["enabled"] and zone_covers(a["src_zones"], b["src_zones"]) and zone_covers(a["dst_zones"], b["dst_zones"]) and addr_covers(a["sources"], b["sources"])
            and addr_covers(a["destinations"], b["destinations"]) and service_covers(a["services"], b["services"]))


def same_match(a, b):
    return all(sorted(a[k]) == sorted(b[k]) for k in ("src_zones", "dst_zones", "sources", "destinations", "services"))


def ports_of(services):
    """Ports named by a service list: (set of ports, spans_all). Ranges are expanded only when small."""
    ports, wide = set(), False
    for s in services:
        r = _svc(s)
        if s == "any":
            wide = True
        elif r:
            if r[2] - r[1] > 2000:
                wide = True
            else:
                ports.update(range(r[1], r[2] + 1))
    return ports, wide


# ---------------------------------------------------------------- findings
def is_internet_facing(rule, pol):
    words = tuple(pol.get("internet_zone_words") or DEFAULT_INTERNET_WORDS)
    zone_ok = "any" in rule["src_zones"] or any(w in z for z in rule["src_zones"] for w in words)
    return rule["enabled"] and rule["action"] == "allow" and "any" in rule["sources"] and zone_ok


def analyse(rules, pol=None, today=None):
    pol = pol or policy()
    today = _today(today)
    risky, clear = {int(k): v for k, v in (pol.get("risky_ports") or {}).items()}, {int(k): v for k, v in (pol.get("cleartext_ports") or {}).items()}
    unused_days, stale_days = pol.get("unused_days", 90), pol.get("disabled_stale_days", 90)
    findings = []

    def add(rule, fid, title, detail, fix):
        findings.append({"device": rule["device"], "rule_key": rule["key"], "rule": rule["name"], "position": rule["position"], "id": fid, "severity": SEVERITY[fid], "title": title, "detail": detail, "recommendation": fix})

    ordered = sorted(rules, key=lambda r: (r["device"], r["position"]))
    by_device = {}
    for r in ordered:
        by_device.setdefault(r["device"], []).append(r)
    for r in ordered:
        allow = r["action"] == "allow"
        ports, wide = ports_of(r["services"])
        if r["enabled"] and allow:
            if "any" in r["sources"] and "any" in r["destinations"] and "any" in r["services"]:
                add(r, "FW001", "Allows any source to any destination on any service", "This rule permits all traffic across the zones it names.", "Replace it with rules for the specific flows that are needed, then remove it.")
            elif is_internet_facing(r, pol):
                hit = sorted(p for p in ports if p in risky)
                if hit or ("any" in r["services"]):
                    if hit:
                        add(r, "FW002", "Internet can reach management, remote-access or database ports", "Exposed: " + ", ".join(f"{p} ({risky[p]})" for p in hit),
                            "Remove the exposure, or restrict the source to known addresses or put the service behind a VPN or bastion.")
                    else:
                        add(r, "FW003", "Internet can reach a destination on any service", "The destination accepts every service from anywhere.", "Name only the services that must be public.")
            if "any" in r["services"] and "any" not in r["sources"] and "any" not in r["destinations"]:
                add(r, "FW004", "Allows any service between named hosts", "Between " + ", ".join(r["sources"][:3]) + " and " + ", ".join(r["destinations"][:3]), "List only the ports the application uses.")
            if "any" in r["destinations"] and "any" not in r["sources"]:
                add(r, "FW005", "Allows any destination from named sources", "From " + ", ".join(r["sources"][:3]), "Name the destinations these sources need.")
            bad = sorted(p for p in ports if p in clear)
            if bad:
                add(r, "FW006", "Allows a clear-text protocol", ", ".join(f"{p} ({clear[p]})" for p in bad), "Use the encrypted equivalent (SFTP/FTPS, SSH, IMAPS/POP3S) and remove the rule.")
            if not r["log"]:
                add(r, "FW007", "Allow rule does not log", "Without logs there is no record of what this rule permitted.", "Turn on logging at session end.")
            quiet = r["hits"] == 0 or (r["last_hit"] and (_days_ago(r["last_hit"], today) or 0) > unused_days)
            old_enough = (_days_ago(r["created"], today) or unused_days + 1) > unused_days
            if quiet and old_enough and (r["hits"] is not None or r["last_hit"]):
                add(r, "FW008", f"Not used for over {unused_days} days", f"Hits: {r['hits']}, last hit: {r['last_hit'] or 'never'}.", "Confirm with the owner and remove it.")
            if not r["owner"]:
                add(r, "FW012", "Allow rule has no owner", "Nobody is recorded as responsible, so it cannot be recertified.", "Record the owner or team in the rule's tag or comment.")
        if r["enabled"] and r["expires"] and r["expires"] < today.isoformat():
            add(r, "FW013", "Rule is past its expiry date", f"Expired {r['expires']} and still enabled.", "Disable and then delete it, or have the owner extend it with a reason.")
        if not r["enabled"] and (_days_ago(r["modified"], today) or 0) > stale_days:
            add(r, "FW009", f"Disabled for over {stale_days} days", f"Last changed {r['modified']}.", "Delete it.")
    for dev, rs in by_device.items():
        for i, b in enumerate(rs):
            if not b["enabled"]:
                continue
            for a in rs[:i]:
                if a["enabled"] and covers(a, b):
                    if a["action"] != b["action"]:
                        add(b, "FW010", "Shadowed: this rule can never apply", f"Rule '{a['name']}' (position {a['position']}) already {a['action']}s all of this traffic.", "Delete this rule, or move it above the rule that shadows it if the intent was different.")
                    else:
                        add(b, "FW011", "Redundant: an earlier rule already does this", f"Rule '{a['name']}' (position {a['position']}) already {a['action']}s all of this traffic.", "Delete this rule.")
                    break
    findings.sort(key=lambda f: (-WEIGHT[f["severity"]], f["device"], f["position"]))
    return findings


def summary(rules, findings):
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in WEIGHT}
    devices = {}
    for r in rules:
        d = devices.setdefault(r["device"], {"rules": 0, "enabled": 0, "allow": 0, "score": 0})
        d["rules"] += 1
        d["enabled"] += r["enabled"]
        d["allow"] += r["enabled"] and r["action"] == "allow"
    for f in findings:
        devices[f["device"]]["score"] += WEIGHT[f["severity"]]
    return {"rules": len(rules), "findings": len(findings), "by_severity": by_sev, "devices": [{"device": k, **v} for k, v in sorted(devices.items())]}


def exposure(rules, findings=None, pol=None, today=None):
    """What the internet can reach: ports exposed by internet-facing allow rules, with which are risky and which rules are unused."""
    pol = pol or policy()
    risky = {int(k): v for k, v in (pol.get("risky_ports") or {}).items()}
    today = _today(today)
    unused_days = pol.get("unused_days", 90)
    by_port, any_open = {}, []
    for r in rules:
        if not is_internet_facing(r, pol):
            continue
        ports, wide = ports_of(r["services"])
        quiet = r["hits"] == 0 or bool(r["last_hit"] and (_days_ago(r["last_hit"], today) or 0) > unused_days)
        if wide:
            any_open.append({"device": r["device"], "rule": r["name"], "destinations": r["destinations"][:5], "unused": quiet})
        for p in ports:
            e = by_port.setdefault(p, {"port": p, "name": risky.get(p), "risky": p in risky, "rules": [], "all_unused": True})
            e["rules"].append({"device": r["device"], "rule": r["name"], "destinations": r["destinations"][:5]})
            e["all_unused"] = e["all_unused"] and quiet
    return {"ports": sorted(by_port.values(), key=lambda e: (not e["risky"], e["port"])), "wide_open_rules": any_open,
            "risky_exposed": sum(1 for e in by_port.values() if e["risky"]), "unused_exposure": sum(1 for e in by_port.values() if e["all_unused"] and any(r for r in e["rules"]))}


# ---------------------------------------------------------------- change requests
def check_request(req, rules, pol=None, topology=None):
    """req: sources, destinations, services (lists), days (int or None). Decides: already allowed / blocked / needs a new rule, how risky, and whether it may be auto-approved."""
    pol = pol or policy()
    rq = pol.get("request") or {}
    from remediation.firewall import model
    asked = {"enabled": True, "action": "allow", "src_zones": ["any"], "dst_zones": ["any"], "sources": sorted({model.norm_address(a) for a in req.get("sources") or []} or {"any"}),
             "destinations": sorted({model.norm_address(a) for a in req.get("destinations") or []} or {"any"}), "services": sorted({model.norm_service(s) for s in req.get("services") or []} or {"any"})}
    # A request names addresses and services, not zones. A rule that applies only between particular zones can decide it for certain only when the
    # request names those zones; otherwise it is reported as a possible match and does not settle the answer.
    sz, dz = [req["src_zone"].lower()] if req.get("src_zone") else None, [req["dst_zone"].lower()] if req.get("dst_zone") else None
    verdict, decided_by, possible = "needs-new-rule", None, []
    for r in sorted(rules, key=lambda x: (x["device"], x["position"])):
        if not r["enabled"]:
            continue
        zones_any = r["src_zones"] == ["any"] and r["dst_zones"] == ["any"]
        probe = {**asked, "src_zones": sz or r["src_zones"], "dst_zones": dz or r["dst_zones"]}
        if not covers(r, probe):
            continue
        hit = {"device": r["device"], "rule": r["name"], "position": r["position"], "action": r["action"], "zones": f"{','.join(r['src_zones'])} to {','.join(r['dst_zones'])}"}
        if zones_any or (sz and dz):
            verdict, decided_by = ("already-allowed" if r["action"] == "allow" else "blocked-by-rule"), hit
            break
        possible.append(hit)
    ports, wide = ports_of(asked["services"])
    risky = {int(k) for k in (pol.get("risky_ports") or {})}
    never = set(rq.get("never_auto_approve_ports") or [])
    reasons, risk = [], "low"

    def raise_to(level, why):
        nonlocal risk
        if level == "high" or risk == "low":
            risk = level
        reasons.append(why)

    if "any" in asked["sources"]:
        raise_to("high", "The source is any address.")
    if "any" in asked["destinations"]:
        raise_to("high", "The destination is any address.")
    if wide:
        raise_to("high", "The service is any, or a very wide port range.")
    if ports & risky:
        raise_to("high", "It includes a management, remote-access or database port: " + ", ".join(str(p) for p in sorted(ports & risky)) + ".")
    days = req.get("days")
    if not days:
        raise_to("medium", "It has no end date.")
    elif days > rq.get("auto_approve_max_days", 30):
        raise_to("medium", f"It lasts {days} days, longer than the {rq.get('auto_approve_max_days', 30)}-day limit for automatic approval.")
    if len(asked["sources"]) > rq.get("auto_approve_max_sources", 5) and "any" not in asked["sources"]:
        raise_to("medium", f"It names {len(asked['sources'])} sources.")
    auto = verdict == "needs-new-rule" and risk == "low" and not (ports & never)
    if verdict == "already-allowed":
        reasons.insert(0, f"Rule '{decided_by['rule']}' on {decided_by['device']} already allows this; no change is needed.")
    if verdict == "blocked-by-rule":
        reasons.insert(0, f"Rule '{decided_by['rule']}' on {decided_by['device']} denies this traffic before any new allow rule would be reached.")
    if possible and verdict == "needs-new-rule":
        reasons.append("These rules would match if the traffic crosses their zones, so check them first: " + "; ".join(f"{p['rule']} on {p['device']} ({p['action']}, {p['zones']})" for p in possible[:3]) + ".")
    if not reasons:
        reasons.append("Specific, time-bound and low-risk.")
    path = None
    if topology is not None:
        try:
            from remediation.enrichment import network_reachability
            targets = [d for d in req.get("destinations") or [] if not _net(d)]
            if targets:
                path = [{"asset": t, **network_reachability.trace_path(t, topology)} for t in targets[:5]]
        except Exception:  # noqa: BLE001 - topology is optional context
            path = None
    return {"verdict": verdict, "decided_by": decided_by, "risk": risk, "reasons": reasons, "auto_approvable": auto and not possible, "possible_rules": possible[:5], "asked": {k: asked[k] for k in ("sources", "destinations", "services")}, "path": path}
