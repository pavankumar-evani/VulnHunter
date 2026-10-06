"""The infrastructure graph: how the internet reaches assets and how an attacker could move once inside.

Nodes: the internet, network hops from network_topology.yaml, assets that carry findings, internet-facing firewall rules and the risky ports they open,
and (from imported discovery output, bounded) domain -> address -> exposed service -> technology.
Edges: internet -> hop or rule ('reaches'), hop -> hop or asset ('routes_to'), rule -> port ('opens'), rule -> asset ('routes_to', when the rule's destination
names the asset), asset -> asset ('pivot', labelled with the ATT&CK tactic).

Pivot edges are heuristic and say so: attack_chains.py chains findings within one asset, so a link between two assets is drawn only when they sit behind
the same network hop (topology) and the first has an entry or pivot stage finding while the second has a pivot or impact stage one. It is "plausible
path", never a proven exploit path.
"""
from remediation.enrichment import attack_chains, attack_mapping, network_reachability
from remediation.asm import parsers as asm_parsers, store as asm_store
from remediation.firewall import analysis as fw_analysis, store as fw_store
from remediation.graphs.schema import SEVERITIES, GraphBuilder, prov

MODULE = "infra"
INTERNET = "internet"
MAX_PIVOT_EDGES = 200
_TOPOLOGY_PROV = prov(source="network_topology.yaml", source_kind="user", confidence="declared")
_PIVOT_PROV = prov(source="attack_chains (same hop, entry/pivot to pivot/impact stage)", source_kind="derived", confidence="heuristic")
MAX_ASM_NODES = 150
NOTE_EMPTY = "No findings, network topology or firewall rules are recorded. Ingest scanner findings (Connections page), fill remediation/config/network_topology.yaml and import firewall rules (Firewall page) to see how the internet reaches your assets."
NOTE_NO_EXPOSURE = "Showing assets with findings only. Add network_topology.yaml entries or import firewall rules (Firewall page) to add how the internet reaches them."
_STAGE_RANK = {"entry": 0, "pivot": 1, "impact": 2}


def _sev(value):
    s = (value or "").strip().lower()
    return s if s in SEVERITIES else None


def _worst(a, b):
    if a is None or b is None:
        return a or b
    return a if SEVERITIES.index(a) <= SEVERITIES.index(b) else b


def _asset_name(f):
    a = f.get("asset") or {}
    return a.get("hostname") or a.get("name")


def _load_topology(context):
    if "topology" in context:
        return context["topology"] or {"assets": []}
    try:
        return network_reachability.load_topology()
    except Exception:  # noqa: BLE001 - optional context: a missing or broken file is "no topology"
        return {"assets": []}


def _load_rules(engine):
    try:
        return fw_store.rules(engine=engine)
    except Exception:  # noqa: BLE001
        return []


def _load_asm(engine, context):
    """In-scope, active external assets from imported attack-surface data (empty when none were imported or the store is unreadable)."""
    if "asm_assets" in context:
        return context["asm_assets"] or []
    try:
        return asm_store.all_assets(engine, in_scope=True, status="active")
    except Exception:  # noqa: BLE001 - optional context
        return []


def _asm_lane(b, assets):
    """domain -> address -> service -> technology, from imported discovery output. Bounded: services first (they are the exposure), then what leads to them."""
    ranked = sorted(assets, key=lambda a: (a["kind"] != "service", a["kind"] != "url", a["value"]))
    budget = MAX_ASM_NODES
    drawn = 0
    for a in ranked:
        if a["kind"] not in ("service", "url") or budget <= 0:
            continue
        d = a["data"]
        host = d.get("host") or a["value"]
        names = [h for h in d.get("hosts") or [] if not asm_parsers.is_ip(h)] or ([host] if not asm_parsers.is_ip(host) else [])
        ips = [i for i in (d.get("ips") or []) + ([host] if asm_parsers.is_ip(host) else []) if asm_parsers.is_ip(i)][:1]
        need = 1 + len(names[:1]) + len(ips) + len(a["technologies"][:3])
        if need > budget:
            continue
        budget -= need
        sev = "high" if any(v.get("severity") in ("critical", "high") for v in d.get("vulns") or []) else ("medium" if d.get("vulns") else None)
        sid = f"asm_service:{a['key']}"
        label = a["value"] if a["kind"] == "url" else a["value"].split("/")[0]
        b.node(sid, label, "asm_service", sev=sev, meta={"asset_kind": a["kind"], "ports": a["ports"][:5], "last_seen": a["last_seen"], "sources": a["sources"]}, href="/attack-surface")
        prev_up = sid
        if ips:
            ip_id = f"asm_ip:{ips[0]}"
            b.node(ip_id, ips[0], "asm_ip", href="/attack-surface")
            b.edge(ip_id, sid, "exposes")
            prev_up = ip_id
        if names:
            dom = f"asm_domain:{names[0]}"
            b.node(dom, names[0], "asm_domain", href="/attack-surface")
            b.edge(dom, prev_up, "resolves_to" if ips else "exposes")
            b.edge(INTERNET, dom, "reaches")
        elif ips:
            b.edge(INTERNET, prev_up, "reaches")
        for t in a["technologies"][:3]:
            tid = f"asm_tech:{asm_parsers.product_version(t)[0]}"
            b.node(tid, asm_parsers.product_version(t)[0] or t, "asm_tech", href="/attack-surface")
            b.edge(sid, tid, "runs")
        drawn += 1
    return drawn > 0


def build(engine=None, findings=None, **context):
    findings = findings or []
    b = GraphBuilder(MODULE, "Exposure and movement", "How the internet reaches assets, and how an attacker could move between them.")
    for k, label in (("internet", "Internet"), ("hop", "Network hop"), ("asset", "Asset"), ("rule", "Firewall rule"), ("port", "Exposed port"),
                     ("reaches", "reaches"), ("routes_to", "routes to"), ("opens", "opens"), ("pivot", "pivot"),
                     ("asm_domain", "Domain or subdomain"), ("asm_ip", "Address"), ("asm_service", "Exposed service"), ("asm_tech", "Technology"),
                     ("resolves_to", "resolves to"), ("exposes", "exposes"), ("runs", "runs")):
        b.kind(k, label)
    topology = _load_topology(context)
    rules = _load_rules(engine)
    asm = _load_asm(engine, context)
    if not findings and not topology.get("assets") and not rules and not asm:
        return b.build(note=NOTE_EMPTY)

    # assets that carry findings
    assets = {}
    for f in findings:
        name = _asset_name(f)
        if not name:
            continue
        a = assets.setdefault(name, {"count": 0, "sev": None, "type": (f.get("asset") or {}).get("type")})
        a["count"] += 1
        a["sev"] = _worst(a["sev"], _sev(f.get("severity")))
    chained = {c["asset_name"] for c in attack_chains.build_chains(findings)} if findings else set()
    for name in sorted(assets):
        a = assets[name]
        b.node(f"asset:{name}", name, "asset", weight=a["count"], sev=a["sev"],
               meta={"open_findings": a["count"], "type": a["type"], "entry_to_impact_chain": name in chained or None}, href="/assets")

    # topology lane: internet -> hops -> asset
    hop_assets = {}  # hop id -> asset names behind it
    exposed = False
    for name in sorted(assets):
        hops = network_reachability.find_asset_path(name, topology)
        if not hops:
            continue
        exposed = True
        prev = INTERNET
        for h in hops:
            hid = f"hop:{h.get('name')}"
            b.node(hid, h.get("name"), "hop", meta={"hop_type": h.get("hop_type"), "default_action": h.get("default_action")}, href="/infrastructure")
            b.edge(prev, hid, "reaches" if prev == INTERNET else "routes_to", prov=_TOPOLOGY_PROV)
            hop_assets.setdefault(hid, set()).add(name)
            prev = hid
        b.edge(prev, f"asset:{name}", "routes_to", prov=_TOPOLOGY_PROV)
    # hops of topology entries with an exact name but no finding are not drawn: nothing to route to

    # firewall lane: internet-facing rules and the risky ports they open
    try:
        pol = context.get("firewall_policy") or fw_analysis.policy()
    except Exception:  # noqa: BLE001
        pol = None
    if rules and pol is not None:
        exp = fw_analysis.exposure(rules, pol=pol)
        lower = {n.lower(): n for n in assets}
        drawn = {}

        def rule_node(r, sev, wide):
            rid = f"rule:{r['device']}/{r['rule']}"
            b.node(rid, r["rule"], "rule", sev=sev, meta={"device": r["device"], "wide_open": wide or None}, href="/firewall")
            b.edge(INTERNET, rid, "reaches", prov=prov(source=f"firewall rules ({r.get('device')})", confidence="declared"))
            for d in r.get("destinations") or []:
                if d.lower() in lower:
                    b.edge(rid, f"asset:{lower[d.lower()]}", "routes_to")
            return rid

        for p in exp["ports"]:
            if not p["risky"]:
                continue
            pid = f"port:{p['port']}"
            b.node(pid, f"{p['port']} {p['name'] or ''}".strip(), "port", weight=len(p["rules"]), sev="high", meta={"unused": p["all_unused"] or None}, href="/firewall")
            for r in p["rules"]:
                drawn[(r["device"], r["rule"])] = rule_node(r, "high", False)
                b.edge(drawn[(r["device"], r["rule"])], pid, "opens")
                exposed = True
        for r in exp["wide_open_rules"]:
            rule_node(r, "critical", True)
            exposed = True

    # attack-chain links between assets that sit behind the same hop
    staged = {}
    if findings:
        for f in attack_mapping.tag_findings(findings) if "attack_techniques" not in findings[0] else findings:
            name = _asset_name(f)
            for t in f.get("attack_techniques") or []:
                stage = attack_chains._stage_for(t.get("tactic"))
                if name and stage:
                    staged.setdefault(name, {}).setdefault(stage, set()).add(t["tactic"])
    pivots = 0
    for hid in sorted(hop_assets):
        names = sorted(hop_assets[hid])
        for src in names:
            for dst in names:
                if src == dst or pivots >= MAX_PIVOT_EDGES:
                    continue
                s, d = staged.get(src, {}), staged.get(dst, {})
                if ("entry" in s or "pivot" in s) and ("pivot" in d or "impact" in d):
                    tactic = sorted(s.get("pivot") or s.get("entry"))[0]
                    b.edge(f"asset:{src}", f"asset:{dst}", "pivot", label=tactic, prov=_PIVOT_PROV)
                    pivots += 1
    if asm:
        exposed = _asm_lane(b, asm) or exposed
    if not exposed:
        return b.build(note=NOTE_NO_EXPOSURE)
    b.node(INTERNET, "Internet", "internet", weight=1, href="/infrastructure")
    return b.build()
