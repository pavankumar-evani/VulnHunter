"""
One application, end to end: its dependency graph joined to its findings, each finding ranked, the open-source findings grouped into the upgrades that
close them, and the network path from the internet to the application.

This is the data behind the Applications page and its interactive graph. It reads what is stored (the SBOM, the application record) and what is passed
in (the findings, the optional topology); it changes nothing.
"""
from remediation.appsec import criticality as crit_mod
from remediation.appsec import graph as g
from remediation.appsec import scoring, store, versions
from remediation.enrichment import attack_chains
from remediation.enrichment import network_reachability as net

CODE_SCAN_TYPES = ("sast", "secrets", "iac", "container", "dast", "cicd")
HOP_LABEL = {"waf": "WAF", "load_balancer": "Load balancer", "dmz": "DMZ", "firewall": "Firewall"}


def app_findings(app_name, findings):
    key = store.norm(app_name)
    return [f for f in findings if store.norm((f.get("asset") or {}).get("name")) == key and f.get("status") not in ("resolved", "closed")]


def reachability(app_name, app, topology=None):
    """The path from the internet to the application, as a lane of stops the UI draws, with an honest note when no path is recorded."""
    try:
        trace = net.trace_path(app_name, topology)
    except (OSError, ValueError):
        trace = {"verdict": "unknown", "hops": []}
    stops = [{"kind": "internet", "name": "Internet", "action": None}]
    for h in trace["hops"]:
        stops.append({"kind": h.get("hop_type", "firewall"), "label": HOP_LABEL.get(h.get("hop_type"), str(h.get("hop_type", "hop")).title()), "name": h.get("name"),
                      "action": str(h.get("default_action", "")).lower() or None})
    stops.append({"kind": "application", "name": app_name, "action": None})
    note = None
    if trace["verdict"] == "unknown":
        note = "No network path is recorded for this application (remediation/config/network_topology.yaml), so exposure is judged only from the 'internet facing' flag."
    elif trace["verdict"] == "denied":
        note = "At least one hop on the recorded path denies traffic. That lowers the score of the application's findings; it does not remove them."
    expo, why = scoring.exposure(app, trace)
    return {"verdict": trace["verdict"], "stops": stops, "exposure": expo, "exposure_reason": why, "note": note,
            "protections": sorted({h.get("hop_type") for h in trace["hops"] if h.get("hop_type")})}


def _chain_roles(findings):
    roles = {}
    try:
        chains = attack_chains.build_chains(findings)
    except Exception:  # noqa: BLE001 - chain tagging is context; a failure must not hide the findings
        return roles
    rank = {"pivot": 3, "entry": 2, "impact": 1}
    for ch in chains:
        for role, items in (("entry", ch["entry"]), ("pivot", ch["pivots"]), ("impact", ch["impact"])):
            for i in items:
                if rank[role] > rank.get(roles.get(i["id"]), 0):
                    roles[i["id"]] = role
    return roles


def _compact(f, scored, comp_ref, role):
    dep = f.get("dependency") or {}
    return {"id": f["id"], "title": f.get("title"), "severity": f.get("severity"), "scan_type": f.get("scan_type"), "cve": f.get("cve"), "cvss": f.get("cvss"),
            "epss": (f.get("epss") or {}).get("score"), "kev": bool((f.get("kev") or {}).get("listed")), "location": f.get("location"), "first_seen": f.get("first_seen"),
            "package": dep.get("package"), "version": dep.get("version"), "fixed_version": dep.get("fixed_version"), "component": comp_ref, "chain_role": role,
            "score": scored["score"], "tier": scored["tier"], "breakdown": scored["breakdown"], "modifiers": scored["modifiers"], "assumptions": scored["assumptions"]}


def _upgrade_items(app, dep_findings, st, rules):
    groups = {}
    for cf in dep_findings:
        key = ((cf.get("package") or "").lower(), (cf.get("ecosystem") or ""))
        groups.setdefault(key, []).append(cf)
    items = []
    for (pkg, eco), fs in groups.items():
        fs.sort(key=lambda x: -x["score"])
        comp = st["comps"].get(fs[0]["component"]) if fs[0]["component"] else None
        current = (comp or {}).get("version") or fs[0].get("version")
        fixed = [x["fixed_version"] for x in fs if x.get("fixed_version")]
        target = versions.highest(fixed)
        unfixed = [x["id"] for x in fs if not x.get("fixed_version")]
        direct = g.is_direct(st, comp["ref"]) if comp else None
        bonus = min(rules["upgrade"]["bonus_cap"], rules["upgrade"]["bonus_per_extra_finding"] * (len(fs) - 1))
        score = round(min(100.0, fs[0]["score"] + bonus), 1)
        items.append({"id": f"dep:{pkg}", "kind": "dependency-upgrade", "application": app["name"], "package": fs[0].get("package"), "ecosystem": eco or (comp or {}).get("ecosystem"),
                      "current_version": current, "target_version": target, "crosses_major": bool(target and versions.crosses_major(current, target)), "direct": direct,
                      "pulled_in_by": g.direct_parents(st, comp["ref"]) if comp else [], "finding_ids": [x["id"] for x in fs], "cves": sorted({x["cve"] for x in fs if x.get("cve")}),
                      "resolves": len(fs), "unfixed_finding_ids": unfixed, "score": score, "tier": scoring.tier(score, rules), "top_finding": fs[0]["id"],
                      "kev": any(x["kev"] for x in fs), "in_sbom": comp is not None,
                      "note": (None if target and not unfixed else ("No fixed version is known for any of these findings: watch the advisory or replace the package." if not target
                                                                    else f"{len(unfixed)} of {len(fs)} finding(s) have no known fixed version, so the upgrade may not close them all."))})
    return items


def analyse(app_name, findings, engine=None, topology=None, rules=None, crit_rules=None, view="focus", limit=300):
    """The full picture for one application. `view` is 'focus' (large graphs are cut down to the direct dependencies, flagged packages and the paths to
    them) or 'all' (refused above 3,000 components)."""
    app = store.get_application(app_name, engine)
    if app is None:
        raise KeyError("No such application")
    rules = rules or scoring.load_rules()
    crit_rules = crit_rules if crit_rules is not None else crit_mod.load_rules()
    name = app["name"]
    mine = app_findings(name, findings)
    reach = reachability(name, app, topology)
    roles = _chain_roles(mine)
    sb = store.get_sbom(name, engine)
    out = {"application": name, "context": app, "reachability": reach, "sbom": None, "root": None, "nodes": [], "edges": [], "hidden": 0, "unmatched_findings": []}
    st, hits, unmatched = None, {}, []
    if sb:
        graph = sb["graph"]
        st = g.structure(graph)
        hits, unmatched = g.match_findings(st, [f for f in mine if (f.get("dependency") or {}).get("package")])
        out["sbom"] = {"format": sb["format"], "uploaded_at": sb["uploaded_at"], "uploaded_by": sb["uploaded_by"], "source": sb["source"], "components": len(graph["components"]),
                       "has_graph": graph["has_graph"], "notes": sb["notes"]}
        out["root"] = {"id": st["root_ref"] or "app", "name": (graph.get("root") or {}).get("name") or name, "version": (graph.get("root") or {}).get("version")}
    comp_of = {fid: ref for ref, ids in hits.items() for fid in ids}
    scored_list, dep_scored = [], []
    for f in mine:
        ref = comp_of.get(f["id"])
        is_dep = bool((f.get("dependency") or {}).get("package"))
        if ref:
            c = st["comps"][ref]
            level = crit_mod.classify(c["name"], c.get("group"), c.get("scope"), crit_rules)["level"]
            depth = {True: "direct", False: "transitive", None: "unknown"}[g.is_direct(st, ref)]
        elif is_dep:
            dep = f["dependency"]
            level, depth = crit_mod.classify(dep.get("package"), None, None, crit_rules)["level"], {True: "direct", False: "transitive"}.get(dep.get("direct"), "unknown")
        else:
            level, depth = scoring.file_sensitivity(f.get("location")), None
        res = scoring.score_finding(f, {"app": app, "reach": reach, "chain_role": roles.get(f["id"]), "package_level": level, "depth": depth}, rules)
        cf = _compact(f, res, ref, roles.get(f["id"]))
        scored_list.append(cf)
        if is_dep:
            dep_scored.append(cf)
    scored_list.sort(key=lambda x: (-x["score"], x["id"]))
    items = _upgrade_items(app, dep_scored, st or {"comps": {}, "depth": {}, "parents": {}, "root_ref": None}, rules) if dep_scored else []
    items += [{"id": x["id"], "kind": "code-fix", "application": name, "finding_ids": [x["id"]], "title": x["title"], "location": x["location"], "scan_type": x["scan_type"],
               "score": x["score"], "tier": x["tier"], "kev": x["kev"], "resolves": 1} for x in scored_list if not x["package"]]
    items.sort(key=lambda x: (-x["score"], x["id"]))
    out["findings"], out["work_items"], out["unmatched_findings"] = scored_list, items, unmatched
    if st:
        score_of = {x["id"]: x for x in scored_list}
        nodes = []
        for ref, c in st["comps"].items():
            ids = hits.get(ref, [])
            top = max((score_of[i] for i in ids), key=lambda x: x["score"], default=None)
            ci = crit_mod.classify(c["name"], c.get("group"), c.get("scope"), crit_rules)
            vulnerable = bool(ids)
            n = {"id": ref, "name": c["name"], "group": c.get("group"), "version": c.get("version"), "ecosystem": c.get("ecosystem"), "purl": c.get("purl"),
                 "licenses": c.get("licenses"), "scope": c.get("scope"), "depth": st["depth"].get(ref), "direct": g.is_direct(st, ref), "criticality": ci,
                 "findings": ids, "vulnerable": vulnerable, "top_score": top["score"] if top else None, "top_tier": top["tier"] if top else None,
                 "worst_severity": min((score_of[i]["severity"] for i in ids), key=lambda s: g.SEVERITY_ORDER.get(s, 9), default=None)}
            if vulnerable:
                anc = g.ancestors(st, ref)
                n["path"] = g.path_to_root(st, ref)
                n["dependents"] = sorted(st["comps"][a]["name"] for a in anc)
                n["pulled_in_by"] = g.direct_parents(st, ref)
                fixed = [score_of[i]["fixed_version"] for i in ids if score_of[i]["fixed_version"]]
                n["fixed_version"] = versions.highest(fixed)
            nodes.append(n)
        edges = [e for e in (graph["edges"]) if e[0] in st["comps"] or e[0] == st["root_ref"]]
        nodes.insert(0, {"id": out["root"]["id"], "name": out["root"]["name"], "version": out["root"]["version"], "kind": "application", "depth": 0, "direct": None, "findings": [], "vulnerable": False})
        if not st["root_ref"]:  # no declared application in the SBOM: draw one above the top-level packages
            edges = edges + [[out["root"]["id"], n["id"]] for n in nodes if n.get("depth") == 1]
        keep = {n["id"] for n in nodes if n.get("kind") == "application" or n.get("depth") == 1 or n["vulnerable"]}
        for n in [n for n in nodes if n["vulnerable"]]:
            cur = n["id"]
            while cur is not None:
                keep.add(cur)
                cur = st["via"].get(cur)
        if view == "all":
            if len(nodes) > 3000:
                raise ValueError("This application has more than 3,000 components; the full graph is too large to draw. Use the focused view.")
            limit = 10 ** 9
        nodes, edges, hidden = g.trim(nodes, edges, keep, limit)
        out["nodes"], out["edges"], out["hidden"] = nodes, edges, hidden
    flagged = [n for n in out["nodes"] if n.get("vulnerable")]
    out["stats"] = {"components": (out["sbom"] or {}).get("components", 0), "direct": sum(1 for n in out["nodes"] if n.get("depth") == 1),
                    "vulnerable_components": len(flagged), "findings": len(scored_list), "dependency_findings": len(dep_scored), "code_findings": len(scored_list) - len(dep_scored),
                    "p1": sum(1 for i in items if i["tier"] == "P1"), "unmatched": len(unmatched), "upgrades": sum(1 for i in items if i["kind"] == "dependency-upgrade")}
    return out


def overview(findings, engine=None, rules=None):
    """One row per application for the list page. Cheap: no graph is loaded."""
    rules = rules or scoring.load_rules()
    apps = store.list_applications(engine)
    sboms = store.sbom_summaries(engine)
    by_app = {}
    for f in findings:
        if f.get("status") in ("resolved", "closed"):
            continue
        by_app.setdefault(store.norm((f.get("asset") or {}).get("name")), []).append(f)
    rows = []
    for a in apps:
        mine = by_app.get(store.norm(a["name"]), [])
        dep = [f for f in mine if (f.get("dependency") or {}).get("package")]
        rows.append({**a, "sbom": sboms.get(a["name"]), "findings": len(mine), "dependency_findings": len(dep), "code_findings": len(mine) - len(dep),
                     "kev": sum(1 for f in mine if (f.get("kev") or {}).get("listed")), "critical": sum(1 for f in mine if f.get("severity") == "Critical")})
    known = {store.norm(a["name"]) for a in apps}
    unregistered = sorted({(f.get("asset") or {}).get("name") for k, fs in by_app.items() if k not in known for f in fs[:1]
                           if any((x.get("dependency") or {}).get("package") or x.get("scan_type") in ("sast", "sca", "secrets") for x in fs)})
    return {"applications": rows, "unregistered": [n for n in unregistered if n][:200]}
