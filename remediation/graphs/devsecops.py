"""The portfolio supply-chain graph: which packages are shared across applications and which of them are vulnerable.

Nodes: applications, packages (only a package that a finding names and the SBOM confirms, or that two or more applications use), and fix proposals.
Edges: application -> package ('uses'), parent package -> vulnerable package ('depends_on', direct parents only, a few per package),
proposal -> package ('fixes') and proposal -> application ('for'). A package's weight is the number of applications that use it, so one vulnerable
package spread across many applications stands out. Built only from stored SBOMs, the findings passed in and recorded proposals.
"""
from remediation.appsec import graph as dep_graph, store as app_store
from remediation.gitops import proposals
from remediation.graphs.schema import SEVERITIES, GraphBuilder

MODULE = "devsecops"
MAX_PARENTS = 3
EMPTY_APPS = "No applications are recorded. Register applications and upload an SBOM for each (Applications page, or POST /api/ingest/sbom from CI) to see the supply chain."
EMPTY_SBOMS = "Applications are recorded but none has an SBOM. Upload an SBOM for each application to see which packages they share."


def _sev(value):
    s = (value or "").strip().lower()
    return s if s in SEVERITIES else None


def _worst(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if SEVERITIES.index(a) <= SEVERITIES.index(b) else b


def _pkg_key(c):
    name = (c.get("name") or "").strip().lower()
    group = (c.get("group") or "").strip().lower()
    full = f"{group}:{name}" if group and ":" not in name else name
    return f"pkg:{(c.get('ecosystem') or '').lower()}:{full}"


def build(engine=None, findings=None, **context):
    findings = findings or []
    b = GraphBuilder(MODULE, "Supply chain", "Applications, the packages they share, which are vulnerable and the fixes in flight.")
    b.kind("application", "Application")
    b.kind("package", "Package")
    b.kind("proposal", "Fix proposal")
    b.kind("uses", "uses")
    b.kind("depends_on", "depends on")
    b.kind("fixes", "fixes")
    apps = app_store.list_applications(engine)
    if not apps:
        return b.build(note=EMPTY_APPS)
    sboms = app_store.sbom_summaries(engine)
    loaded = []  # (app, structure, {ref: [finding ids]}, {finding id: severity})
    for app in apps:
        sb = app_store.get_sbom(app["name"], engine)
        if not sb:
            continue
        st = dep_graph.structure(sb["graph"])
        mine = [f for f in findings if app_store.norm((f.get("asset") or {}).get("name")) == app_store.norm(app["name"])]
        hits, _ = dep_graph.match_findings(st, mine)
        sev_by_id = {f.get("id"): _sev(f.get("severity")) for f in mine}
        loaded.append((app, st, hits, sev_by_id))
    if not loaded:
        for app in apps:
            b.node(f"app:{app['name']}", app["name"], "application", meta={"environment": app.get("environment"), "sbom": app["name"] in sboms}, href="/applications")
        return b.build(note=EMPTY_SBOMS)

    users = {}  # package key -> set of application names
    for app, st, _hits, _s in loaded:
        for c in st["comps"].values():
            users.setdefault(_pkg_key(c), set()).add(app["name"])

    pkg_nodes = {}  # package key -> meta accumulators
    app_sev = {}
    for app, st, hits, sev_by_id in sorted(loaded, key=lambda x: x[0]["name"]):
        app_id = f"app:{app['name']}"
        vuln_refs = set(hits)
        keep = {r for r in st["comps"] if r in vuln_refs or len(users[_pkg_key(st["comps"][r])]) >= 2}
        for ref in sorted(keep):
            c = st["comps"][ref]
            key = _pkg_key(c)
            ids = hits.get(ref, [])
            sev = None
            for fid in ids:
                sev = _worst(sev, sev_by_id.get(fid))
            info = pkg_nodes.setdefault(key, {"label": ((c.get("group") + ":") if c.get("group") and ":" not in c["name"] else "") + c["name"], "versions": set(), "findings": 0})
            if c.get("version"):
                info["versions"].add(c["version"])
            info["findings"] += len(ids)
            b.node(key, info["label"], "package", weight=1, sev=sev,
                   meta={"ecosystem": c.get("ecosystem"), "applications": len(users[key]), "vulnerable": bool(ids) or None}, href="/dependencies")
            b.edge(app_id, key, "uses", label=c.get("version"))
            app_sev[app["name"]] = _worst(app_sev.get(app["name"]), sev)
            if ids:  # direct parents of a vulnerable transitive package: where a developer can act
                parents = sorted((p for p in dep_graph.ancestors(st, ref) if st["depth"].get(p) == 1), key=lambda p: st["comps"][p]["name"])[:MAX_PARENTS]
                for p in parents:
                    pc = st["comps"][p]
                    pkey = _pkg_key(pc)
                    b.node(pkey, ((pc.get("group") + ":") if pc.get("group") and ":" not in pc["name"] else "") + pc["name"], "package", weight=0,
                           meta={"ecosystem": pc.get("ecosystem")}, href="/dependencies")
                    b.edge(pkey, key, "depends_on")
                    b.edge(app_id, pkey, "uses", label=pc.get("version"))
        b.node(app_id, app["name"], "application", weight=max(1, len(vuln_refs)), sev=app_sev.get(app["name"]),
               meta={"environment": app.get("environment"), "criticality": app.get("business_criticality"), "team": app.get("team"), "vulnerable_packages": len(vuln_refs)},
               href="/applications")
    for key, info in pkg_nodes.items():
        b.node(key, info["label"], "package", weight=0, meta={"versions": sorted(info["versions"]), "matched_findings": info["findings"]})
    for app in apps:  # an application with no SBOM is still part of the portfolio
        if app["name"] not in {a["name"] for a, *_ in loaded}:
            b.node(f"app:{app['name']}", app["name"], "application", meta={"environment": app.get("environment"), "sbom": False}, href="/applications")

    # fix proposals: only dependency upgrades whose package is drawn
    by_label = {}
    for key, info in pkg_nodes.items():
        by_label.setdefault(info["label"].lower().rsplit(":", 1)[-1], key)
    for p in sorted(proposals.list_proposals(engine=engine), key=lambda x: x["id"]):
        pkg = ((p["summary"] or {}).get("package") or "").lower().rsplit(":", 1)[-1]
        key = by_label.get(pkg)
        if not key or p["kind"] != "dependency-upgrade":
            continue
        pid = f"proposal:{p['id']}"
        b.node(pid, p["title"] or f"Proposal {p['id']}", "proposal", meta={"status": p["status"], "from": p["summary"].get("from"), "to": p["summary"].get("to")}, href="/fix-prs")
        b.edge(pid, key, "fixes", label=p["status"])
        if f"app:{p['application']}" in b._nodes:
            b.edge(pid, f"app:{p['application']}", "for")
    return b.build()
