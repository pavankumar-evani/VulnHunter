"""The whole-estate graph: every module's relationship graph read through the ontology and merged into one, plus the findings and recorded controls.

Nothing new is invented. Each module builder (remediation/graphs/*) still decides what is connected to what; this module re-labels its nodes and edges as
ontology classes and relations (the `mappings` in ontology.yaml), joins nodes that are the same thing across modules (the same asset, team, person,
technique or package), and adds three layers from stored data:

    findings      a Finding node per queue finding (capped), `affects` its asset, `instance-of` a Vulnerability when it has a CVE (KEV and EPSS only when the
                  enrichment recorded them), `tagged-with` the ATT&CK techniques already on it, and the Vulnerability `exploits` a Package when the finding's
                  dependency names one of the SBOM packages in the graph (a name match, marked heuristic)
    controls      the controls inventory as Control nodes that `protect` the assets their pattern matches and `mitigate` the techniques their class addresses
    derived       three Asset facts computed from the graph itself and listed under meta.derived: internet_facing (a path from an Internet node through
                  `reaches`), owned (an `owns` or `assigned-to` edge) and verified_controls

Unknown stays unknown: internet_facing is left unset on an asset that no infrastructure data covers (and everywhere when there is no Internet node), owned is
set only for assets the remediation graph covers, and verified_controls only when the controls inventory could be read. A node keeps `origin`, the
(module, id) pairs it came from, so a result can be drawn back on the module graph it belongs to. Size is capped; the result says when it was.
"""
import fnmatch

from remediation import graphs as module_graphs
from remediation.graphs.schema import SEVERITIES, GraphBuilder
from remediation.ontology import ontology as onto_mod
from remediation.ontology.ontology import slug

MODULE = "estate"
MAX_NODES = 2500
MAX_FINDINGS = 1500
SHARED = {"Asset", "Team", "Person", "Technique", "Package"}   # the same real thing in several modules: one node
_ORDER = ("infra", "remediation", "devsecops", "appsec", "soc", "ai", "grc", "admin")


def _sev(value):
    s = (str(value or "")).strip().lower()
    return s if s in SEVERITIES else None


def _pkg_tail(name):
    return str(name or "").strip().lower().rsplit(":", 1)[-1]


def _as_bool(v):
    return v if isinstance(v, bool) else None


def _finding_prov(f):
    from remediation.graphs.schema import prov
    return prov(source=f.get("source"), observed_at=f.get("last_seen"), confidence="observed" if f.get("source") else None)


def _load_controls(engine):
    try:
        from remediation.controls import store as controls_store
        return controls_store.list_controls(engine=engine)
    except Exception:  # noqa: BLE001 - optional layer: an unreadable inventory is "unknown", never a failure of the estate
        return None


def _load_mitigations():
    try:
        from remediation.enrichment import client_controls
        data = client_controls.load()
        return data.get("techniques") or {}, data.get("mitigations") or {}
    except Exception:  # noqa: BLE001
        return {}, {}


def build(engine=None, findings=None, graphs=None, controls="load", max_nodes=MAX_NODES, max_findings=MAX_FINDINGS, onto=None, modules=None):
    """The estate graph (the shape of graphs/schema.py plus `origin` on nodes and `sources`/`skipped` on the graph).

    `graphs` may supply already-built {module: graph} (otherwise each module builder is run; one that fails is reported in `sources`, never fatal);
    `controls` is a list of controls-inventory rows, None for "could not be read", or "load" to read the inventory."""
    from remediation.graphs.schema import prov as make_prov
    onto = onto or onto_mod.load()
    findings = list(findings or [])
    g = GraphBuilder(MODULE, "Whole estate", "Every module's graph read through the ontology, with findings, vulnerabilities and recorded controls.")
    origin = {}                 # estate id -> set of (module, original id)
    cls_of = {}                 # estate id -> class
    sources, skipped = [], {"nodes": 0, "edges": 0}
    asset_by_lower = {}
    notes = []

    def put(eid, cls, label, weight=1, sev=None, meta=None, href=None, prov=None, org=None):
        g.node(eid, label, slug(cls), weight=weight, sev=sev, meta=meta, href=href, prov=prov)
        cls_of[eid] = cls
        if org:
            origin.setdefault(eid, set()).add(org)
        return eid

    # ---------------------------------------------------------------- 1. module graphs
    built = {}
    for m in (modules or _ORDER):
        if m not in module_graphs.MODULES:
            continue
        if graphs and m in graphs:
            built[m] = graphs[m]
            continue
        try:
            built[m] = module_graphs.build(m, engine=engine, findings=findings)
        except Exception as exc:  # noqa: BLE001 - a module whose data cannot be read must not hide the others
            built[m] = None
            sources.append({"module": m, "nodes": 0, "edges": 0, "error": f"{type(exc).__name__}: {exc}"[:200]})
    mapping_to_estate = {}      # (module, node id) -> estate id
    for m in [x for x in _ORDER if x in built] + [x for x in built if x not in _ORDER]:
        gr = built[m]
        if gr is None:
            continue
        sources.append({"module": m, "nodes": len(gr.get("nodes") or []), "edges": len(gr.get("edges") or []), "truncated": bool(gr.get("truncated"))})
        for n in gr.get("nodes") or []:
            cls = onto.node_class(m, n.get("kind"))
            if cls is None:
                skipped["nodes"] += 1
                continue
            nid = n["id"]
            if cls == "Asset" and ":" in nid:       # an asset by name, whatever module called it host: or asset:
                name = nid.split(":", 1)[1]
                eid = asset_by_lower.setdefault(name.lower(), f"asset:{name}")
            elif cls in SHARED:
                eid = nid
            else:
                eid = f"{m}/{nid}"
            if eid in cls_of and cls_of[eid] != cls:
                eid = f"{m}/{nid}"
            mapping_to_estate[(m, nid)] = eid
            meta = dict(n.get("meta") or {})
            if cls == "AIAsset":
                meta.setdefault("reviewed", n.get("kind") != "shadow")
                meta.setdefault("kind", n.get("kind"))
            if cls == "Package" and meta.get("vulnerable") is None:
                meta.pop("vulnerable", None)
            put(eid, cls, n.get("label") or nid, weight=n.get("weight") or 1, sev=n.get("sev"), meta=meta, href=n.get("href"), prov=n.get("prov"), org=(m, nid))
        for e in gr.get("edges") or []:
            rel = onto.edge_relation(m, e.get("kind"))
            s, t = mapping_to_estate.get((m, e.get("source"))), mapping_to_estate.get((m, e.get("target")))
            if rel is None or s is None or t is None:
                skipped["edges"] += 1
                continue
            g.edge(s, t, rel, label=e.get("label"), weight=e.get("weight") or 1, prov=e.get("prov"))

    # ---------------------------------------------------------------- 2. findings layer
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    ordered = sorted(findings, key=lambda f: (rank.get(_sev(f.get("severity")), 9), str(f.get("id"))))
    if len(ordered) > max_findings:
        notes.append(f"Showing the {max_findings} most severe of {len(ordered)} findings.")
        ordered = ordered[:max_findings]
    vuln_meta = {}
    pkg_index = {}
    for eid, cls in cls_of.items():
        if cls == "Package":
            pkg_index.setdefault(_pkg_tail(g._nodes[eid]["label"]), eid)
    for f in ordered:
        fid = f.get("id")
        asset = f.get("asset") if isinstance(f.get("asset"), dict) else {}
        name = asset.get("hostname") or asset.get("name")
        if not fid or not name:
            continue
        aid = asset_by_lower.setdefault(str(name).lower(), f"asset:{name}")
        put(aid, "Asset", name, weight=0, meta={"type": asset.get("type")} if asset.get("type") else None, href="/assets", org=None)
        sev = _sev(f.get("severity"))
        kev = f["kev"].get("listed") if isinstance(f.get("kev"), dict) and f.get("cve") else None
        epss = f["epss"].get("score") if isinstance(f.get("epss"), dict) and f.get("cve") else None
        fnode = f"finding:{fid}"
        fprov = _finding_prov(f)
        put(fnode, "Finding", f.get("title") or str(fid), sev=sev, href="/queue", prov=fprov,
            meta={"severity": sev, "scan_type": f.get("scan_type"), "source": f.get("source"), "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen"),
                  "kev": _as_bool(kev), "epss": epss if isinstance(epss, (int, float)) and not isinstance(epss, bool) else None})
        g.edge(fnode, aid, "affects", prov=fprov)
        cve = str(f.get("cve") or "").strip().upper()
        if cve:
            vid = f"cve:{cve}"
            vm = vuln_meta.setdefault(vid, {"cve": cve, "kev": None, "epss": None})
            if _as_bool(kev) is not None and vm["kev"] is None:
                vm["kev"] = _as_bool(kev)
            if isinstance(epss, (int, float)) and not isinstance(epss, bool) and vm["epss"] is None:
                vm["epss"] = epss
            put(vid, "Vulnerability", cve, weight=1, meta=dict(vm), href="/queue")
            g.edge(fnode, vid, "instance-of", prov=fprov)
            pkg = _pkg_tail((f.get("dependency") or {}).get("package"))
            if pkg and pkg in pkg_index:
                g.edge(vid, pkg_index[pkg], "exploits",
                       prov=make_prov(source="finding dependency name matched to an SBOM package name", source_kind="derived", confidence="heuristic"))
        for t in f.get("attack_techniques") or []:
            tid = str((t or {}).get("technique_id") or "").strip().upper()
            if tid:
                put(f"technique:{tid}", "Technique", tid, weight=0, meta={"tactic": t.get("tactic")} if t.get("tactic") else None, href="/hunting?tab=proposals")
                g.edge(fnode, f"technique:{tid}", "tagged-with", prov=make_prov(source="ATT&CK mapping recorded on the finding", source_kind="derived", confidence="heuristic"))

    # ---------------------------------------------------------------- 3. controls layer
    rows = _load_controls(engine) if controls == "load" else controls
    asset_ids = {eid for eid, c in cls_of.items() if c == "Asset"}      # exactly Asset: an AI system is not matched against control patterns
    verified = {a: 0 for a in asset_ids}
    if rows:
        tech_map, mitig = _load_mitigations()
        classes_by_tech = {t: {(mitig.get(mid) or {}).get("class") for mid in mids} for t, mids in tech_map.items()}
        present_tech = {eid: g._nodes[eid]["label"].upper() for eid, c in cls_of.items() if c == "Technique"}
        for r in sorted(rows, key=lambda x: (x.get("id") if x.get("id") is not None else 0, x.get("asset_name") or "")):
            cid = f"inventory/control:{r.get('id') if r.get('id') is not None else (r.get('asset_name'), r.get('control_class'), r.get('name'))}"
            state = r.get("state") if r.get("state") in ("verified", "claimed") else None
            cprov = make_prov(source=r.get("source"), source_kind="connector" if state == "verified" else "user" if state == "claimed" else None,
                              observed_at=r.get("last_seen"), confidence="observed" if state == "verified" else "declared" if state == "claimed" else None)
            put(cid, "Control", r.get("name") or str(r.get("control_class")), href="/controls", prov=cprov,
                meta={"control_class": r.get("control_class"), "state": state, "applies_to": r.get("asset_name")})
            pattern = str(r.get("asset_name") or "").lower()
            for aid in sorted(asset_ids):
                if pattern and fnmatch.fnmatchcase(aid.split(":", 1)[1].lower(), pattern):
                    g.edge(cid, aid, "protects", prov=cprov)
                    if state == "verified":
                        verified[aid] += 1
            for teid, tid in sorted(present_tech.items()):
                if r.get("control_class") in classes_by_tech.get(tid, ()):
                    g.edge(cid, teid, "mitigates", prov=make_prov(source="attack_mitigations.yaml", source_kind="derived", confidence="declared"))
    if rows is not None:
        for aid, k in verified.items():
            g._nodes[aid]["meta"]["verified_controls"] = k
            g._nodes[aid]["meta"].setdefault("derived", []).append("verified_controls")

    # ---------------------------------------------------------------- 4. derived asset facts
    edges = list(g._edges.values())
    rels = {r for rel in ("reaches",) for r in onto.with_subrelations(rel)}
    out_adj = {}
    for e in edges:
        if e["kind"] in rels:
            out_adj.setdefault(e["source"], []).append(e["target"])
    internet = sorted(eid for eid, c in cls_of.items() if c == "Internet")
    if internet:
        seen, todo = set(internet), list(internet)
        while todo:
            for nxt in out_adj.get(todo.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        covered = {eid for (m, _nid), eid in mapping_to_estate.items() if m == "infra"}
        for aid in asset_ids:
            if aid in seen:
                g._nodes[aid]["meta"]["internet_facing"] = True
            elif aid in covered:
                g._nodes[aid]["meta"]["internet_facing"] = False
            else:
                continue
            g._nodes[aid]["meta"].setdefault("derived", []).append("internet_facing")
    owners = {e["target"] for e in edges if e["kind"] in ("owns", "assigned-to")}
    rem_assets = {eid for (m, _nid), eid in mapping_to_estate.items() if m == "remediation" and cls_of.get(eid) == "Asset"}
    for aid in sorted(rem_assets & asset_ids):
        g._nodes[aid]["meta"]["owned"] = aid in owners
        g._nodes[aid]["meta"].setdefault("derived", []).append("owned")

    # ---------------------------------------------------------------- 5. finish
    for cls in sorted(set(cls_of.values())):
        g.kind(slug(cls), cls)
    for rel in sorted({e["kind"] for e in g._edges.values()}):
        g.kind(rel, rel)
    if skipped["nodes"] or skipped["edges"]:
        notes.append(f"{skipped['nodes']} nodes and {skipped['edges']} edges of a module graph have no entry in the ontology mappings and are left out (run validate on that module).")
    failed = [s["module"] for s in sources if s.get("error")]
    if failed:
        notes.append("Not available: " + ", ".join(failed) + ".")
    if not g._nodes:
        notes.append("Nothing is recorded yet: connect data sources so the module graphs and the findings queue have content.")
    out = g.build(note=" ".join(notes) or None, limit=max_nodes)
    keep = {n["id"] for n in out["nodes"]}
    for n in out["nodes"]:
        n["origin"] = [{"module": m, "id": i} for m, i in sorted(origin.get(n["id"], ()))]
    out["sources"] = sorted(sources, key=lambda s: s["module"])
    out["skipped"] = skipped
    out["origin_modules"] = sorted({m for k in keep for m, _ in origin.get(k, ())})
    return out
