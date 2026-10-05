"""
The dependency graph of one application: which packages are direct, which are pulled in by others, how far each sits from the application, and which
scanner findings belong to which package.

Everything is computed from the stored SBOM (sbom_parse.py's shape) and the findings that name the application; nothing is guessed. When the SBOM is a
flat list with no edges, depth and directness are reported as unknown rather than invented, and the UI says the graph is not available.

Matching a finding to a package: a finding's `dependency.package` is compared with the component's name and its group:name, ignoring case, preferring a
component whose version equals the finding's. A finding that matches no component is returned as unmatched, because that mismatch is worth seeing
(the scanner and the SBOM disagree about what is installed).
"""
from collections import deque

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def structure(graph):
    """Adjacency, depths and the shortest path from the application to each component. Pure; no findings involved."""
    comps = {c["ref"]: c for c in graph["components"]}
    root = graph.get("root")
    root_ref = root["ref"] if root else None
    children, parents = {}, {}
    for a, b in graph["edges"]:
        children.setdefault(a, []).append(b)
        parents.setdefault(b, []).append(a)
    depth, via = {}, {}
    if graph.get("has_graph"):
        if root_ref:
            starts = [root_ref]
            depth[root_ref] = 0
        else:  # no declared application: components nobody depends on are the top level
            starts = [r for r in comps if not parents.get(r)]
            for r in starts:
                depth[r] = 1
                via[r] = None
        queue = deque(starts)
        while queue:
            cur = queue.popleft()
            for ch in children.get(cur, ()):
                if ch in comps and ch not in depth:
                    depth[ch] = depth[cur] + 1
                    via[ch] = cur
                    queue.append(ch)
    return {"comps": comps, "root_ref": root_ref, "root_name": (root or {}).get("name") or "application", "children": children, "parents": parents, "depth": depth, "via": via}


def is_direct(st, ref):
    c = st["comps"][ref]
    d = st["depth"].get(ref)
    if d is not None:
        return d == 1
    return c.get("direct_hint")


def path_to_root(st, ref):
    """Names from the application down to the component along the shortest recorded path, or [] when no path is recorded."""
    out, cur, guard = [], ref, 0
    if ref not in st["depth"]:
        return []
    while cur is not None and guard < 200:
        c = st["comps"].get(cur)
        out.append(c["name"] if c else st["root_name"])
        cur = st["via"].get(cur) if cur != st["root_ref"] else None
        guard += 1
    return list(reversed(out))


def ancestors(st, ref):
    """Every component that depends on `ref`, directly or not (the application itself excluded): the packages a change to `ref` can reach."""
    seen, queue = set(), deque([ref])
    while queue:
        cur = queue.popleft()
        for p in st["parents"].get(cur, ()):
            if p not in seen and p != st["root_ref"] and p in st["comps"]:
                seen.add(p)
                queue.append(p)
    return seen


def direct_parents(st, ref):
    """The direct dependencies that pull `ref` in: the places a developer can actually act (upgrade the parent, or override the transitive version)."""
    if is_direct(st, ref):
        return []
    return sorted({st["comps"][a]["name"] for a in ancestors(st, ref) if st["depth"].get(a) == 1})


def _short(name):
    """Maven-style group:artifact -> artifact; other names are kept whole (npm scopes and Go module paths contain / and are part of the name)."""
    return (name or "").lower().rsplit(":", 1)[-1]


def match_findings(st, findings):
    """({component ref: [finding ids]}, [unmatched finding ids]) for findings that carry a `dependency.package`."""
    by_name = {}
    for ref, c in st["comps"].items():
        keys = {(c["name"] or "").lower(), f"{(c.get('group') or '')}:{c['name']}".lower()}
        for k in keys:
            by_name.setdefault(k, []).append(ref)
        by_name.setdefault(_short(c["name"]), []).append(ref)
    hits, unmatched = {}, []
    for f in findings:
        dep = f.get("dependency") or {}
        pkg = (dep.get("package") or "").strip().lower()
        if not pkg:
            continue
        cands = by_name.get(pkg) or by_name.get(_short(pkg)) or []
        cands = list(dict.fromkeys(cands))
        if dep.get("ecosystem"):
            same = [r for r in cands if (st["comps"][r].get("ecosystem") or dep["ecosystem"]).lower() == dep["ecosystem"].lower()]
            cands = same or cands
        exact = [r for r in cands if dep.get("version") and st["comps"][r].get("version") == dep["version"]]
        pick = exact or cands
        if not pick:
            unmatched.append(f["id"])
        else:
            for r in (exact[:1] or pick[:1]):
                hits.setdefault(r, []).append(f["id"])
    return hits, unmatched


def trim(nodes, edges, keep, limit):
    """For a large graph: the application, its direct dependencies, every flagged node and the paths to them. Returns (nodes, edges, hidden_count)."""
    if len(nodes) <= limit:
        return nodes, edges, 0
    kept = [n for n in nodes if n["id"] in keep]
    ids = {n["id"] for n in kept}
    hidden = len(nodes) - len(kept)
    return kept, [e for e in edges if e[0] in ids and e[1] in ids], hidden
