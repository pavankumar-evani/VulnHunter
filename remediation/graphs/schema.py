"""The one shape every module's relationship graph is returned in, and a small builder that makes it deterministic.

A graph is a plain dict (JSON on the wire):

    {"module": "soc", "title": ..., "description": ..., "directed": True,
     "kinds": {"host": {"label": "Host"}, ...},          # every node and edge kind used, with a display label
     "nodes": [{"id": "host:web-01", "label": "web-01", "kind": "host", "weight": 3, "sev": "high",
                "meta": {"findings": 3}, "href": "/assets"}],
     "edges": [{"source": "host:web-01", "target": "tech:T1190", "kind": "exposes", "label": null, "weight": 1}],
     "truncated": False, "totals": {"nodes": 12, "edges": 15}, "note": "text shown when the graph is empty or capped"}

Graph theory (components, shortest paths, centrality, single points of failure) is computed in the browser from this shape
(dashboard/static/js/graphTheory.js), so a builder only has to say what is connected to what, from real stored data, and nothing
else. A builder never invents a node: with no data it returns an empty graph and a note that says what to connect.

Optional provenance (remediation/ontology/provenance.py reads it): a node or edge may carry `"prov": {"source": str|None, "source_kind": "connector"|"scan"|"user"|"derived"|None,
"observed_at": str|None, "confidence": "observed"|"declared"|"heuristic"|None}`. The key is present only when a builder passed `prov=` for a fact it can actually
trace to stored data; a missing key (or a None inside it) means unknown, never a guess.
"""
PROV_KEYS = ("source", "source_kind", "observed_at", "confidence")


def prov(source=None, source_kind=None, observed_at=None, confidence=None):
    """Build a provenance dict; None when nothing at all is known (so the caller can pass it straight to node/edge)."""
    p = {"source": source, "source_kind": source_kind, "observed_at": observed_at, "confidence": confidence}
    return p if any(v is not None for v in p.values()) else None


def _merge_prov(cur, new):
    """Fill the gaps in cur from new; a value already known is kept."""
    if not new:
        return cur
    out = dict(cur or {})
    for k in PROV_KEYS:
        if out.get(k) is None and new.get(k) is not None:
            out[k] = new[k]
    return out

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_LIMIT = 400


class GraphBuilder:
    def __init__(self, module, title, description, directed=True):
        self.module, self.title, self.description, self.directed = module, title, description, directed
        self._nodes = {}
        self._edges = {}
        self._kinds = {}

    def kind(self, key, label):
        self._kinds[key] = {"label": label}

    def node(self, node_id, label, kind, weight=1, sev=None, meta=None, href=None, prov=None):
        """Add a node, or merge into the existing one (weights add up, the worst severity wins, meta is merged)."""
        node_id = str(node_id)
        cur = self._nodes.get(node_id)
        if cur is None:
            self._nodes[node_id] = {"id": node_id, "label": str(label), "kind": kind, "weight": weight,
                                    "sev": sev if sev in SEVERITIES else None, "meta": dict(meta or {}), "href": href}
            if prov:
                self._nodes[node_id]["prov"] = dict(prov)
            return node_id
        cur["weight"] += weight
        if sev in SEVERITIES and (cur["sev"] is None or SEVERITIES.index(sev) < SEVERITIES.index(cur["sev"])):
            cur["sev"] = sev
        cur["meta"].update(meta or {})
        cur["href"] = cur["href"] or href
        if prov:
            cur["prov"] = _merge_prov(cur.get("prov"), prov)
        return node_id

    def edge(self, source, target, kind, label=None, weight=1, prov=None):
        """Add an edge between two nodes already added. A repeated edge (same source, target, kind) adds to its weight."""
        source, target = str(source), str(target)
        if source == target:
            return
        key = (source, target, kind)
        cur = self._edges.get(key)
        if cur is None:
            self._edges[key] = {"source": source, "target": target, "kind": kind, "label": label, "weight": weight}
            if prov:
                self._edges[key]["prov"] = dict(prov)
        else:
            cur["weight"] += weight
            if prov:
                cur["prov"] = _merge_prov(cur.get("prov"), prov)

    def build(self, note=None, limit=DEFAULT_LIMIT):
        edges = [e for e in self._edges.values() if e["source"] in self._nodes and e["target"] in self._nodes]
        nodes = list(self._nodes.values())
        total_nodes, total_edges = len(nodes), len(edges)
        truncated = False
        if len(nodes) > limit:
            degree = {}
            for e in edges:
                degree[e["source"]] = degree.get(e["source"], 0) + e["weight"]
                degree[e["target"]] = degree.get(e["target"], 0) + e["weight"]
            keep = sorted(nodes, key=lambda n: (-degree.get(n["id"], 0), -n["weight"], n["id"]))[:limit]
            ids = {n["id"] for n in keep}
            nodes = [n for n in nodes if n["id"] in ids]
            edges = [e for e in edges if e["source"] in ids and e["target"] in ids]
            truncated = True
            note = (note + " " if note else "") + f"Showing the {limit} best-connected of {total_nodes} nodes."
        nodes.sort(key=lambda n: n["id"])
        edges.sort(key=lambda e: (e["source"], e["target"], e["kind"]))
        used = {n["kind"] for n in nodes} | {e["kind"] for e in edges}
        kinds = {k: v for k, v in sorted(self._kinds.items()) if k in used}
        for k in sorted(used - set(kinds)):
            kinds[k] = {"label": k.replace("_", " ").replace("-", " ").title()}
        return {"module": self.module, "title": self.title, "description": self.description, "directed": self.directed,
                "kinds": kinds, "nodes": nodes, "edges": edges, "truncated": truncated,
                "totals": {"nodes": total_nodes, "edges": total_edges}, "note": note}


def empty(module, title, description, note, directed=True):
    """The honest empty state: nothing recorded yet, and what to connect."""
    return GraphBuilder(module, title, description, directed).build(note=note)
