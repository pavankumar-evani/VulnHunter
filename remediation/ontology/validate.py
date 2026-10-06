"""A SHACL-like conformance check of a relationship graph against the ontology. No extra dependency, and it never changes or drops the graph it reads.

validate(graph) takes the shape remediation/graphs/schema.py defines (a dict with `nodes` and `edges`, and optionally `module`, `truncated`) and returns a report:

    {"module", "conforms": bool, "checked": {"nodes": n, "edges": n}, "counts": {rule: n}, "violations": [...], "notes": [...], "truncated_violations": bool}

Each violation names the offending node or edge and the rule it breaks:

    unknown-class        a node whose kind is not a class in the ontology (for the graph's module)
    unknown-relation     an edge whose kind is not a relation
    domain-range         an edge whose source or target class does not fit any signature of its relation
    required-attribute   a node lacking an attribute its class (or an ancestor) requires
    attribute-type       an attribute whose value does not fit the declared type or enum
    cardinality          a node with more (or, on a complete graph, fewer) edges of a relation than the relation allows
    dangling-edge        an edge whose source or target is not a node of the graph
    invalid-provenance   a provenance block with a value outside the vocabulary

An empty graph conforms (nothing is claimed). A graph the builder truncated is checked for what it contains, minimum cardinalities are skipped, and the
report says so: a missing edge may only be one that was cut.
"""
from remediation.ontology import ontology as onto_mod
from remediation.ontology import provenance

MAX_VIOLATIONS = 500


def _viol(rule, message, node=None, edge=None, detail=None):
    v = {"rule": rule, "message": message}
    if node is not None:
        v["node"] = node
    if edge is not None:
        v["edge"] = {"source": edge.get("source"), "target": edge.get("target"), "kind": edge.get("kind")}
    if detail:
        v["detail"] = detail
    return v


def _type_problem(spec, value):
    """A sentence when `value` does not fit the declared attribute spec, else None. None (unknown) always fits."""
    if value is None:
        return None
    t = spec["type"]
    if t == "bool" and not isinstance(value, bool):
        return f"expected true or false, found {value!r}"
    if t == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return f"expected a number, found {value!r}"
    if t == "string" and not isinstance(value, str):
        return f"expected text, found {value!r}"
    if t == "enum" and value not in spec["values"]:
        return f"expected one of {', '.join(spec['values'])}, found {value!r}"
    return None


def classify(graph, module=None, onto=None):
    """({node id: class or None}, [relation or None per edge]) using the module's mapping; read-only."""
    onto = onto or onto_mod.load()
    module = module or graph.get("module")
    classes = {n["id"]: onto.node_class(module, n.get("kind")) for n in graph.get("nodes") or []}
    rels = [onto.edge_relation(module, e.get("kind")) for e in graph.get("edges") or []]
    return classes, rels


def validate(graph, module=None, onto=None):
    onto = onto or onto_mod.load()
    module = module or graph.get("module")
    nodes, edges = list(graph.get("nodes") or []), list(graph.get("edges") or [])
    classes, rels = classify(graph, module, onto)
    by_id = {n["id"]: n for n in nodes}
    out, notes = [], []

    for n in nodes:
        cls = classes[n["id"]]
        if cls is None:
            out.append(_viol("unknown-class", f"node kind {n.get('kind')!r} is not a class in the ontology", node=n["id"], detail={"kind": n.get("kind"), "module": module}))
            continue
        attrs = onto.attributes(cls)
        for a in onto.required(cls):
            if onto_mod.attr_value(n, a) is None:
                out.append(_viol("required-attribute", f"{cls} requires {a}", node=n["id"], detail={"class": cls, "attribute": a}))
        for a, spec in attrs.items():
            problem = _type_problem(spec, onto_mod.attr_value(n, a))
            if problem:
                out.append(_viol("attribute-type", f"{cls}.{a}: {problem}", node=n["id"], detail={"class": cls, "attribute": a}))
        p = n.get("prov")
        if p is not None:
            for bad in provenance.problems(p):
                out.append(_viol("invalid-provenance", f"node provenance: {bad}", node=n["id"]))

    out_count, in_count = {}, {}
    for e, rel in zip(edges, rels):
        s, t = by_id.get(e.get("source")), by_id.get(e.get("target"))
        if s is None or t is None:
            out.append(_viol("dangling-edge", "an end of this edge is not a node of the graph", edge=e))
            continue
        if rel is None:
            out.append(_viol("unknown-relation", f"edge kind {e.get('kind')!r} is not a relation in the ontology", edge=e, detail={"kind": e.get("kind"), "module": module}))
        else:
            cs, ct = classes[s["id"]], classes[t["id"]]
            if cs is not None and ct is not None and not onto.allows(rel, cs, ct):
                wanted = ", ".join(f"{d} -> {r}" for d, r in onto.signatures(rel))
                out.append(_viol("domain-range", f"{rel} cannot run from {cs} to {ct}; allowed: {wanted}", edge=e,
                                 detail={"relation": rel, "source_class": cs, "target_class": ct}))
            out_count[(rel, s["id"])] = out_count.get((rel, s["id"]), 0) + 1
            in_count[(rel, t["id"])] = in_count.get((rel, t["id"]), 0) + 1
        p = e.get("prov")
        if p is not None:
            for bad in provenance.problems(p):
                out.append(_viol("invalid-provenance", f"edge provenance: {bad}", edge=e))

    complete = not graph.get("truncated")
    if not complete:
        notes.append("The graph was truncated by its builder, so minimum cardinalities were not checked (a missing edge may be one that was cut).")
    for rel in sorted(onto.relations):
        spec = onto.relations[rel]
        if spec.get("inverse_of"):
            continue
        s_card, t_card = onto.cardinality(rel)
        if not (s_card or t_card):
            continue
        domains = {d for d, _ in onto.signatures(rel)}
        ranges = {r for _, r in onto.signatures(rel)}
        for n in nodes:
            cls = classes[n["id"]]
            if cls is None:
                continue
            if any(onto.is_a(cls, d) for d in domains):
                k = out_count.get((rel, n["id"]), 0)
                if s_card.get("max") is not None and k > s_card["max"]:
                    out.append(_viol("cardinality", f"{cls} may have at most {s_card['max']} outgoing {rel}, has {k}", node=n["id"],
                                     detail={"relation": rel, "side": "source", "max": s_card["max"], "found": k}))
                if complete and s_card.get("min") is not None and k < s_card["min"]:
                    out.append(_viol("cardinality", f"{cls} needs at least {s_card['min']} outgoing {rel}, has {k}", node=n["id"],
                                     detail={"relation": rel, "side": "source", "min": s_card["min"], "found": k}))
            if any(onto.is_a(cls, r) for r in ranges):
                k = in_count.get((rel, n["id"]), 0)
                if t_card.get("max") is not None and k > t_card["max"]:
                    out.append(_viol("cardinality", f"{cls} may have at most {t_card['max']} incoming {rel}, has {k}", node=n["id"],
                                     detail={"relation": rel, "side": "target", "max": t_card["max"], "found": k}))
                if complete and t_card.get("min") is not None and k < t_card["min"]:
                    out.append(_viol("cardinality", f"{cls} needs at least {t_card['min']} incoming {rel}, has {k}", node=n["id"],
                                     detail={"relation": rel, "side": "target", "min": t_card["min"], "found": k}))

    counts = {}
    for v in out:
        counts[v["rule"]] = counts.get(v["rule"], 0) + 1
    cap = len(out) > MAX_VIOLATIONS
    return {"module": module, "conforms": not out, "checked": {"nodes": len(nodes), "edges": len(edges)}, "counts": dict(sorted(counts.items())),
            "violations": out[:MAX_VIOLATIONS], "truncated_violations": cap, "notes": notes}


def validate_all(graphs, onto=None):
    """Validate several module graphs ({module: graph}); the overall verdict and one report each."""
    reports = {m: validate(g, m, onto) for m, g in sorted(graphs.items())}
    return {"conforms": all(r["conforms"] for r in reports.values()), "modules": reports,
            "totals": {"nodes": sum(r["checked"]["nodes"] for r in reports.values()), "edges": sum(r["checked"]["edges"] for r in reports.values()),
                       "violations": sum(sum(r["counts"].values()) for r in reports.values())}}
