"""The Fact view: every edge of a graph as a statement (subject, relation, object) with where it came from, when it was seen and how sure that is.

Builders attach a `prov` block (remediation/graphs/schema.py) only where stored data says where a link came from. This module reads it and never fills a gap:
a field the data does not say is None in the Fact and is listed under `unknown`, never defaulted to "now", to the graph's module or to a confident-sounding
value. The vocabulary:

    source_kind   connector (pulled by a connector) | scan (a scan result) | user (a person or a file a person maintains) | derived (computed by Quanta
                  from other facts)
    confidence    observed (seen in data) | declared (recorded by a person or in a file, not independently seen) | heuristic (inferred by a rule that can
                  be wrong, for example a name match)
"""
from remediation.ontology import ontology as onto_mod

SOURCE_KINDS = ("connector", "scan", "user", "derived")
CONFIDENCES = ("observed", "declared", "heuristic")
FIELDS = ("source", "source_kind", "observed_at", "confidence")


def problems(p):
    """Sentences describing what is wrong with a provenance block (empty list when it is fine)."""
    if not isinstance(p, dict):
        return ["provenance must be an object"]
    out = [f"unknown field {k!r}" for k in p if k not in FIELDS]
    if p.get("source_kind") is not None and p["source_kind"] not in SOURCE_KINDS:
        out.append(f"source_kind {p['source_kind']!r} is not one of {', '.join(SOURCE_KINDS)}")
    if p.get("confidence") is not None and p["confidence"] not in CONFIDENCES:
        out.append(f"confidence {p['confidence']!r} is not one of {', '.join(CONFIDENCES)}")
    for k in ("source", "observed_at"):
        if p.get(k) is not None and not isinstance(p[k], str):
            out.append(f"{k} must be text")
    return out


def fact_for(edge, relation=None, subject_label=None, object_label=None):
    """One edge as a Fact dict. Unknown stays None and is named in `unknown`."""
    p = edge.get("prov") or {}
    vals = {k: (p.get(k) if p.get(k) not in ("", None) else None) for k in FIELDS}
    return {"subject": edge.get("source"), "subject_label": subject_label, "relation": relation or edge.get("kind"), "edge_kind": edge.get("kind"),
            "object": edge.get("target"), "object_label": object_label, **vals,
            "unknown": [k for k in FIELDS if vals[k] is None], "known": any(v is not None for v in vals.values())}


def facts(graph, module=None, onto=None):
    """Every edge of the graph as a Fact, in the graph's own (deterministic) order."""
    onto = onto or onto_mod.load()
    module = module or graph.get("module")
    labels = {n["id"]: n.get("label") for n in graph.get("nodes") or []}
    return [fact_for(e, onto.edge_relation(module, e.get("kind")), labels.get(e.get("source")), labels.get(e.get("target"))) for e in graph.get("edges") or []]


def coverage(fact_list):
    """How much of the provenance is known: counts per field and overall, for an honest 'this much is traceable' figure."""
    n = len(fact_list)
    per = {k: sum(1 for f in fact_list if f[k] is not None) for k in FIELDS}
    return {"facts": n, "with_any": sum(1 for f in fact_list if f["known"]), "per_field": per,
            "by_source_kind": {k: sum(1 for f in fact_list if f["source_kind"] == k) for k in SOURCE_KINDS},
            "by_confidence": {k: sum(1 for f in fact_list if f["confidence"] == k) for k in CONFIDENCES}}
