"""A small, safe multi-hop path query over the estate graph, written as a structured pattern (JSON), never as free text.

A pattern is a start node and a list of steps:

    {"start": {"class": "Asset", "where": [{"attr": "internet_facing", "op": "eq", "value": true}]},
     "steps": [{"relation": "runs", "direction": "out", "repeat": "one", "to": {"class": "Application"}},
               {"relation": "depends-on", "repeat": "star", "max_depth": 4, "to": {"class": "Component"}},
               {"relation": "exploits", "direction": "in", "to": {"class": "Vulnerability", "where": [{"attr": "kev", "op": "eq", "value": true}]}}],
     "limit": 50}

which reads  Asset(internet_facing = true) -runs-> Application -depends-on*-> Component <-exploits- Vulnerability(kev = true).

Everything is checked against the ontology before anything runs: every class, relation and attribute must exist, every value must fit the attribute's declared
type, and every step must be a hop the relation's signatures allow between those classes. Nothing the caller sends is evaluated: there is no expression
language, no regular expression (`contains` is a plain substring test) and no way to name a function. Depth, steps, conditions, result size and total work
are capped, and a capped result says so.

Semantics worth knowing:
  * a class matches its subclasses (Asset matches an AIAsset); a relation also follows its special cases (`reaches` follows `routes-to`); an inverse relation
    (`owned-by`) is the original read backwards, as `direction: in` is.
  * `repeat: one` is one hop; `star` is zero or more and `plus` one or more, up to `max_depth`. A repeated step returns the shortest path to each node it can
    reach (not every route), so a result is a set of reasons, not an enumeration of all paths. Paths never revisit a node.
  * an attribute that is not recorded is unknown and satisfies no condition (not even `ne`); `exists: false` is how to ask for "not recorded".
  * an empty result carries the reason: which stage matched nothing, and whether the data simply does not record what the question asks about.
"""
import copy
from pathlib import Path

import yaml

from remediation.graphs.schema import SEVERITIES
from remediation.ontology import ontology as onto_mod
from remediation.ontology import provenance, validate

QUESTIONS_PATH = Path(__file__).resolve().parent.parent / "config" / "ontology_questions.yaml"
LIMITS = {"max_steps": 8, "max_depth": 6, "default_depth": 4, "default_limit": 50, "max_limit": 200, "max_where": 8, "max_in": 50, "max_text": 200,
          "work_budget": 250000, "max_partial_paths": 5000}
OPS = ("eq", "ne", "lt", "le", "gt", "ge", "in", "contains", "exists")
REPEATS = ("one", "star", "plus")
RESERVED_ATTRS = {"label": {"type": "string"}, "severity": {"type": "enum", "values": list(SEVERITIES)}}
_NODE_KEYS = {"class", "where"}
_COND_KEYS = {"attr", "op", "value"}
_STEP_KEYS = {"relation", "direction", "repeat", "max_depth", "to"}
_PATTERN_KEYS = {"start", "steps", "limit", "provenance"}


class QueryError(ValueError):
    """The pattern is not a valid question; the message says why and is safe to show."""


# ------------------------------------------------------------------------------------------------------------------ parsing
def _check_keys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise QueryError(f"{where} must be an object")
    extra = sorted(set(obj) - allowed)
    if extra:
        raise QueryError(f"{where}: unknown field {extra[0]!r} (allowed: {', '.join(sorted(allowed))})")


def _text(v, where):
    if not isinstance(v, str) or not v.strip():
        raise QueryError(f"{where} must be non-empty text")
    if len(v) > LIMITS["max_text"]:
        raise QueryError(f"{where} is longer than {LIMITS['max_text']} characters")
    return v


def _scalar_fits(spec, value, where):
    t = spec["type"]
    if t == "bool" and not isinstance(value, bool):
        raise QueryError(f"{where}: expected true or false")
    if t == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        raise QueryError(f"{where}: expected a number")
    if t in ("string", "enum"):
        _text(value, where)
        if t == "enum" and value not in spec["values"]:
            raise QueryError(f"{where}: must be one of {', '.join(spec['values'])}")


def _parse_node(spec, where, onto):
    _check_keys(spec, _NODE_KEYS, where)
    cls = _text(spec.get("class"), f"{where}.class")
    if not onto.has_class(cls):
        raise QueryError(f"{where}: unknown class {cls!r}")
    conds_in = spec.get("where") or []
    if not isinstance(conds_in, list) or len(conds_in) > LIMITS["max_where"]:
        raise QueryError(f"{where}.where must be a list of at most {LIMITS['max_where']} conditions")
    declared = {**RESERVED_ATTRS, **onto.attributes(cls)}
    conds = []
    for i, c in enumerate(conds_in):
        w = f"{where}.where[{i}]"
        _check_keys(c, _COND_KEYS, w)
        attr, op = _text(c.get("attr"), f"{w}.attr"), c.get("op", "eq")
        if attr not in declared:
            raise QueryError(f"{w}: {cls} has no attribute {attr!r} (declared: {', '.join(sorted(declared))})")
        if op not in OPS:
            raise QueryError(f"{w}: op must be one of {', '.join(OPS)}")
        aspec, value = declared[attr], c.get("value")
        if op == "exists":
            if not isinstance(value, bool):
                raise QueryError(f"{w}: exists takes true or false")
        elif op == "in":
            if not isinstance(value, list) or not value or len(value) > LIMITS["max_in"]:
                raise QueryError(f"{w}: in takes a list of 1 to {LIMITS['max_in']} values")
            for v in value:
                _scalar_fits(aspec, v, w)
        elif op in ("lt", "le", "gt", "ge"):
            if aspec["type"] != "number" or isinstance(value, bool) or not isinstance(value, (int, float)):
                raise QueryError(f"{w}: {op} needs a number attribute and a number")
        elif op == "contains":
            if aspec["type"] not in ("string", "enum"):
                raise QueryError(f"{w}: contains needs a text attribute")
            _text(value, w + ".value")
        else:
            _scalar_fits(aspec, value, w)
        conds.append({"attr": attr, "op": op, "value": copy.deepcopy(value)})
    return {"class": cls, "where": conds}


def parse(pattern, onto=None):
    """Validate a structured pattern against the ontology and return it normalised (defaults filled in). Raises QueryError."""
    onto = onto or onto_mod.load()
    _check_keys(pattern, _PATTERN_KEYS, "pattern")
    if "start" not in pattern:
        raise QueryError("pattern.start is required")
    start = _parse_node(pattern["start"], "start", onto)
    steps_in = pattern.get("steps") or []
    if not isinstance(steps_in, list) or len(steps_in) > LIMITS["max_steps"]:
        raise QueryError(f"pattern.steps must be a list of at most {LIMITS['max_steps']} steps")
    limit = pattern.get("limit", LIMITS["default_limit"])
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= LIMITS["max_limit"]:
        raise QueryError(f"pattern.limit must be a whole number from 1 to {LIMITS['max_limit']}")
    prov_on = pattern.get("provenance", True)
    if not isinstance(prov_on, bool):
        raise QueryError("pattern.provenance must be true or false")
    steps, here = [], start["class"]
    for i, s in enumerate(steps_in):
        w = f"steps[{i}]"
        _check_keys(s, _STEP_KEYS, w)
        rel = _text(s.get("relation"), f"{w}.relation")
        if not onto.has_relation(rel):
            raise QueryError(f"{w}: unknown relation {rel!r}")
        direction = s.get("direction", "out")
        if direction not in ("out", "in"):
            raise QueryError(f"{w}.direction must be out or in")
        repeat = s.get("repeat", "one")
        if repeat not in REPEATS:
            raise QueryError(f"{w}.repeat must be one of {', '.join(REPEATS)}")
        depth = s.get("max_depth", LIMITS["default_depth"] if repeat != "one" else 1)
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= LIMITS["max_depth"]:
            raise QueryError(f"{w}.max_depth must be a whole number from 1 to {LIMITS['max_depth']}")
        if repeat == "one" and "max_depth" in s and depth != 1:
            raise QueryError(f"{w}: max_depth applies to star and plus only")
        to = _parse_node(s.get("to") or {}, f"{w}.to", onto)
        _check_hop(onto, rel, direction, repeat, here, to["class"], w)
        steps.append({"relation": rel, "direction": direction, "repeat": repeat, "max_depth": depth, "to": to})
        here = to["class"]
    return {"start": start, "steps": steps, "limit": limit, "provenance": prov_on}


def _hop_signatures(onto, rel, direction):
    """[(from_class, to_class)] a step may take, including the relation's special cases, in the direction walked."""
    base, flipped = onto.base(rel)
    walk_out = (direction == "out") != flipped
    sigs = []
    for r in onto.with_subrelations(base):
        for d, g in onto.signatures(r):
            sigs.append((d, g) if walk_out else (g, d))
    return sigs


def _check_hop(onto, rel, direction, repeat, from_cls, to_cls, where):
    sigs = _hop_signatures(onto, rel, direction)
    if repeat == "one":
        if not any(onto.overlaps(from_cls, a) and onto.overlaps(to_cls, b) for a, b in sigs):
            ok = "; ".join(f"{a} -> {b}" for a, b in sigs)
            raise QueryError(f"{where}: {rel} ({direction}) cannot go from {from_cls} to {to_cls}; it connects {ok}")
        return
    if not any(onto.overlaps(from_cls, a) for a, _ in sigs) or not any(onto.overlaps(to_cls, b) for _, b in sigs):
        raise QueryError(f"{where}: {rel} ({direction}) cannot start at {from_cls} and end at {to_cls}")
    if not any(onto.overlaps(a, b) for a, b in sigs):
        raise QueryError(f"{where}: {rel} cannot be repeated, its ends are different kinds of thing")


def _cond_text(c):
    v = c["value"]
    sym = {"eq": "=", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=", "in": "in", "contains": "contains", "exists": "exists"}[c["op"]]
    return f"{c['attr']} {sym} {str(v).lower() if isinstance(v, bool) else v}"


def _node_text(n):
    return n["class"] + (f"({', '.join(_cond_text(c) for c in n['where'])})" if n["where"] else "")


def explain(pattern):
    """A normalised pattern as one readable line, for display only."""
    parts = [_node_text(pattern["start"])]
    for s in pattern["steps"]:
        mark = {"one": "", "star": "*", "plus": "+"}[s["repeat"]]
        arrow = f"-{s['relation']}{mark}->" if s["direction"] == "out" else f"<-{s['relation']}{mark}-"
        parts += [arrow, _node_text(s["to"])]
    return " ".join(parts)


# ------------------------------------------------------------------------------------------------------------------ evaluation
def _holds(node, cond):
    have = onto_mod.attr_value(node, cond["attr"])
    op, want = cond["op"], cond["value"]
    if op == "exists":
        return (have is not None) == want
    if have is None:
        return False
    if op == "eq":
        return have == want
    if op == "ne":
        return have != want
    if op == "in":
        return have in want
    if op == "contains":
        return isinstance(have, str) and want.lower() in have.lower()
    if isinstance(have, bool) or not isinstance(have, (int, float)):
        return False
    return {"lt": have < want, "le": have <= want, "gt": have > want, "ge": have >= want}[op]


class _Estate:
    """The graph indexed for walking: node class per id, adjacency by canonical (base) relation."""

    def __init__(self, graph, onto):
        self.onto, self.graph = onto, graph
        self.nodes = {n["id"]: n for n in graph.get("nodes") or []}
        classes, rels = validate.classify(graph, graph.get("module") or "estate", onto)
        self.cls = {i: c for i, c in classes.items() if c is not None}
        self.out, self.inn, self.edge_count = {}, {}, {}
        for e, rel in zip(graph.get("edges") or [], rels):
            if rel is None or e["source"] not in self.cls or e["target"] not in self.cls:
                continue
            base, flipped = onto.base(rel)
            s, t = (e["target"], e["source"]) if flipped else (e["source"], e["target"])
            rec = {"source": s, "target": t, "relation": base, "edge": e}
            self.out.setdefault((base, s), []).append(rec)
            self.inn.setdefault((base, t), []).append(rec)
            self.edge_count[base] = self.edge_count.get(base, 0) + 1

    def matches(self, node_id, spec):
        c = self.cls.get(node_id)
        return c is not None and self.onto.is_a(c, spec["class"]) and all(_holds(self.nodes[node_id], x) for x in spec["where"])

    def of_class(self, cls):
        return sorted(i for i, c in self.cls.items() if self.onto.is_a(c, cls))

    def neighbours(self, node_id, rels, direction):
        table, key = (self.out, "target") if direction == "out" else (self.inn, "source")
        for r in rels:
            for rec in table.get((r, node_id), ()):
                yield rec, rec[key]


def _diagnose(est, spec, label):
    """Why nothing matched `spec`: the first sentence that explains it."""
    pool = est.of_class(spec["class"])
    if not pool:
        return f"{label}: the estate graph has no {spec['class']} nodes."
    for c in spec["where"]:
        known = [i for i in pool if onto_mod.attr_value(est.nodes[i], c["attr"]) is not None]
        if c["op"] != "exists" and not known:
            return (f"{label}: none of the {len(pool)} {spec['class']} nodes records {c['attr']}, so nothing can match {_cond_text(c)}. "
                    f"Quanta does not hold that fact yet; connect a source that supplies it.")
        if not [i for i in pool if _holds(est.nodes[i], c)]:
            return f"{label}: {len(known)} of {len(pool)} {spec['class']} nodes record {c['attr']}, none satisfies {_cond_text(c)}."
    return f"{label}: no {spec['class']} node satisfies all of {', '.join(_cond_text(c) for c in spec['where'])} together."


def run(graph, pattern, onto=None):
    """Run a pattern against an estate graph. The pattern is validated first (QueryError on a bad one); the result is always a dict."""
    onto = onto or onto_mod.load()
    pat = parse(pattern, onto)
    est = _Estate(graph, onto)
    budget = {"work": 0, "hit": False, "partial": False}
    stages = []

    starts = [i for i in est.of_class(pat["start"]["class"]) if est.matches(i, pat["start"])]
    stages.append({"stage": 0, "label": _node_text(pat["start"]), "matched": len(starts)})
    paths = [{"nodes": [i], "edges": []} for i in starts]
    reason = None
    if not starts:
        reason = _diagnose(est, pat["start"], "Start")
    for k, step in enumerate(pat["steps"], 1):
        if not paths:
            break
        base, flipped = onto.base(step["relation"])
        rels = onto.with_subrelations(base)
        direction = step["direction"] if not flipped else ("in" if step["direction"] == "out" else "out")
        grown = []
        for p in paths:
            for ext in _extend(est, p, rels, direction, step, budget):
                grown.append(ext)
                if len(grown) >= LIMITS["max_partial_paths"]:
                    budget["partial"] = True
                    break
            if budget["hit"] or budget["partial"]:
                break
        paths = grown
        stages.append({"stage": k, "label": f"{step['relation']}{'' if step['repeat'] == 'one' else '*' if step['repeat'] == 'star' else '+'} {_node_text(step['to'])}", "matched": len(paths)})
        if not paths and reason is None:
            reason = _step_reason(est, step, rels, k, onto)
    truncated = budget["hit"] or budget["partial"] or len(paths) > pat["limit"]
    paths = paths[:pat["limit"]]
    if budget["hit"]:
        note = f"The search stopped after {LIMITS['work_budget']} steps of work; the result may be incomplete."
    elif budget["partial"]:
        note = f"More than {LIMITS['max_partial_paths']} partial paths were found at one step; the result may be incomplete."
    elif truncated:
        note = f"Showing the first {pat['limit']} results."
    else:
        note = None
    out_paths = [_render_path(est, p, pat) for p in paths]
    if not out_paths and reason is None:
        reason = "No path matches."
    gnote = graph.get("note")
    return {"ok": True, "text": explain(pat), "pattern": pat, "count": len(out_paths), "paths": out_paths, "truncated": truncated, "note": note,
            "reason": None if out_paths else reason, "stages": stages,
            "estate": {"nodes": len(est.nodes), "edges": len(graph.get("edges") or []), "truncated": bool(graph.get("truncated")), "note": gnote},
            "limits": {k: LIMITS[k] for k in ("max_steps", "max_depth", "max_limit", "work_budget")}}


def _extend(est, path, rels, direction, step, budget):
    """Paths grown by one step from `path` (a list; empty when none)."""
    last = path["nodes"][-1]
    seen_in_path = set(path["nodes"])
    to = step["to"]
    if step["repeat"] == "one":
        for rec, nxt in est.neighbours(last, rels, direction):
            budget["work"] += 1
            if budget["work"] > LIMITS["work_budget"]:
                budget["hit"] = True
                return
            if nxt not in seen_in_path and est.matches(nxt, to):
                yield {"nodes": path["nodes"] + [nxt], "edges": path["edges"] + [(rec, step)]}
        return
    # star / plus: shortest path to each node reachable within max_depth
    lo = 0 if step["repeat"] == "star" else 1
    parent = {last: None}
    frontier, depth = [last], 0
    found = []
    if lo == 0 and est.matches(last, to):
        found.append(last)
    while frontier and depth < step["max_depth"]:
        depth += 1
        nxt_frontier = []
        for cur in frontier:
            for rec, nxt in est.neighbours(cur, rels, direction):
                budget["work"] += 1
                if budget["work"] > LIMITS["work_budget"]:
                    budget["hit"] = True
                    return
                if nxt in parent or nxt in seen_in_path:
                    continue
                parent[nxt] = (cur, rec)
                nxt_frontier.append(nxt)
                if est.matches(nxt, to):
                    found.append(nxt)
        frontier = nxt_frontier
    for end in sorted(found):
        chain, cur = [], end
        while parent[cur] is not None:
            prev, rec = parent[cur]
            chain.append((cur, rec))
            cur = prev
        chain.reverse()
        yield {"nodes": path["nodes"] + [n for n, _ in chain], "edges": path["edges"] + [(rec, step) for _, rec in chain]}


def _step_reason(est, step, rels, k, onto):
    base_total = sum(est.edge_count.get(r, 0) for r in rels)
    label = f"Step {k} ({step['relation']})"
    if base_total == 0:
        return f"{label}: no {step['relation']} links are recorded in the estate graph at all, so nothing can be followed."
    to = step["to"]
    pool = est.of_class(to["class"])
    if not pool:
        return f"{label}: the estate graph has no {to['class']} nodes."
    hits = [i for i in pool if est.matches(i, to)]
    if not hits:
        return _diagnose(est, to, label)
    return f"{label}: {len(hits)} {to['class']} nodes match, but none is linked by {step['relation']} to what the earlier steps found."


def _render_path(est, path, pat):
    nodes = []
    for i in path["nodes"]:
        n = est.nodes[i]
        nodes.append({"id": i, "label": n.get("label"), "class": est.cls[i], "kind": n.get("kind"), "sev": n.get("sev"), "href": n.get("href"),
                      "origin": n.get("origin") or []})
    edges, unknown = [], 0
    for rec, step in path["edges"]:
        e = rec["edge"]
        item = {"source": e["source"], "target": e["target"], "relation": rec["relation"], "kind": e.get("kind"), "step": pat["steps"].index(step) + 1}
        if pat["provenance"]:
            f = provenance.fact_for(e, rec["relation"], est.nodes[e["source"]].get("label"), est.nodes[e["target"]].get("label"))
            item["fact"] = f
            unknown += 0 if f["known"] else 1
        edges.append(item)
    out = {"nodes": nodes, "edges": edges, "length": len(edges)}
    if pat["provenance"]:
        out["edges_without_provenance"] = unknown
    return out


# ------------------------------------------------------------------------------------------------------------------ named questions
def load_questions(path=None, onto=None):
    """The named questions (config/ontology_questions.yaml), each with its pattern normalised and readable text. A question whose pattern no longer fits the
    ontology is returned with an `error` instead of being dropped, so an edit that breaks one is visible."""
    onto = onto or onto_mod.load()
    data = yaml.safe_load(Path(path or QUESTIONS_PATH).read_text(encoding="utf-8")) or {}
    out, seen = [], set()
    for q in data.get("questions") or []:
        qid = q.get("id")
        if not qid or qid in seen:
            raise onto_mod.OntologyError(f"question id missing or repeated: {qid!r}")
        seen.add(qid)
        item = {"id": qid, "title": q.get("title"), "question": q.get("question"), "why": q.get("why"), "limits": q.get("limits"), "module": q.get("module")}
        try:
            pat = parse(q.get("pattern") or {}, onto)
            item.update(pattern=pat, text=explain(pat))
        except QueryError as exc:
            item.update(pattern=None, text=None, error=str(exc))
        out.append(item)
    return out


def run_question(graph, question_id, onto=None, path=None):
    onto = onto or onto_mod.load()
    for q in load_questions(path, onto):
        if q["id"] == question_id:
            if q.get("error"):
                raise QueryError(f"question {question_id} is out of date: {q['error']}")
            res = run(graph, q["pattern"], onto)
            res["question"] = {k: q[k] for k in ("id", "title", "question", "why", "limits")}
            return res
    raise KeyError(question_id)
