"""Loads remediation/config/ontology.yaml and answers questions about it (is-a, relation lookup, how a module's graph kinds map onto it).

The file is re-read when it changes on disk (an administrator edits it) and checked on load: a class whose parent does not exist, a relation
signature that names an unknown class, an inverse that is not mutual, or a mapping onto something undeclared is a hard error here, so every other module
can rely on a consistent vocabulary.
"""
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "ontology.yaml"
ATTR_TYPES = ("bool", "string", "number", "enum")
_CACHE = {"key": None, "onto": None}


class OntologyError(ValueError):
    pass


def slug(name):
    """Class id -> the lower-case, hyphenated form a node's `kind` uses in the estate graph (FirewallRule -> firewall-rule, AIAsset -> ai-asset)."""
    name = str(name)
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and (not name[i - 1].isupper() or (i + 1 < len(name) and name[i + 1].islower())):
            out.append("-")
        out.append(ch.lower())
    return "".join(out)


class Ontology:
    def __init__(self, data):
        self.raw = data
        self.version = data.get("version")
        self.classes = {k: dict(v or {}) for k, v in (data.get("classes") or {}).items()}
        self.relations = {k: dict(v or {}) for k, v in (data.get("relations") or {}).items()}
        self.mappings = data.get("mappings") or {}
        self._check()
        self._ancestors = {c: self._chain(c) for c in self.classes}
        self._slugs = {slug(c): c for c in self.classes}
        self._subs = {}
        for r, spec in self.relations.items():
            if spec.get("sub_relation_of"):
                self._subs.setdefault(spec["sub_relation_of"], []).append(r)

    # ------------------------------------------------------------- loading and self-check
    def _chain(self, cls):
        out, seen = [cls], {cls}
        while self.classes[out[-1]].get("is_a"):
            parent = self.classes[out[-1]]["is_a"]
            if parent in seen:
                raise OntologyError(f"class {cls} has an is-a cycle through {parent}")
            seen.add(parent)
            out.append(parent)
        return out

    def _check(self):
        roots = [c for c, s in self.classes.items() if not s.get("is_a")]
        if roots != ["Thing"]:
            raise OntologyError(f"exactly one root class named Thing is expected, found {roots}")
        for c, s in self.classes.items():
            if s.get("is_a") and s["is_a"] not in self.classes:
                raise OntologyError(f"class {c} is_a unknown class {s['is_a']}")
            if not (s.get("description") or "").strip():
                raise OntologyError(f"class {c} has no description")
            for a, spec in (s.get("attributes") or {}).items():
                if spec.get("type") not in ATTR_TYPES:
                    raise OntologyError(f"{c}.{a}: type must be one of {ATTR_TYPES}")
                if spec["type"] == "enum" and not spec.get("values"):
                    raise OntologyError(f"{c}.{a}: an enum needs values")
            for a in s.get("required") or []:
                if a not in (s.get("attributes") or {}):
                    raise OntologyError(f"{c}: required attribute {a} is not declared")
        for r, s in self.relations.items():
            if not (s.get("description") or "").strip():
                raise OntologyError(f"relation {r} has no description")
            if bool(s.get("signatures")) == bool(s.get("inverse_of")):
                raise OntologyError(f"relation {r} needs either signatures or inverse_of, not both and not neither")
            for sig in s.get("signatures") or []:
                for side in ("domain", "range"):
                    if sig.get(side) not in self.classes:
                        raise OntologyError(f"relation {r}: {side} {sig.get(side)!r} is not a class")
            inv = s.get("inverse_of")
            if inv and (inv not in self.relations or not self.relations[inv].get("signatures")):
                raise OntologyError(f"relation {r}: inverse_of {inv!r} must be a relation with signatures")
            if s.get("sub_relation_of") and s["sub_relation_of"] not in self.relations:
                raise OntologyError(f"relation {r}: sub_relation_of {s['sub_relation_of']!r} is not a relation")
        for mod, m in self.mappings.items():
            for kind, cls in (m.get("nodes") or {}).items():
                if cls not in self.classes:
                    raise OntologyError(f"mapping {mod}: node kind {kind!r} maps to unknown class {cls!r}")
            for kind, rel in (m.get("edges") or {}).items():
                if rel not in self.relations:
                    raise OntologyError(f"mapping {mod}: edge kind {kind!r} maps to unknown relation {rel!r}")

    # ------------------------------------------------------------- classes
    def has_class(self, name):
        return name in self.classes

    def is_a(self, cls, ancestor):
        return cls in self._ancestors and ancestor in self._ancestors[cls]

    def subclasses(self, cls):
        return sorted(c for c in self.classes if self.is_a(c, cls))

    def overlaps(self, a, b):
        return self.is_a(a, b) or self.is_a(b, a)

    def class_from_slug(self, text):
        """A node kind that is already a class (the estate graph writes kinds as class slugs); None otherwise."""
        return self._slugs.get(text)

    def attributes(self, cls):
        """Declared attributes of a class including inherited ones: {name: spec}."""
        out = {}
        for c in reversed(self._ancestors.get(cls, [])):
            out.update(self.classes[c].get("attributes") or {})
        return out

    def required(self, cls):
        out = []
        for c in reversed(self._ancestors.get(cls, [])):
            out += [a for a in self.classes[c].get("required") or [] if a not in out]
        return out

    # ------------------------------------------------------------- relations
    def has_relation(self, name):
        return name in self.relations

    def signatures(self, rel):
        """[(domain, range)] of a relation, resolving an inverse by swapping the original's."""
        spec = self.relations[rel]
        if spec.get("inverse_of"):
            return [(s["range"], s["domain"]) for s in self.relations[spec["inverse_of"]]["signatures"]]
        return [(s["domain"], s["range"]) for s in spec["signatures"]]

    def base(self, rel):
        """(base relation, flipped): an inverse relation is read as its original traversed backwards."""
        inv = self.relations[rel].get("inverse_of")
        return (inv, True) if inv else (rel, False)

    def with_subrelations(self, rel):
        """The relation and every relation that is a special case of it (transitively): what a question about `rel` follows."""
        out, todo = [], [rel]
        while todo:
            r = todo.pop()
            if r not in out:
                out.append(r)
                todo += self._subs.get(r, [])
        return sorted(out)

    def allows(self, rel, source_cls, target_cls):
        """True when an edge of `rel` from a node of source_cls to a node of target_cls fits a signature (subclasses allowed)."""
        return any(self.is_a(source_cls, d) and self.is_a(target_cls, r) for d, r in self.signatures(rel))

    def cardinality(self, rel):
        spec = self.relations[rel]
        return spec.get("source_cardinality") or {}, spec.get("target_cardinality") or {}

    # ------------------------------------------------------------- module mappings
    def node_class(self, module, kind):
        """The class of a node of `kind` in a module graph (or the estate graph); None when the kind is not in the vocabulary."""
        m = (self.mappings.get(module) or {}).get("nodes") or {}
        if kind in m:
            return m[kind]
        return self.class_from_slug(kind)

    def edge_relation(self, module, kind):
        m = (self.mappings.get(module) or {}).get("edges") or {}
        if kind in m:
            return m[kind]
        return kind if kind in self.relations else None

    # ------------------------------------------------------------- wire form
    def describe(self):
        """The JSON shape served by GET /api/ontology."""
        classes = []
        for c in sorted(self.classes):
            s = self.classes[c]
            classes.append({"id": c, "is_a": s.get("is_a"), "description": s["description"],
                            "attributes": {a: {"type": v["type"], "values": v.get("values"), "description": v.get("description")}
                                           for a, v in sorted((s.get("attributes") or {}).items())},
                            "required": list(s.get("required") or [])})
        relations = []
        for r in sorted(self.relations):
            s = self.relations[r]
            src, tgt = self.cardinality(r)
            relations.append({"id": r, "description": s["description"], "inverse_of": s.get("inverse_of"), "transitive": bool(s.get("transitive")),
                              "sub_relation_of": s.get("sub_relation_of"),
                              "signatures": [{"domain": d, "range": g} for d, g in self.signatures(r)],
                              "source_cardinality": src or None, "target_cardinality": tgt or None})
        return {"version": self.version, "classes": classes, "relations": relations,
                "mappings": {m: {"nodes": dict(sorted((v.get("nodes") or {}).items())), "edges": dict(sorted((v.get("edges") or {}).items()))}
                             for m, v in sorted(self.mappings.items())}}


def load(path=None):
    path = Path(path or PATH)
    key = (str(path), path.stat().st_mtime_ns)
    if _CACHE["key"] != key:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        _CACHE["onto"], _CACHE["key"] = Ontology(data), key
    return _CACHE["onto"]


def attr_value(node, name):
    """A node's value for an attribute, or None when it is not recorded (None means unknown, never false). `label` and `severity` live on the
    node itself; everything else is in its meta."""
    if name == "label":
        return node.get("label")
    if name == "severity" and node.get("sev"):
        return node["sev"]
    return (node.get("meta") or {}).get(name)
