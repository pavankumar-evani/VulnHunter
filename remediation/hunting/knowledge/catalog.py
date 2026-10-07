"""
The hunting knowledge catalog: MITRE ATT&CK (Enterprise, Mobile, ICS) and MITRE ATLAS, loaded from the compact files under `data/` that
`scripts/build_hunt_knowledge.py` generates from MITRE's public data. Nothing here is typed in by hand; if the files are missing the catalog is empty and says so
(`available` is false), never filled with guesses.

`get()` returns a cached `Catalog`; `reload()` drops the cache (after a refresh of the data files). Lookups are by id and case-insensitive. Joins are computed once on
load: technique <-> group, technique <-> software, group <-> software, technique <-> mitigation, ATLAS technique <-> case study.
"""
import json
import re
import threading
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
FRAMEWORKS = ("enterprise", "mobile", "ics", "atlas")
LABEL = {"enterprise": "ATT&CK Enterprise", "mobile": "ATT&CK Mobile", "ics": "ATT&CK ICS", "atlas": "MITRE ATLAS (AI systems)"}
_TID = re.compile(r"^(AML\.T\d{4}(?:\.\d{3})?|T\d{4}(?:\.\d{3})?)$", re.I)


def norm_id(x):
    return str(x or "").strip().upper()


def parent_id(tid):
    """The parent technique id: T1059.001 -> T1059, AML.T0051.001 -> AML.T0051; a parent is its own parent."""
    t = norm_id(tid)
    if t.startswith("AML."):
        return t.rsplit(".", 1)[0] if t.count(".") == 2 else t
    return t.split(".")[0]


def related(lead_tid, picked):
    """Is a lead written for `lead_tid` about one of the `picked` techniques? Exact id, a sub-technique of a picked parent, or the parent of a picked sub-technique; a DIFFERENT sub-technique of
    the same parent is not (a Kerberoasting report does not get the golden-ticket lead)."""
    lt = norm_id(lead_tid)
    picked = {norm_id(p) for p in picked}
    return lt in picked or parent_id(lt) in picked or any(parent_id(p) == lt for p in picked)


def is_technique_id(x):
    return bool(_TID.match(str(x or "").strip()))


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class Catalog:
    def __init__(self, data_dir=None):
        d = Path(data_dir or DATA_DIR)
        self.dir = d
        self.manifest = _read(d / "manifest.json") or {}
        self.techniques, self.tactics, self.meta = {}, {}, {}   # id -> record ; framework -> [tactic] ; framework -> {name, version}
        for fw in ("enterprise", "mobile", "ics"):
            doc = _read(d / f"{fw}.json")
            if not doc:
                continue
            self.meta[fw] = {k: doc.get(k) for k in ("name", "version", "modified")}
            self.tactics[fw] = doc.get("tactics") or []
            for t in doc.get("techniques") or []:
                t["framework"] = fw
                t["parent"] = t["id"].split(".")[0] if "." in t["id"] else None
                self.techniques.setdefault(t["id"].upper(), t)   # enterprise first, so a shared id resolves to Enterprise
        atlas = _read(d / "atlas.json")
        self.atlas_mitigations = {m["id"].upper(): m for m in (_read(d / "atlas_mitigations.json") or {}).get("mitigations", [])}
        self.case_studies = {c["id"].upper(): c for c in (_read(d / "atlas_cases.json") or {}).get("case_studies", [])}
        if atlas:
            self.meta["atlas"] = {k: atlas.get(k) for k in ("name", "version")}
            self.tactics["atlas"] = atlas.get("tactics") or []
            for t in atlas.get("techniques") or []:
                t["framework"] = "atlas"
                t["parent"] = t.get("parent") or (t["id"].split(".")[0] if t["id"].count(".") == 2 else None)
                self.techniques[t["id"].upper()] = t
        self.groups = {g["id"].upper(): g for g in (_read(d / "groups.json") or {}).get("groups", [])}
        self.software = {s["id"].upper(): s for s in (_read(d / "software.json") or {}).get("software", [])}
        self.mitigations = {m["id"].upper(): m for m in (_read(d / "mitigations.json") or {}).get("mitigations", [])}
        self.mitigations.update(self.atlas_mitigations)
        self.renamed = {r["old"].upper(): r["new"].upper() for r in (_read(d / "renamed.json") or {}).get("renamed", [])}
        self.available = bool(self.techniques)
        self._join()

    # -------------------------------------------------------------- joins
    def _join(self):
        self.groups_by_tech, self.software_by_tech, self.groups_by_software = {}, {}, {}
        for gid, g in self.groups.items():
            for t in g.get("techniques", []):
                self.groups_by_tech.setdefault(t.upper(), []).append(gid)
            for s in g.get("software", []):
                self.groups_by_software.setdefault(s.upper(), []).append(gid)
        for sid, s in self.software.items():
            for t in s.get("techniques", []):
                self.software_by_tech.setdefault(t.upper(), []).append(sid)
        self.children = {}
        for tid, t in self.techniques.items():
            if t.get("parent"):
                self.children.setdefault(t["parent"].upper(), []).append(tid)
        for k in self.children:
            self.children[k].sort()
        self.tactic_name = {}
        for fw, tl in self.tactics.items():
            for t in tl:
                self.tactic_name[(fw, t.get("shortname") or t["id"])] = t["name"]
                self.tactic_name[(fw, t["id"])] = t["name"]
        self.aliases = {}
        for coll in (self.groups, self.software):
            for rid, r in coll.items():
                for n in [r["name"], *r.get("aliases", [])]:
                    self.aliases.setdefault(n.lower(), rid)

    # -------------------------------------------------------------- basic lookups
    def resolve(self, tid):
        """The current id for a technique id: itself if it exists, the successor if MITRE merged or renumbered it, else None."""
        k = norm_id(tid)
        if k in self.techniques:
            return k
        new = self.renamed.get(k) or self.renamed.get(k.split(".")[0])
        return new if new in self.techniques else None

    def exists(self, tid):
        return norm_id(tid) in self.techniques

    def technique(self, tid, detail=True):
        t = self.techniques.get(norm_id(tid))
        if not t:
            return None
        if not detail:
            return t
        k = norm_id(tid)
        fw = t["framework"]
        out = {**t, "framework_label": LABEL[fw], "tactic_names": [self.tactic_name.get((fw, s), s) for s in t.get("tactics", [])],
               "subtechniques": [{"id": c, "name": self.techniques[c]["name"]} for c in self.children.get(k, [])],
               "groups": [{"id": g, "name": self.groups[g]["name"]} for g in sorted(self.groups_by_tech.get(k, []))],
               "software": [{"id": s, "name": self.software[s]["name"], "type": self.software[s]["type"]} for s in sorted(self.software_by_tech.get(k, []))],
               "mitigation_details": [{"id": m, "name": self.mitigations[m.upper()]["name"]} for m in t.get("mitigations", []) if m.upper() in self.mitigations],
               "case_study_details": [{"id": c, "name": self.case_studies[c.upper()]["name"]} for c in t.get("case_studies", []) if c.upper() in self.case_studies]}
        if t.get("parent"):
            p = self.techniques.get(t["parent"].upper())
            out["parent_name"] = p["name"] if p else None
        out["url"] = technique_url(t["id"])
        return out

    def group(self, gid):
        g = self._find(self.groups, gid)
        if not g:
            return None
        return {**g, "technique_details": [self._brief(t) for t in g.get("techniques", [])], "software_details": [self._brief_sw(s) for s in g.get("software", [])],
                "url": f"https://attack.mitre.org/groups/{g['id']}/"}

    def software_item(self, sid):
        s = self._find(self.software, sid)
        if not s:
            return None
        k = s["id"].upper()
        return {**s, "technique_details": [self._brief(t) for t in s.get("techniques", [])],
                "groups": [{"id": g, "name": self.groups[g]["name"]} for g in sorted(self.groups_by_software.get(k, [])) if g in self.groups],
                "url": f"https://attack.mitre.org/software/{s['id']}/"}

    def _find(self, coll, x):
        if not x:
            return None
        r = coll.get(norm_id(x))
        if not r:
            rid = self.aliases.get(str(x).strip().lower())
            r = coll.get(rid) if rid else None
        return r

    def _brief(self, tid):
        t = self.techniques.get(norm_id(tid))
        return {"id": tid, "name": t["name"] if t else None, "tactics": t.get("tactics", []) if t else [], "known": bool(t)}

    def _brief_sw(self, sid):
        s = self.software.get(norm_id(sid))
        return {"id": sid, "name": s["name"] if s else None, "type": s["type"] if s else None}

    def resolve_actor(self, name):
        """A group or software record id for a name or alias (case-insensitive), or None."""
        return self.aliases.get(str(name or "").strip().lower())

    def tactic_names_for(self, tid):
        t = self.techniques.get(norm_id(tid))
        return [self.tactic_name.get((t["framework"], s), s) for s in t.get("tactics", [])] if t else []

    # -------------------------------------------------------------- matrices
    def matrix(self, framework):
        """{framework, label, name, version, tactics: [{id, shortname, name, description, techniques: [{id, name, subtechniques: [{id, name}]}]}]}."""
        if framework not in self.tactics:
            return None
        cols = []
        for tac in self.tactics[framework]:
            key = tac.get("shortname") or tac["id"]
            tops = sorted((t for t in self.techniques.values() if t["framework"] == framework and key in t.get("tactics", []) and not t.get("parent")), key=lambda t: t["id"])
            # an ATLAS or ATT&CK sub-technique can carry its own tactic; show it under its parent regardless
            cols.append({"id": tac["id"], "shortname": key, "name": tac["name"], "description": tac.get("description", ""),
                         "techniques": [{"id": t["id"], "name": t["name"], "subtechniques": [{"id": c, "name": self.techniques[c]["name"]} for c in self.children.get(t["id"].upper(), [])]} for t in tops]})
        meta = self.meta.get(framework, {})
        return {"framework": framework, "label": LABEL[framework], "name": meta.get("name"), "version": meta.get("version"), "tactics": cols,
                "counts": {"techniques": sum(1 for t in self.techniques.values() if t["framework"] == framework and not t.get("parent")),
                           "subtechniques": sum(1 for t in self.techniques.values() if t["framework"] == framework and t.get("parent"))}}

    def frameworks(self):
        out = []
        for fw in FRAMEWORKS:
            if fw in self.tactics:
                n = sum(1 for t in self.techniques.values() if t["framework"] == fw)
                out.append({"id": fw, "label": LABEL[fw], "name": self.meta[fw].get("name"), "version": self.meta[fw].get("version"), "tactics": len(self.tactics[fw]), "techniques": n})
        return out

    def techniques_of(self, framework=None):
        return [t for t in self.techniques.values() if not framework or t["framework"] == framework]

    # -------------------------------------------------------------- search
    def search(self, q, kinds=("technique", "group", "software", "case-study"), limit=25):
        """Ranked hits: exact id, then name or alias, then name words, then description words. Returns [{kind, id, name, score, framework?, snippet}]."""
        q = (q or "").strip().lower()
        if not q:
            return []
        words = [w for w in re.split(r"\W+", q) if len(w) > 1] or [q]
        hits = []

        def score(idv, name, aliases, desc):
            idl = idv.lower()
            if q == idl:
                return 100
            if q == name.lower() or q in [a.lower() for a in aliases]:
                return 90
            s = 0
            hay = " ".join([name, *aliases]).lower()
            if q in hay:
                s = 60
            elif all(w in hay for w in words):
                s = 45
            elif all(w in (hay + " " + (desc or "").lower()) for w in words):
                s = 20
            return s

        if "technique" in kinds:
            for t in self.techniques.values():
                s = score(t["id"], t["name"], [], t.get("description"))
                if s:
                    hits.append({"kind": "technique", "id": t["id"], "name": t["name"], "score": s + (3 if not t.get("parent") else 0), "framework": t["framework"], "snippet": t.get("description", "")[:140]})
        if "group" in kinds:
            for g in self.groups.values():
                s = score(g["id"], g["name"], g.get("aliases", []), g.get("description"))
                if s:
                    hits.append({"kind": "group", "id": g["id"], "name": g["name"], "score": s, "snippet": g.get("description", "")[:140]})
        if "software" in kinds:
            for sw in self.software.values():
                s = score(sw["id"], sw["name"], sw.get("aliases", []), sw.get("description"))
                if s:
                    hits.append({"kind": "software", "id": sw["id"], "name": sw["name"], "score": s, "type": sw["type"], "snippet": sw.get("description", "")[:140]})
        if "case-study" in kinds:
            for c in self.case_studies.values():
                s = score(c["id"], c["name"], [], c.get("summary"))
                if s:
                    hits.append({"kind": "case-study", "id": c["id"], "name": c["name"], "score": s, "snippet": c.get("summary", "")[:140]})
        hits.sort(key=lambda h: (-h["score"], h["id"]))
        return hits[:limit]


def technique_url(tid):
    tid = str(tid)
    if tid.upper().startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{tid.upper()}"
    return "https://attack.mitre.org/techniques/" + tid.upper().replace(".", "/") + "/"


_lock = threading.Lock()
_cache = {}


def get(data_dir=None):
    key = str(data_dir or DATA_DIR)
    with _lock:
        if key not in _cache:
            _cache[key] = Catalog(data_dir)
        return _cache[key]


def reload():
    with _lock:
        _cache.clear()
