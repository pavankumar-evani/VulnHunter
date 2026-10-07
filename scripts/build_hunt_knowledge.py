#!/usr/bin/env python
"""
Builds the hunting knowledge base from MITRE's public data and writes COMPACT catalogs under remediation/hunting/knowledge/data/.

Sources (public, read at build time; nothing is invented):
  MITRE ATT&CK Enterprise / Mobile / ICS   STIX 2.1 bundles from the attack-stix-data repository
  MITRE ATLAS (AI systems)                 dist/ATLAS.yaml from the atlas-data repository

Run it to create or refresh the catalogs:
    python scripts/build_hunt_knowledge.py                    # download everything, rewrite data/
    python scripts/build_hunt_knowledge.py --from-dir DIR     # offline: DIR holds enterprise.json mobile.json ics.json atlas.yaml
    python scripts/build_hunt_knowledge.py --skip mobile ics  # leave a framework out

What is kept: for each technique and sub-technique its id, name, tactics, platforms, data components, a trimmed description, trimmed detection guidance (the
detection strategies' first analytic), and mitigation ids; for each group its aliases, trimmed description and the techniques and software it uses; for each
piece of software its type (malware or tool), aliases, platforms and techniques; for ATLAS its tactics, techniques, mitigations and case studies. Revoked and
deprecated objects are dropped. A manifest records every source URL, the published version, the date retrieved and the counts. Text is trimmed to keep the
checked-in catalogs small (the full text is one click away on attack.mitre.org / atlas.mitre.org via each id). The ATT&CK and ATLAS content is MITRE's and is
used under their terms (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/); keep the manifest with any redistribution.
"""
import argparse
import datetime
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "remediation" / "hunting" / "knowledge" / "data"
ATTACK_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
SOURCES = {
    "enterprise": f"{ATTACK_BASE}/enterprise-attack/enterprise-attack.json",
    "mobile": f"{ATTACK_BASE}/mobile-attack/mobile-attack.json",
    "ics": f"{ATTACK_BASE}/ics-attack/ics-attack.json",
    "atlas": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml",
}
FILES = {"enterprise": "enterprise.json", "mobile": "mobile.json", "ics": "ics.json", "atlas": "atlas.yaml"}
DESC_MAX, DET_MAX, SW_MAX, CASE_MAX = 300, 220, 220, 420

_CITE = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_TAGS = re.compile(r"</?[a-z]+[^>]*>")


def trim(text, limit):
    """Plain text, first paragraph, cut at a sentence end when one falls inside the limit."""
    if not text:
        return ""
    t = _CITE.sub("", str(text))
    t = _LINK.sub(r"\1", t)
    t = _TAGS.sub("", t).replace("`", "")
    t = re.sub(r"\s+", " ", t.split("\n\n")[0] if "\n\n" in t else t).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    end = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: end + 1] if end > limit * 0.5 else cut.rsplit(" ", 1)[0] + "...").strip()


def _flag(v):
    return v is True or str(v).lower() == "true"


def _ext_id(obj):
    for r in obj.get("external_references") or []:
        if r.get("external_id") and r.get("source_name", "").startswith(("mitre-", "mitre")):
            return r["external_id"]
    return None


def _live(obj):
    return not (_flag(obj.get("revoked")) or _flag(obj.get("x_mitre_deprecated")))


def fetch(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "quanta-hunt-knowledge-builder"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed public https URLs
        return resp.read()


# ---------------------------------------------------------------- ATT&CK
def transform_attack(bundle, domain):
    """One ATT&CK STIX bundle -> (framework dict, groups by id, software by id, mitigations by id, renamed {old technique id: current id})."""
    objs = bundle["objects"]
    by_ref = {o["id"]: o for o in objs}
    live = {o["id"]: o for o in objs if _live(o)}
    col = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    tactics_raw = [o for o in live.values() if o["type"] == "x-mitre-tactic"]
    order = []
    for mx in (o for o in objs if o["type"] == "x-mitre-matrix"):
        for ref in mx.get("tactic_refs") or []:
            if ref not in order:
                order.append(ref)
    tactics_raw.sort(key=lambda o: order.index(o["id"]) if o["id"] in order else 999)
    tactics = [{"id": _ext_id(o), "shortname": o.get("x_mitre_shortname"), "name": o["name"], "description": trim(o.get("description"), 200)} for o in tactics_raw]

    comp_name = {o["id"]: o["name"] for o in live.values() if o["type"] == "x-mitre-data-component"}
    analytics = {o["id"]: o for o in live.values() if o["type"] == "x-mitre-analytic"}
    strategies = {o["id"]: o for o in live.values() if o["type"] == "x-mitre-detection-strategy"}
    rel = [o for o in objs if o["type"] == "relationship" and not _flag(o.get("revoked")) and not _flag(o.get("x_mitre_deprecated"))]

    renamed = {}
    for r in objs:   # a technique that was merged or renumbered is revoked by its successor: keep the mapping so older tags still resolve
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by":
            a, b = by_ref.get(r["source_ref"]), by_ref.get(r["target_ref"])
            if a and b and a["type"] == b["type"] == "attack-pattern" and _ext_id(a) and _ext_id(b) and _ext_id(a) != _ext_id(b) and _live(b):
                renamed[_ext_id(a)] = _ext_id(b)
    detects, mitigates = {}, {}
    uses_t, uses_sw = {}, {}   # intrusion-set/software -> technique ids ; intrusion-set -> software ids
    for r in rel:
        s, t, kind = r["source_ref"], r["target_ref"], r["relationship_type"]
        if kind == "detects" and s in strategies and t in live:
            detects.setdefault(t, []).append(s)
        elif kind == "mitigates" and s in live and by_ref.get(s, {}).get("type") == "course-of-action" and t in live:
            mitigates.setdefault(t, []).append(s)
        elif kind == "uses" and s in live and t in live:
            st, tt = live[s]["type"], live[t]["type"]
            if st in ("intrusion-set", "malware", "tool") and tt == "attack-pattern":
                uses_t.setdefault(s, set()).add(_ext_id(live[t]))
            elif st == "intrusion-set" and tt in ("malware", "tool"):
                uses_sw.setdefault(s, set()).add(_ext_id(live[t]))

    techniques = []
    for o in live.values():
        if o["type"] != "attack-pattern":
            continue
        tid = _ext_id(o)
        if not tid:
            continue
        det, comps = [], []
        for sid in sorted(detects.get(o["id"], []), key=lambda x: strategies[x]["name"]):
            st = strategies[sid]
            first = next((analytics[a] for a in st.get("x_mitre_analytic_refs") or [] if a in analytics), None)
            line = st["name"] + (": " + trim(first.get("description"), DET_MAX) if first else "")
            det.append(line[: DET_MAX + 80])
            for a in st.get("x_mitre_analytic_refs") or []:
                for ls in (analytics.get(a) or {}).get("x_mitre_log_source_references") or []:
                    n = comp_name.get(ls.get("x_mitre_data_component_ref"))
                    if n and n not in comps:
                        comps.append(n)
        for legacy in o.get("x_mitre_data_sources") or []:
            if legacy not in comps:
                comps.append(legacy)
        if not det and o.get("x_mitre_detection"):
            det.append(trim(o["x_mitre_detection"], DET_MAX))
        techniques.append({
            "id": tid, "name": o["name"], "domain": domain, "tactics": [p["phase_name"] for p in o.get("kill_chain_phases") or []],
            "platforms": o.get("x_mitre_platforms") or [], "data_sources": comps[:10], "description": trim(o.get("description"), DESC_MAX), "detection": det[:2],
            "mitigations": sorted({_ext_id(by_ref[m]) for m in mitigates.get(o["id"], []) if _ext_id(by_ref[m])}),
        })
    techniques.sort(key=lambda t: t["id"])

    groups, software, mitigs = {}, {}, {}
    for o in live.values():
        if o["type"] == "intrusion-set":
            gid = _ext_id(o)
            groups[gid] = {"id": gid, "name": o["name"], "aliases": [a for a in o.get("aliases") or [] if a != o["name"]][:12], "description": trim(o.get("description"), 260),
                           "techniques": sorted(uses_t.get(o["id"], ())), "software": sorted(uses_sw.get(o["id"], ())), "domains": [domain]}
        elif o["type"] in ("malware", "tool"):
            sid = _ext_id(o)
            software[sid] = {"id": sid, "name": o["name"], "type": o["type"], "aliases": [a for a in (o.get("x_mitre_aliases") or []) if a != o["name"]][:8],
                             "platforms": o.get("x_mitre_platforms") or [], "description": trim(o.get("description"), SW_MAX), "techniques": sorted(uses_t.get(o["id"], ())), "domains": [domain]}
        elif o["type"] == "course-of-action":
            mid = _ext_id(o)
            mitigs[mid] = {"id": mid, "name": o["name"], "description": trim(o.get("description"), 180), "domain": domain}
    # group -> software ids use the software's external id, which is already what uses_sw holds
    fw = {"framework": domain, "name": col.get("name"), "version": col.get("x_mitre_version"), "modified": col.get("modified"), "spec": col.get("x_mitre_attack_spec_version"),
          "tactics": tactics, "techniques": techniques}
    return fw, groups, software, mitigs, renamed


# ---------------------------------------------------------------- ATLAS
def transform_atlas(doc):
    m = (doc.get("matrices") or [{}])[0]
    tactics = [{"id": t["id"], "name": t["name"], "description": trim(t.get("description"), 200)} for t in m.get("tactics") or []]
    tech = []
    for t in m.get("techniques") or []:
        tech.append({"id": t["id"], "name": t["name"], "tactics": list(t.get("tactics") or []), "parent": t.get("subtechnique-of"), "maturity": t.get("maturity"),
                     "description": trim(t.get("description"), DESC_MAX), "mitigations": []})
    by_id = {t["id"]: t for t in tech}
    mitigs = []
    for mi in m.get("mitigations") or []:
        mitigs.append({"id": mi["id"], "name": mi["name"], "description": trim(mi.get("description"), 220), "techniques": [x["id"] for x in mi.get("techniques") or []]})
        for x in mi.get("techniques") or []:
            if x["id"] in by_id:
                by_id[x["id"]]["mitigations"].append(mi["id"])
    cases = []
    for c in doc.get("case-studies") or []:
        steps = c.get("procedure") or []
        cases.append({"id": c["id"], "name": c["name"], "date": str(c.get("incident-date") or ""), "summary": trim(c.get("summary"), CASE_MAX),
                      "techniques": sorted({s.get("technique") for s in steps if s.get("technique")}), "tactics": sorted({s.get("tactic") for s in steps if s.get("tactic")})})
    for t in tech:
        t["case_studies"] = sorted(c["id"] for c in cases if t["id"] in c["techniques"])
    return {"framework": "atlas", "name": doc.get("name"), "version": str(doc.get("version")), "tactics": tactics, "techniques": tech, "mitigations": mitigs, "case_studies": cases}


# ---------------------------------------------------------------- output
def dump_list_file(path, head, key, rows):
    """One record per line so a refresh produces a readable git diff."""
    lines = ['"' + k + '":' + json.dumps(v, ensure_ascii=False, separators=(",", ":")) + "," for k, v in head.items()]
    body = ',\n'.join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in rows)
    path.write_text("{\n" + "\n".join(lines) + f'\n"{key}":[\n' + body + "\n]}\n", encoding="utf-8")


def _merge(into, new):
    for k, v in new.items():
        if k not in into:
            into[k] = v
        else:
            into[k]["domains"] = sorted(set(into[k].get("domains", [])) | set(v.get("domains", [])))
            for f in ("techniques", "software"):
                if f in v:
                    into[k][f] = sorted(set(into[k].get(f, [])) | set(v[f]))


def build(raw, skip=(), retrieved=None, urls=None):
    """`raw` maps framework -> parsed document. Returns {filename: (head, key, rows)} plus the manifest."""
    out, groups, software, mitigs, renamed, manifest = {}, {}, {}, {}, {}, {"retrieved": retrieved or datetime.date.today().isoformat(), "tool": "scripts/build_hunt_knowledge.py", "sources": {}}
    for name in ("enterprise", "mobile", "ics"):
        if name in skip or name not in raw:
            continue
        fw, g, s, mi, rn = transform_attack(raw[name], name)
        for k, v in rn.items():
            renamed.setdefault(k, v)
        _merge(groups, g)
        _merge(software, s)
        for k, v in mi.items():
            mitigs.setdefault(k, v)
        out[f"{name}.json"] = ({k: fw[k] for k in ("framework", "name", "version", "modified", "spec", "tactics")}, "techniques", fw["techniques"])
        manifest["sources"][name] = {"url": (urls or SOURCES)[name], "name": fw["name"], "version": fw["version"], "modified": fw["modified"], "counts": {"tactics": len(fw["tactics"]), "techniques": len(fw["techniques"])}}
    if groups:
        out["groups.json"] = ({}, "groups", sorted(groups.values(), key=lambda x: x["id"]))
        out["software.json"] = ({}, "software", sorted(software.values(), key=lambda x: x["id"]))
        out["mitigations.json"] = ({}, "mitigations", sorted(mitigs.values(), key=lambda x: x["id"]))
        out["renamed.json"] = ({}, "renamed", [{"old": k, "new": v} for k, v in sorted(renamed.items())])
        manifest["counts"] = {"groups": len(groups), "software": len(software), "mitigations": len(mitigs)}
    if "atlas" not in skip and "atlas" in raw:
        at = transform_atlas(raw["atlas"])
        out["atlas.json"] = ({k: at[k] for k in ("framework", "name", "version", "tactics")}, "techniques", at["techniques"])
        out["atlas_mitigations.json"] = ({}, "mitigations", at["mitigations"])
        out["atlas_cases.json"] = ({}, "case_studies", at["case_studies"])
        manifest["sources"]["atlas"] = {"url": (urls or SOURCES)["atlas"], "name": at["name"], "version": at["version"], "counts": {"tactics": len(at["tactics"]), "techniques": len(at["techniques"]),
                                                                                                                              "mitigations": len(at["mitigations"]), "case_studies": len(at["case_studies"])}}
    return out, manifest


def write(out, manifest, out_dir=OUT):
    out_dir.mkdir(parents=True, exist_ok=True)
    size = 0
    for fname, (head, key, rows) in out.items():
        p = out_dir / fname
        dump_list_file(p, head, key, rows)
        size += p.stat().st_size
        manifest.setdefault("files", {})[fname] = {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()[:16]}
    manifest["total_bytes"] = size
    manifest["seed"] = False
    manifest["note"] = ("Generated from MITRE ATT&CK and MITRE ATLAS public data by scripts/build_hunt_knowledge.py; text is trimmed. Refresh by re-running the script. "
                        "Techniques are matched to the live ATT&CK site by id for the full text.")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return size


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from-dir", help="read enterprise.json mobile.json ics.json atlas.yaml from this directory instead of downloading")
    ap.add_argument("--skip", nargs="*", default=[], choices=list(SOURCES))
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    raw = {}
    for name, fname in FILES.items():
        if name in a.skip:
            continue
        try:
            data = (Path(a.from_dir) / fname).read_bytes() if a.from_dir else fetch(SOURCES[name])
        except (OSError, ValueError) as exc:
            print(f"{name}: could not read {'file' if a.from_dir else SOURCES[name]} ({exc}); NOT writing a partial catalog", file=sys.stderr)
            return 2
        raw[name] = yaml.safe_load(data) if name == "atlas" else json.loads(data)
        print(f"{name}: read {len(data):,} bytes")
    out, manifest = build(raw, skip=a.skip)
    size = write(out, manifest, Path(a.out))
    print(f"wrote {len(out)} files, {size:,} bytes to {a.out}")
    print(json.dumps(manifest.get("counts", {})), {k: v["counts"] for k, v in manifest["sources"].items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
