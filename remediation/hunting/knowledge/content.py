"""
Out-of-the-box content: for each scenario, the Sigma detection rules it implies (also rendered for the SIEM languages), the preventive and detective controls MITRE lists for its
techniques, and a detection use case. All of it is SUGGESTION.

  * A suggested use case becomes a PROPOSED use case when promoted. It is never counted as coverage until an engineer implements it and an enabled rule claims the technique.
  * A suggested rule is imported DISABLED. An enabled rule is what counts as coverage, so enabling is a separate, evidenced step.
  * A suggested control goes on a planning list ("planned"). Nothing here writes the controls inventory as claimed or verified.
Coverage status per scenario: `enabled` (every technique is claimed by an enabled rule), `proposed` (a use case for it exists and is not rejected), `absent` (rules are
recorded and do not cover it), `cannot-tell` (no rules are recorded, so coverage cannot be judged).
"""
from pathlib import Path

import yaml

from remediation.enrichment import client_controls
from remediation.hunting import usecases
from remediation.hunting.knowledge import catalog as cat, readiness, scenarios, store

ATLAS_CONTROLS_PATH = Path(__file__).with_name("controls_atlas.yaml")
PRIORITY_SCORE = {"high": 70, "medium": 50, "low": 30}


def _parent(t):
    return str(t).upper().split(".")[0]


_ATLAS_CACHE = {"mtime": None, "data": None}


def _atlas_controls():
    mtime = ATLAS_CONTROLS_PATH.stat().st_mtime
    if _ATLAS_CACHE["data"] is None or _ATLAS_CACHE["mtime"] != mtime:
        with open(ATLAS_CONTROLS_PATH, encoding="utf-8") as fh:
            _ATLAS_CACHE["data"], _ATLAS_CACHE["mtime"] = yaml.safe_load(fh) or {}, mtime
    return _ATLAS_CACHE["data"]


def control_class_labels():
    base = dict(client_controls.load().get("control_classes") or {})
    base.update(_atlas_controls().get("ai_classes") or {})
    return base


# ---------------------------------------------------------------- controls
def controls_for(tids, c=None, planned=None):
    """Mitigations for the techniques, most-covering first. ATT&CK mitigations come from the catalog (MITRE's own list per technique), with the control class and indicative
    NIST 800-53 families from attack_mitigations.yaml where Quanta has mapped them; ATLAS mitigations get a class and action from controls_atlas.yaml and no NIST mapping.
    `mapped: false` says Quanta has not mapped that mitigation to a control class yet."""
    c = c or cat.get()
    mit_yaml = client_controls.load().get("mitigations") or {}
    atlas_extra = (_atlas_controls().get("mitigations") or {})
    labels = control_class_labels()
    planned = planned or {}
    by = {}
    for tid in dict.fromkeys(str(t).upper() for t in tids):
        t = c.technique(tid, detail=False)
        if not t:
            continue
        for mid in t.get("mitigations", []):
            by.setdefault(mid.upper(), []).append(tid)
    out = []
    for mid, techs in by.items():
        m = c.mitigations.get(mid, {})
        y, a = mit_yaml.get(mid) or {}, atlas_extra.get(mid) or {}
        klass = y.get("class") or a.get("class")
        key = f"control:{mid}"
        pl = planned.get(key)
        out.append({"id": mid, "name": m.get("name") or y.get("name") or mid, "class": klass, "class_label": labels.get(klass) if klass else None,
                    "nist": list(y.get("nist") or []), "nist_note": None if y.get("nist") else ("MITRE publishes no NIST mapping for ATLAS mitigations; none is recorded." if mid.startswith("AML.") else "Not mapped to NIST 800-53 families yet."),
                    "action": y.get("action") or a.get("action") or m.get("description") or "", "mitre_says": m.get("description", ""), "mapped": bool(klass),
                    "framework": "atlas" if mid.startswith("AML.") else "attack", "techniques": sorted(techs), "covers": len(techs),
                    "status": (pl or {}).get("status") or "suggested", "plan_key": key,
                    "url": f"https://atlas.mitre.org/mitigations/{mid}" if mid.startswith("AML.") else f"https://attack.mitre.org/mitigations/{mid}/"})
    out.sort(key=lambda x: (-x["covers"], x["id"]))
    return out


# ---------------------------------------------------------------- rules
def rules_for(s):
    """The scenario's detection rule drafts: one per lead, Sigma where the lead is a selection, with every other rendering and an honest status per language."""
    out = []
    for i, lead in enumerate(s["leads"]):
        r = scenarios.render_lead(lead, s, hyp_text=scenarios.hypothesis_text(s))
        out.append({"index": i, "key": f"rule:{s['id']}:{i}", "name": lead["name"], "technique": lead["technique"], "languages": r["languages"], "expressible": r["expressible"],
                    "notes": lead.get("notes", ""), "tuning": s["tuning"], "expected_false_positives": s["benign"], "status": "draft"})
    return out


def use_case_for(s, c=None):
    """The detection use case the store keeps (status proposed on promotion)."""
    c = c or cat.get()
    rules = rules_for(s)
    sigma = next((r["languages"]["sigma"]["query"] for r in rules if r["languages"]["sigma"]["status"] == "provided"),
                 "# No single-event Sigma rule exists for this scenario (it needs counting or a baseline).\n# Build it from the SPL or KQL lead and test it against recent data before enabling.\n")
    first = c.technique(s["techniques"][0], detail=False) or {}
    score = PRIORITY_SCORE[s["priority"]] + (5 if s["severity"] == "critical" else 0)
    return {"key": f"ootb-{s['id']}", "kind": "ootb-scenario", "title": f"Detect: {s['title']}", "hypothesis": scenarios.hypothesis_text(s, "the in-scope systems"), "techniques": [t for t in s["techniques"] if not t.startswith("AML.")] or s["techniques"],
            "data_sources": [readiness.CLASS_LABEL[d] for d in s["data_sources"]], "evidence": {"scenario": s["id"], "origin": "Quanta out-of-the-box library", "reasons": ["Suggested from the scenario library; not derived from your data",
                                                                                                                                           f"Severity {s['severity']}, priority {s['priority']}"]},
            "score": score, "sigma": sigma, "expected_false_positives": s["benign"], "test_plan": usecases.test_plan(first.get("name") or s["title"], 30) + [f"Tuning: {t}" for t in s["tuning"][:3]]}


# ---------------------------------------------------------------- coverage
def coverage(s, rules_recorded, covered_parents, ucs):
    """-> {status, covered, of, detail}. `ucs` is {use case key: status}."""
    parents = sorted({_parent(t) for t in s["techniques"] if not t.upper().startswith("AML.")})
    atlas_only = not parents
    have = [p for p in parents if p in covered_parents]
    uc = ucs.get(f"ootb-{s['id']}")
    if parents and len(have) == len(parents) and rules_recorded:
        st, detail = "enabled", "Every ATT&CK technique of this scenario is claimed by an enabled detection rule."
    elif uc and uc != "rejected":
        st, detail = "proposed", f"A detection use case exists for it (status {uc}); it is not counted as coverage until implemented and evidenced."
    elif not rules_recorded:
        st, detail = "cannot-tell", "No detection rules are recorded in Quanta, so whether this is covered cannot be judged."
    elif atlas_only:
        st, detail = "absent", "Rules are recorded, and none claims AI-system techniques; Quanta cannot match ATLAS techniques to ATT&CK rule tags, so confirm in your own tool."
    else:
        st, detail = "absent", f"{len(have)} of {len(parents)} techniques are claimed by an enabled rule." if have else "No enabled rule claims these techniques."
    return {"status": st, "covered": len(have), "of": len(parents), "detail": detail, "use_case_status": uc}


# ---------------------------------------------------------------- the library
def _facets(items):
    def count(key, many=False):
        out = {}
        for it in items:
            for v in (it[key] if many else [it[key]]):
                out[v] = out.get(v, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))
    return {"category": count("category"), "tactic": count("tactics", True), "platform": count("platforms", True), "data_source": count("data_sources", True),
            "framework": count("frameworks", True), "coverage": count("coverage_status")}


def library(engine_state, c=None, scn=None, filters=None):
    """Catalog of out-of-the-box scenarios with coverage status. `engine_state` = {rules, usecases (rows), planned (dict key->item)}."""
    c = c or cat.get()
    scn = scn if scn is not None else scenarios.load()
    f = filters or {}
    rules = engine_state.get("rules")
    covered = usecases.covered_techniques(rules) if rules else set()
    ucs = {u["key"]: u["status"] for u in engine_state.get("usecases") or []}
    planned = engine_state.get("planned") or {}
    sig = engine_state.get("signals")
    items = []
    for s in scn:
        techs = [c.technique(t, detail=False) for t in s["techniques"]]
        tactics = sorted({c.tactic_name.get((t["framework"], x), x) for t in techs if t for x in t.get("tactics", [])})
        platforms = sorted({p for t in techs if t for p in (t.get("platforms") or [])})
        cov = coverage(s, bool(rules), covered, ucs)
        rd = readiness.assess(s["data_sources"], sig) if sig is not None else None
        item = {"id": s["id"], "title": s["title"], "category": s["category"], "pack": s.get("pack"), "severity": s["severity"], "priority": s["priority"], "tactics": tactics, "platforms": platforms,
                "data_sources": s["data_sources"], "frameworks": sorted({t["framework"] for t in techs if t}), "techniques": [{"id": t["id"], "name": t["name"]} for t in techs if t],
                "coverage": cov, "coverage_status": cov["status"], "rules": len(s["leads"]), "controls_available": len(controls_for(s["techniques"], c)), "use_case_key": f"ootb-{s['id']}",
                "readiness": rd["status"] if rd else None, "hypothesis": scenarios.hypothesis_text(s), "planned_controls": sum(1 for k, v in planned.items() if v.get("status") == "planned" and s["id"] in (v.get("ref", {}).get("scenarios") or []))}
        items.append(item)

    def keep(it):
        if f.get("category") and it["category"] != f["category"]:
            return False
        if f.get("tactic") and f["tactic"].lower() not in [t.lower() for t in it["tactics"]] and f["tactic"].lower().replace(" ", "-") not in [t.lower().replace(" ", "-") for t in it["tactics"]]:
            return False
        if f.get("platform") and f["platform"].lower() not in [p.lower() for p in it["platforms"]]:
            return False
        if f.get("data_source") and f["data_source"] not in it["data_sources"]:
            return False
        if f.get("status") and it["coverage_status"] != f["status"]:
            return False
        if f.get("framework") and f["framework"] not in it["frameworks"]:
            return False
        if f.get("scenario") and it["id"] != f["scenario"]:
            return False
        if f.get("q"):
            q = f["q"].lower()
            if q not in (it["title"] + " " + it["hypothesis"] + " " + " ".join(t["id"] + " " + t["name"] for t in it["techniques"])).lower():
                return False
        return True
    shown = [i for i in items if keep(i)]
    return {"items": shown, "total": len(items), "shown": len(shown), "facets": _facets(items), "coverage_note":
            "Coverage status counts only enabled detection rules that name the technique. A proposed use case or a planned control is never counted.",
            "rules_recorded": bool(rules)}


def scenario_content(s, c=None, planned=None):
    """Everything suggested for one scenario."""
    c = c or cat.get()
    return {"scenario": scenarios.summary(s, c), "rules": rules_for(s), "controls": controls_for(s["techniques"], c, planned), "use_case": use_case_for(s, c),
            "response": {"playbook": s["playbook"], "definition": scenarios.playbooks().get(s["playbook"]), "steps": s["response"],
                         "note": "Recommendations for a person. Quanta does not contain or change anything."}}


# ---------------------------------------------------------------- promotion
class PromoteError(ValueError):
    pass


def promote(kind, args, actor, engine=None, c=None):
    """kind: use-case | rule | control. Everything lands as a draft: a PROPOSED use case, a DISABLED rule, a PLANNED control."""
    from remediation.hunting import detection, usecase_store
    c = c or cat.get()
    if kind in ("use-case", "rule"):
        s = scenarios.get(args.get("scenario_id") or "")
        if not s:
            raise PromoteError("Unknown scenario_id")
    if kind == "use-case":
        case = use_case_for(s, c)
        have = usecase_store.get(case["key"], engine)
        usecase_store.sync([case], engine)
        row = usecase_store.get(case["key"], engine)
        return {"kind": "use-case", "key": case["key"], "status": row["status"], "already_existed": bool(have), "counted_as_coverage": False,
                "note": "A proposed use case. It is not counted as coverage until an engineer implements it and an enabled rule that names the technique is evidenced."}
    if kind == "rule":
        idx = args.get("lead_index")
        if not isinstance(idx, int) or not (0 <= idx < len(s["leads"])):
            raise PromoteError("lead_index must be the index of one of the scenario's leads")
        r = rules_for(s)[idx]
        sg = r["languages"]["sigma"]
        if sg["status"] != "provided":
            raise PromoteError(f"This lead has no single-event Sigma rule to import ({sg.get('reason', '')}). Use its SPL or KQL form in your own tool.")
        parsed = detection.parse_sigma(sg["query"])[0]
        rule = detection.upsert_rule(parsed["name"], parsed["platform"], parsed["logic"], parsed["techniques"] or [r["technique"]], "sigma", enabled=False, engine=engine)
        return {"kind": "rule", "rule_id": rule["id"], "name": rule["name"], "enabled": rule["enabled"], "counted_as_coverage": False,
                "note": "Imported disabled. Review and test it, then enable it on the Detection engineering tab; only an enabled rule counts as coverage."}
    if kind == "control":
        cid = str(args.get("control_id") or "").upper()
        m = c.mitigations.get(cid)
        if not m:
            raise PromoteError("Unknown control_id (an ATT&CK M#### or ATLAS AML.M#### mitigation id)")
        scn_ids = [x for x in (args.get("scenario_ids") or ([args["scenario_id"]] if args.get("scenario_id") else []))]
        item = store.plan(f"control:{cid}", "control", f"{cid} {m['name']}", {"control_id": cid, "name": m["name"], "scenarios": scn_ids, "techniques": args.get("techniques") or []},
                          args.get("note"), actor, engine)
        return {"kind": "control", "key": item["key"], "status": item["status"], "counted_as_coverage": False, "is_implemented": False,
                "note": "On the planning list as planned. It is not in the controls inventory; record it there yourself, as claimed or verified, once it exists."}
    raise PromoteError("kind must be use-case, rule or control")
