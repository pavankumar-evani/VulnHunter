"""
The threat model engine: validates a system model, applies the STRIDE rules, and joins each threat to what Quanta knows about the real
environment.

* Model: components (process, service, datastore, external, ai-model), data flows, trust zones, data classes.
* Threats: raised by the rules in rules.py, each traceable to a rule and the facts in the model.
* Joined to reality: a threat is linked to the live findings on the model's assets that would let it happen (same ATT&CK technique or CWE),
  and to the security controls recorded for those assets (the controls inventory), so the same threat reads differently when a
  known-exploited flaw is sitting on the component or when the mitigating control is verified.

Scoring is deliberately simple and shown, not hidden:
  likelihood  rule base, minus 1 when the weakness is only unconfirmed, plus 1 for an internet-facing component, plus 1 when a live finding
              could realise the threat and 2 when that finding is on the CISA KEV list (capped at 5)
  impact      the rule base
  inherent    likelihood x impact (1 to 25): 15+ Critical, 10+ High, 5+ Medium, else Low
  residual    inherent x (1 - 0.7 x control coverage), where coverage is the share of the rule's mitigating control classes recorded for the
              component's assets (verified 1, claimed 0.5, otherwise 0). A control never takes risk to zero. With no controls recorded
              for the assets, residual equals inherent and the threat says controls are unknown.
These are for ranking and conversation, not a quantified risk.
"""
import fnmatch
import re

from remediation.threatmodel import rules as R

MAX_COMPONENTS, MAX_FLOWS = 200, 1000
REVIEW_STATUSES = ("open", "accepted", "mitigated", "not-applicable")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,59}$")


class ModelError(ValueError):
    def __init__(self, problems):
        self.problems = problems
        super().__init__("; ".join(problems[:8]))


def normalise_model(model):
    """Validates and completes a model. Raises ModelError listing every problem found."""
    problems = []
    if not isinstance(model, dict):
        raise ModelError(["The model must be an object with components, data_flows and trust_zones."])
    comps, flows, zones = model.get("components") or [], model.get("data_flows") or [], model.get("trust_zones") or []
    if len(comps) > MAX_COMPONENTS or len(flows) > MAX_FLOWS:
        raise ModelError([f"At most {MAX_COMPONENTS} components and {MAX_FLOWS} data flows per model."])
    out_c, ids = [], set()
    for i, c in enumerate(comps):
        cid = str(c.get("id") or "")
        if not _ID.match(cid):
            problems.append(f"component {i + 1}: id must be 1 to 60 letters, digits, dots, dashes or underscores")
            continue
        if cid in ids:
            problems.append(f"component id {cid!r} is used twice")
        ids.add(cid)
        if c.get("type") not in R.COMPONENT_TYPES:
            problems.append(f"component {cid}: type must be one of {', '.join(R.COMPONENT_TYPES)}")
        out_c.append({**c, "id": cid, "name": str(c.get("name") or cid)[:120], "assets": [str(a) for a in (c.get("assets") or [])][:50],
                      "handles": [str(h).lower() for h in (c.get("handles") or [])]})
    zone_ids = set()
    out_z = []
    for z in zones:
        zid = str(z.get("id") or "")
        if not _ID.match(zid):
            problems.append(f"trust zone id {zid!r} is not valid")
            continue
        zone_ids.add(zid)
        out_z.append({"id": zid, "name": str(z.get("name") or zid)[:80], "trust": int(z.get("trust", 1))})
    for c in out_c:
        if c.get("trust_zone") and c["trust_zone"] not in zone_ids:
            problems.append(f"component {c['id']}: trust_zone {c['trust_zone']!r} is not defined")
    by_id = {c["id"]: c for c in out_c}
    out_f = []
    for i, f in enumerate(flows):
        a, b = str(f.get("from") or ""), str(f.get("to") or "")
        if a not in by_id or b not in by_id:
            problems.append(f"data flow {i + 1}: 'from' and 'to' must name existing components")
            continue
        ca, cb = by_id[a], by_id[b]
        za, zb = ca.get("trust_zone") or ("internet" if ca.get("internet_facing") else None), cb.get("trust_zone") or None
        out_f.append({**f, "id": str(f.get("id") or f"{a}->{b}#{i + 1}")[:80], "from": a, "to": b, "name": f"{ca['name']} to {cb['name']}",
                      "from_type": ca.get("type"), "to_type": cb.get("type"), "data": [str(d).lower() for d in (f.get("data") or [])],
                      "crosses_zones": bool(za and zb and za != zb) or (ca.get("type") == "external" and cb.get("type") != "external")})
    if problems:
        raise ModelError(problems)
    return {"components": out_c, "data_flows": out_f, "trust_zones": out_z, "data_classes": [str(d).lower() for d in (model.get("data_classes") or [])]}


def _level(score):
    return "Critical" if score >= 15 else "High" if score >= 10 else "Medium" if score >= 5 else "Low"


def _assets_match(patterns, name):
    return any(fnmatch.fnmatchcase((name or "").lower(), p.lower()) for p in patterns)


def _finding_overlap(finding, rule, techs_of, cwes_of):
    return bool(set(techs_of(finding)) & set(rule["techniques"])) or bool(set(cwes_of(finding)) & set(rule["cwe"]))


def _fill(rule, el):
    data = ", ".join(sorted(R.SENSITIVE & set(el.get("handles") or el.get("data") or []))) or "sensitive data"
    return rule["text"].format(name=el.get("name", el.get("id")), data=data, where=el.get("secrets_management", "configuration"),
                               tools=", ".join(str(t) for t in (el.get("tools") or [])) or "tools")


def analyse(model, findings=None, controls_for=None, reviews=None):
    """Threats for a normalised model, joined to findings and controls. `controls_for(asset_names)` returns the controls inventory entries
    that apply (defaults to the controls store); `reviews` maps a threat key to {status, note, reviewer}."""
    from remediation.controls import store as controls_store
    from remediation.enrichment import attack_mapping, client_controls
    from remediation.guidance.engine import finding_cwes
    model = normalise_model(model)
    findings = findings or []
    reviews = reviews or {}
    classes = client_controls.load()["control_classes"]
    controls_for = controls_for or (lambda names: [c for n in names for c in controls_store.for_asset(n)])

    def techs_of(f):
        return [t["technique_id"] for t in (f.get("attack_techniques") or attack_mapping.map_finding_to_attack(f, all_matches=True))]

    out = []
    elements = [("component", c) for c in model["components"]] + [("flow", f) for f in model["data_flows"]]
    for rule in R.RULES:
        for kind, el in elements:
            if rule["applies"] != kind:
                continue
            if kind == "component" and el["type"] not in rule["kinds"]:
                continue
            confidence = rule["fires"](el, model)
            if not confidence:
                continue
            comp = el if kind == "component" else next(c for c in model["components"] if c["id"] == el["to"])
            patterns = comp.get("assets") or []
            linked = []
            if patterns:
                for f in findings:
                    if _assets_match(patterns, (f.get("asset") or {}).get("name")) and _finding_overlap(f, rule, techs_of, finding_cwes):
                        linked.append(f)
            kev = any((f.get("kev") or {}).get("listed") for f in linked)
            lik = rule["likelihood"] - (1 if confidence == "unconfirmed" else 0) + (1 if comp.get("internet_facing") else 0) + (2 if kev else 1 if linked else 0)
            lik = max(1, min(5, lik))
            inherent = lik * rule["impact"]
            entries = controls_for(patterns) if patterns else []
            by_class = {}
            for e in entries:
                by_class.setdefault(e["control_class"], []).append(e)
            ctl = []
            for cls in rule["controls"]:
                have = by_class.get(cls, [])
                status = ("unknown" if not entries else "verified" if any(h["state"] == "verified" for h in have) else "claimed" if have else "absent")
                ctl.append({"control_class": cls, "label": classes.get(cls, cls), "status": status})
            coverage = None
            if entries:
                coverage = sum(1.0 if c["status"] == "verified" else 0.5 if c["status"] == "claimed" else 0 for c in ctl) / len(ctl)
            residual = round(inherent * (1 - 0.7 * coverage), 1) if coverage is not None else float(inherent)
            key = f"{rule['id']}:{el['id']}"
            out.append({
                "key": key, "rule_id": rule["id"], "stride": rule["stride"], "stride_name": R.STRIDE[rule["stride"]],
                "element": {"id": el["id"], "name": el.get("name", el["id"]), "kind": kind}, "title": rule["title"], "description": _fill(rule, el),
                "confidence": confidence, "likelihood": lik, "impact": rule["impact"], "inherent_score": inherent, "rating": _level(inherent),
                "controls": ctl, "coverage_pct": None if coverage is None else round(coverage * 100), "residual_score": residual, "residual_rating": _level(residual),
                "controls_known": coverage is not None, "techniques": rule["techniques"], "cwe": rule["cwe"],
                "findings": [{"id": f["id"], "title": f.get("title"), "severity": f.get("severity"), "kev": bool((f.get("kev") or {}).get("listed"))} for f in linked[:10]],
                "findings_total": len(linked), "review": reviews.get(key) or {"status": "open", "note": None, "reviewer": None},
            })
    out.sort(key=lambda t: (-t["residual_score"], -t["inherent_score"], t["key"]))
    return {"model": model, "threats": out, "summary": summarise(out)}


def summarise(threats):
    def count(field, values):
        return {v: sum(1 for t in threats if t[field] == v) for v in values}
    live = [t for t in threats if t["review"]["status"] in ("open",)]
    return {"total": len(threats), "open": len(live), "by_rating": count("rating", ("Critical", "High", "Medium", "Low")),
            "by_residual_rating": count("residual_rating", ("Critical", "High", "Medium", "Low")),
            "by_stride": {R.STRIDE[k]: sum(1 for t in threats if t["stride"] == k) for k in R.STRIDE},
            "unconfirmed": sum(1 for t in threats if t["confidence"] == "unconfirmed"),
            "with_live_findings": sum(1 for t in threats if t["findings_total"]),
            "with_kev": sum(1 for t in threats if any(f["kev"] for f in t["findings"])),
            "controls_unknown": sum(1 for t in threats if not t["controls_known"])}
