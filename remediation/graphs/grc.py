"""GRC graph: which evidence backs which control, which frameworks share it, and which risks depend on it.

Nodes: frameworks, controls (one hub per control id, shared by every framework that carries it), automated tests (the latest evidence
result), register risks, and the threat-model threat or finding group a risk cites. Edges: control -> framework (part of), evidence ->
control (evidences), risk -> control (mitigated by), risk -> threat / finding group (cites).

A risk has no stored control field, so a risk is tied to a control in two honest ways only: its text names the control id (for example
"SI-2"), or it is the "kev-overdue" finding risk, which is tied to the controls the known-exploited-vulnerability test evidences.
Only controls with a status, a current attestation or a linked risk are drawn, so a 1,000-control catalog does not bury the picture.
"""
import re

from remediation.graphs.schema import GraphBuilder
from remediation.grc import catalog, evidence, report, risks as risks_mod
from remediation.utils import db as db_module

_STATUS_SEV = {"not-satisfied": "high", "partially": "medium", "satisfied": "low"}
_SEV_RANK = {"high": 0, "medium": 1, "low": 2, None: 3}
_RESULT_SEV = {"fail": "high", "warn": "medium", "pass": "low"}
_LEVEL_SEV = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
_CONTROL_ID = re.compile(r"[A-Z]{2,3}(?:\.[A-Z]{2,3})?-\d+(?:\(\d+\))?")
NOTE_EMPTY = ("No control framework is loaded yet. Open Risk & Compliance (/grc) to load a built-in framework or import a catalog, "
              "then run the automated control tests so there is evidence to draw.")


def _mentioned(risk):
    text = " ".join(str(risk.get(k) or "") for k in ("title", "description", "treatment_plan")).upper()
    return set(_CONTROL_ID.findall(text))


def build(engine=None, findings=None, **context):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    findings = findings or []
    g = GraphBuilder("grc", "Control evidence and risk graph",
                     "Which automated evidence backs which control, which frameworks share it, and which risks depend on it.")
    for key, label in (("framework", "Framework"), ("control", "Control"), ("evidence", "Automated test"), ("risk", "Risk"), ("threat", "Threat"),
                       ("findings", "Finding group"), ("part-of", "part of"), ("evidences", "evidences"), ("mitigated-by", "mitigated by"), ("cites", "cites")):
        g.kind(key, label)

    frameworks = catalog.list_frameworks(engine)
    if not frameworks:
        return g.build(note=NOTE_EMPTY)
    today = context.get("today")
    today = today.isoformat() if hasattr(today, "isoformat") else today
    latest = evidence.latest(engine)
    maps = report.mapping()
    live_risks = risks_mod.list_risks(engine, include_closed=False)

    # Per framework, the real status of every control (report.py does the computing).
    per_control = {}  # control_id -> {"title", "frameworks": {framework_id: row}}
    for fw in frameworks:
        for row in report.framework_report(fw["id"], engine, today=today)["controls"]:
            per_control.setdefault(row["control_id"], {"title": row["title"], "frameworks": {}})["frameworks"][fw["id"]] = row

    # Risk -> control links (see the module docstring).
    kev_controls = {c for ctls in (evidence.config().get("mappings") or {}).get("kev-remediation", {}).values() for c in ctls}
    risk_links = {}
    for r in live_risks:
        linked = {c for c in _mentioned(r) if c in per_control}
        if r["source"] == "finding" and r["source_ref"] == "kev-overdue":
            linked |= {c for c in kev_controls if c in per_control}
        risk_links[r["id"]] = sorted(linked)
    risk_controls = {c for ls in risk_links.values() for c in ls}

    included = {}
    for cid, info in per_control.items():
        rows = list(info["frameworks"].values())
        if (any(r["status"] != "not-evidenced" for r in rows) or any(r["attestation"] and r["attestation"]["current"] for r in rows)
                or cid in risk_controls):
            included[cid] = info

    used_frameworks, used_tests = set(), set()
    for cid in sorted(included):
        info = included[cid]
        sev, statuses = None, []
        for fid, row in sorted(info["frameworks"].items()):
            statuses.append(row["status"])
            s = _STATUS_SEV.get(row["status"])
            if _SEV_RANK[s] < _SEV_RANK[sev]:
                sev = s
            used_frameworks.add(fid)
        worst = next((st for st in ("not-satisfied", "partially", "satisfied", "no-evidence") if st in statuses), "not-evidenced")
        attested = any(r["attestation"] and r["attestation"]["current"] for r in info["frameworks"].values())
        g.node(f"control:{cid}", cid, "control", weight=len(info["frameworks"]), sev=sev,
               meta={"title": info["title"], "status": worst, "frameworks": len(info["frameworks"]), "attested": attested}, href="/grc")
        for fid in sorted(info["frameworks"]):
            g.edge(f"control:{cid}", f"framework:{fid}", "part-of", "part of")
            for tid in maps.get(fid, {}).get(cid, []):
                if tid in latest:
                    used_tests.add(tid)
                    g.edge(f"evidence:{tid}", f"control:{cid}", "evidences", "evidences")

    for fw in frameworks:
        if fw["id"] in used_frameworks:
            shown = sum(1 for i in included.values() if fw["id"] in i["frameworks"])
            g.node(f"framework:{fw['id']}", fw["name"], "framework", weight=shown,
                   meta={"version": fw.get("version"), "controls_in_catalog": fw["control_count"], "controls_shown": shown}, href="/grc")
    for tid in sorted(used_tests):
        row = latest[tid]
        g.node(f"evidence:{tid}", row["title"], "evidence", sev=_RESULT_SEV.get(row["result"]),
               meta={"result": row["result"], "metric": row["metric"], "threshold": row["threshold"], "collected_at": row["collected_at"]}, href="/grc")

    kev_open = sum(1 for f in findings if (f.get("kev") or {}).get("listed") and (f.get("sla") or {}).get("breached"))
    for r in live_risks:
        rid = f"risk:{r['id']}"
        lvl = r["residual_level"] or r["inherent_level"]
        g.node(rid, r["title"], "risk", weight=r["residual_score"] or r["inherent_score"], sev=_LEVEL_SEV.get(lvl),
               meta={"status": r["status"], "level": lvl, "owner": r["owner"], "source": r["source"], "treatment": r["treatment"]}, href="/grc")
        for cid in risk_links[r["id"]]:
            g.edge(rid, f"control:{cid}", "mitigated-by", "mitigated by")
        if r["source"] == "threat" and r["source_ref"]:
            g.node(f"threat:{r['source_ref']}", r["source_ref"], "threat", href="/threat-models")
            g.edge(rid, f"threat:{r['source_ref']}", "cites", "cites")
        elif r["source"] == "finding" and r["source_ref"]:
            g.node(f"findings:{r['source_ref']}", r["source_ref"], "findings",
                   meta={"matching_findings": kev_open} if r["source_ref"] == "kev-overdue" else {}, href="/queue")
            g.edge(rid, f"findings:{r['source_ref']}", "cites", "cites")

    if not included and not live_risks:
        return g.build(note="Frameworks are loaded but no control has evidence yet. Run the automated control tests on Risk & Compliance (/grc), "
                            "or record an attestation or a risk that names a control.")
    return g.build(note="Controls with no evidence, attestation or linked risk are left out. A control shared by several frameworks is one node.")
