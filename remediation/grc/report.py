"""
Where each framework control stands, and how to hand that to an auditor.

For every control in a framework this combines three things: the latest automated evidence (tests mapped to the control), the most recent
attestation by a named person, and whether anything covers the control at all. The status is:

  satisfied        every mapped test passes
  partially        some mapped tests pass or warn
  not-satisfied    at least one mapped test fails
  no-evidence      no mapped test has a usable result (all `na`, or none run)
  not-evidenced    no test covers this control; it needs an attestation or a control Quanta does not observe

An attestation is a person's statement that the control is effective, partially effective or ineffective as of a date, with an optional
expiry; it sits next to the evidence and never replaces it. Coverage counts a control as evidenced when it has either usable test evidence or a
current attestation, and says how many controls Quanta cannot speak to at all.

The OSCAL export is an Assessment Results document in the OSCAL 1.1 shape (observations from the tests, a finding per control with its
satisfied / not-satisfied state). It records that Quanta observed these things; it is not an audit opinion. Validate it with NIST's OSCAL tooling
before submitting it anywhere.
"""
import datetime
import json
import uuid

from sqlalchemy import insert, select

from remediation.grc import catalog, evidence
from remediation.utils import db as db_module

ATTEST_RESULTS = ("effective", "partially-effective", "ineffective")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def attest(framework_id, control_id, result, statement, actor, valid_until=None, engine=None):
    if result not in ATTEST_RESULTS:
        raise ValueError(f"result must be one of {', '.join(ATTEST_RESULTS)}")
    if not (statement or "").strip():
        raise ValueError("Say what the attestation rests on")
    if valid_until:
        try:
            datetime.date.fromisoformat(str(valid_until)[:10])
        except ValueError:
            raise ValueError("valid_until must be a date like 2026-12-31") from None
    engine = _engine(engine)
    if not any(c["control_id"] == control_id for c in catalog.controls_of(framework_id, engine)):
        raise KeyError("No such control in that framework")
    with engine.begin() as conn:
        conn.execute(insert(db_module.grc_attestations), {"framework_id": framework_id, "control_id": control_id, "result": result, "statement": statement,
                                                          "attested_by": actor, "attested_at": _now(), "valid_until": str(valid_until)[:10] if valid_until else None})


def _attestations(framework_id, engine):
    t = db_module.grc_attestations
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.framework_id == framework_id).order_by(t.c.id)).mappings().all()
    out = {}
    for r in rows:
        out[r["control_id"]] = dict(r)
    return out


def mapping():
    """{framework_id: {control_id: [test ids]}} from grc_tests.yaml."""
    out = {}
    for tid, fws in (evidence.config().get("mappings") or {}).items():
        for fid, ctls in fws.items():
            for c in ctls:
                out.setdefault(fid, {}).setdefault(c, []).append(tid)
    return out


def control_status(tests):
    results = [t["result"] for t in tests]
    usable = [r for r in results if r in ("pass", "fail", "warn")]
    if not tests:
        return "not-evidenced"
    if "fail" in usable:
        return "not-satisfied"
    if not usable:
        return "no-evidence"
    return "satisfied" if all(r == "pass" for r in usable) and len(usable) == len(results) else "partially"


def framework_report(framework_id, engine=None, today=None):
    engine = _engine(engine)
    today = today or datetime.date.today().isoformat()
    fw = next((f for f in catalog.list_frameworks(engine) if f["id"] == framework_id), None)
    if not fw:
        raise KeyError("No such framework")
    latest, maps, atts = evidence.latest(engine), mapping().get(framework_id, {}), _attestations(framework_id, engine)
    rows = []
    for c in catalog.controls_of(framework_id, engine):
        tests = [latest[t] for t in maps.get(c["control_id"], []) if t in latest]
        ids = maps.get(c["control_id"], [])
        status = "not-evidenced" if not ids else control_status(tests) if tests else "no-evidence"
        att = atts.get(c["control_id"])
        current = bool(att and (not att["valid_until"] or att["valid_until"] >= today))
        rows.append({"control_id": c["control_id"], "title": c["title"], "family": c["family"], "statement": c["statement"], "status": status,
                     "tests": [{"test_id": t["test_id"], "title": t["title"], "result": t["result"], "detail": t["detail"], "collected_at": t["collected_at"]} for t in tests],
                     "mapped_tests": ids, "attestation": dict(att, current=current) if att else None})
    evidenced = sum(1 for r in rows if r["status"] in ("satisfied", "partially", "not-satisfied") or (r["attestation"] and r["attestation"]["current"]))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("satisfied", "partially", "not-satisfied", "no-evidence", "not-evidenced")}
    return {"framework": fw, "controls": rows, "counts": counts, "total": len(rows), "evidenced": evidenced,
            "evidenced_pct": round(100 * evidenced / len(rows)) if rows else None,
            "note": ("Controls marked not-evidenced are ones Quanta cannot observe (people, process, physical); they need an attestation or evidence from another system. "
                     "A passing test is evidence that Quanta observed something, not an audit conclusion.")}


def to_oscal(framework_id, engine=None):
    rep = framework_report(framework_id, engine)
    now = _now()
    observations, findings, uid = [], [], lambda: str(uuid.uuid4())
    for c in rep["controls"]:
        obs_ids = []
        for t in c["tests"]:
            oid = uid()
            obs_ids.append(oid)
            observations.append({"uuid": oid, "title": t["title"], "description": f"{t['detail']} (observed by Quanta automated test {t['test_id']}: {t['result']})",
                                 "methods": ["TEST"], "collected": t["collected_at"]})
        if c["status"] in ("satisfied", "not-satisfied", "partially"):
            findings.append({"uuid": uid(), "title": f"{c['control_id']}: {c['title']}", "description": f"Status from automated evidence: {c['status']}.",
                             "target": {"type": "objective-id", "target-id": c["control_id"].lower(),
                                        "status": {"state": "satisfied" if c["status"] == "satisfied" else "not-satisfied"}},
                             "related-observations": [{"observation-uuid": o} for o in obs_ids]})
    doc = {"assessment-results": {
        "uuid": uid(),
        "metadata": {"title": f"Quanta automated control evidence: {rep['framework']['name']}", "last-modified": now, "version": "1.0", "oscal-version": "1.1.2",
                     "remarks": "Observations recorded by Quanta's automated tests. Not an audit opinion."},
        "import-ap": {"href": "#assessment-plan-not-provided"},
        "results": [{"uuid": uid(), "title": "Automated evidence", "description": "Latest results of Quanta's automated control tests.", "start": now,
                     "reviewed-controls": {"control-selections": [{"include-controls": [{"control-id": c["control_id"].lower()} for c in rep["controls"] if c["tests"]]}]},
                     "observations": observations, "findings": findings}]}}
    return json.loads(json.dumps(doc))
