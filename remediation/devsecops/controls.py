"""
The DevSecOps control library, and where each repository stands against it.

Evidence comes from three places and is never guessed:
  - scan runs: each time a SARIF file (or coverage report) is uploaded, Quanta records that a scan of that type ran on that repository, even when
    it found nothing, because a clean scan is still proof that the scan happens;
  - findings: a pipeline-check finding for a rule means that control is failing for the repository;
  - Quanta itself: for example, whether any threat model exists.
A control with none of these (branch protection, signing, rotation) cannot be seen by Quanta; a person records its state and a note, and the page
says which statuses are observed and which are stated.

Statuses:
  evidenced     seen in the data (a scan ran / a pipeline check ran and found none of the rules)
  failing       a pipeline check found a violation that is still open
  no-evidence   Quanta could have seen it and did not (nothing uploaded yet)
  not-observable  Quanta has no way to see it; see the recorded state
A recorded state (implemented, planned, not-applicable, not-implemented) is shown beside the observed one and never overrides it.

Policy mapping: a security policy's sentences are matched to controls by the keywords in the library. It is a reading aid: the match is a keyword
hit, not an understanding of the sentence, and unmatched sentences are listed so nothing is silently dropped.
"""
import datetime
import json
import re
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module

LIBRARY_PATH = Path(__file__).with_name("library.yaml")
STAGES = ("design", "code", "build", "test", "release", "operate")
STATES = ("implemented", "planned", "not-applicable", "not-implemented")


def library():
    with open(LIBRARY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


CUSTOM_EVIDENCE = ("scan_type", "clean_of")
_CUSTOM_ID = re.compile(r"^org-[a-z0-9][a-z0-9-]{0,48}$")
GATE_RECENT_DAYS = 30


def full_library(engine=None):
    """The shipped library plus the organisation's own controls (marked `custom`). A custom control uses the same evidence model, so it shows the same
    statuses: evidenced from a scan, failing from a pipeline check, or not observable until someone records it."""
    return library() + [dict(c, custom=True) for c in custom_controls(engine)]


def custom_controls(engine=None):
    engine, t = _engine(engine), db_module.devsecops_custom_controls
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id)).mappings().all()
    return [{"id": r["id"], "stage": r["stage"], "title": r["title"], "why": r["why"], "how": r["how"], "keywords": json.loads(r["keywords_json"] or "[]"),
             "evidence": json.loads(r["evidence_json"] or "null") or None, "created_by": r["created_by"], "created_at": r["created_at"]} for r in rows]


def save_custom_control(control_id, fields, actor, engine=None):
    """Create or replace one organisation control. Raises ValueError with a readable message."""
    if not _CUSTOM_ID.match(control_id or ""):
        raise ValueError("The id must start with org- and use lowercase letters, digits and hyphens (for example org-change-ticket)")
    stage = fields.get("stage")
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {', '.join(STAGES)}")
    title, why, how = ((fields.get(k) or "").strip() for k in ("title", "why", "how"))
    if not (title and why and how):
        raise ValueError("A title, why it matters and how to put it in place are all required")
    ev = fields.get("evidence") or None
    if ev:
        if not isinstance(ev, dict) or len(ev) != 1 or next(iter(ev)) not in CUSTOM_EVIDENCE:
            raise ValueError("evidence is optional; if given it is {scan_type: <type>} or {clean_of: [<pipeline rule ids>]}")
        if "clean_of" in ev and not (isinstance(ev["clean_of"], list) and all(isinstance(x, str) for x in ev["clean_of"])):
            raise ValueError("clean_of must be a list of pipeline rule ids")
    kw = [k.strip().lower() for k in (fields.get("keywords") or []) if isinstance(k, str) and k.strip()][:20]
    if control_id in {c["id"] for c in library()}:
        raise ValueError("That id belongs to a built-in control")
    engine, t = _engine(engine), db_module.devsecops_custom_controls
    vals = {"stage": stage, "title": title[:200], "why": why[:600], "how": how[:1500], "keywords_json": json.dumps(kw), "evidence_json": json.dumps(ev) if ev else None,
            "created_by": actor, "created_at": _now()}
    with engine.begin() as conn:
        if conn.execute(update(t).where(t.c.id == control_id).values(**vals)).rowcount == 0:
            conn.execute(insert(t), {"id": control_id, **vals})
    return next(c for c in custom_controls(engine) if c["id"] == control_id)


def delete_custom_control(control_id, engine=None):
    engine, t = _engine(engine), db_module.devsecops_custom_controls
    with engine.begin() as conn:
        n = conn.execute(delete(t).where(t.c.id == control_id)).rowcount
        conn.execute(delete(db_module.devsecops_status).where(db_module.devsecops_status.c.control_id == control_id))
    return bool(n)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- scan runs
def record_scan_run(asset, scan_type, tool, source, findings, actor, engine=None):
    engine, t = _engine(engine), db_module.scan_runs
    with engine.begin() as conn:
        conn.execute(insert(t), {"asset": (asset or "unspecified")[:200], "scan_type": scan_type, "tool": (tool or "")[:120], "source": (source or "")[:120],
                                 "findings": int(findings), "received_at": _now(), "received_by": actor})


def scan_runs(engine=None):
    engine, t = _engine(engine), db_module.scan_runs
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).order_by(t.c.id.desc())).mappings().all()]


# ---------------------------------------------------------------- recorded states
def set_state(asset, control_id, state, note, actor, engine=None):
    if state not in STATES:
        raise ValueError(f"state must be one of {', '.join(STATES)}")
    if control_id not in {c["id"] for c in full_library(engine)}:
        raise KeyError("No such control")
    if not (asset or "").strip():
        raise ValueError("Name the repository or application")
    engine, t = _engine(engine), db_module.devsecops_status
    vals = {"state": state, "note": (note or "")[:500], "set_by": actor, "set_at": _now()}
    with engine.begin() as conn:
        if conn.execute(update(t).where(t.c.asset == asset.strip(), t.c.control_id == control_id).values(**vals)).rowcount == 0:
            conn.execute(insert(t), {"asset": asset.strip(), "control_id": control_id, **vals})


def clear_state(asset, control_id, engine=None):
    engine, t = _engine(engine), db_module.devsecops_status
    with engine.begin() as conn:
        return bool(conn.execute(delete(t).where(t.c.asset == asset, t.c.control_id == control_id)).rowcount)


def states(engine=None):
    engine, t = _engine(engine), db_module.devsecops_status
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t)).mappings().all()]


# ---------------------------------------------------------------- status
def _norm(s):
    return (s or "").strip().lower()


def assets(runs, recorded, findings):
    names = {}
    for n in [r["asset"] for r in runs] + [r["asset"] for r in recorded] + [(f.get("asset") or {}).get("name") for f in findings
                                                                            if (f.get("asset") or {}).get("type") == "code-repository" or f.get("scan_type") == "cicd"]:
        if n:
            names.setdefault(_norm(n), n)
    return sorted(names.values(), key=str.lower)


def control_status(control, asset, runs, recorded, findings, threat_models=0, extras=None):
    ev = control.get("evidence") or {}
    a = _norm(asset)
    mine_runs = [r for r in runs if _norm(r["asset"]) == a]
    rec = next((r for r in recorded if _norm(r["asset"]) == a and r["control_id"] == control["id"]), None)
    status, detail = "not-observable", "Quanta cannot see this control; record its state."
    if "scan_type" in ev:
        hit = next((r for r in mine_runs if r["scan_type"] == ev["scan_type"]), None)
        status, detail = ("evidenced", f"{hit['tool'] or 'A scan'} ran {hit['received_at'][:10]} ({hit['findings']} finding(s))") if hit else ("no-evidence", f"No {ev['scan_type']} scan has been uploaded for this repository.")
    elif "clean_of" in ev:
        bad = [f for f in findings if _norm((f.get("asset") or {}).get("name")) == a and f.get("rule_id") in ev["clean_of"] and f.get("status") not in ("resolved", "closed")]
        checked = next((r for r in mine_runs if r["scan_type"] == "cicd"), None)
        if bad:
            status, detail = "failing", f"{len(bad)} open pipeline finding(s): " + ", ".join(sorted({f['rule_id'] for f in bad}))
        elif checked:
            status, detail = "evidenced", f"Pipeline checked {checked['received_at'][:10]}; none of {', '.join(ev['clean_of'])} found."
        else:
            status, detail = "no-evidence", "The pipeline has not been checked for this repository."
    elif "quanta" in ev:
        extras = extras or {}
        if ev["quanta"] == "threat-models":
            status, detail = ("evidenced", f"{threat_models} threat model(s) exist in Quanta.") if threat_models else ("no-evidence", "No threat model has been created in Quanta.")
        elif ev["quanta"] == "sbom":
            s = (extras.get("sboms") or {}).get(a)
            status, detail = (("evidenced", f"An SBOM ({s['format']}, {s['components']} components) was stored {s['uploaded_at'][:10]}.") if s
                              else ("no-evidence", "No SBOM is stored for this application."))
        elif ev["quanta"] == "gate-runs":
            at = (extras.get("gate_runs") or {}).get(a)
            now = datetime.datetime.now(datetime.timezone.utc)
            recent = bool(at) and (now - datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)).days <= GATE_RECENT_DAYS
            status, detail = (("evidenced", f"The release gate was last evaluated {at[:10]}.") if recent
                              else ("no-evidence", f"The release gate has not been evaluated for this application in the last {GATE_RECENT_DAYS} days."))
    return {"control_id": control["id"], "status": status, "detail": detail,
            "recorded": {"state": rec["state"], "note": rec["note"], "set_by": rec["set_by"], "set_at": rec["set_at"]} if rec else None}


def repo_report(asset, lib, runs, recorded, findings, threat_models=0, extras=None):
    rows = [{**{k: c.get(k) for k in ("id", "stage", "title", "why", "how", "snippets", "owasp_cicd", "ssdf", "custom")}, **control_status(c, asset, runs, recorded, findings, threat_models, extras)}
            for c in lib]
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("evidenced", "failing", "no-evidence", "not-observable")}
    counts["recorded_implemented"] = sum(1 for r in rows if r["status"] in ("no-evidence", "not-observable") and r["recorded"] and r["recorded"]["state"] == "implemented")
    return {"asset": asset, "controls": rows, "counts": counts}


def overview(runs, recorded, findings, threat_models=0, extras=None, lib=None):
    lib = lib if lib is not None else library()
    names = assets(runs, recorded, findings)
    repos = [repo_report(n, lib, runs, recorded, findings, threat_models, extras) for n in names]
    per_control = []
    for c in lib:
        sts = [next(r for r in rp["controls"] if r["id"] == c["id"]) for rp in repos]
        per_control.append({"id": c["id"], "title": c["title"], "stage": c["stage"], "evidenced": sum(s["status"] == "evidenced" for s in sts),
                            "failing": sum(s["status"] == "failing" for s in sts), "no_evidence": sum(s["status"] in ("no-evidence", "not-observable") for s in sts)})
    return {"stages": STAGES, "library": lib, "repos": [{"asset": r["asset"], "counts": r["counts"]} for r in repos], "per_control": per_control,
            "note": "Evidenced and failing are observed from uploaded scans and pipeline checks. Controls Quanta cannot see are shown as not observable until a person records their state."}


# ---------------------------------------------------------------- policy mapping
def split_requirements(text):
    parts = re.split(r"(?:\r?\n)+|(?<=[.;!?])\s+(?=[A-Z0-9\"'(])", text or "")
    out = []
    for p in parts:
        p = re.sub(r"^\s*(?:[-*•]|\d+[.)]|\([a-z0-9]+\))\s*", "", p).strip()
        if len(p) >= 15:
            out.append(p[:400])
    return out[:300]


def map_policy(text, lib=None):
    lib = lib or library()
    matches, unmatched = [], []
    for sentence in split_requirements(text):
        low = sentence.lower()
        hits = [c for c in lib if any(k in low for k in c.get("keywords") or [])]
        if hits:
            matches.append({"requirement": sentence, "controls": [{"id": c["id"], "title": c["title"], "stage": c["stage"]} for c in hits]})
        else:
            unmatched.append(sentence)
    covered = {c["id"] for m in matches for c in m["controls"]}
    return {"matched": matches, "unmatched": unmatched, "controls_referenced": sorted(covered), "controls_not_mentioned": [c["id"] for c in lib if c["id"] not in covered],
            "note": "A match is a keyword hit between a sentence and a control, not an understanding of the sentence. Read the unmatched sentences too."}
