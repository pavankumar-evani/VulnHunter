"""
The risk register.

A risk is a statement of what could go wrong, who owns it, how bad it is before and after controls, and what is being done about it. Quanta
fills the register from what it already knows rather than from blank forms: a threat from a threat model (`source: threat`), a cluster of
known-exploited findings past their deadline (`source: finding`), or a risk exception (`source: exception`). People add and edit risks
directly too.

Scoring is the plain likelihood x impact grid, 1 to 5 each: 15+ Critical, 10+ High, 5+ Medium, else Low. A risk is accepted only with a
reason and a review date, and the register shows which are overdue for review.
"""
import datetime

from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module

STATUSES = ("identified", "assessed", "treating", "accepted", "closed")
TREATMENTS = ("mitigate", "accept", "transfer", "avoid")
SOURCES = ("manual", "threat", "finding", "exception")


def level(score):
    return "Critical" if score >= 15 else "High" if score >= 10 else "Medium" if score >= 5 else "Low"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _grid(v, name):
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number from 1 to 5") from None
    if not 1 <= n <= 5:
        raise ValueError(f"{name} must be a whole number from 1 to 5")
    return n


def _date(v, name):
    if v in (None, ""):
        return None
    try:
        return datetime.date.fromisoformat(str(v)[:10]).isoformat()
    except ValueError:
        raise ValueError(f"{name} must be a date like 2026-12-31") from None


def _clean(data, partial=False):
    out = {}
    if "title" in data or not partial:
        title = (data.get("title") or "").strip()
        if not title or len(title) > 200:
            raise ValueError("A title of 1 to 200 characters is required")
        out["title"] = title
    for k in ("inherent_likelihood", "inherent_impact"):
        if k in data or not partial:
            out[k] = _grid(data.get(k), k)
    for k in ("residual_likelihood", "residual_impact"):
        if data.get(k) not in (None, ""):
            out[k] = _grid(data[k], k)
        elif k in data:
            out[k] = None
    if "status" in data or not partial:
        s = data.get("status") or "identified"
        if s not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        out["status"] = s
    if data.get("treatment") not in (None, ""):
        if data["treatment"] not in TREATMENTS:
            raise ValueError(f"treatment must be one of {', '.join(TREATMENTS)}")
        out["treatment"] = data["treatment"]
    for k in ("description", "category", "owner", "treatment_plan"):
        if k in data:
            out[k] = (data[k] or "")[:4000] or None
    for k in ("due_date", "review_date"):
        if k in data:
            out[k] = _date(data[k], k)
    if out.get("status") == "accepted" or out.get("treatment") == "accept":
        if not (data.get("treatment_plan") or "").strip() or not data.get("review_date"):
            raise ValueError("Accepting a risk needs the reason (in the treatment plan) and a review date")
    return out


def create(data, actor, source="manual", source_ref=None, engine=None):
    if source not in SOURCES:
        raise ValueError(f"source must be one of {', '.join(SOURCES)}")
    row = _clean(data)
    engine, t, stamp = _engine(engine), db_module.grc_risks, _now()
    with engine.begin() as conn:
        if source_ref and conn.execute(select(t.c.id).where(t.c.source == source, t.c.source_ref == source_ref, t.c.status != "closed")).first():
            raise ValueError("This risk is already in the register")
        rid = conn.execute(insert(t), {**{"description": None, "category": None, "owner": None, "residual_likelihood": None, "residual_impact": None,
                                          "treatment": None, "treatment_plan": None, "due_date": None, "review_date": None}, **row,
                                       "source": source, "source_ref": source_ref, "created_by": actor, "created_at": stamp, "updated_at": stamp}).inserted_primary_key[0]
    return get(rid, engine)


def get(risk_id, engine=None):
    engine, t = _engine(engine), db_module.grc_risks
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(risk_id))).mappings().first()
    return _view(dict(r)) if r else None


def _view(r, today=None):
    today = today or datetime.date.today().isoformat()
    r["inherent_score"] = r["inherent_likelihood"] * r["inherent_impact"]
    r["inherent_level"] = level(r["inherent_score"])
    if r["residual_likelihood"] and r["residual_impact"]:
        r["residual_score"] = r["residual_likelihood"] * r["residual_impact"]
        r["residual_level"] = level(r["residual_score"])
    else:
        r["residual_score"], r["residual_level"] = None, None
    r["review_overdue"] = bool(r["review_date"] and r["review_date"] < today and r["status"] != "closed")
    r["treatment_overdue"] = bool(r["due_date"] and r["due_date"] < today and r["status"] not in ("closed", "accepted"))
    return r


def list_risks(engine=None, include_closed=True):
    engine, t = _engine(engine), db_module.grc_risks
    with engine.connect() as conn:
        rows = [_view(dict(r)) for r in conn.execute(select(t).order_by(t.c.id)).mappings().all()]
    if not include_closed:
        rows = [r for r in rows if r["status"] != "closed"]
    rows.sort(key=lambda r: (r["status"] == "closed", -(r["residual_score"] or r["inherent_score"]), r["id"]))
    return rows


def update_risk(risk_id, data, engine=None):
    current = get(risk_id, engine)
    if not current:
        raise KeyError("No such risk")
    merged = {**{k: current[k] for k in ("treatment_plan", "review_date", "status", "treatment")}, **data}
    values = _clean(merged, partial=True)
    values = {k: v for k, v in values.items() if k in data or k in ("status", "treatment")}
    values["updated_at"] = _now()
    engine, t = _engine(engine), db_module.grc_risks
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(risk_id)).values(**values))
    return get(risk_id, engine)


def delete_risk(risk_id, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        return conn.execute(delete(db_module.grc_risks).where(db_module.grc_risks.c.id == int(risk_id))).rowcount == 1


def summary(risks):
    live = [r for r in risks if r["status"] != "closed"]
    return {"total": len(live), "by_level": {lv: sum(1 for r in live if (r["residual_level"] or r["inherent_level"]) == lv) for lv in ("Critical", "High", "Medium", "Low")},
            "review_overdue": sum(1 for r in live if r["review_overdue"]), "treatment_overdue": sum(1 for r in live if r["treatment_overdue"]),
            "no_owner": sum(1 for r in live if not r["owner"]), "accepted": sum(1 for r in live if r["status"] == "accepted")}


def suggestions(findings, threat_analyses=(), existing=None):
    """Risks worth registering, drawn from live data and threat models, that are not in the register yet."""
    existing = existing if existing is not None else list_risks()
    have = {(r["source"], r["source_ref"]) for r in existing if r["status"] != "closed"}
    out = []
    kev_overdue = [f for f in findings if (f.get("kev") or {}).get("listed") and (f.get("sla") or {}).get("breached")]
    if kev_overdue and ("finding", "kev-overdue") not in have:
        assets = sorted({(f.get("asset") or {}).get("name") for f in kev_overdue if (f.get("asset") or {}).get("name")})
        out.append({"source": "finding", "source_ref": "kev-overdue", "title": "Known-exploited vulnerabilities remain unpatched past their deadline",
                    "description": f"{len(kev_overdue)} finding(s) on {len(assets)} asset(s) are on the CISA Known Exploited Vulnerabilities list and past their SLA. "
                                   f"Examples: {', '.join(f['id'] for f in kev_overdue[:5])}.",
                    "category": "Vulnerability management", "inherent_likelihood": 5, "inherent_impact": 4})
    for a in threat_analyses:
        for t in a["threats"]:
            ref = f"{a['id']}:{t['key']}"
            if t["residual_score"] >= 10 and t["review"]["status"] == "open" and ("threat", ref) not in have:
                out.append({"source": "threat", "source_ref": ref, "title": f"{t['title']}: {t['element']['name']}", "description": t["description"],
                            "category": f"Threat model: {a['name']}", "inherent_likelihood": t["likelihood"], "inherent_impact": t["impact"]})
    return out
