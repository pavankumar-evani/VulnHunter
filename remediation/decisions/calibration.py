"""
Calibration: is a stated probability true as often as it says?

Each decision's answers are logged (table decision_log: decision, question, value, probability, route and an opaque reference; no text, no prompt, no
person) and later the human outcome is recorded: "accepted" (the person agreed with the answer) or "overridden". From the judged rows this module
computes reliability bins, the Brier score, the expected calibration error (ECE) and the override rate, per decision and per confidence band.

Honesty rules: with fewer judged outcomes than `calibration.min_outcomes` (decision_policy.yaml) it reports "not-enough-outcomes" and no figure, never a
claim of calibration; a band with fewer than `min_band_outcomes` shows counts only. Suggested threshold changes are recommendations for a person to
apply; this module never edits the policy.

  Brier = mean((p - y)^2)  where p is the probability of the chosen value and y is 1 when accepted, else 0.
  ECE   = sum over bins of (n_bin / n) * |accuracy_bin - mean_p_bin|.
"""
import datetime
import re

from sqlalchemy import insert, select, update

from remediation.decisions import gate as gate_mod
from remediation.decisions import registry, schema
from remediation.utils import db as db_module

OUTCOMES = ("accepted", "overridden")
REF = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def record(decision, answers, route, ref=None, model_calls_avoided=0, engine=None, now=None):
    """Logs one row per answered question. Returns the row ids. `ref` is an opaque identifier (letters, digits, . : _ -), never free text."""
    if ref is not None and not REF.match(str(ref)):
        raise schema.SchemaViolation("ref must be a short identifier (letters, digits, . : _ -), not text")
    if route not in gate_mod.ROUTES:
        raise schema.SchemaViolation(f"route must be one of {', '.join(gate_mod.ROUTES)}")
    engine, t, ids = _engine(engine), db_module.decision_log, []
    with engine.begin() as conn:
        for q, a in answers.items():
            res = conn.execute(insert(t), {"decision": decision.name, "question": q, "ref": ref, "logged_at": now or _now(), "value": str(a.value),
                                           "probability": a.probability, "confidence": a.confidence, "route": route, "evaluator": a.evaluator[:64],
                                           "version": a.version[:16], "model_calls_avoided": int(model_calls_avoided) if not ids else 0})
            ids.append(res.inserted_primary_key[0])
    return ids


def record_outcome(log_id, outcome, outcome_value=None, engine=None, now=None):
    """Records what the person did with one logged answer. Returns True when a row was updated (an already-judged row is left alone)."""
    if outcome not in OUTCOMES:
        raise schema.SchemaViolation(f"outcome must be one of {', '.join(OUTCOMES)}")
    engine, t = _engine(engine), db_module.decision_log
    with engine.begin() as conn:
        row = conn.execute(select(t).where(t.c.id == log_id)).first()
        if row is None:
            raise KeyError("No such decision log entry")
        if outcome_value is not None:
            registry.get(row.decision).question(row.question).check(outcome_value)
        if row.outcome:
            return False
        conn.execute(update(t).where(t.c.id == log_id, t.c.outcome.is_(None)).values(outcome=outcome, outcome_value=outcome_value, outcome_at=now or _now()))
    return True


def record_outcome_for_ref(decision_name, ref, outcome, question=None, outcome_value=None, engine=None, now=None):
    """Judges every not-yet-judged row for (decision, ref[, question]). Returns how many rows were updated."""
    engine, t = _engine(engine), db_module.decision_log
    q = select(t.c.id).where(t.c.decision == decision_name, t.c.ref == ref, t.c.outcome.is_(None))
    if question:
        q = q.where(t.c.question == question)
    with engine.connect() as conn:
        ids = [r.id for r in conn.execute(q)]
    return sum(bool(record_outcome(i, outcome, outcome_value if question else None, engine, now)) for i in ids)


def rows(engine=None):
    engine, t = _engine(engine), db_module.decision_log
    with engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(select(t))]


# ---------------------------------------------------------------- the math (pure)

def brier(pairs):
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def reliability(pairs, bins):
    """Equal-width bins over [0, 1] (the top bin includes 1.0). Empty bins are omitted. Returns (bins list, ECE)."""
    n, out, ece = len(pairs), [], 0.0
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        members = [(p, y) for p, y in pairs if lo <= p < hi or (i == bins - 1 and p == 1.0)]
        if not members:
            continue
        mp, acc = sum(p for p, _ in members) / len(members), sum(y for _, y in members) / len(members)
        ece += len(members) / n * abs(acc - mp)
        out.append({"low": round(lo, 4), "high": round(hi, 4), "n": len(members), "mean_probability": round(mp, 4), "accuracy": round(acc, 4), "gap": round(acc - mp, 4)})
    return out, ece


def _band(p, thresholds):
    return "auto" if p >= thresholds["auto"] else "review" if p >= thresholds["review"] else "human"


def summarise(logged, policy=None):
    """The calibration report for a list of logged rows. Pure: no database."""
    policy = policy or gate_mod.load_policy()
    cal = policy.get("calibration") or {}
    min_n, min_band, nbins = int(cal.get("min_outcomes", 30)), int(cal.get("min_band_outcomes", 10)), int(cal.get("bins", 5))
    max_override, ece_warn = float(cal.get("max_override_rate_auto_band", 0.05)), float(cal.get("ece_warn", 0.10))
    names = sorted({r["decision"] for r in logged} | set((policy.get("decisions") or {})))
    out = {}
    for name in names:
        mine = [r for r in logged if r["decision"] == name]
        judged = [r for r in mine if r["outcome"] in OUTCOMES]
        dpol = (policy.get("decisions") or {}).get(name) or {}
        d = {"logged": len(mine), "judged": len(judged), "model_calls_avoided": sum(r.get("model_calls_avoided") or 0 for r in mine),
             "routes": {k: sum(r["route"] == k for r in mine) for k in gate_mod.ROUTES}, "thresholds": dpol.get("thresholds"), "recommendations": []}
        if len(judged) < min_n:
            d.update(status="not-enough-outcomes", message=f"{len(judged)} judged outcome(s); at least {min_n} are needed before anything is reported as calibrated.", needed=min_n)
            out[name] = d
            continue
        pairs = [(float(r["probability"]), 1 if r["outcome"] == "accepted" else 0) for r in judged]
        bins, ece = reliability(pairs, nbins)
        d.update(status="measured", brier=round(brier(pairs), 4), ece=round(ece, 4), calibrated=ece <= ece_warn, bins=bins,
                 override_rate=round(sum(1 for _, y in pairs if not y) / len(pairs), 4))
        th = dpol.get("thresholds")
        if th:
            bands = {}
            for b in ("auto", "review", "human"):
                mem = [(p, y) for p, y in pairs if _band(p, th) == b]
                if len(mem) >= min_band:
                    bands[b] = {"n": len(mem), "override_rate": round(sum(1 for _, y in mem if not y) / len(mem), 4)}
                else:
                    bands[b] = {"n": len(mem), "override_rate": None, "note": "not enough outcomes in this band"}
            d["bands"] = bands
            d["recommendations"] = _recommend(name, d, bands, th, pairs, min_band, max_override, ece_warn, dpol)
        out[name] = d
    total = sum(v["judged"] for v in out.values())
    return {"decisions": out, "model_calls_avoided": sum(v["model_calls_avoided"] for v in out.values()), "judged_total": total,
            "min_outcomes": min_n, "note": "Probabilities are shown as calibrated only for a decision with enough judged outcomes and an ECE within the limit. Recommendations are advice and are never applied automatically."}


def _recommend(name, d, bands, th, pairs, min_band, max_override, ece_warn, dpol):
    rec = []
    eligible = dpol.get("reversible") is True and dpol.get("local") is True and not registry.DECISIONS[name].touches_environment if name in registry.DECISIONS else False
    if d["ece"] > ece_warn:
        rec.append({"kind": "do-not-trust-probabilities", "message": f"ECE is {d['ece']}, above {ece_warn}: the stated probabilities do not match how often people agreed. Do not raise any threshold; tune the evaluator's weights first."})
    auto = bands["auto"]
    if auto["override_rate"] is not None and auto["override_rate"] > max_override:
        # the lowest threshold above the current one at which the over-threshold override rate falls to the limit, from the data
        for cand in sorted({round(p, 2) for p, _ in pairs if p > th["auto"]}):
            mem = [(p, y) for p, y in pairs if p >= cand]
            if len(mem) >= min_band and sum(1 for _, y in mem if not y) / len(mem) <= max_override:
                rec.append({"kind": "raise-auto-threshold", "to": cand, "message": f"People overrode {round(100 * auto['override_rate'])}% of answers at or above the auto threshold {th['auto']}, over the {round(100 * max_override)}% limit. At {cand} the override rate would have been within it."})
                break
        else:
            rec.append({"kind": "raise-auto-threshold", "to": None, "message": f"People overrode {round(100 * auto['override_rate'])}% of answers at or above the auto threshold {th['auto']}, and no higher threshold in the data brings that within {round(100 * max_override)}%. Keep this decision at review."})
    elif eligible and auto["override_rate"] is None and bands["review"]["override_rate"] is not None and bands["review"]["override_rate"] <= max_override:
        rec.append({"kind": "consider-lowering-auto-threshold", "message": f"Answers in the review band ({th['review']} to {th['auto']}) were overridden only {round(100 * bands['review']['override_rate'])}% of the time over {bands['review']['n']} outcomes. The auto threshold could be lowered, for a person to decide; it stays inside the reversible-and-local rule."})
    if not eligible:
        rec.append({"kind": "info", "message": "This decision can never be routed auto (it is not reversible and local, or it touches a customer environment), so there is no auto threshold to tune."})
    return rec


def report(engine=None, policy=None):
    return summarise(rows(engine), policy)
