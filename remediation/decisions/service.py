"""Glue: evaluate a decision (dry), and the two hooks existing code uses to log a SOC verdict and later record the analyst's disposition."""
from remediation.decisions import calibration, gate, registry, router, schema

# What an analyst's disposition means for a verdict the layer recommended. "escalate-l2" is a hand-off, not a claim, so it is never judged.
_DISPOSITION_VERDICT = {"true-positive": "likely-true-positive", "false-positive": "likely-false-positive", "benign": "likely-false-positive"}


def evaluate(decision_name, state, evaluator=None, policy=None, purpose="decide"):
    """Evaluates one decision without side effects. Returns {decision, answers[], gate, router}. `evaluator` is any schema.Evaluator."""
    decision = registry.get(decision_name)
    policy = policy or gate.load_policy()
    answers = schema.run(decision, evaluator or registry.default_evaluator(decision_name, policy), state or {})
    g = gate.gate(decision, answers, state, policy)
    r = router.needs_generated_text(answers, g["route"], purpose)
    return {"decision": decision.name, "title": decision.title, "answers": [a.to_dict() for a in answers.values()], "gate": g, "router": r,
            "_answers": answers}


def public(result):
    return {k: v for k, v in result.items() if not k.startswith("_")}


def log_soc_verdict(alert, inv, engine=None, policy=None):
    """Logs the triage verdict of one finished investigation (counts only). Returns the log ids; never raises into the caller."""
    try:
        res = evaluate("soc-alert-triage", {"signals": inv["signals"], "severity": alert.get("severity")}, policy=policy)
        avoided = 0 if res["router"]["needs_model"] else 1
        return calibration.record(registry.get("soc-alert-triage"), res["_answers"], res["gate"]["route"], ref=f"alert:{alert['id']}", model_calls_avoided=avoided, engine=engine)
    except Exception:  # noqa: BLE001 - logging a decision must never break the investigation
        return []


def judge_soc_disposition(alert_id, disposition, engine=None):
    """When an analyst sets a disposition, judges the logged verdict: accepted when it agrees, overridden when it does not. An escalate verdict is not judged."""
    mapped = _DISPOSITION_VERDICT.get(disposition)
    if not mapped:
        return 0
    try:
        t = calibration.db_module.decision_log
        eng = calibration._engine(engine)
        from sqlalchemy import select
        with eng.connect() as conn:
            row = conn.execute(select(t).where(t.c.decision == "soc-alert-triage", t.c.ref == f"alert:{alert_id}", t.c.outcome.is_(None)).order_by(t.c.id.desc())).first()
        if row is None or row.value == "escalate-l2":
            return 0
        return calibration.record_outcome_for_ref("soc-alert-triage", f"alert:{alert_id}", "accepted" if row.value == mapped else "overridden",
                                                  question="verdict", outcome_value=mapped, engine=eng)
    except Exception:  # noqa: BLE001
        return 0
