"""The numbers on the attack-surface page, in one place so the page, the API and the capabilities catalog agree. Always carries the age of the data."""
import datetime

from remediation.asm import findings as asm_findings, store


def build(engine=None, queue_findings=None, days=7, now=None):
    engine = store._engine(engine)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    assets = store.all_assets(engine)
    scope = store.get_scope(engine)
    known = asm_findings.known_assets(queue_findings or [], store.ownership(engine))
    res = asm_findings.evaluate(assets, known, now=now)
    live = [a for a in assets if a["in_scope"] and a["status"] == "active"]
    by_kind = {k: sum(1 for a in live if a["kind"] == k) for k in store.KINDS}
    ch = store.list_changes(engine, days=days, now=now, in_scope=True, limit=5000)
    by_change = {c: sum(1 for x in ch if x["change"] == c) for c in ("new", "changed", "disappeared", "reappeared")}
    by_rule, by_sev = {}, {}
    for f in res["findings"]:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    age = store.data_age(engine, now)
    return {"assets": {"total": len(live), "by_kind": by_kind, "out_of_scope": sum(1 for a in assets if not a["in_scope"] and a["status"] == "active"),
                       "gone": sum(1 for a in assets if a["status"] == "gone")},
            "period_days": days, "changes": {"new": by_change["new"] + by_change["reappeared"], "changed": by_change["changed"], "disappeared": by_change["disappeared"]},
            "exposed_risky_services": by_rule.get("ASM-PORT", 0), "shadow_assets": by_rule.get("ASM-SHADOW", 0), "findings": {"total": len(res["findings"]), "by_rule": by_rule, "by_severity": by_sev},
            "gaps": res["gaps"], "capped": res["capped"], "skipped_info": res["skipped_info"], "data_age": age, "scope": {"declared": bool(scope["domains"] or scope["cidrs"]), "domains": len(scope["domains"]),
                                                                                                                     "cidrs": len(scope["cidrs"])},
            "stale": age["stale"], "note": "Built from imported tool output only. Quanta did not scan and cannot see anything that was not imported."}
