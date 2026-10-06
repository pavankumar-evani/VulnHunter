"""
Migration 7's data step: every existing soc_case that has no incident gets one, so nothing that is open (or recently closed) disappears from the new view.

The case stays exactly as it is and becomes the incident's work item (case_id); the incident mirrors its status, tier, owner and alerts. Idempotent: a case that
already has an incident is skipped, so running it twice (or on a database that already has incidents) changes nothing. Expand-only: nothing is dropped or rewritten.
"""
import json

from sqlalchemy import insert, select

from remediation.utils import db as db_module

STATUS = {"new": "new", "escalated": "new", "in_progress": "investigating", "pending": "investigating", "resolved": "resolved", "closed": "resolved"}


def backfill(engine):
    t, it, ia = db_module.soc_cases, db_module.soc_incidents, db_module.soc_incident_alerts
    made = 0
    with engine.begin() as conn:
        have = {r[0] for r in conn.execute(select(it.c.case_id).where(it.c.case_id.isnot(None)))}
        for c in conn.execute(select(t).order_by(t.c.id)).mappings().all():
            if c["id"] in have:
                continue
            assets = json.loads(c["assets_json"] or "[]")
            ents = json.loads(c["entities_json"] or "{}")
            iid = conn.execute(insert(it), {
                "title": c["title"], "severity": c["severity"], "base_severity": c["severity"], "priority": c["priority"], "tier": c["tier"], "queue": f"L{c['tier']}",
                "status": STATUS.get(c["status"], "new"), "assignee": c["assignee"], "verdict": c["resolution"] if c["status"] in ("resolved", "closed") else None,
                "summary": c["summary"], "routing_reason_json": json.dumps([f"Migrated from case {c['id']}; it was routed before incidents existed, so no routing reasons were recorded."]),
                "correlation_json": "[]", "kill_chain_json": "[]",
                "entities_json": json.dumps({"hosts": [a.lower() for a in assets], "users": [ents["user"].lower()] if ents.get("user") else [], "indicators": []}),
                "assets_json": json.dumps(assets), "techniques_json": c["techniques_json"] or "[]", "cves_json": "[]", "case_id": c["id"], "source": "migrated",
                "escalation_count": c["escalation_count"], "created_at": c["created_at"], "updated_at": c["updated_at"], "last_alert_at": c["created_at"],
                "assigned_at": c["acknowledged_at"], "resolved_at": c["resolved_at"]}).inserted_primary_key[0]
            conn.execute(insert(db_module.soc_incident_events), {"incident_id": iid, "kind": "created", "actor": "migration", "body": f"Created from case {c['id']} when incidents were introduced",
                                                                 "data_json": json.dumps({"case_id": c["id"]}), "created_at": c["created_at"]})
            first = True
            for (aid,) in conn.execute(select(db_module.soc_case_alerts.c.alert_id).where(db_module.soc_case_alerts.c.case_id == c["id"]).order_by(db_module.soc_case_alerts.c.id)).all():
                if conn.execute(select(ia.c.id).where(ia.c.alert_id == aid)).first():
                    continue
                conn.execute(insert(ia), {"incident_id": iid, "alert_id": aid, "role": "primary" if first else "correlated", "reasons_json": "[]", "facts_json": "{}",
                                          "linked_at": c["created_at"]})
                first = False
            made += 1
    return made
