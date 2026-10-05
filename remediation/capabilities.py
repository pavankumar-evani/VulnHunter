"""
The capability catalog and what each capability currently holds.

The catalog (remediation/config/capabilities.yaml) says what Quanta does, grouped into five areas. For each capability this adds a short live status:
how much it holds right now ("14 rules", "3 playbooks"), and whether it is in use yet. A capability with nothing in it is "ready", not "broken":
the page says what to connect or load to give it something to work on. Counting is cheap, and a count that cannot be read is simply omitted.
"""
from pathlib import Path

import yaml
from sqlalchemy import func, select

from remediation.utils import db as db_module

CATALOG_PATH = Path(__file__).resolve().parent / "config" / "capabilities.yaml"


def catalog(path=None):
    with open(path or CATALOG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def _count(engine, table, *where):
    q = select(func.count()).select_from(table)
    for w in where:
        q = q.where(w)
    with engine.connect() as conn:
        return conn.execute(q).scalar() or 0


def _plural(n, one, many=None):
    return f"{n} {one if n == 1 else (many or one + 's')}"


def metrics(findings, engine=None):
    """{capability id: short text} for those that hold something. Anything unreadable is left out."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    t = db_module
    out = {}

    def put(cid, n, text):
        if n:
            out[cid] = text

    def safe(fn):
        try:
            fn()
        except Exception:  # noqa: BLE001 - a status that cannot be read is omitted, never an error on the page
            pass

    n = len(findings)
    kev = sum(1 for f in findings if (f.get("kev") or {}).get("listed"))
    put("queue", n, f"{n:,} findings, {kev} known-exploited")
    safe(lambda: put("remediation", sum(1 for f in findings if f.get("remediation_approval")), f"{sum(1 for f in findings if f.get('remediation_approval'))} with an approval record"))
    safe(lambda: put("compensating", _count(engine, t.asset_controls), _plural(_count(engine, t.asset_controls), "control") + " recorded"))
    safe(lambda: put("attack-paths", sum(1 for f in findings if f.get("attack_techniques")), f"{sum(1 for f in findings if f.get('attack_techniques')):,} findings tagged with ATT&CK techniques"))
    safe(lambda: put("devsecops", _count(engine, t.scan_runs), _plural(_count(engine, t.scan_runs), "scan upload") + " recorded"))
    safe(lambda: put("devsecops-queue", _count(engine, t.remediation_factory), _plural(_count(engine, t.remediation_factory), "finding") + " queued"))
    safe(lambda: put("cyber-risk", _count(engine, t.risk_scenarios), _plural(_count(engine, t.risk_scenarios), "scenario")))
    safe(lambda: put("grc", _count(engine, t.grc_risks), _plural(_count(engine, t.grc_risks), "risk") + " in the register"))
    safe(lambda: put("threat-models", _count(engine, t.threat_models), _plural(_count(engine, t.threat_models), "model")))
    safe(lambda: put("detection", _count(engine, t.detection_rules), _plural(_count(engine, t.detection_rules), "rule") + " in the inventory"))
    safe(lambda: put("hunting", _count(engine, t.hunts), _plural(_count(engine, t.hunts), "hunt")))
    safe(lambda: put("intel", _count(engine, t.threat_intel_reports), _plural(_count(engine, t.threat_intel_reports), "report")))
    safe(lambda: put("ai-security", _count(engine, t.ai_assets), _plural(_count(engine, t.ai_assets), "AI asset") + " recorded"))
    safe(lambda: put("ai-usage", _count(engine, t.ai_usage_events), f"{_count(engine, t.ai_usage_events):,} usage records"))
    safe(lambda: put("triage", _count(engine, t.soc_alerts, t.soc_alerts.c.status != "closed"), _plural(_count(engine, t.soc_alerts, t.soc_alerts.c.status != "closed"), "open alert")))
    safe(lambda: put("soc-cases", _count(engine, t.soc_cases, t.soc_cases.c.status.in_(("new", "in_progress", "pending", "escalated"))), _plural(_count(engine, t.soc_cases, t.soc_cases.c.status.in_(("new", "in_progress", "pending", "escalated"))), "open case")))
    safe(lambda: put("darkweb", _count(engine, t.darkweb_hits, t.darkweb_hits.c.status == "new"), _plural(_count(engine, t.darkweb_hits, t.darkweb_hits.c.status == "new"), "new hit")))
    safe(lambda: put("soar", _count(engine, t.soar_playbooks), _plural(_count(engine, t.soar_playbooks), "playbook")
                     + (f", {_count(engine, t.soar_runs, t.soar_runs.c.status == 'waiting-approval')} waiting for approval" if _count(engine, t.soar_runs, t.soar_runs.c.status == "waiting-approval") else "")))
    def firewall():
        with engine.connect() as conn:
            devices = conn.execute(select(func.count(t.fw_rules.c.device.distinct()))).scalar() or 0
        n_rules = _count(engine, t.fw_rules)
        put("firewall", n_rules, f"{n_rules:,} rules from {_plural(devices, 'firewall')}")

    safe(firewall)
    safe(lambda: put("iam", _count(engine, t.iam_entitlements), f"{_count(engine, t.iam_entitlements):,} entitlements"))
    safe(lambda: put("ownership", _count(engine, t.asset_ownership), _plural(_count(engine, t.asset_ownership), "asset") + " with an owner"))
    safe(lambda: put("support", _count(engine, t.support_tickets, t.support_tickets.c.status != "resolved"), _plural(_count(engine, t.support_tickets, t.support_tickets.c.status != "resolved"), "open ticket")))
    safe(lambda: put("connections", _count(engine, t.connections), _plural(_count(engine, t.connections), "connection")))
    return out


def build(findings, is_admin, engine=None):
    cat = catalog()
    m = metrics(findings, engine)
    out = []
    for dom in cat:
        groups, total, active = [], 0, 0
        for g in dom["groups"]:
            items = []
            for i in g["items"]:
                if i.get("admin") and not is_admin:
                    continue
                items.append({**i, "metric": m.get(i["id"]), "state": "active" if i["id"] in m else "ready"})
            if items:
                total += len(items)
                active += sum(1 for i in items if i["state"] == "active")
                groups.append({"number": g["number"], "title": g["title"], "items": items})
        if groups:
            out.append({"id": dom["id"], "number": dom["number"], "title": dom["title"], "summary": dom["summary"], "groups": groups, "capabilities": total, "in_use": active})
    return out
