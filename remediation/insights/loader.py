"""
Builds the detectors' snapshot from the stored data. Read-only. A source that cannot be read becomes None (so the detectors that need it report a gap)
rather than an empty list (which would read as "nothing happened"). Findings and assets come from the caller because the scored queue is built by the
dashboard layer; everything else is read straight from the database.
"""
from pathlib import Path

import yaml
from sqlalchemy import select

from remediation.insights.model import now_utc
from remediation.utils import db as db_module

GRC_TESTS_PATH = Path(__file__).resolve().parent.parent / "config" / "grc_tests.yaml"
ROW_LIMIT = 20000


def _rows(engine, table, order=None, limit=ROW_LIMIT, drop=()):
    try:
        q = select(table)
        if order is not None:
            q = q.order_by(order.desc())
        with engine.connect() as conn:
            return [{k: v for k, v in dict(r).items() if k not in drop} for r in conn.execute(q.limit(limit)).mappings().all()]
    except Exception:  # noqa: BLE001 - an unreadable source is a gap, not a crash
        return None


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


def load(engine=None, findings=None, assets=None, now=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    t = db_module
    from remediation.exceptions import store as exc_store
    from remediation.licensing import license as lic
    from remediation.remediation_approvals import store as appr_store

    mappings = _safe(lambda: (yaml.safe_load(GRC_TESTS_PATH.read_text(encoding="utf-8")) or {}).get("mappings") or {})
    return {
        "now": now or now_utc(),
        "findings": findings, "assets": assets,
        "exceptions": _safe(lambda: exc_store.list_exceptions_with_status(engine=engine)),
        "approvals": _safe(lambda: appr_store.list_approvals_with_status(engine=engine)),
        "activity": _rows(engine, t.activity_log, t.activity_log.c.id, 3000),
        "alerts": _rows(engine, t.soc_alerts, t.soc_alerts.c.id),
        "hunts": _rows(engine, t.hunts, t.hunts.c.id, 2000),
        "cases": _rows(engine, t.soc_cases, t.soc_cases.c.id, 2000),
        "connections": _rows(engine, t.connections, drop=("secrets_blob", "config")),
        "api_keys": _rows(engine, t.api_keys, drop=("key_hash",)),
        "ai_events": _rows(engine, t.ai_usage_events, t.ai_usage_events.c.id),
        "grc_evidence": _rows(engine, t.grc_evidence, t.grc_evidence.c.id),
        "grc_mappings": mappings,
        "controls": _rows(engine, t.asset_controls),
        "license": _safe(lic.status),
        "baseline": None,
    }
