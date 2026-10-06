"""
Everything the generators read, gathered once per refresh and passed down (never fetched per item: per-item reads in a loop are slow on a synced working directory).

Generators are pure functions of a `Context`; `load()` is the only part that touches the database. A field left `None` means "Quanta does not hold this data" (the
generator then reports a gap), which is different from an empty list ("held, and nothing in it").
"""
import datetime
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "hunt_engine.yaml"
DEFAULT_CFG = {"industry": None, "max_suggestions": 25, "refresh_minutes": 360, "kev_recent_days": 45, "intel_min_priority": "medium", "material_new_refs": 3,
               "business_hours_utc": [6, 20], "low_and_slow": {"min_alerts": 4, "min_days": 3, "max_severity": "Medium"}, "exposure": {"max_assets": 15},
               "identity": {"max_identities": 15}, "lessons": {"max_per_run": 10}, "learning": {"min_samples": 2, "suppress_after_benign": 3}}
FIELDS = ("findings", "alerts", "rules", "hunts", "intel", "cvd", "darkweb", "entitlements", "roster", "iam_findings", "controls", "ownership", "connections", "usecases")


def config(path=None):
    try:
        with open(path or CONFIG_PATH, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
    except OSError:
        loaded = {}
    out = {**DEFAULT_CFG, **loaded}
    for k in ("low_and_slow", "exposure", "identity", "lessons", "learning"):
        out[k] = {**DEFAULT_CFG[k], **(loaded.get(k) or {})}
    return out


class Context:
    def __init__(self, now=None, cfg=None, stats=None, **kw):
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.cfg = cfg or config()
        self.stats = stats or {}
        for f in FIELDS:
            setattr(self, f, kw.pop(f, None))
        if kw:
            raise TypeError(f"Unknown context fields: {', '.join(sorted(kw))}")
        self.industry = self.cfg.get("industry")

    # helpers every generator uses
    def open_findings(self):
        return [f for f in self.findings or [] if not (f.get("status") in ("resolved", "closed") or (f.get("exception") or {}).get("active"))]

    def days_since(self, date_text):
        """Whole days from an ISO date or timestamp to now, or None when it cannot be read."""
        try:
            d = datetime.datetime.fromisoformat(str(date_text).replace("Z", "+00:00")[:25])
        except (TypeError, ValueError):
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return max(0, (self.now - d).days)

    def facing(self, asset):
        return ((self.ownership or {}).get(asset) or {}).get("facing") or "unknown"

    def team(self, asset):
        return ((self.ownership or {}).get(asset) or {}).get("team")


def load(findings, engine=None, now=None, cfg=None):
    """Reads the stores a refresh needs. `findings` is the live queue (passed in so this module does not depend on the dashboard)."""
    from remediation.connections import store as conn_store
    from remediation.controls import store as controls_store
    from remediation.cvd import store as cvd_store
    from remediation.darkweb import watch as darkweb
    from remediation.hunting import detection, service as hunt_service, store as hunt_store, usecase_store
    from remediation.iam import model as iam_model, store as iam_store
    from remediation.inventory import asset_inventory
    from remediation.utils import db as db_module

    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    cfg = cfg or config()
    ent = iam_store.entitlements(engine)
    roster = iam_store.roster(engine)
    try:
        advisories = cvd_store.list_advisories(engine)
        cvd = [m for m in cvd_store.summary(advisories, findings).get("matches", [])] if advisories else []
    except Exception:  # noqa: BLE001 - an unreadable feed is a gap, never a failed refresh
        cvd = None
    return Context(now=now, cfg=cfg, findings=findings, alerts=hunt_store.list_alerts(engine), rules=detection.list_rules(engine), hunts=hunt_store.list_hunts(engine),
                   intel=hunt_service.list_intel(engine), cvd=cvd, darkweb=darkweb.list_hits(engine), entitlements=ent, roster=roster,
                   iam_findings=iam_model.analyse(ent, roster) if ent else [], controls=controls_store.list_controls(engine=engine),
                   ownership=asset_inventory.load_ownership(engine), connections=conn_store.list_connections(engine), usecases=usecase_store.list_all(engine))
