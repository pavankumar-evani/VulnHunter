"""
The controls inventory: which security controls actually protect which assets.

Compensating-control advice is only as specific as this data. It is filled three ways:
  * a connector or script pushes what it observes (`POST /api/ingest/controls` with a `controls:write` key) -> state "verified";
  * a person records one on the Controls page, or imports a CSV -> state "claimed";
  * the older firewall-and-EDR file (remediation/config/security_controls.yaml) is read as "claimed" entries, so nothing already
    recorded there is lost.

An entry applies to one asset name or to a glob such as `WEB-*` (one rule for a whole tier). `control_class` comes from a fixed
vocabulary (attack_mitigations.yaml) so the advice can check for it; `name` says what the control is in the client's own words
("Palo Alto edge firewall", "CrowdStrike Falcon, prevention on"). Re-sending the same (asset, class, name) refreshes `last_seen`
rather than adding a duplicate.
"""
import datetime
import fnmatch
import re
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module

MITIGATIONS_PATH = Path(__file__).resolve().parent.parent / "enrichment" / "attack_mitigations.yaml"
STATES = ("verified", "claimed")
_ASSET_RE = re.compile(r"^[\w.*?\[\]-]{1,120}$")


def control_classes():
    return yaml.safe_load(MITIGATIONS_PATH.read_text(encoding="utf-8"))["control_classes"]


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def validate(asset_name, control_class, name, state):
    if not _ASSET_RE.match(asset_name or ""):
        raise ValueError("asset_name must be 1 to 120 characters: letters, digits, dots, dashes, and * ? for patterns")
    if control_class not in control_classes():
        raise ValueError(f"control_class must be one of: {', '.join(control_classes())}")
    if not (name or "").strip() or len(name) > 160:
        raise ValueError("name is required (160 characters at most)")
    if state not in STATES:
        raise ValueError("state must be verified or claimed")


def upsert(asset_name, control_class, name, state, source, actor, detail=None, engine=None, now=None):
    """Adds the control, or refreshes it (last_seen, state, detail) when the same one is already recorded. A verified entry is
    never downgraded to claimed by a person re-typing it."""
    asset_name, name = (asset_name or "").strip(), (name or "").strip()
    validate(asset_name, control_class, name, state)
    engine, t, stamp = _engine(engine), db_module.asset_controls, _now(now)
    with engine.begin() as conn:
        row = conn.execute(select(t).where(t.c.asset_name == asset_name, t.c.control_class == control_class, t.c.name == name)).mappings().first()
        if row:
            keep_verified = row["state"] == "verified" and state == "claimed"
            conn.execute(update(t).where(t.c.id == row["id"]).values(
                last_seen=stamp, state="verified" if keep_verified else state, detail=detail if detail is not None else row["detail"]))
            return get(row["id"], engine)
        new_id = conn.execute(insert(t), {"asset_name": asset_name, "control_class": control_class, "name": name, "state": state,
                                          "source": (source or "manual")[:80], "detail": detail, "last_seen": stamp,
                                          "created_by": actor, "created_at": stamp}).inserted_primary_key[0]
    return get(new_id, engine)


def get(control_id, engine=None):
    engine = _engine(engine)
    with engine.connect() as conn:
        row = conn.execute(select(db_module.asset_controls).where(db_module.asset_controls.c.id == int(control_id))).mappings().first()
    return dict(row) if row else None


def delete_control(control_id, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        return conn.execute(delete(db_module.asset_controls).where(db_module.asset_controls.c.id == int(control_id))).rowcount == 1


def list_controls(asset=None, engine=None):
    engine = _engine(engine)
    t = db_module.asset_controls
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(select(t).order_by(t.c.asset_name, t.c.control_class, t.c.id)).mappings().all()]
    if asset:
        rows = [r for r in rows if fnmatch.fnmatchcase(asset.lower(), r["asset_name"].lower())]
    return rows


def legacy_controls(asset_name):
    """Entries implied by security_controls.yaml (firewall rules and EDR policy), as claimed controls."""
    try:
        from remediation.enrichment import control_coverage
        entry = control_coverage.find_asset_controls(asset_name)
    except Exception:  # noqa: BLE001 - an unreadable legacy file must not break advice
        return []
    if not entry:
        return []
    out = []
    if any(str(r.get("action", "")).lower() == "deny" for r in entry.get("firewall_rules") or []):
        out.append({"asset_name": asset_name, "control_class": "network-filtering", "name": "Firewall deny rules (security_controls.yaml)",
                    "state": "claimed", "source": "security_controls.yaml"})
    edr = entry.get("edr") or {}
    if edr.get("mode") in ("block", "detect"):
        out.append({"asset_name": asset_name, "control_class": "edr", "name": f"EDR in {edr['mode']} mode (security_controls.yaml)",
                    "state": "claimed", "source": "security_controls.yaml"})
    return out


def for_asset(asset_name, engine=None):
    """Every control that applies to the asset: exact or glob entries, plus the legacy file's."""
    if not asset_name:
        return []
    return list_controls(asset_name, engine) + legacy_controls(asset_name)


def import_csv(text, actor, engine=None):
    """CSV with columns asset_name, control_class, name, state (optional, default claimed), detail (optional). Returns
    (added_or_refreshed, errors[{line, error}]); a bad row never blocks the others."""
    import csv
    import io
    done, errors = 0, []
    reader = csv.DictReader(io.StringIO(text))
    for i, row in enumerate(reader, 2):
        try:
            upsert(row.get("asset_name") or row.get("asset"), (row.get("control_class") or row.get("class") or "").strip(), row.get("name"),
                   (row.get("state") or "claimed").strip().lower(), "csv-import", actor, detail=row.get("detail") or None, engine=engine)
            done += 1
        except ValueError as exc:
            errors.append({"line": i, "error": str(exc)})
        if i > 5002:
            errors.append({"line": i, "error": "More than 5000 rows; split the file."})
            break
    return done, errors
