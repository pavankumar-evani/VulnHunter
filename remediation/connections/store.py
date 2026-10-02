"""
Stored connector connections: one row per configured source, credentials encrypted.

Non-secret settings (URLs, usernames) are plain JSON; every secret field is encrypted
together as one blob (remediation/connections/crypto.py). The public view of a connection
never contains a secret, only the *names* of the secret fields that are set, so the UI can
show "password: set" and let an admin replace it. Leaving a secret blank when editing keeps
the stored one.
"""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.audit.activity_log import record_activity
from remediation.connections import crypto, registry
from remediation.utils import db as db_module

MIN_SCHEDULE_MINUTES = 15
MAX_SCHEDULE_MINUTES = 7 * 24 * 60
STALE_RUN_MINUTES = 60  # a "running" flag older than this is treated as a crashed run


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _public(row):
    r = dict(row)
    blob = r.pop("secrets_blob", None)
    secret_names = []
    if blob:
        try:
            secret_names = sorted(crypto.decrypt(blob).keys())
        except (crypto.EncryptionNotConfigured, crypto.DecryptionFailed):
            secret_names = ["(unreadable: check QUANTA_ENCRYPTION_KEY)"]
    r["config"] = json.loads(r["config"]) if r.get("config") else {}
    r["enabled"] = bool(r["enabled"])
    r["secrets_set"] = secret_names
    spec = registry.SPECS.get(r["type"]) or {}
    r["label"] = spec.get("label", r["type"])
    r["output"] = spec.get("output")
    return r


def _validate_schedule(minutes):
    minutes = int(minutes or 0)
    if minutes and not MIN_SCHEDULE_MINUTES <= minutes <= MAX_SCHEDULE_MINUTES:
        raise ValueError(f"Schedule must be 0 (manual only) or between {MIN_SCHEDULE_MINUTES} and {MAX_SCHEDULE_MINUTES} minutes")
    return minutes


def list_connections(engine=None):
    engine = _engine(engine)
    t = db_module.connections
    with engine.connect() as conn:
        return [_public(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def get_public(connection_id, engine=None):
    engine = _engine(engine)
    t = db_module.connections
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.id == int(connection_id))).mappings().first()
    return _public(row) if row else None


def get_values(connection_id, engine=None):
    """(public view, full values incl. decrypted secrets) - for running a sync only."""
    engine = _engine(engine)
    t = db_module.connections
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.id == int(connection_id))).mappings().first()
    if not row:
        return None, None
    values = json.loads(row["config"]) if row["config"] else {}
    if row["secrets_blob"]:
        values.update(crypto.decrypt(row["secrets_blob"]))
    return _public(row), values


def create(name, conn_type, values, actor, enabled=True, schedule_minutes=0, engine=None, now=None):
    name = (name or "").strip()
    if not name or len(name) > 80:
        raise ValueError("A name of 1 to 80 characters is required")
    config, secrets = registry.split_values(conn_type, values)
    blob = crypto.encrypt(secrets) if secrets else None  # raises EncryptionNotConfigured when no key
    engine = _engine(engine)
    t = db_module.connections
    stamp = _now(now)
    with engine.begin() as conn:
        if conn.execute(select(t.c.id).where(t.c.name == name)).first():
            raise ValueError(f"A connection named {name!r} already exists")
        new_id = conn.execute(insert(t), {
            "name": name, "type": conn_type, "config": json.dumps(config), "secrets_blob": blob, "enabled": 1 if enabled else 0,
            "schedule_minutes": _validate_schedule(schedule_minutes), "last_run_at": None, "last_status": None, "last_message": None,
            "last_count": None, "created_by": actor, "created_at": stamp, "updated_at": stamp}).inserted_primary_key[0]
    record_activity(actor, "connection.create", name, {"type": conn_type, "scheduled": bool(schedule_minutes)}, engine=engine)
    return get_public(new_id, engine)


def update_connection(connection_id, actor, values=None, name=None, enabled=None, schedule_minutes=None, engine=None, now=None):
    engine = _engine(engine)
    public, current = get_values(connection_id, engine)
    if not public:
        raise KeyError("No such connection")
    changes = {}
    if name is not None:
        name = name.strip()
        if not name or len(name) > 80:
            raise ValueError("A name of 1 to 80 characters is required")
        changes["name"] = name
    if values is not None:
        # a blank submitted secret keeps the stored one; other fields take the submitted value
        merged = {}
        for f in registry.SPECS[public["type"]]["fields"]:
            name = f["name"]
            if f["secret"]:
                v = values.get(name)
                merged[name] = v if v not in (None, "") else current.get(name)
            else:
                merged[name] = values[name] if name in values else current.get(name)
        config, secrets = registry.split_values(public["type"], merged)
        changes["config"] = json.dumps(config)
        changes["secrets_blob"] = crypto.encrypt(secrets) if secrets else None
    if enabled is not None:
        changes["enabled"] = 1 if enabled else 0
    if schedule_minutes is not None:
        changes["schedule_minutes"] = _validate_schedule(schedule_minutes)
    if not changes:
        return public
    changes["updated_at"] = _now(now)
    t = db_module.connections
    with engine.begin() as conn:
        if "name" in changes and conn.execute(select(t.c.id).where(t.c.name == changes["name"], t.c.id != int(connection_id))).first():
            raise ValueError(f"A connection named {changes['name']!r} already exists")
        conn.execute(update(t).where(t.c.id == int(connection_id)).values(**changes))
    record_activity(actor, "connection.update", public["name"], {k: ("(changed)" if k in ("config", "secrets_blob") else v) for k, v in changes.items() if k != "updated_at"}, engine=engine)
    return get_public(connection_id, engine)


def registry_is_secret(conn_type, field):
    spec = registry.SPECS.get(conn_type) or {}
    return any(f["name"] == field and f["secret"] for f in spec.get("fields", []))


def delete_connection(connection_id, actor, engine=None):
    engine = _engine(engine)
    public = get_public(connection_id, engine)
    if not public:
        raise KeyError("No such connection")
    with engine.begin() as conn:
        conn.execute(delete(db_module.connections).where(db_module.connections.c.id == int(connection_id)))
    record_activity(actor, "connection.delete", public["name"], {"type": public["type"]}, engine=engine)


def claim_run(connection_id, engine=None, now=None):
    """Marks the connection running unless a run is already in progress (a stale flag, from a
    crashed run, is overridden). Returns True if this caller owns the run."""
    engine = _engine(engine)
    t = db_module.connections
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stale_before = _now(now - datetime.timedelta(minutes=STALE_RUN_MINUTES))
    with engine.begin() as conn:
        res = conn.execute(update(t).where(
            t.c.id == int(connection_id),
            (t.c.last_status.is_(None)) | (t.c.last_status != "running") | (t.c.last_run_at < stale_before))
            .values(last_status="running", last_run_at=_now(now), last_message="Sync running"))
    return res.rowcount == 1


def finish_run(connection_id, status, message, count=None, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.connections
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(connection_id)).values(
            last_status=status, last_message=(message or "")[:1000], last_count=count, last_run_at=_now(now)))


def due(engine=None, now=None):
    """Enabled, scheduled connections whose last run is older than their interval."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    out = []
    for c in list_connections(engine):
        if not c["enabled"] or not c["schedule_minutes"] or c["last_status"] == "running":
            continue
        if not c["last_run_at"]:
            out.append(c)
            continue
        last = datetime.datetime.strptime(c["last_run_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        if now - last >= datetime.timedelta(minutes=c["schedule_minutes"]):
            out.append(c)
    return out
