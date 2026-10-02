"""
Quanta API keys: how scanners, SOAR tools, CI jobs and ticketing systems call *into* Quanta.

(Outbound is the other direction: Quanta calling a vendor with the vendor's key, stored on the
Connections page. This module is only for keys that Quanta issues.)

Design, following common API-key practice:
* A key looks like `qk_<8 hex prefix>_<43 url-safe chars>` - 256 bits of randomness.
* Only a SHA-256 hash is stored, never the key. With that much entropy a fast hash is correct
  (a slow password hash would only add latency). The full key is shown exactly once, on creation.
* The prefix is stored in clear so a key can be recognised in a list and found quickly.
* Each key carries explicit scopes, an optional expiry, a last-used time and can be revoked.
* Comparison is constant time. Keys are sent as `Authorization: Bearer <key>` or `X-API-Key`,
  never in a URL.

Scopes:
  ingest:write    push findings or a scanner export into the queue
  tickets:update  report ticket state changes back (ServiceNow, Jira and similar)
  read:findings   read the findings export
"""
import datetime
import hashlib
import hmac
import json
import re
import secrets

from sqlalchemy import insert, select, update

from remediation.audit.activity_log import record_activity
from remediation.utils import db as db_module

SCOPES = ("ingest:write", "tickets:update", "read:findings", "controls:write", "ai-usage:write", "soc:write")
_FORMAT = re.compile(r"^qk_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$")
LAST_USED_RESOLUTION_SECONDS = 60


def _now(now=None):
    return now or datetime.datetime.now(datetime.timezone.utc)


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _parse(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) if value else None


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _public(row):
    r = dict(row)
    r.pop("key_hash", None)
    r["scopes"] = json.loads(r["scopes"]) if r.get("scopes") else []
    r["key_hint"] = f"qk_{r['prefix']}_..."
    return r


def create(name, scopes, created_by, expires_days=None, engine=None, now=None):
    """Returns (public record, the full key). The full key cannot be recovered later."""
    name = (name or "").strip()
    if not name or len(name) > 80:
        raise ValueError("A name of 1 to 80 characters is required")
    scopes = sorted(set(scopes or []))
    if not scopes or any(s not in SCOPES for s in scopes):
        raise ValueError(f"Choose at least one scope from: {', '.join(SCOPES)}")
    if expires_days is not None and not 1 <= int(expires_days) <= 3650:
        raise ValueError("Expiry must be between 1 and 3650 days (or none)")
    token = f"qk_{secrets.token_hex(4)}_{secrets.token_urlsafe(32)}"
    current = _now(now)
    row = {"name": name, "prefix": token[3:11], "key_hash": _hash(token), "scopes": json.dumps(scopes), "created_by": created_by,
           "created_at": _fmt(current), "expires_at": _fmt(current + datetime.timedelta(days=int(expires_days))) if expires_days else None,
           "last_used_at": None, "revoked_at": None}
    engine = _engine(engine)
    with engine.begin() as conn:
        new_id = conn.execute(insert(db_module.api_keys), row).inserted_primary_key[0]
    record_activity(created_by, "apikey.create", name, {"scopes": scopes, "prefix": row["prefix"], "expires_at": row["expires_at"]}, engine=engine)
    return _public({**row, "id": new_id}), token


def verify(token, scope=None, engine=None, now=None):
    """The key's public record if the token is valid (right hash, not revoked, not expired and,
    when `scope` is given, carrying it); otherwise None. Never raises on a malformed token."""
    m = _FORMAT.match(token or "")
    if not m:
        return None
    engine = _engine(engine)
    t = db_module.api_keys
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.prefix == m.group(1))).mappings().all()
    current = _now(now)
    digest = _hash(token)
    for row in rows:
        if not hmac.compare_digest(row["key_hash"], digest):
            continue
        if row["revoked_at"] or (row["expires_at"] and _parse(row["expires_at"]) <= current):
            return None
        rec = _public(row)
        if scope and scope not in rec["scopes"]:
            return None
        last = _parse(row["last_used_at"])
        if not last or (current - last).total_seconds() >= LAST_USED_RESOLUTION_SECONDS:
            with engine.begin() as conn:
                conn.execute(update(t).where(t.c.id == row["id"]).values(last_used_at=_fmt(current)))
        return rec
    return None


def list_keys(engine=None):
    engine = _engine(engine)
    t = db_module.api_keys
    with engine.connect() as conn:
        return [_public(r) for r in conn.execute(select(t).order_by(t.c.id.desc())).mappings().all()]


def revoke(key_id, actor, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.api_keys
    with engine.begin() as conn:
        row = conn.execute(select(t).where(t.c.id == int(key_id))).mappings().first()
        if not row:
            raise KeyError("No such key")
        if not row["revoked_at"]:
            conn.execute(update(t).where(t.c.id == int(key_id)).values(revoked_at=_fmt(_now(now))))
    record_activity(actor, "apikey.revoke", row["name"], {"prefix": row["prefix"]}, engine=engine)
    return _public({**row, "revoked_at": row["revoked_at"] or _fmt(_now(now))})
