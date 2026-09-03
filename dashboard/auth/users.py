"""
Local user store - one row per account in the shared SQLite database (see
remediation/utils/db.py) - previously a flat JSON file, seeded with two demo accounts
(one admin, one regular user). A production version needs real SSO via oidc.py instead
of local passwords at all - see KNOWLEDGE_TRANSFER.md.

Demo credentials (intentionally public - this is a demo seed file, not a real secret):
see dashboard/README.md for the actual email/password pair. Change or delete these before
any real deployment.
"""
from pathlib import Path

from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

from . import passwords

VALID_ROLES = ("admin", "user")
MIN_PASSWORD_LENGTH = 8
# Real, on-disk lock guarding each user row's read-modify-write cycle (create/
# set_team/set_role/set_password) - the same class of race every other migrated store
# in this repo guards against.
LOCK_PATH = Path(__file__).resolve().parent / ".users.lock"

# A precomputed, valid-shaped hash used only so verify_login() always pays the same
# real PBKDF2 cost whether or not the email exists - see verify_login()'s docstring.
# The "password" it corresponds to is arbitrary and isn't attached to any real account.
_DUMMY_HASH = passwords.hash_password("no-such-user-timing-safety-placeholder")


def _row_to_record(row):
    return {"name": row["name"], "role": row["role"], "team": row["team"], "password_hash": row["password_hash"]}


def load_users(engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.users)).mappings().all()
    return {r["email"]: _row_to_record(r) for r in rows}


def save_users(users, engine=None):
    """Replaces the entire table's contents with `users` - same "rewrite everything"
    semantics the old JSON file had. Not used by this module's own functions (which do
    targeted single-row writes instead, see create_user/set_team/set_role/
    set_password below), kept for API parity with the other migrated stores."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    rows = [{"email": email, **fields} for email, fields in users.items()]
    with engine.begin() as conn:
        conn.execute(delete(db_module.users))
        if rows:
            conn.execute(insert(db_module.users), rows)


def find_user(email, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    key = (email or "").strip().lower()
    with engine.connect() as conn:
        row = conn.execute(select(db_module.users).where(db_module.users.c.email == key)).mappings().first()
    return _row_to_record(row) if row is not None else None


def verify_login(email, password, engine=None):
    """Returns {email, name, role} on success (never the password hash), None on any
    failure (unknown email or wrong password) - deliberately the same response shape
    either way so a caller can't distinguish "no such user" from "wrong password" and
    use that to enumerate valid emails. That includes response *timing*, not just the
    return value: verify_password() (deliberately slow, 600k-iteration PBKDF2) is
    always invoked, against a real user's hash or the precomputed dummy one - never
    skipped via a plain `not user or ...` short-circuit, which would make an
    unknown-email login return near-instantly while a wrong-password one takes the
    full PBKDF2 cost, a measurable side-channel an attacker could use to enumerate
    which emails have accounts without ever seeing a different response body."""
    user = find_user(email, engine=engine)
    password_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = passwords.verify_password(password, password_hash)
    if not user or not password_ok:
        return None
    key = email.strip().lower()
    return {
        "email": key, "name": user.get("name", key), "role": user.get("role", "user"),
        "team": user.get("team"),
    }


def create_user(email, password, name, role="user", team=None, engine=None, lock_path=None):
    if not email or "@" not in email:
        raise ValueError("A valid email is required")
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}, got {role!r}")
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    key = email.strip().lower()
    row = {
        "email": key, "name": name or email, "role": role, "team": team or None,
        "password_hash": passwords.hash_password(password),
    }
    # Locked for the full check-then-insert cycle: two concurrent signups for the same
    # email would otherwise both pass the "does this exist yet" check before either
    # commits, and the loser would hit a raw IntegrityError instead of the intended,
    # caller-visible ValueError.
    with FileLock(lock_path or LOCK_PATH):
        with engine.begin() as conn:
            existing = conn.execute(select(db_module.users).where(db_module.users.c.email == key)).mappings().first()
            if existing is not None:
                raise ValueError(f"A user with email {email!r} already exists")
            conn.execute(insert(db_module.users), row)
    return {"email": key, "name": row["name"], "role": role, "team": row["team"]}


def list_users(engine=None):
    """Every real user account, sorted by email - never the password hash. The Admin
    Settings "Team Management" section's own data source; also used wherever a real
    team name needs to be validated against accounts that actually exist."""
    users = load_users(engine)
    return [
        {"email": email, "name": info.get("name", email), "role": info.get("role", "user"), "team": info.get("team")}
        for email, info in sorted(users.items())
    ]


def _update_one_field(email, field, value, lock_path=None, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    key = (email or "").strip().lower()
    with FileLock(lock_path or LOCK_PATH):
        with engine.begin() as conn:
            existing = conn.execute(select(db_module.users).where(db_module.users.c.email == key)).mappings().first()
            if existing is None:
                raise KeyError(f"No user with email {email!r}")
            conn.execute(update(db_module.users).where(db_module.users.c.email == key).values(**{field: value}))
            merged = {**existing, field: value}
    return merged, key


def set_team(email, team, engine=None, lock_path=None):
    """Real, admin-set per-user team assignment - the field dashboard/app.py's
    _scope_to_team() reads to enforce per-team RBAC on finding/asset views. Pass ""
    (or None) to clear a user's team back to unassigned. Raises KeyError for an
    unknown email, same convention as set_password()."""
    new_team = (team or "").strip() or None
    merged, key = _update_one_field(email, "team", new_team, lock_path=lock_path, engine=engine)
    return {"email": key, "name": merged.get("name", key), "role": merged.get("role", "user"), "team": merged["team"]}


def set_role(email, role, engine=None, lock_path=None):
    """Real, admin-set role change for an EXISTING user (create_user() only sets the
    initial role at creation time - this is the missing "promote/demote later"
    counterpart). Raises ValueError for an invalid role, KeyError for an unknown
    email."""
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}, got {role!r}")
    merged, key = _update_one_field(email, "role", role, lock_path=lock_path, engine=engine)
    return {"email": key, "name": merged.get("name", key), "role": role, "team": merged.get("team")}


def set_password(email, new_password, engine=None, lock_path=None):
    if not new_password or len(new_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    new_hash = passwords.hash_password(new_password)
    merged, key = _update_one_field(email, "password_hash", new_hash, lock_path=lock_path, engine=engine)
    return {"email": key, "name": merged.get("name", key), "role": merged.get("role", "user")}
