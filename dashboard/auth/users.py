"""
Local user store - a single local JSON file (dashboard/auth/users.json), committed and
seeded with two demo accounts (one admin, one regular user) - the same real-editable-
config pattern as remediation/exceptions/exceptions.json and asset_ownership.json, not a
database. A production version needs real persistence (and almost certainly real SSO via
oidc.py instead of local passwords at all) - see KNOWLEDGE_TRANSFER.md.

Demo credentials (intentionally public - this is a demo seed file, not a real secret):
see dashboard/README.md for the actual email/password pair. Change or delete these before
any real deployment.
"""
import json
from pathlib import Path

from . import passwords

DEFAULT_USERS_PATH = Path(__file__).resolve().parent / "users.json"
VALID_ROLES = ("admin", "user")
MIN_PASSWORD_LENGTH = 8

# A precomputed, valid-shaped hash used only so verify_login() always pays the same
# real PBKDF2 cost whether or not the email exists - see verify_login()'s docstring.
# The "password" it corresponds to is arbitrary and isn't attached to any real account.
_DUMMY_HASH = passwords.hash_password("no-such-user-timing-safety-placeholder")


def load_users(path=None):
    # Resolved inside the body (not a bound default parameter) - see
    # remediation/exceptions/store.py's docstring for why a bound default parameter
    # silently breaks test patching of DEFAULT_USERS_PATH.
    path = Path(path) if path is not None else DEFAULT_USERS_PATH
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def save_users(users, path=None):
    path = Path(path) if path is not None else DEFAULT_USERS_PATH
    path.write_text(json.dumps(users, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def find_user(email, path=None):
    return load_users(path).get((email or "").strip().lower())


def verify_login(email, password, path=None):
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
    user = find_user(email, path=path)
    password_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = passwords.verify_password(password, password_hash)
    if not user or not password_ok:
        return None
    key = email.strip().lower()
    return {
        "email": key, "name": user.get("name", key), "role": user.get("role", "user"),
        "team": user.get("team"),
    }


def create_user(email, password, name, role="user", team=None, path=None):
    if not email or "@" not in email:
        raise ValueError("A valid email is required")
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}, got {role!r}")
    users = load_users(path)
    key = email.strip().lower()
    if key in users:
        raise ValueError(f"A user with email {email!r} already exists")
    users[key] = {
        "name": name or email, "role": role, "team": team or None,
        "password_hash": passwords.hash_password(password),
    }
    save_users(users, path)
    return {"email": key, "name": users[key]["name"], "role": role, "team": users[key]["team"]}


def list_users(path=None):
    """Every real user account, sorted by email - never the password hash. The Admin
    Settings "Team Management" section's own data source; also used wherever a real
    team name needs to be validated against accounts that actually exist."""
    users = load_users(path)
    return [
        {"email": email, "name": info.get("name", email), "role": info.get("role", "user"), "team": info.get("team")}
        for email, info in sorted(users.items())
    ]


def set_team(email, team, path=None):
    """Real, admin-set per-user team assignment - the field dashboard/app.py's
    _scope_to_team() reads to enforce per-team RBAC on finding/asset views. Pass ""
    (or None) to clear a user's team back to unassigned. Raises KeyError for an
    unknown email, same convention as set_password()."""
    users = load_users(path)
    key = (email or "").strip().lower()
    if key not in users:
        raise KeyError(f"No user with email {email!r}")
    users[key]["team"] = (team or "").strip() or None
    save_users(users, path)
    return {"email": key, "name": users[key].get("name", key), "role": users[key].get("role", "user"), "team": users[key]["team"]}


def set_role(email, role, path=None):
    """Real, admin-set role change for an EXISTING user (create_user() only sets the
    initial role at creation time - this is the missing "promote/demote later"
    counterpart). Raises ValueError for an invalid role, KeyError for an unknown
    email."""
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}, got {role!r}")
    users = load_users(path)
    key = (email or "").strip().lower()
    if key not in users:
        raise KeyError(f"No user with email {email!r}")
    users[key]["role"] = role
    save_users(users, path)
    return {"email": key, "name": users[key].get("name", key), "role": role, "team": users[key].get("team")}


def set_password(email, new_password, path=None):
    if not new_password or len(new_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    users = load_users(path)
    key = (email or "").strip().lower()
    if key not in users:
        raise KeyError(f"No user with email {email!r}")
    users[key]["password_hash"] = passwords.hash_password(new_password)
    save_users(users, path)
    return {"email": key, "name": users[key].get("name", key), "role": users[key].get("role", "user")}
