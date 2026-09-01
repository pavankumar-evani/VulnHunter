"""
FastAPI dependencies wrapping sessions.py/users.py - get_current_user (never raises),
require_login (401 if not logged in), require_admin (401 if not logged in, 403 if logged
in but not an admin). See dashboard/app.py for exactly which routes use which.
"""
import os
import secrets

from fastapi import HTTPException, Request

from . import sessions

SESSION_COOKIE_NAME = "vulnhunter_session"

_env_secret = os.environ.get("VULNHUNTER_SESSION_SECRET")
if _env_secret:
    SESSION_SECRET = _env_secret
else:
    # No real secret configured - generate one for this process only. This keeps the
    # dashboard usable out of the box, but every session is invalidated on restart, and
    # multiple worker processes would each mint incompatible cookies. Set
    # VULNHUNTER_SESSION_SECRET to a real, stable secret before any real deployment.
    SESSION_SECRET = secrets.token_hex(32)
    print(
        "WARNING: VULNHUNTER_SESSION_SECRET is not set - using a random secret "
        "generated for this process only. Set it to a real, stable value before any "
        "real deployment (see dashboard/README.md).",
    )


def get_current_user(request: Request):
    """Returns {email, name, role, team} if a valid, unexpired session cookie is
    present, else None - never raises, since "not logged in" is an ordinary, expected
    state for most requests in this dashboard (only mutation routes, plus per-team
    filtering on finding/asset views, require login at all). `team` is None for an
    admin or any user with no team assigned - see app.py's _scope_to_team()."""
    cookie_value = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_value:
        return None
    claims = sessions.verify_session_cookie(cookie_value, SESSION_SECRET)
    if not claims:
        return None
    return {
        "email": claims.get("email"), "name": claims.get("name"),
        "role": claims.get("role"), "team": claims.get("team"),
    }


def require_login(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    return user


def require_admin(request: Request):
    user = require_login(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def validate_production_requirements():
    """Raises RuntimeError if VULNHUNTER_REQUIRE_LOGIN_FOR_READS (dashboard/app.py's
    opt-in "close the anonymous-read gap" middleware) is on but no real
    VULNHUNTER_SESSION_SECRET was configured - running that combination would log
    every user out on every restart (or mint incompatible cookies across multiple
    worker processes, see SESSION_SECRET's own comment above), defeating the point of
    requiring login everywhere. Called from app.py's startup event (not at import
    time here), so a test can exercise this directly with controlled env vars rather
    than needing to reload this whole module."""
    require_login_for_reads = os.environ.get("VULNHUNTER_REQUIRE_LOGIN_FOR_READS", "").strip().lower() in ("1", "true", "yes")
    if require_login_for_reads and not os.environ.get("VULNHUNTER_SESSION_SECRET"):
        raise RuntimeError(
            "VULNHUNTER_REQUIRE_LOGIN_FOR_READS is set but VULNHUNTER_SESSION_SECRET is "
            "not - refusing to start. Running with every read gated but no stable "
            "session secret would log every user out on the next restart (and mint "
            "incompatible cookies across multiple worker processes). Set a real, "
            "stable VULNHUNTER_SESSION_SECRET first - see dashboard/README.md.",
        )
