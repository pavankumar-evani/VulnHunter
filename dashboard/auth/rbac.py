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
    """Returns {email, name, role} if a valid, unexpired session cookie is present,
    else None - never raises, since "not logged in" is an ordinary, expected state for
    most requests in this dashboard (only mutation routes require login at all)."""
    cookie_value = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_value:
        return None
    claims = sessions.verify_session_cookie(cookie_value, SESSION_SECRET)
    if not claims:
        return None
    return {"email": claims.get("email"), "name": claims.get("name"), "role": claims.get("role")}


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
