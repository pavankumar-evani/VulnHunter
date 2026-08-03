"""
A signed-cookie session mechanism - HMAC-SHA256 over a base64url-encoded JSON payload,
stdlib only (`hmac`, `hashlib`, `json`, `base64`, `time`). Built as a from-scratch
alternative to Starlette's `SessionMiddleware`, which pulls in the third-party
`itsdangerous` package for exactly this signing - this does the same job (a tamper-proof,
server-stateless cookie: nothing is stored server-side, so any process restart doesn't
invalidate every session) without a new dependency.

Cookie format: "<base64url(payload_json)>.<base64url(hmac_sha256(payload_bytes))>" -
the same "signed token" shape JWT uses, deliberately simplified (no alg-negotiation
header, no third-party JWT library) since this is a single first-party cookie this same
codebase both issues and verifies, not a token meant to be verified by other services.

Security note this is NOT: this does not encrypt the payload, only authenticates it - the
role/email are visible to anyone with the cookie (matching how a JWT's claims are visible
without decryption). Don't put secrets in the session payload.
"""
import base64
import hashlib
import hmac
import json
import time

DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 12  # 12 hours


def _b64encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def _b64decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload_b64, secret):
    return _b64encode(hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest())


def create_session_cookie(claims, secret, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + max_age_seconds}
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature_b64 = _sign(payload_b64, secret)
    return f"{payload_b64}.{signature_b64}"


def verify_session_cookie(cookie_value, secret):
    """Returns the claims dict if the cookie is validly signed and not expired, else
    None - a tampered, malformed, or expired cookie is just "not logged in," never a
    500 error, since a stale browser cookie is an expected, ordinary condition."""
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, _, signature_b64 = cookie_value.partition(".")
    expected_signature_b64 = _sign(payload_b64, secret)
    if not hmac.compare_digest(signature_b64, expected_signature_b64):
        return None
    try:
        claims = json.loads(_b64decode(payload_b64))
    except (ValueError, UnicodeDecodeError):
        return None
    if claims.get("exp", 0) < time.time():
        return None
    return claims
