"""
A real OpenID Connect Authorization Code + PKCE client - built against the OIDC Discovery
(https://openid.net/specs/openid-connect-discovery-1_0.html) and Authorization Code Flow
with PKCE (RFC 7636) specs, using `requests` (already a real dependency of this dashboard
via the ServiceNow/Jira/Splunk/CrowdStrike connectors) rather than the third-party
`authlib`/`python-jose` packages - no new pip dependency was added for this.

Like every other connector in this repo, this was built against the public spec and has
NOT been exercised against a real identity provider (Okta, Azure AD/Entra, Auth0, Google,
etc.) - no real IdP credentials were available while building it. Before pointing it at a
real provider, register a real OAuth application there, set the four OIDC_* environment
variables below, and verify a full login round-trip manually first.

Deliberately inert unless configured: is_configured() is False (and the login page hides
the "Sign in with SSO" button entirely) unless OIDC_ISSUER, OIDC_CLIENT_ID,
OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URI are all set as real environment variables - this
code cannot register a real OAuth application on anyone's behalf, so it stays dormant
until a real operator supplies real provider credentials.

Honest scope limit: this client does NOT verify the ID token's JWT signature against the
provider's JWKS - it trusts the userinfo endpoint's response over TLS instead (a common,
simpler pattern for a first-party confidential client, but a real production hardening
pass should add JWKS-based ID token signature verification too, e.g. via a real JWT
library once one is actually needed).
"""
import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import requests

REQUIRED_ENV_VARS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI")
DEFAULT_SCOPE = "openid profile email"


def is_configured():
    return all(os.environ.get(var) for var in REQUIRED_ENV_VARS)


def provider_name():
    return os.environ.get("OIDC_PROVIDER_NAME", "SSO")


def _config():
    return {
        "issuer": os.environ["OIDC_ISSUER"].rstrip("/"),
        "client_id": os.environ["OIDC_CLIENT_ID"],
        "client_secret": os.environ["OIDC_CLIENT_SECRET"],
        "redirect_uri": os.environ["OIDC_REDIRECT_URI"],
    }


def discover(issuer, session=None):
    """Fetches the provider's real discovery document - the endpoints below are read
    from here, never hardcoded, since they differ per provider."""
    session = session or requests
    resp = session.get(f"{issuer}/.well-known/openid-configuration")
    resp.raise_for_status()
    return resp.json()


def generate_pkce_pair():
    """S256 PKCE (RFC 7636) - protects the authorization code exchange even though this
    is a confidential client with a client_secret; PKCE is cheap insurance and is what
    every current OIDC provider expects/recommends regardless of client type."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(state, code_challenge, discovery_doc=None, session=None):
    cfg = _config()
    discovery_doc = discovery_doc or discover(cfg["issuer"], session=session)
    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{discovery_doc['authorization_endpoint']}?{urlencode(params)}"


def exchange_code_for_token(code, code_verifier, discovery_doc=None, session=None):
    session = session or requests
    cfg = _config()
    discovery_doc = discovery_doc or discover(cfg["issuer"], session=session)
    resp = session.post(discovery_doc["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg["redirect_uri"],
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code_verifier": code_verifier,
    })
    resp.raise_for_status()
    return resp.json()


def fetch_userinfo(access_token, discovery_doc=None, session=None):
    session = session or requests
    cfg = _config()
    discovery_doc = discovery_doc or discover(cfg["issuer"], session=session)
    resp = session.get(
        discovery_doc["userinfo_endpoint"],
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp.raise_for_status()
    return resp.json()
