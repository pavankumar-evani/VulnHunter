"""
Local auth MVP + OIDC-ready client code.

Everything in this package is stdlib-only except `oidc.py`, which uses `requests`
(already a real dependency of this dashboard, via the ServiceNow/Jira/Splunk/CrowdStrike
connectors) to talk to a real OpenID Connect provider - no new pip dependency was added
for any of this (no `authlib`, no `python-jose`, no `passlib`).

Modules:
- `passwords.py` - PBKDF2-HMAC-SHA256 hashing/verification (`hashlib.pbkdf2_hmac`,
  stdlib only).
- `sessions.py` - a signed-cookie session mechanism (HMAC-SHA256 over a JSON payload,
  stdlib only) - a from-scratch alternative to Starlette's `SessionMiddleware`
  (which depends on the third-party `itsdangerous` package).
- `users.py` - the local user store (one row per account in the shared
  `remediation/vulnhunter.db` SQLite database - see `remediation/utils/db.py`) and
  login verification.
- `oidc.py` - a real OpenID Connect Authorization Code + PKCE client, built against
  the OIDC discovery/token/userinfo spec. Functional but inert unless real provider
  environment variables are set - see its module docstring for the same
  "built-against-docs, unverified-against-a-real-IdP" caveat every other connector in
  this repo carries (ServiceNow, Jira, Splunk, CrowdStrike, Tenable, Armis).
- `rbac.py` - FastAPI dependencies (`get_current_user`, `require_login`,
  `require_admin`) used to gate sensitive routes in `dashboard/app.py`.
- `login_audit.py` - records every login attempt (success or failure, never the
  password) into the shared `remediation/audit/activity_log.py` feed.

Scope decision (stated plainly, not hidden): only sensitive *mutation* endpoints are
gated behind login in this pass - real ServiceNow/Jira/Splunk sends, real pipeline runs,
real AI-assist spends, priority-rule edits, exception create/revoke. Every existing GET/
read endpoint remains open, same as before this feature existed. Gating every read route
too would mean retrofitting auth into the entire existing dashboard test suite in one
pass; this scopes the security-sensitive *actions* first (mirroring the project's
existing dry-run-by-default safety model) rather than building a parallel, half-finished
access-control system across everything at once. See dashboard/README.md and
KNOWLEDGE_TRANSFER.md for the full reasoning and what a production version still needs.
"""
