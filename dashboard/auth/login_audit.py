"""
Real login-attempt audit trail - before this module, `/api/auth/login` checked
credentials and set a cookie on success, but recorded nothing anywhere: not a
successful login, not a failed one. That's a real, previously-unbuilt gap (see
KNOWLEDGE_TRANSFER.md/cli/README.md's existing "audit trail... tied to a real user
identity" callout).

Reuses remediation/audit/activity_log.py - the same unified activity feed every other
real admin action in this app now writes to - rather than a separate, parallel log file
just for auth. `actor` is the attempted email (real input, never fabricated); the
password itself is never recorded here or anywhere else.
"""
from remediation.audit.activity_log import record_activity


def record_login_attempt(email, success):
    record_activity(email, "login.success" if success else "login.failure", target=None)
