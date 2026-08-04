"""
VulnShop Admin API - a deliberately vulnerable internal-admin surface bolted onto
VulnShop, used ONLY to test VulnHunter's Secrets/API-authorization detection guidance.
DO NOT deploy this anywhere.

Planted vulnerabilities (for scoring / demo reference):
  14. Hardcoded AWS access key                        -> CWE-798 -- FIXED below
  15. Hardcoded JWT signing secret                     -> CWE-798 -- FIXED below
  16. No authentication/authorization on admin route    -> CWE-284/CWE-863
  17. Wildcard CORS on a sensitive endpoint             -> CWE-942 -- FIXED below
  18. Mass assignment on user profile update            -> CWE-915 -- FIXED below
"""
import os

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# VULN 14 (CWE-798) - FIXED: read from the environment instead of hardcoding.
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]

# VULN 15 (CWE-798) - FIXED: read from the environment instead of hardcoding.
JWT_SIGNING_SECRET = os.environ["JWT_SIGNING_SECRET"]

# VULN 17 (CWE-942) - FIXED: scoped to the admin path and a single named origin,
# configurable via the environment, instead of a wildcard applied to the whole app.
ADMIN_CONSOLE_ORIGIN = os.environ.get("ADMIN_CONSOLE_ORIGIN", "https://admin.vulnshop.internal")
CORS(app, resources={r"/admin/*": {"origins": ADMIN_CONSOLE_ORIGIN}})


@app.route("/admin/users", methods=["GET"])
def list_all_users():
    """VULN 16 (CWE-284/CWE-863): returns every user's full record (including email and
    internal notes) with no authentication check at all - no session/token validation,
    no role check, nothing gating this from a completely anonymous request."""
    return jsonify({"users": _load_all_users_from_db()})


_PROFILE_UPDATABLE_FIELDS = {"name", "email", "phone", "notification_prefs"}


@app.route("/admin/users/<user_id>", methods=["PUT"])
def update_user_profile(user_id):
    """VULN 18 (CWE-915) - FIXED: only an explicit allow-list of profile fields is
    applied, so a caller can no longer set `role`/`is_admin`/etc. via this endpoint
    (previously the entire request body was applied to the user record as-is)."""
    body = request.get_json(force=True) or {}
    updates = {k: v for k, v in body.items() if k in _PROFILE_UPDATABLE_FIELDS}
    _apply_updates_to_user(user_id, updates)
    return jsonify({"status": "updated", "user_id": user_id})


def _load_all_users_from_db():
    return []  # stub - a real implementation would query the users table


def _apply_updates_to_user(user_id, updates):
    pass  # stub - a real implementation would UPDATE the users table with `updates`


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
