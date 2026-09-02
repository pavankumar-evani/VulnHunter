"""
VulnShop Admin API - a deliberately vulnerable internal-admin surface bolted onto
VulnShop, used ONLY to test VulnHunter's Secrets/API-authorization detection guidance.
DO NOT deploy this anywhere.

Planted vulnerabilities (for scoring / demo reference):
  14. Hardcoded AWS access key                        -> CWE-798
  15. Hardcoded JWT signing secret                     -> CWE-798
  16. No authentication/authorization on admin route    -> CWE-284/CWE-863
  17. Wildcard CORS on a sensitive endpoint             -> CWE-942
  18. Mass assignment on user profile update            -> CWE-915
"""
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# VULN 14 (CWE-798): hardcoded AWS credentials.
AWS_ACCESS_KEY_ID = "AKIAFAKE0000000DEMO1"
AWS_SECRET_ACCESS_KEY = "DEMOfakeSecretAccessKeyNotReal0000000000"

# VULN 15 (CWE-798): hardcoded JWT signing secret - anyone with source access can forge
# a valid admin token.
JWT_SIGNING_SECRET = "vulnshop-demo-jwt-secret-DO-NOT-USE-IN-PRODUCTION"

# VULN 17 (CWE-942): wildcard CORS applied globally, including the admin blueprint below -
# any origin can read responses from these endpoints via a browser, not just vulnshop's
# own frontend.
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/admin/users", methods=["GET"])
def list_all_users():
    """VULN 16 (CWE-284/CWE-863): returns every user's full record (including email and
    internal notes) with no authentication check at all - no session/token validation,
    no role check, nothing gating this from a completely anonymous request."""
    return jsonify({"users": _load_all_users_from_db()})


@app.route("/admin/users/<user_id>", methods=["PUT"])
def update_user_profile(user_id):
    """VULN 18 (CWE-915): mass assignment - the entire request body is applied directly
    to the user record with no allow-list, so a caller can set fields like `role` or
    `is_admin` that a profile-update endpoint should never let them touch."""
    updates = request.get_json(force=True)
    _apply_updates_to_user(user_id, updates)  # e.g. {"is_admin": true} is accepted as-is
    return jsonify({"status": "updated", "user_id": user_id})


def _load_all_users_from_db():
    return []  # stub - a real implementation would query the users table


def _apply_updates_to_user(user_id, updates):
    pass  # stub - a real implementation would UPDATE the users table with `updates`


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
