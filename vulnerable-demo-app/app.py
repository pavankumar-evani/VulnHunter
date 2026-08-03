"""
VulnShop - a deliberately vulnerable demo app used ONLY to test VulnHunter.
DO NOT deploy this anywhere. It contains intentional security flaws for
demonstration purposes in a Claude Code hackathon.

Planted vulnerabilities (for scoring / demo reference):
  1. Hardcoded API key / secret            -> CWE-798
  2. SQL Injection in /user endpoint        -> CWE-89
  3. Use of eval() on user input            -> CWE-95
  4. Command injection in /ping endpoint    -> CWE-78
  5. Debug mode enabled in production       -> CWE-489
  6. Weak/no password hashing (plaintext)   -> CWE-256
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# FIXED (VULN-1, CWE-798): secret now comes from the environment, never hardcoded.
STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]
DB_PATH = "vulnshop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/user")
def get_user():
    """FIXED (VULN-2, CWE-89): parameterized query instead of string concatenation."""
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify({"id": row[0], "username": row[1], "email": row[2]})
    return jsonify({"error": "not found"}), 404


@app.route("/calc")
def calc():
    """VULN 3: eval() on untrusted input (CWE-95)."""
    expression = request.args.get("expr", "0")
    result = eval(expression)  # noqa: S307
    return jsonify({"result": result})


@app.route("/ping")
def ping():
    """FIXED (VULN-4, CWE-78): argument list with shell=False, no shell interpolation."""
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(["ping", "-c", "1", host])
    return jsonify({"output": output.decode(errors="ignore")})


@app.route("/register", methods=["POST"])
def register():
    """VULN 6: Storing passwords in plaintext (CWE-256)."""
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")  # stored as-is, no hashing
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "registered"})


@app.route("/charge", methods=["POST"])
def charge():
    """Demonstrates the hardcoded key actually being used."""
    data = request.get_json(force=True)
    amount = data.get("amount")
    # pretend to call Stripe with the hardcoded key above
    return jsonify({"status": "charged", "amount": amount, "key_used": STRIPE_API_KEY[:10] + "..."})


if __name__ == "__main__":
    # FIXED (VULN-5, CWE-489): debug mode now gated behind an env var, off by default.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
