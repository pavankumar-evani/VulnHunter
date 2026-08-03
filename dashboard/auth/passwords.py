"""
Password hashing - PBKDF2-HMAC-SHA256 via Python's stdlib `hashlib.pbkdf2_hmac`, no
third-party crypto dependency (no `bcrypt`, no `passlib`). PBKDF2 is a real, still-NIST-
approved KDF (SP 800-132) - not as memory-hard as bcrypt/argon2, but a legitimate choice
for a stdlib-only constraint, and the iteration count below is tunable if this ever needs
to move to a real deployment.

Stored format: "pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>" - the iteration count
travels with the hash so a future increase doesn't invalidate already-stored hashes.
"""
import hashlib
import secrets

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000  # OWASP's 2023 minimum recommendation for PBKDF2-SHA256
SALT_BYTES = 16


def hash_password(password, iterations=DEFAULT_ITERATIONS):
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored_hash):
    """Constant-time comparison via secrets.compare_digest - a naive `==` on the hash
    strings would leak timing information about how many leading bytes matched."""
    try:
        algorithm, iterations_str, salt_hex, digest_hex = stored_hash.split("$")
    except (ValueError, AttributeError):
        return False
    if algorithm != ALGORITHM:
        return False
    iterations = int(iterations_str)
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return secrets.compare_digest(actual, expected)
