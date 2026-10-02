"""
Encryption for stored connector credentials (Fernet: AES-128-CBC + HMAC-SHA256).

Quanta's connectors originally asked for credentials fresh on every action and kept none.
A scheduled sync needs them stored, so this is an explicit, opt-in capability: it works only
when `QUANTA_ENCRYPTION_KEY` is set, the key lives outside the database (environment or your
secrets manager), and without it nothing secret is ever written. Credentials are encrypted
as one blob per connection, never logged, and never returned by any API.

Key rotation: `QUANTA_ENCRYPTION_KEY` may hold several comma-separated keys, newest first.
New data is encrypted with the first; any of them can decrypt. Re-save a connection (or run
`quanta-admin rotate-keys`) to move it to the newest key, then drop the old one.
"""
import json
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class EncryptionNotConfigured(RuntimeError):
    pass


class DecryptionFailed(RuntimeError):
    pass


def _keys():
    raw = os.environ.get("QUANTA_ENCRYPTION_KEY", "").strip()
    return [k.strip() for k in raw.split(",") if k.strip()]


def available():
    try:
        return bool(_cipher())
    except EncryptionNotConfigured:
        return False


def _cipher():
    keys = _keys()
    if not keys:
        raise EncryptionNotConfigured(
            "QUANTA_ENCRYPTION_KEY is not set, so credentials cannot be stored. Generate one with "
            "`python cli/quanta_admin.py gen-key` and set it in the environment.")
    try:
        return MultiFernet([Fernet(k.encode()) for k in keys])
    except (ValueError, TypeError) as exc:
        raise EncryptionNotConfigured(f"QUANTA_ENCRYPTION_KEY is not a valid key: {exc}") from exc


def generate_key():
    return Fernet.generate_key().decode()


def encrypt(secrets):
    return _cipher().encrypt(json.dumps(secrets, separators=(",", ":")).encode()).decode()


def decrypt(token):
    try:
        return json.loads(_cipher().decrypt(token.encode()).decode())
    except InvalidToken as exc:
        raise DecryptionFailed("Stored credentials could not be decrypted with the current QUANTA_ENCRYPTION_KEY") from exc


def rotate(token):
    """Re-encrypts a token under the newest key."""
    return _cipher().rotate(token.encode()).decode()
