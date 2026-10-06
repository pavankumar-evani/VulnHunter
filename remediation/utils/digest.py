"""Short stable keys for de-duplication.

These are identifiers, not security controls: nothing here authenticates, signs or protects anything. SHA-1 is kept (and declared as
not-for-security) because the keys are already stored, so a different algorithm would stop existing records matching.
"""
import hashlib


def dedup_sha1(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha1(data, usedforsecurity=False)  # nosec B324 - dedup key, see module docstring
