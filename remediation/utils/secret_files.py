"""
Secrets from files, so a key vault can supply them without ever putting them in an
environment variable, a manifest or an image.

Kubernetes (and Docker) can mount a secret as a file: the Secrets Store CSI driver mounts
Azure Key Vault, AWS Secrets Manager, GCP Secret Manager or HashiCorp Vault objects that way,
and External Secrets can sync a vault entry into a Secret that is mounted the same way. For any
setting `NAME`, setting `NAME_FILE=/path/to/file` makes Quanta read the value from that file
instead. An explicit `NAME` always wins over `NAME_FILE`. The file's trailing newline is stripped.

Applies to the settings that are secrets: QUANTA_SESSION_SECRET, QUANTA_ENCRYPTION_KEY,
QUANTA_DATABASE_URL, QUANTA_METRICS_TOKEN, QUANTA_ADMIN_PASSWORD, SMTP_PASSWORD, SMTP_USERNAME,
OIDC_CLIENT_SECRET. It runs once, before any of them is read.
"""
import os

SECRET_SETTINGS = (
    "QUANTA_SESSION_SECRET", "QUANTA_ENCRYPTION_KEY", "QUANTA_DATABASE_URL", "QUANTA_METRICS_TOKEN",
    "QUANTA_ADMIN_PASSWORD", "SMTP_USERNAME", "SMTP_PASSWORD", "OIDC_CLIENT_SECRET",
)


def load_file_env(environ=None):
    """Fills NAME from NAME_FILE for every secret setting. Returns the names it filled. A
    NAME_FILE that points at a missing or unreadable file is an error, not a silent skip:
    a misspelt mount path must not start the app with a random session secret."""
    env = os.environ if environ is None else environ
    filled = []
    for name in SECRET_SETTINGS:
        path = env.get(f"{name}_FILE", "").strip()
        if not path or env.get(name, "").strip():
            continue
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().rstrip("\r\n")
        except OSError as exc:
            raise RuntimeError(f"{name}_FILE is set to {path!r} but it cannot be read: {exc}") from exc
        if not value:
            raise RuntimeError(f"{name}_FILE is set to {path!r} but the file is empty")
        env[name] = value
        filled.append(name)
    return filled
