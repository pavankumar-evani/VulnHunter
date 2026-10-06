"""Which environment this Quanta process is: dev, test or prod. One definition, read by everything that behaves differently between them.

    QUANTA_ENV                 dev | test | prod. When unset it is `prod` if the older QUANTA_PRODUCTION flag is on, otherwise `dev`.
                               An unrecognised value is an error (a typo must not silently mean "not production").
    QUANTA_ALLOW_SIMULATION    true lets a PROD process run simulated connectors (a hosted demonstration site). Off by default: production never
                               shows simulated data unless an operator says so on purpose, and the page then says so.
    QUANTA_BUILD_SHA / QUANTA_BUILD_TIME   stamped into the image by the build, shown by /api/status so a running instance can be tied to a commit.

The same image is promoted through all three; only these settings and the per-environment configuration change.
"""
import os
from pathlib import Path

ENVIRONMENTS = ("dev", "test", "prod")
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
VERSION_FILE = Path(__file__).resolve().parent.parent.parent / "VERSION"


class EnvironmentError_(ValueError):
    """QUANTA_ENV holds something that is not dev, test or prod."""


def _env(env):
    return os.environ if env is None else env


def name(env=None):
    e = _env(env)
    raw = (e.get("QUANTA_ENV") or "").strip().lower()
    if raw:
        if raw not in ENVIRONMENTS:
            raise EnvironmentError_(f"QUANTA_ENV={raw!r} is not one of {', '.join(ENVIRONMENTS)}")
        return raw
    legacy = (e.get("QUANTA_PRODUCTION") or "").strip().lower()
    return "prod" if legacy in _TRUE else "dev"


def is_prod(env=None):
    return name(env) == "prod"


def flag(key, env=None, default=False):
    raw = (_env(env).get(key) or "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return default


def simulation_allowed(env=None):
    """Simulated connectors (recorded vendor responses replayed through the real connector code) run in dev and test, and in prod only when allowed on purpose."""
    return (not is_prod(env)) or flag("QUANTA_ALLOW_SIMULATION", env)


def version():
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def info(env=None):
    e = _env(env)
    return {"environment": name(env), "version": version(), "build_sha": (e.get("QUANTA_BUILD_SHA") or "").strip() or None,
            "build_time": (e.get("QUANTA_BUILD_TIME") or "").strip() or None, "simulation_allowed": simulation_allowed(env)}
