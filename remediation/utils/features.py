"""Feature flags (remediation/config/features.yaml): is a named feature on in this environment?

    enabled("relationship-graphs")            # uses QUANTA_ENV
    enabled("x", env="prod")                  # explicit environment

QUANTA_FEATURES_ON / QUANTA_FEATURES_OFF are comma lists that override the file; OFF wins. An unknown name is False and nothing here
raises: a missing or unreadable file means every flag is off.
"""
import os
from pathlib import Path

import yaml

from remediation.utils import environment

FEATURES_FILE = Path(__file__).resolve().parent.parent / "config" / "features.yaml"


def _csv(key):
    return {x.strip() for x in (os.environ.get(key) or "").split(",") if x.strip()}


def load():
    try:
        data = yaml.safe_load(FEATURES_FILE.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _env_name(env):
    if env:
        return str(env).strip().lower()
    try:
        return environment.name()
    except environment.EnvironmentError_:
        return "prod"  # an invalid setting must not switch experimental features on


def enabled(name, env=None):
    try:
        if name in _csv("QUANTA_FEATURES_OFF"):
            return False
        if name in _csv("QUANTA_FEATURES_ON"):
            return True
        spec = load().get(name)
        if not isinstance(spec, dict):
            return False
        return _env_name(env) in [str(e).strip().lower() for e in (spec.get("enabled_in") or [])]
    except Exception:  # noqa: BLE001 - a flag read must never take a request down
        return False


def snapshot(env=None):
    """{"environment": ..., "features": {name: {"enabled": bool, "description": str}}} for the API and the sidebar."""
    out = {}
    for n, spec in load().items():
        out[n] = {"enabled": enabled(n, env), "description": (spec or {}).get("description", "") if isinstance(spec, dict) else ""}
    for n in sorted(_csv("QUANTA_FEATURES_ON") - set(out)):
        out[n] = {"enabled": enabled(n, env), "description": "enabled by QUANTA_FEATURES_ON"}
    return {"environment": _env_name(env), "features": out}
