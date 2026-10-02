"""The API security thresholds, patterns and detectors (remediation/config/api_security.yaml), re-read when the file changes."""
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "api_security.yaml"
_CACHE = {"stamp": None, "cfg": None}


def load(path=None):
    p = Path(path or PATH)
    stamp = (str(p), p.stat().st_mtime)
    if _CACHE["stamp"] != stamp:
        _CACHE["cfg"] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        _CACHE["stamp"] = stamp
    return _CACHE["cfg"]


def threshold(name):
    return load()["thresholds"][name]
