"""
Package criticality: how sensitive a dependency is, from what it does (remediation/config/appsec_criticality.yaml).

A name-based reading aid. It says why it chose a level, so a person can disagree and add an override for an internal library.
"""
import re
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "appsec_criticality.yaml"
LEVELS = ("critical", "high", "medium", "low")


def load_rules(path=None):
    with open(path or PATH, encoding="utf-8") as fh:
        rules = yaml.safe_load(fh) or {}
    for key in ("development_scope_level", "default_level"):
        if rules.get(key, "medium") not in LEVELS:
            raise ValueError(f"{key} must be one of {', '.join(LEVELS)}")
    for entry in (rules.get("overrides") or []) + [c for c in rules.get("categories") or []]:
        if entry.get("level") not in LEVELS:
            raise ValueError(f"level must be one of {', '.join(LEVELS)}: {entry}")
    return rules


def _words(text):
    return "-" + re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") + "-"


def _hit(needle, haystack):
    return _words(needle) in haystack


def classify(name, group=None, scope=None, rules=None):
    """{"level", "category", "reason"} for a package. `scope` 'optional' (development and test dependencies) caps the level."""
    rules = rules if rules is not None else load_rules()
    hay = _words(f"{group or ''}-{name or ''}")
    for o in rules.get("overrides") or []:
        if _hit(o["match"], hay):
            return _cap({"level": o["level"], "category": "override", "reason": o.get("reason") or "Set by your override"}, scope, rules)
    for c in rules.get("categories") or []:
        if any(_hit(m, hay) for m in c.get("match") or []):
            return _cap({"level": c["level"], "category": c["id"], "reason": c["reason"]}, scope, rules)
    return _cap({"level": rules.get("default_level", "medium"), "category": "other", "reason": "Not recognised as a sensitive kind of package"}, scope, rules)


def _cap(result, scope, rules):
    if scope == "optional":
        cap = rules.get("development_scope_level", "low")
        if LEVELS.index(result["level"]) < LEVELS.index(cap):
            return {**result, "level": cap, "reason": result["reason"] + "; capped because it is a development or optional dependency"}
    return result
