"""
Support ticket routing: pick the assignment team (and optionally an assignee) for a new
ticket from remediation/config/support_routing.yaml. First matching rule wins; a rule's
team is used only if that team exists, so a stale rule can never create a phantom queue.
"""
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "support_routing.yaml"
_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def load_rules(path=RULES_PATH):
    try:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def route(kind, subject, description, priority, existing_teams, rules=None):
    """Returns {team, assignee, rule}. `existing_teams` is the set of real team names."""
    rules = rules if rules is not None else load_rules()
    by_lower = {t.lower(): t for t in existing_teams}
    text = f"{subject} {description}".lower()
    for rule in rules.get("rules") or []:
        team = by_lower.get(str(rule.get("team", "")).lower())
        if not team:
            continue
        content = []  # kinds / keywords: matching either one is enough
        if rule.get("kinds"):
            content.append(kind in rule["kinds"])
        if rule.get("keywords"):
            content.append(any(str(k).lower() in text for k in rule["keywords"]))
        urgent_enough = _RANK.get(priority, 9) <= _RANK.get(rule.get("min_priority"), 9) if rule.get("min_priority") else True
        if (any(content) if content else bool(rule.get("min_priority"))) and urgent_enough:
            return {"team": team, "assignee": (rule.get("assignee") or "").lower() or None, "rule": rule.get("name")}
    default = by_lower.get(str(rules.get("default_team") or "").lower())
    return {"team": default, "assignee": None, "rule": "default" if default else None}
