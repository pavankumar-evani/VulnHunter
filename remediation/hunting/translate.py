"""
Renders a Sigma-style selection as a Splunk SPL search, scoped to the hosts a hunt is about.

This is a small, honest translator, not pySigma: it handles the modifiers the hunt library uses (contains, startswith, endswith, exact match,
lists as OR, several fields as AND) and nothing else. Field names are Sigma's, so the analyst maps them to their own data model. Quanta never
runs the result; the analyst runs it in their SIEM and records what they found.
"""
import re

_MODS = ("contains", "startswith", "endswith")


def _q(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _clause(key, value):
    field, _, mod = key.partition("|")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", field):
        raise ValueError(f"Unsupported field name: {field}")
    if mod and mod not in _MODS:
        raise ValueError(f"Unsupported modifier: {mod}")
    values = value if isinstance(value, list) else [value]
    parts = []
    for v in values:
        if isinstance(v, (int, float)) and not mod:
            parts.append(f"{field}={v}")
        elif mod == "contains":
            parts.append(f'{field}="*{_wild(v)}*"')
        elif mod == "startswith":
            parts.append(f'{field}="{_wild(v)}*"')
        elif mod == "endswith":
            parts.append(f'{field}="*{_wild(v)}"')
        else:
            parts.append(f"{field}={_q(v)}")
    return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"


def _wild(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def to_spl(selection, hosts=None, index=None):
    """One SPL search for a selection; `hosts` narrows it to the affected assets."""
    if not selection:
        raise ValueError("A detection needs at least one field")
    body = " ".join(_clause(k, v) for k, v in selection.items())
    head = f"index={index} " if index else ""
    scope = ""
    if hosts:
        scope = "(" + " OR ".join(f"host={_q(h)}" for h in sorted(hosts)[:50]) + ") "
    return f"search {head}{scope}{body}".strip()
