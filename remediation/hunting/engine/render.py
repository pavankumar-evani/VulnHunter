"""
Renders a hypothesis's queries: Splunk SPL (the existing translator, so the existing run flow keeps working), a Sigma rule, a Microsoft Sentinel/Defender KQL
search and a plain-language description. Field names are Sigma's; the analyst maps them to their own data model. Quanta runs none of these.
"""
import datetime
import re
from pathlib import Path

import yaml

from remediation.hunting import generate, translate, usecases
from remediation.utils.digest import dedup_sha1

EXT_PATH = Path(__file__).with_name("library_ext.yaml")
_MODS = ("contains", "startswith", "endswith")


def library():
    with open(EXT_PATH, encoding="utf-8") as fh:
        ext = yaml.safe_load(fh) or {}
    return {**ext, **generate.library()}


def _kq(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_kql(selection, hosts=None):
    """A small KQL search over all tables (`union *`), Sigma modifiers contains/startswith/endswith, lists as OR, fields as AND, hosts as DeviceName."""
    if not selection:
        raise ValueError("A detection needs at least one field")
    parts = []
    for key, value in selection.items():
        field, _, mod = key.partition("|")
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", field):
            raise ValueError(f"Unsupported field name: {field}")
        if mod and mod not in _MODS:
            raise ValueError(f"Unsupported modifier: {mod}")
        ors = []
        for v in value if isinstance(value, list) else [value]:
            if isinstance(v, (int, float)) and not mod:
                ors.append(f"{field} == {v}")
            else:
                op = {"contains": "contains", "startswith": "startswith", "endswith": "endswith"}.get(mod, "==")
                ors.append(f"{field} {op} {_kq(v)}")
        parts.append(ors[0] if len(ors) == 1 else "(" + " or ".join(ors) + ")")
    scope = ""
    if hosts:
        scope = "| where DeviceName in~ (" + ", ".join(_kq(h) for h in sorted(hosts)[:50]) + ") "
    return f"union * {scope}| where " + " and ".join(parts)


def queries_for(technique_ids, hosts=(), identities=(), lib=None, index=None, today=None, hyp_text=""):
    """-> (queries, missing). One record per library detection with every rendering; `missing` lists techniques the library has no entry for."""
    lib = lib if lib is not None else library()
    today = today or datetime.date.today()
    out, missing = [], []
    for tid in technique_ids:
        entry = lib.get(tid.split(".")[0])
        if not entry:
            missing.append(tid)
            continue
        for d in entry.get("detections", []):
            sel = dict(d["selection"])
            if identities and entry.get("domain") == "identity":
                sel["TargetUserName"] = sorted(identities)[:50]
            scope_hosts = None if entry.get("domain") == "identity" else (sorted(hosts)[:50] or None)
            key = f"hunt-{tid}-{dedup_sha1(d['name'].encode()).hexdigest()[:8]}"
            sigma = usecases.sigma_draft(key, f"Quanta hunt - {d['name']}", hyp_text or entry["hunt"], [tid], sel,
                                         usecases.LOGSOURCE.get(tid, {"category": "process_creation"}), "medium", today)
            out.append({"technique": tid, "name": d["name"], "domain": entry.get("domain", "endpoint"), "source": "SIEM", "language": "splunk-spl",
                        "query": translate.to_spl(sel, scope_hosts, index), "kql": to_kql(sel, scope_hosts), "sigma": sigma,
                        "description": f"{entry['hunt']}. {entry.get('notes') or ''}".strip(), "result": None, "notes": ""})
    return out, missing
