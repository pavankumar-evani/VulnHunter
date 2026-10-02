"""
Entitlements in one shape, and what is wrong with them.

An entitlement is one person's grant on one system: user, account, system, entitlement (role or group), privileged, last_login, status, manager,
department, granted_at. They are read from a CSV or JSON export (an identity provider, an ERP security report, a directory dump). An optional HR roster
(user, status, manager, department, end_date) lets Quanta spot access that outlived the job.

Findings:
  IAM001 Critical  a person the roster says has left still has active access
  IAM002 High/Medium  an active account unused for longer than dormant_days (High when the access is privileged)
  IAM003 Medium    an account with no matching person in the roster (only when a roster is loaded)
  IAM004 Medium    privileged access on more systems than the policy allows
  IAM005 SoD       a person holds two entitlements that should not be held together (see sod_rules in iam_policy.yaml)
  IAM006 Medium    a shared or non-human looking account with no manager or owner recorded
  IAM007 Low       an active account that has never been used
The rules read what the export says; a person with two accounts under different names is two people to this analysis.
"""
import csv
import datetime
import io
import json
import re
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "iam_policy.yaml"
ALIASES = {
    "user": ("user", "username", "user name", "email", "person", "employee", "login name", "upn"),
    "account": ("account", "account id", "account name", "sam account name", "samaccountname", "id"),
    "system": ("system", "application", "app", "target system", "resource"),
    "entitlement": ("entitlement", "role", "group", "permission", "access", "profile", "role name", "group name"),
    "privileged": ("privileged", "is admin", "admin", "is_privileged", "elevated"),
    "last_login": ("last login", "last_login", "last logon", "last used", "last activity", "lastlogontimestamp"),
    "status": ("status", "account status", "enabled", "state"),
    "manager": ("manager", "owner", "supervisor", "account owner"),
    "department": ("department", "dept", "business unit", "org"),
    "granted_at": ("granted", "granted at", "created", "grant date", "assigned"),
}
SEV_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}


class IamFormatError(ValueError):
    pass


def policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _date(v):
    s = str(v or "").strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return m.group(0)
    m = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", s)
    return f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}" if m else None


def _bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "x")


def make_entitlement(raw, pol=None):
    pol = pol or policy()
    user = str(raw.get("user") or raw.get("account") or "").strip().lower()
    account = str(raw.get("account") or user).strip().lower()
    system = str(raw.get("system") or "").strip()
    ent = str(raw.get("entitlement") or "").strip()
    if not user or not system or not ent:
        raise IamFormatError("Each row needs a user, a system and an entitlement")
    status = str(raw.get("status") or "active").strip().lower()
    enabled = raw.get("status")
    if str(enabled).strip().lower() in ("false", "0", "no", "disabled", "inactive", "locked"):
        status = "disabled"
    elif str(enabled).strip().lower() in ("true", "1", "yes", "enabled"):
        status = "active"
    low = ent.lower()
    priv = _bool(raw.get("privileged")) or any(k in low for k in pol.get("privileged_keywords") or [])
    return {"user": user, "account": account, "system": system[:120], "entitlement": ent[:200], "privileged": priv, "last_login": _date(raw.get("last_login")), "status": "disabled" if status in ("disabled", "inactive", "locked") else "active",
            "manager": (str(raw.get("manager") or "").strip().lower() or None), "department": (str(raw.get("department") or "").strip() or None), "granted_at": _date(raw.get("granted_at"))}


def from_csv(text, pol=None):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise IamFormatError("The CSV has no header row")
    cols = {}
    for field, names in ALIASES.items():
        for h in reader.fieldnames:
            if (h or "").strip().lower() in names:
                cols.setdefault(field, h)
    for need in ("user", "system", "entitlement"):
        if need not in cols and not (need == "user" and "account" in cols):
            raise IamFormatError(f"No column for '{need}' was recognised. Columns seen: {', '.join(h for h in reader.fieldnames if h)}")
    out = []
    for row in reader:
        raw = {f: row.get(h) for f, h in cols.items()}
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue
        out.append(make_entitlement(raw, pol))
    if not out:
        raise IamFormatError("The file has no rows")
    return out


def from_json(text, pol=None):
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise IamFormatError(f"Not valid JSON: {exc}") from exc
    items = data.get("entitlements") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise IamFormatError("Expected a list of entitlements, or an object with an 'entitlements' list")
    return [make_entitlement(i, pol) for i in items]


def parse(text, fmt=None, pol=None):
    fmt = fmt or ("json" if text.lstrip()[:1] in "[{" else "csv")
    return from_json(text, pol) if fmt == "json" else from_csv(text, pol)


def parse_roster(text):
    """HR roster rows: user, status, manager, department, end_date."""
    reader = csv.DictReader(io.StringIO(text))
    names = {"user": ("user", "username", "email", "employee", "person", "id"), "status": ("status", "employment status", "state"), "manager": ("manager", "supervisor"),
             "department": ("department", "dept"), "end_date": ("end date", "end_date", "termination date", "last day", "left")}
    cols = {}
    for f, ns in names.items():
        for h in reader.fieldnames or []:
            if (h or "").strip().lower() in ns:
                cols.setdefault(f, h)
    if "user" not in cols:
        raise IamFormatError(f"No user column was recognised in the roster. Columns seen: {', '.join(h for h in (reader.fieldnames or []) if h)}")
    out = []
    for row in reader:
        u = (row.get(cols["user"]) or "").strip().lower()
        if u:
            out.append({"user": u, "status": (row.get(cols.get("status", "")) or "active").strip().lower(), "manager": (row.get(cols.get("manager", "")) or "").strip().lower() or None,
                        "department": (row.get(cols.get("department", "")) or "").strip() or None, "end_date": _date(row.get(cols.get("end_date", "")))})
    if not out:
        raise IamFormatError("The roster has no rows")
    return out


def _days(d, today):
    try:
        return (today - datetime.date.fromisoformat(d)).days
    except (TypeError, ValueError):
        return None


def analyse(entitlements, roster=None, pol=None, today=None):
    pol = pol or policy()
    today = today or datetime.date.today()
    findings = []
    people = {r["user"]: r for r in (roster or [])}
    departed = set(pol.get("departed_statuses") or [])

    def add(fid, sev, user, title, detail, fix, system=None, ent=None):
        findings.append({"id": fid, "severity": sev, "user": user, "system": system, "entitlement": ent, "title": title, "detail": detail, "recommendation": fix})

    by_user = {}
    for e in entitlements:
        by_user.setdefault(e["user"], []).append(e)
        active = e["status"] == "active"
        p = people.get(e["user"])
        if active and p and p["status"] in departed:
            add("IAM001", "Critical", e["user"], "A person who has left still has access", f"Roster status '{p['status']}'" + (f", ended {p['end_date']}" if p["end_date"] else "") + f"; still holds {e['entitlement']} on {e['system']}.",
                "Disable the account and remove the entitlement; review what it was used for since the leaving date.", e["system"], e["entitlement"])
        age = _days(e["last_login"], today)
        if active and age is not None and age > pol.get("dormant_days", 90):
            add("IAM002", "High" if e["privileged"] else "Medium", e["user"], f"Unused for {age} days", f"{e['entitlement']} on {e['system']}, last used {e['last_login']}.",
                "Confirm it is still needed; if not, disable it. Dormant privileged accounts are favourite targets.", e["system"], e["entitlement"])
        if active and e["last_login"] is None and (_days(e["granted_at"], today) or 0) > pol.get("never_used_days", 30) and e["granted_at"]:
            add("IAM007", "Low", e["user"], "Granted but never used", f"{e['entitlement']} on {e['system']} granted {e['granted_at']}.", "Remove access that was granted and never needed.", e["system"], e["entitlement"])
        if roster and e["user"] not in people and not any(re.search(r"\b" + re.escape(g) + r"\b", e["user"]) for g in pol.get("generic_account_patterns") or []):
            add("IAM003", "Medium", e["user"], "No matching person in the roster", f"{e['entitlement']} on {e['system']}.", "Find the owner, or disable the account.", e["system"], e["entitlement"])
        generic = any(re.search(r"(^|[^a-z])" + re.escape(g) + r"([^a-z]|$)", e["account"]) for g in pol.get("generic_account_patterns") or [])
        if active and generic and not e["manager"] and not (p and p["manager"]):
            add("IAM006", "Medium", e["user"], "Shared or non-human account with no owner", f"{e['account']} holds {e['entitlement']} on {e['system']}.", "Record an accountable owner so the account can be reviewed.", e["system"], e["entitlement"])
    seen_pairs = set()
    for user, es in by_user.items():
        act = [e for e in es if e["status"] == "active"]
        systems = {e["system"] for e in act if e["privileged"]}
        if len(systems) > pol.get("max_privileged_systems", 3):
            add("IAM004", "Medium", user, f"Privileged access on {len(systems)} systems", ", ".join(sorted(systems)[:8]), "Reduce standing privilege; use time-limited elevation where possible.")
        for rule in pol.get("sod_rules") or []:
            a_hits = [e for e in act if any(w in e["entitlement"].lower() for w in rule["a"])]
            b_hits = [e for e in act if any(w in e["entitlement"].lower() for w in rule["b"])]
            if a_hits and b_hits and (user, rule["id"]) not in seen_pairs:
                seen_pairs.add((user, rule["id"]))
                add("IAM005", rule["severity"], user, f"Separation of duties: {rule['name']}", f"{a_hits[0]['entitlement']} on {a_hits[0]['system']} together with {b_hits[0]['entitlement']} on {b_hits[0]['system']}.",
                    "Remove one of the two, or record a compensating control and a named approver.")
    findings.sort(key=lambda f: (-SEV_WEIGHT[f["severity"]], f["user"], f["id"]))
    return findings


def summary(entitlements, findings, roster=None):
    return {"entitlements": len(entitlements), "people": len({e["user"] for e in entitlements}), "systems": len({e["system"] for e in entitlements}), "privileged": sum(1 for e in entitlements if e["privileged"]),
            "roster_loaded": bool(roster), "findings": len(findings), "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_WEIGHT},
            "by_rule": {r: sum(1 for f in findings if f["id"] == r) for r in sorted({f["id"] for f in findings})}}


def precheck(user, system, entitlement, entitlements, pol=None):
    """Would granting this entitlement create a separation-of-duties conflict, or add privilege? Used before access is requested."""
    pol = pol or policy()
    user = user.strip().lower()
    low = entitlement.lower()
    mine = [e for e in entitlements if e["user"] == user and e["status"] == "active"]
    conflicts = []
    for rule in pol.get("sod_rules") or []:
        mine_a, mine_b = any(w in low for w in rule["a"]), any(w in low for w in rule["b"])
        for e in mine:
            el = e["entitlement"].lower()
            if (mine_a and any(w in el for w in rule["b"])) or (mine_b and any(w in el for w in rule["a"])):
                conflicts.append({"rule": rule["id"], "name": rule["name"], "severity": rule["severity"], "conflicts_with": f"{e['entitlement']} on {e['system']}"})
    priv = any(k in low for k in pol.get("privileged_keywords") or [])
    return {"conflicts": conflicts, "privileged": priv, "already_held": any(e["system"].lower() == system.lower() and e["entitlement"].lower() == low for e in mine),
            "verdict": "blocked-pending-exception" if any(c["severity"] == "Critical" for c in conflicts) else "needs-review" if conflicts or priv else "no-issue-found"}
