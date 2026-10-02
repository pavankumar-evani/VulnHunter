"""
SOAR playbooks: an ordered list of steps run against an alert, with explicit rules about what a playbook may do.

A step has a type, parameters, and an optional `when` condition (a path into the run's data, an operator and a value; the step is skipped when
it is false). Step types:

  investigate          the L1 investigation (remediation/hunting/soc.py); params: reputation, siem (both look outside Quanta, so need a live run)
  enrich-indicators    look up the alert's public indicators with the reputation connection
  add-note             append text to the alert's notes
  update-alert         set the alert to investigating and/or assign it; a playbook can never close an alert
  notify               email addresses or the chat webhook
  request-approval     pause the run until another administrator approves or rejects it
  response-action      a signed request to a webhook you own (isolate a host, block an address, disable an account, open a ticket, ...)

Rules checked when a playbook is saved, not just when it runs:
  - at most `max_steps` steps; only the response actions the policy allows;
  - a response action that changes something in your environment must have a request-approval step before it, and at run time it still
    refuses to go unless an approval was actually recorded in that run;
  - a playbook that starts by itself on new alerts (trigger mode on-alert) may only investigate locally, add notes, set investigating, notify and
    use the non-destructive actions create-ticket and enrich-asset. Anything that looks up indicators, searches the SIEM, or changes your
    environment is started by a person.
"""
import datetime
import json
import re
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select, update

from remediation.connectors.webhook_connector import ACTIONS
from remediation.utils import db as db_module

CONFIG = Path(__file__).resolve().parent.parent / "config" / "soar_policy.yaml"
TEMPLATES = Path(__file__).with_name("templates.yaml")
STEP_TYPES = {
    "investigate": "Investigate the alert (verdict recommendation)",
    "enrich-indicators": "Look up the alert's public indicators",
    "add-note": "Add a note to the alert",
    "update-alert": "Mark the alert investigating / assign it",
    "notify": "Send a notification",
    "request-approval": "Pause for a second person to approve",
    "response-action": "Ask your automation to act (signed webhook)",
}
OPS = ("eq", "ne", "in", "gte", "truthy", "falsy")
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]
AUTO_SAFE_ACTIONS = ("create-ticket", "enrich-asset")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def policy():
    with open(CONFIG, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def templates():
    with open(TEMPLATES, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def is_destructive(action):
    return bool(ACTIONS.get(action, (None, False))[1])


def validate(name, trigger, steps, pol=None):
    """Raises ValueError with a readable message; returns the cleaned (trigger, steps)."""
    pol = pol or policy()
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValueError("A name of 1 to 120 characters is required")
    trigger = trigger or {"mode": "manual"}
    mode = trigger.get("mode", "manual")
    if mode not in ("manual", "on-alert"):
        raise ValueError("The trigger mode must be manual or on-alert")
    clean_trigger = {"mode": mode}
    if mode == "on-alert":
        sev = trigger.get("min_severity")
        if sev is not None and sev not in SEVERITY_ORDER:
            raise ValueError(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
        clean_trigger.update({"min_severity": sev or "High", "techniques": [str(t).upper() for t in (trigger.get("techniques") or [])][:20],
                              "rule_contains": (trigger.get("rule_contains") or "")[:100]})
    if not isinstance(steps, list) or not steps:
        raise ValueError("A playbook needs at least one step")
    if len(steps) > pol.get("max_steps", 25):
        raise ValueError(f"A playbook can have at most {pol.get('max_steps', 25)} steps")
    allowed_actions = set(pol.get("allowed_response_actions") or [])
    out, approval_seen = [], False
    for i, st in enumerate(steps, 1):
        t = (st or {}).get("type")
        if t not in STEP_TYPES:
            raise ValueError(f"Step {i}: unknown step type '{t}'")
        p = dict((st.get("params") or {}))
        clean = {"type": t, "params": {}}
        when = st.get("when")
        if when:
            if not isinstance(when, dict) or not re.fullmatch(r"[A-Za-z0-9_.]{1,80}", str(when.get("path", ""))) or when.get("op") not in OPS:
                raise ValueError(f"Step {i}: the condition needs a path and one of the operators {', '.join(OPS)}")
            clean["when"] = {"path": when["path"], "op": when["op"], "value": when.get("value")}
        if t == "investigate":
            clean["params"] = {"reputation": bool(p.get("reputation")), "siem": bool(p.get("siem"))}
        elif t == "add-note":
            if not str(p.get("text", "")).strip():
                raise ValueError(f"Step {i}: the note needs text")
            clean["params"] = {"text": str(p["text"])[:500]}
        elif t == "update-alert":
            status = p.get("status")
            if status and status not in (pol.get("alert_statuses_playbooks_may_set") or []):
                raise ValueError(f"Step {i}: a playbook may only set the status to {', '.join(pol.get('alert_statuses_playbooks_may_set') or [])}; closing an alert is a person's decision")
            if not status and not p.get("assignee"):
                raise ValueError(f"Step {i}: choose a status or an assignee")
            clean["params"] = {k: v for k, v in (("status", status), ("assignee", p.get("assignee"))) if v}
        elif t == "notify":
            channel = p.get("channel")
            if channel not in ("email", "webhook"):
                raise ValueError(f"Step {i}: the channel must be email or webhook")
            if not str(p.get("text", "")).strip():
                raise ValueError(f"Step {i}: the notification needs text")
            to = [x.strip() for x in (p.get("to") or []) if x and x.strip()] if isinstance(p.get("to"), list) else [x.strip() for x in str(p.get("to") or "").split(",") if x.strip()]
            if channel == "email" and (not to or not all(_EMAIL.match(x) for x in to)):
                raise ValueError(f"Step {i}: give one or more valid email addresses")
            clean["params"] = {"channel": channel, "text": str(p["text"])[:1000], **({"to": to} if channel == "email" else {})}
        elif t == "request-approval":
            clean["params"] = {"message": str(p.get("message") or "Approve this response?")[:300]}
            approval_seen = True
        elif t == "response-action":
            action = p.get("action")
            if action not in ACTIONS or action not in allowed_actions:
                raise ValueError(f"Step {i}: '{action}' is not an allowed response action")
            if not str(p.get("target", "")).strip():
                raise ValueError(f"Step {i}: the action needs a target")
            if is_destructive(action) and not approval_seen:
                raise ValueError(f"Step {i}: '{action}' changes your environment, so a request-approval step must come before it")
            clean["params"] = {"action": action, "target": str(p["target"])[:200], "reason": str(p.get("reason") or "")[:300]}
        out.append(clean)
    if mode == "on-alert":
        for i, st in enumerate(out, 1):
            p = st["params"]
            bad = (st["type"] == "enrich-indicators" or (st["type"] == "investigate" and (p["reputation"] or p["siem"])) or st["type"] == "request-approval"
                   or (st["type"] == "response-action" and p["action"] not in AUTO_SAFE_ACTIONS))
            if bad:
                raise ValueError(f"Step {i}: a playbook that starts on its own may not use '{st['type']}' this way. It can investigate locally, add notes, mark an alert investigating, "
                                 "notify, and open tickets. Looking outside Quanta or changing your environment is started by a person.")
    return clean_trigger, out


def _row(r):
    d = dict(r)
    d["trigger"] = json.loads(d.pop("trigger_json"))
    d["steps"] = json.loads(d.pop("steps_json"))
    d["enabled"] = bool(d["enabled"])
    return d


def save(name, description, trigger, steps, actor, enabled=True, playbook_id=None, engine=None):
    trigger, steps = validate(name, trigger, steps)
    engine, t, now = _engine(engine), db_module.soar_playbooks, _now()
    vals = {"name": name.strip(), "description": (description or "")[:500], "trigger_json": json.dumps(trigger), "steps_json": json.dumps(steps),
            "enabled": 1 if enabled else 0, "updated_at": now, "updated_by": actor}
    with engine.begin() as conn:
        dup = conn.execute(select(t.c.id).where(t.c.name == vals["name"])).first()
        if dup and dup[0] != playbook_id:
            raise ValueError("A playbook with that name already exists")
        if playbook_id:
            if not conn.execute(update(t).where(t.c.id == int(playbook_id)).values(**vals)).rowcount:
                raise KeyError("No such playbook")
            pid = int(playbook_id)
        else:
            pid = conn.execute(insert(t), {**vals, "created_by": actor, "created_at": now}).inserted_primary_key[0]
    return get(pid, engine)


def get(pid, engine=None):
    engine, t = _engine(engine), db_module.soar_playbooks
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(pid))).mappings().first()
    return _row(r) if r else None


def list_all(engine=None):
    engine, t = _engine(engine), db_module.soar_playbooks
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def remove(pid, engine=None):
    engine, t = _engine(engine), db_module.soar_playbooks
    with engine.begin() as conn:
        return bool(conn.execute(delete(t).where(t.c.id == int(pid))).rowcount)


def matches_trigger(pb, alert):
    """Does an on-alert playbook apply to this alert?"""
    tr = pb["trigger"]
    if tr.get("mode") != "on-alert" or not pb["enabled"]:
        return False
    if SEVERITY_ORDER.index(alert["severity"]) < SEVERITY_ORDER.index(tr.get("min_severity", "High")):
        return False
    if tr.get("techniques") and (alert.get("technique") or "").upper().split(".")[0] not in {t.split(".")[0] for t in tr["techniques"]}:
        return False
    if tr.get("rule_contains") and tr["rule_contains"].lower() not in (alert.get("rule_name") or "").lower():
        return False
    return True
