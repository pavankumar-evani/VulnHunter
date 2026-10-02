"""
AI-drafted playbooks and use-case refinements, with the guardrails that make a model's output safe to look at.

A language model is used in exactly two places in Quanta's SOC tooling, both optional, both off until an administrator confirms a call, both subject to the AI usage
policy (per-user daily cap, recorded in AI usage), and in neither does its output do anything by itself:

  1. Draft a playbook for an alert type. The model is given the alert's category, technique and rule and the list of step types and response actions the policy allows,
     and asked for a JSON list of steps. The answer is parsed and run through the SAME validator every playbook goes through (playbooks.validate): unknown steps,
     disallowed actions, a destructive action with no approval step before it, closing an alert, and automatic starts that look outside Quanta are all rejected
     with the validator's own messages. What comes back is a DRAFT for a person to edit and save; it is never saved or run by this module.
  2. Refine a detection use case. The model is given the use case's hypothesis and evidence (no raw log data) and asked for: a sharper hypothesis, ways an adversary
     could evade the draft rule, false-positive sources to test for, and test ideas. The answer is stored beside the use case as text labelled as an AI suggestion;
     it does not change the draft rule.

The prompts contain only what the user would see on screen (names, counts, technique ids), never prompt-injectable raw alert text: free-text fields from alerts
are not included.
"""
import json
import re

from remediation.connectors.webhook_connector import ACTIONS
from remediation.soar import playbooks

STEP_HELP = {
    "investigate": 'params: {"reputation": bool, "siem": bool}', "enrich-indicators": "params: {}", "add-note": 'params: {"text": "..."}',
    "update-alert": 'params: {"status": "investigating", "assignee": "..."}', "notify": 'params: {"channel": "webhook"|"email", "text": "...", "to": ["..."] (email only)}',
    "request-approval": 'params: {"message": "..."}', "response-action": 'params: {"action": "<allowed action>", "target": "{asset}"|"{user}"|"{first_ip}"|"...", "reason": "..."}'}


def playbook_prompt(feat):
    pol = playbooks.policy()
    actions = [f"{a} ({'changes the environment, needs a request-approval step before it' if ACTIONS[a][1] else 'safe'})" for a in pol.get("allowed_response_actions") or [] if a in ACTIONS]
    return (
        "You draft SOAR playbooks for a security product. Answer with ONLY a JSON object {\"name\": str, \"description\": str, \"steps\": [...]} and nothing else.\n"
        f"Alert type: category={feat['category']}, ATT&CK technique={feat['technique'] or 'unknown'}, detection rule={feat['rule'] or 'unknown'}, severity={feat['severity']}.\n"
        "Each step is {\"type\": <step type>, \"params\": {...}, optional \"when\": {\"path\": str, \"op\": eq|ne|in|gte|truthy|falsy, \"value\": any}}.\n"
        "Step types: " + "; ".join(f"{k} ({v})" for k, v in STEP_HELP.items()) + ".\n"
        "Allowed response actions: " + "; ".join(actions) + ".\n"
        "Data you may reference in params text as {title} {severity} {asset} {user} {first_ip} {verdict} {confidence} and in conditions as investigation.verdict, investigation.signals.<name>.\n"
        "Rules: start with an investigate step; a response action that changes the environment MUST come after a request-approval step; never close an alert; keep it under 10 steps; "
        "prefer notify and add-note over response actions unless the alert type clearly calls for containment.")


def parse_draft(text):
    """Pulls a JSON object out of a model reply (fenced or bare). Raises ValueError if there is none."""
    if not isinstance(text, str):
        raise ValueError("The model returned no text")
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S) or re.search(r"(\{.*\})", text, re.S)
    if not m:
        raise ValueError("The model's answer contained no JSON object")
    try:
        data = json.loads(m.group(1))
    except ValueError as exc:
        raise ValueError(f"The model's JSON could not be read: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
        raise ValueError("The draft has no list of steps")
    return data


def check_draft(text, trigger=None):
    """-> {ok, name, description, steps, errors}. The validator's rejection is returned as errors, not raised."""
    try:
        data = parse_draft(text)
    except ValueError as exc:
        return {"ok": False, "name": None, "description": None, "steps": [], "errors": [str(exc)]}
    name = str(data.get("name") or "Drafted playbook")[:120]
    try:
        _, steps = playbooks.validate(name, trigger or {"mode": "manual"}, data["steps"])
    except ValueError as exc:
        return {"ok": False, "name": name, "description": str(data.get("description") or "")[:500], "steps": data["steps"], "errors": [str(exc)]}
    return {"ok": True, "name": name, "description": str(data.get("description") or "")[:500], "steps": steps, "errors": []}


def usecase_prompt(case):
    ev = {k: v for k, v in (case.get("evidence") or {}).items() if isinstance(v, (int, float, str, list, dict))}
    return (
        "You help detection engineers. Below is a proposed detection use case (a hypothesis with counts as evidence; no raw logs). Reply in plain text with four short sections: "
        "1) A sharper one-sentence hypothesis. 2) Three ways an adversary could evade the draft rule. 3) Three likely sources of false positives to test for. 4) Three test ideas. "
        "Do not invent evidence beyond what is given, and say so when something is a guess.\n\n"
        f"Title: {case['title']}\nKind: {case['kind']}\nATT&CK techniques: {', '.join(case.get('techniques') or [])}\nHypothesis: {case['hypothesis']}\nEvidence: {json.dumps(ev)[:1500]}\n"
        f"Data sources: {', '.join(case.get('data_sources') or [])}")
