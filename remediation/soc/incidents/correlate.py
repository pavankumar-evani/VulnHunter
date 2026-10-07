"""
Alert correlation: which incident (if any) a new alert belongs to, and why.

Pure functions over plain dicts, weights and windows from remediation/config/soc_routing.yaml. For one alert and each open incident, every rule that applies adds
its weight once and is recorded with a plain-language detail; the incident with the highest score at or above join_threshold wins (ties go to the one most recently
active). No score is learned and no rule guesses: a missing field means that rule does not apply. A different technique on a different host with nothing else in
common is never grouped.

Duplicates: the same detection rule on the same host within duplicate_minutes of an alert already in the incident is a duplicate. It is grouped (counted, listed)
and does not add a line of work.

Kill chain: each alert's technique maps to an ATT&CK tactic through remediation/hunting/attack_tactics.yaml; the incident's stages are the distinct tactics in the
order of the `kill_chain` list. An unmapped technique has no stage; none is guessed.
"""
import ipaddress

from remediation.soc.incidents import store


def _lc(v):
    return str(v).strip().lower() if v not in (None, "") else None


def _public_ip(v):
    try:
        return ipaddress.ip_address(v).is_global
    except ValueError:
        return False


def keys(alert):
    """The identities an alert carries: hosts (including private addresses), users and public indicators, all lower case."""
    e = alert.get("entities") or {}
    hosts = {x for x in (_lc(alert.get("asset")), _lc(e.get("host"))) if x}
    users = {x for x in (_lc(e.get("user")),) if x}
    inds = set()
    for ip in e.get("ips") or []:
        (inds if _public_ip(ip) else hosts).add(_lc(ip))
    for d in list(e.get("domains") or []) + list(e.get("hashes") or []):
        if _lc(d):
            inds.add(_lc(d))
    return {"hosts": hosts, "users": users, "indicators": inds}


def technique_parent(t):
    return str(t).upper().split(".")[0] if t else None


def tactic_stage(tactic, order):
    return order.index(tactic) if tactic in order else None


def _minutes(a, b):
    ta, tb = store.parse(a), store.parse(b)
    return abs((ta - tb).total_seconds()) / 60 if ta and tb else None


def is_duplicate(alert, inc_alerts, pol):
    """True when an alert already in the incident is the same rule on the same host within duplicate_minutes."""
    rule, host = alert.get("rule_name"), _lc(alert.get("asset"))
    if not rule or not host:
        return None
    win = pol["correlation"]["duplicate_minutes"]
    for o in inc_alerts:
        gap = _minutes(alert.get("received_at"), o.get("received_at"))
        if o.get("rule_name") == rule and _lc(o.get("asset")) == host and gap is not None and gap <= win:
            return o["id"]
    return None


def score(alert, facts, inc, pol):
    """Returns (score, reasons[]). `inc` = {"id", "last_alert_at", "alerts": [alert dicts each with "facts"]}. Zero when the incident is outside the window."""
    cor, w = pol["correlation"], pol["correlation"]["weights"]
    gap = _minutes(alert.get("received_at"), inc.get("last_alert_at"))
    if gap is not None and gap > cor["window_minutes"]:
        return 0.0, []
    mine = keys(alert)
    theirs = {"hosts": set(), "users": set(), "indicators": set()}
    for o in inc["alerts"]:
        for k, v in keys(o).items():
            theirs[k] |= v
    reasons = []

    def add(code, detail):
        reasons.append({"reason": code, "weight": w[code], "detail": detail})

    if mine["hosts"] & theirs["hosts"]:
        add("shared_host", f"Same host: {', '.join(sorted(mine['hosts'] & theirs['hosts']))}.")
    if mine["users"] & theirs["users"]:
        add("shared_user", f"Same account: {', '.join(sorted(mine['users'] & theirs['users']))}.")
    if mine["indicators"] & theirs["indicators"]:
        add("shared_indicator", f"Same indicator: {', '.join(sorted(mine['indicators'] & theirs['indicators']))}.")
    rule = alert.get("rule_name")
    if rule:
        near = [o for o in inc["alerts"] if o.get("rule_name") == rule and _minutes(alert.get("received_at"), o.get("received_at")) is not None
                and _minutes(alert.get("received_at"), o.get("received_at")) <= cor["burst_minutes"]]
        if near:
            add("same_rule_burst", f"The rule '{rule}' fired again within {cor['burst_minutes']} minutes (alert {near[0]['id']}).")
    cves = set(facts.get("cves") or [])
    their_cves = {c for o in inc["alerts"] for c in (o.get("facts") or {}).get("cves", [])}
    if cves & their_cves:
        add("shared_cve", f"Hosts in both carry the same vulnerability: {', '.join(sorted(cves & their_cves))}.")
    tech = technique_parent(alert.get("technique"))
    if tech and any(technique_parent(o.get("technique")) == tech and _lc(o.get("asset")) != _lc(alert.get("asset")) for o in inc["alerts"]):
        add("same_technique", f"The same ATT&CK technique ({tech}) on another host.")
    order = pol["kill_chain"]
    st = tactic_stage(facts.get("tactic"), order)
    their_tactics = {(o.get("facts") or {}).get("tactic") for o in inc["alerts"]} - {None}
    if reasons and st is not None and their_tactics and facts.get("tactic") not in their_tactics:
        add("kill_chain_progression", f"{facts['tactic']} follows {', '.join(sorted(their_tactics, key=lambda t: tactic_stage(t, order) if tactic_stage(t, order) is not None else 99))} in the same incident.")
    return round(sum(r["weight"] for r in reasons), 3), reasons


def best_incident(alert, facts, candidates, pol):
    """Returns (incident, score, reasons, duplicate_of) for the best open incident, or (None, 0, [], None)."""
    best = None
    for inc in candidates:
        if inc["status"] not in store.OPEN:
            continue
        s, reasons = score(alert, facts, inc, pol)
        if s >= pol["correlation"]["join_threshold"] and (best is None or (s, inc.get("last_alert_at") or "") > (best[1], best[0].get("last_alert_at") or "")):
            best = (inc, s, reasons)
    if not best:
        return None, 0.0, [], None
    return best[0], best[1], best[2], is_duplicate(alert, best[0]["alerts"], pol)


# ---------------------------------------------------------------- the kill chain and severity roll-up
def kill_chain(alert_facts, pol):
    """alert_facts: [{"id", "technique", "received_at", "facts"}] -> the stages in kill-chain order, each with its alerts and techniques."""
    order, stages = pol["kill_chain"], {}
    for a in alert_facts:
        tac = a["facts"].get("tactic")
        i = tactic_stage(tac, order)
        if i is None:
            continue
        s = stages.setdefault(tac, {"tactic": tac, "order": i, "late_stage": tac in pol["late_stage"], "alert_ids": [], "techniques": [], "first_seen": a.get("received_at")})
        s["alert_ids"].append(a["id"])
        t = a["facts"].get("technique") or a.get("technique")
        if t and t not in s["techniques"]:
            s["techniques"].append(t)
        if a.get("received_at") and (not s["first_seen"] or a["received_at"] < s["first_seen"]):
            s["first_seen"] = a["received_at"]
    return sorted(stages.values(), key=lambda s: s["order"])


def roll_up_severity(severities, chain, pol):
    """The highest alert severity, raised one level by kill-chain progression. Returns (severity, base, raised_reason or None)."""
    base = max(severities, key=store.sev_index) if severities else "Medium"
    r = pol["severity_rollup"]
    n, late = len(chain), any(s["late_stage"] for s in chain)
    why = None
    if n >= r["raise_at_stages"]:
        why = f"The alerts span {n} stages of the kill chain ({' > '.join(s['tactic'] for s in chain)})."
    elif late and n >= r["raise_at_stages_with_late"]:
        why = f"The alerts reach a late stage ({[s['tactic'] for s in chain if s['late_stage']][0]}) after {n - 1} earlier stage(s) ({' > '.join(s['tactic'] for s in chain)})."
    if not why:
        return base, base, None
    cap = store.sev_index(r["cap"])
    raised = store.SEVERITIES[min(store.sev_index(base) + 1, cap)]
    if raised == base:
        return base, base, None
    return raised, base, why
