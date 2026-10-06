"""
Routing: which tier an incident needs and who (or which queue) gets it. Explicit rules from remediation/config/soc_routing.yaml; every decision comes with the list
of reasons that produced it, stored on the incident as routing_reason.

Tier required: start from the severity's base tier; each rule that applies (known-exploited vulnerability on the host, crown-jewel asset, late kill-chain stage,
low confidence on a High or Critical incident, many hosts) can only raise it.

Who: candidates are analysts who are active, marked available, inside their shift (or on call, for an urgent priority), at a tier at or above the one required and
under their capacity. Among them the order is: has the needed specialty; handled a related incident recently (continuity: the same host or user within
continuity_hours) or already owns this one; lowest sufficient tier (keeps senior analysts free); lightest weighted load (open incidents weighted by priority and by
how close their clock is to breaching); then email, so the result is repeatable. Nobody qualified means the incident goes to the tier's queue and the lead is told;
it is never dropped and never given to someone who does not qualify.
"""
from remediation.soc.incidents import store

REASON_LABELS = {"kev": "a known-exploited vulnerability is open on a host involved", "crown_jewel": "a crown-jewel asset is involved",
                 "critical_asset_critical_severity": "a Critical incident on a high-criticality asset",
                 "late_stage_progression": "the kill chain has reached a late stage", "low_confidence_high_severity": "confidence is low on a High or Critical incident",
                 "many_hosts": "many hosts are involved"}


def required_tier(view, pol=None):
    """view: {severity, confidence, kev, crown_jewel, critical_asset, late_stage_progression, hosts}. Returns (tier, reasons[])."""
    pol = pol or store.policy()
    tr = pol["tier_required"]
    base = tr["base_by_severity"].get(view["severity"], 1)
    tier, reasons = base, [f"Severity {view['severity']} starts at tier {base}."]
    conf, low = view.get("confidence"), pol["confidence"]["low_below"]
    flags = {"kev": bool(view.get("kev")), "crown_jewel": bool(view.get("crown_jewel")),
             "critical_asset_critical_severity": bool(view.get("critical_asset")) and view["severity"] == "Critical",
             "late_stage_progression": bool(view.get("late_stage_progression")),
             "low_confidence_high_severity": conf is not None and conf < low and store.sev_index(view["severity"]) >= store.sev_index("High"),
             "many_hosts": len(view.get("hosts") or []) >= tr["many_hosts_at"]}
    for rule in tr["rules"]:
        if flags.get(rule["when"]):
            if rule["tier"] > tier:
                reasons.append(f"Raised to tier {rule['tier']}: {REASON_LABELS[rule['when']]} ({rule['name']}).")
            tier = max(tier, rule["tier"])
    return min(tier, pol["escalation"]["max_tier"]), reasons


def needed_specialty(category, asset_types, pol=None):
    pol = pol or store.policy()
    a = pol["analysts"]
    for t in asset_types or []:
        if t in a["specialty_by_asset_type"]:
            return a["specialty_by_asset_type"][t], f"asset type {t}"
    if category and category in a["specialty_by_category"]:
        return a["specialty_by_category"][category], f"alert category {category}"
    return None, None


def weighted_load(email, incidents, slas, pol):
    w, m, total = pol["routing"]["priority_weight"], pol["routing"]["sla_multiplier"], 0.0
    for i in incidents:
        if i["assignee"] == email and i["status"] in store.OPEN:
            total += w.get(i["priority"], 1) * m.get((slas.get(i.get("case_id")) or "ok"), 1.0)
    return round(total, 2)


def eligibility(a, view, now, pol, load_count, exclude=()):
    """Returns None when the analyst qualifies, otherwise the reason they do not."""
    from remediation.soc.incidents import roster
    if a["email"] in exclude:
        return "excluded for this decision"
    if not a["available"]:
        return "marked unavailable"
    if not roster.on_shift(a, now) and not (a["on_call"] and view["priority"] in pol["analysts"]["on_call_priorities"]):
        return "outside their shift" + (" (on call, but this is not an urgent priority)" if a["on_call"] else "")
    if a["tier"] < view["tier"]:
        return f"works the L{a['tier']} queue; L{view['tier']} is needed"
    if load_count >= a["capacity"]:
        return f"at capacity ({load_count} of {a['capacity']})"
    return None


def choose(view, roster_rows, incidents, related, now, pol=None, slas=None, exclude=(), current=None):
    """view: {tier, priority, specialty, specialty_why, severity}. related: [{assignee, incident_id, at}] handled recently for the same host or user.
    Returns {assignee, queue, tier, reasons[], candidates[], unrouted}."""
    pol, slas = pol or store.policy(), slas or {}
    counts = {}
    for i in incidents:
        if i["status"] in store.OPEN and i["assignee"]:
            counts[i["assignee"]] = counts.get(i["assignee"], 0) + 1
    cands, rejected = [], []
    for a in roster_rows:
        why_not = eligibility(a, view, now, pol, counts.get(a["email"], 0) - (1 if a["email"] == current else 0), exclude)
        if why_not:
            rejected.append({"email": a["email"], "tier": a["tier"], "eligible": False, "why_not": why_not})
            continue
        cands.append(a)
    queue = (pol.get("queue_names") or {}).get(view["tier"]) or f"L{view['tier']}"
    reasons = [f"Tier {view['tier']} needed; priority {view['priority']}."]
    spec = view.get("specialty")
    if not cands:
        reasons.append("Nobody who qualifies is available" + (": " + "; ".join(f"{r['email']} {r['why_not']}" for r in rejected[:6]) if rejected else " (no analysts are on the roster)") + f". Routed to the {queue} queue and the lead is alerted.")
        return {"assignee": None, "queue": queue, "tier": view["tier"], "reasons": reasons, "candidates": rejected, "unrouted": True}
    related_by = {}
    for r in related:
        related_by.setdefault(r["assignee"], r["incident_id"])
    if spec and not any(a["skills"] for a in cands):
        spec = None      # nobody on the roster has specialties recorded, so there is nothing to match on and nothing to report
    have_spec = [a for a in cands if spec and spec in a["skills"]]
    if spec:
        if have_spec:
            reasons.append(f"Needs the {spec} specialty ({view['specialty_why']}); {len(have_spec)} qualified analyst(s) have it.")
        else:
            reasons.append(f"Needs the {spec} specialty ({view['specialty_why']}) but no available analyst has it, so it is routed by tier and load.")

    def key(a):
        return (0 if (not spec or not have_spec or spec in a["skills"]) else 1, 0 if (a["email"] == current or a["email"] in related_by) else 1, a["tier"],
                weighted_load(a["email"], incidents, slas, pol), a["email"])
    ranked = sorted(cands, key=key)
    top = ranked[0]
    why = []
    if spec and spec in top["skills"]:
        why.append(f"has the {spec} specialty")
    if top["email"] == current:
        why.append("already owns this incident")
    elif top["email"] in related_by:
        why.append(f"handled related incident {related_by[top['email']]} (continuity)")
    why.append(f"L{top['tier']}" + (" is the lowest sufficient tier" if top["tier"] == min(a["tier"] for a in cands) else ""))
    why.append(f"weighted load {weighted_load(top['email'], incidents, slas, pol)} ({counts.get(top['email'], 0)} open of {top['capacity']})")
    if top["on_call"] and not _in_shift(top, now):
        why.append("on call outside their shift for an urgent priority")
    reasons.append(f"Routed to {top['email']}: " + "; ".join(why) + ".")
    if len(ranked) > 1:
        reasons.append(f"{len(ranked) - 1} other qualified analyst(s): " + ", ".join(f"{a['email']} (load {weighted_load(a['email'], incidents, slas, pol)})" for a in ranked[1:5]) + ".")
    return {"assignee": top["email"], "queue": queue, "tier": view["tier"], "reasons": reasons, "unrouted": False,
            "candidates": [{"email": a["email"], "tier": a["tier"], "eligible": True, "load": weighted_load(a["email"], incidents, slas, pol), "rank": n + 1} for n, a in enumerate(ranked)] + rejected}


def _in_shift(a, now):
    from remediation.soc.incidents import roster
    return roster.on_shift(a, now)


def still_eligible(assignee_email, view, roster_rows, incidents, now, pol=None):
    """Whether the current owner still qualifies (used by the rebalance). Returns (ok, why_not)."""
    pol = pol or store.policy()
    a = next((x for x in roster_rows if x["email"] == assignee_email), None)
    if a is None:
        return False, "no longer on the active roster"
    counts = sum(1 for i in incidents if i["assignee"] == assignee_email and i["status"] in store.OPEN) - 1   # not counting this incident itself
    why = eligibility(a, view, now, pol, max(0, counts))
    return why is None, why
