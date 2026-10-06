"""
The incident summary: one deterministic paragraph built only from fields the incident actually holds (what happened, who and what is involved, the evidence, the
vulnerability context, what Quanta recommends). A part with no data is left out rather than filled in; the same incident always gives the same text.

An optional model-written version can be requested by a person through the confirm-gated route (never required, never saved without being asked). The prompt for it
carries counts, tactic names and verdict labels only: no alert free text, host names or account names.
"""


def _list(items, limit=5):
    items = [str(i) for i in items if i]
    more = len(items) - limit
    return ", ".join(items[:limit]) + (f" and {more} more" if more > 0 else "")


def build(inc, alerts):
    """inc: the incident dict (severity, tier, kill_chain, entities, assets, cves, confidence, techniques, ...). alerts: the alert dicts with role and facts."""
    real = [a for a in alerts if a.get("role") != "duplicate"]
    dups = len(alerts) - len(real)
    first = alerts[0] if alerts else None
    parts = []
    # what happened
    if first:
        n = f"{len(alerts)} alert(s)" + (f" ({dups} duplicate)" if dups else "")
        parts.append(f"{inc['severity']} incident: {n}, starting with '{first['title']}' at {first.get('received_at') or 'an unknown time'}.")
        if len(real) > 1:
            parts.append("Also: " + _list(a["title"] for a in real[1:]) + ".")
    chain = inc.get("kill_chain") or []
    if chain:
        parts.append("Kill chain: " + " > ".join(s["tactic"] for s in chain) + (f" ({len(chain)} stages; severity raised one level)." if inc["severity"] != inc.get("base_severity") else f" ({len(chain)} stage(s))."))
    # entities
    ent = inc.get("entities") or {}
    bits = []
    if ent.get("hosts"):
        bits.append("hosts " + _list(ent["hosts"]))
    if ent.get("users"):
        bits.append("accounts " + _list(ent["users"]))
    if ent.get("indicators"):
        bits.append("indicators " + _list(ent["indicators"]))
    if bits:
        parts.append("Involved: " + "; ".join(bits) + ".")
    # evidence
    facts = [a.get("facts") or {} for a in real]
    reasons = []
    for f in facts:
        for r in f.get("reasons") or []:
            if r not in reasons and not r.startswith("No signal either way"):
                reasons.append(r)
    verdicts = sorted({f["verdict"] for f in facts if f.get("verdict")})
    if verdicts:
        parts.append("First-look verdict: " + _list(verdicts) + (f", confidence {round(100 * inc['confidence'])}% that this is a real threat." if inc.get("confidence") is not None else "."))
    if reasons:
        parts.append("Evidence: " + " ".join(reasons[:3]))
    # vulnerability context
    kev = sorted({c for f in facts for c in f.get("kev_cves") or []})
    opened = [f["open_findings"] for f in facts if f.get("open_findings") is not None]
    if kev:
        parts.append(f"Vulnerability context: known-exploited vulnerabilities on the involved host(s): {_list(kev)}.")
    elif opened and max(opened) > 0:
        parts.append(f"Vulnerability context: {max(opened)} open finding(s) on the involved host(s), none known-exploited.")
    elif opened:
        parts.append("Vulnerability context: Quanta holds no open findings for the involved host(s).")
    owners = sorted({f["owner"] for f in facts if f.get("owner")})
    if owners:
        parts.append("Owner: " + _list(owners) + ".")
    # recommendation
    rec = [f"handle in the L{inc['tier']} queue"]
    books = sorted({(f.get("runbook") or {}).get("name") for f in facts if (f.get("runbook") or {}).get("name")})
    if books:
        rec.append("follow the runbook " + _list(books, 2))
    parts.append("Recommended: " + "; ".join(rec) + ".")
    return " ".join(parts)


def ai_prompt(inc):
    """The prompt for an optional model-written summary. Counts and labels only."""
    chain = " > ".join(s["tactic"] for s in inc.get("kill_chain") or []) or "none mapped"
    return ("You are helping a SOC analyst. Write one short paragraph (at most 90 words) that tells an analyst what to look at first for this incident, "
            "using only the facts below. Do not invent hosts, users or indicators.\n"
            f"Severity: {inc['severity']}. Alerts: {inc.get('alert_count', 0)}, duplicates: {inc.get('duplicate_count', 0)}. Kill-chain stages: {chain}. "
            f"Hosts involved: {len((inc.get('entities') or {}).get('hosts', []))}. Accounts involved: {len((inc.get('entities') or {}).get('users', []))}. "
            f"Known-exploited vulnerabilities on the hosts: {len(inc.get('cves') or [])}. Tier needed: L{inc['tier']}. "
            f"Confidence that it is a real threat: {'unknown' if inc.get('confidence') is None else round(100 * inc['confidence'])}%.")
