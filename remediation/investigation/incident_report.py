"""
The incident investigation report: what an analyst opens instead of starting an investigation from a blank ticket.

It is assembled, not written. Every input is data Quanta already holds (the incident's alerts, the investigations saved for them, earlier alerts and incidents, the findings
queue, access records, asset ownership, the runbooks and the SOAR ranking) plus, only when a person confirmed it, reputation lookups and a few bounded SIEM searches from the
query playbook. Each statement in the report cites evidence items listed in the report (evidence.py); a statement with no evidence is dropped and counted.

Nothing here changes an alert, an incident or any environment. "Unknown" is a value: an owner, a privilege level, a tool action, a reputation that was not looked up are all
reported as unknown or "not looked up", never filled in and never counted as clean.

Sections (see docs/INVESTIGATION_REPORTS.md for the exact JSON): verdict and rationale, investigation summary, historical correlation, associated entities, indicators
(reputation and blast radius), ATT&CK mapping with the next step per technique, attack flow (nodes, edges, stages) and behaviour timeline, root-cause hypothesis, what the tools
did, recommended actions (which need a second person), references (the exact searches and lookups, so they can be reproduced), merged follow-ups and the limits of this report.
"""
import datetime
import ipaddress
from collections import Counter

from remediation.connectors import reputation_connector
from remediation.hunting import report as hunt_report
from remediation.hunting import triage as hunt_triage
from remediation.investigation import playbook as qpb
from remediation.investigation.evidence import Ledger, now_iso, parse

TACTIC_ORDER = hunt_report.TACTIC_ORDER
SCHEMA = 1
LABELS = ("true-positive", "false-positive", "action-needed")
# An action whose text names one of these changes an environment, so it needs a second person (conservative on purpose; a playbook says so itself).
CHANGES_ENV = ("isolate", "contain", "disable", "block", "reset", "quarantine", "patch", "restrict", "revoke", "kill", "delete", "remove", "rotate", "shut")


def _lc(v):
    return str(v or "").strip().lower()


def _short(text, n=120):
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 1].rstrip() + "..."


def _internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _tech(a):
    return (a.get("technique") or "").upper().split(".")[0] or None


class _Index:
    """Alerts by (kind, lower-case value), built once so each lookup is a dict hit, not a scan of every stored alert."""

    def __init__(self, alerts):
        self.by = {}
        self.earliest = None
        for a in alerts:
            d = parse(a.get("received_at"))
            if d and (self.earliest is None or d < self.earliest):
                self.earliest = d
            seen = set()
            for kind, v in hunt_report._vals(a) + ([("rule", a["rule_name"])] if a.get("rule_name") else []):
                k = (kind, _lc(v))
                if k not in seen:
                    seen.add(k)
                    self.by.setdefault(k, []).append(a)

    def get(self, kind, value):
        return self.by.get((kind, _lc(value)), [])


# ---------------------------------------------------------------- pieces
def _alert_evidence(led, a):
    return led.add("alert", f"stored alert #{a['id']} ({a['source']} / {a['external_id']})", f"{a['severity']}: {a['title']}" + (f" on {a['asset']}" if a.get("asset") else ""),
                   at=a.get("received_at"), key=("alert", a["id"]))


def _entities_of(alerts):
    out, seen = [], set()
    for a in alerts:
        for kind, v in hunt_report._vals(a):
            k = (kind, _lc(v))
            if k not in seen:
                seen.add(k)
                out.append((kind, v))
    return out


def history_rows(led, inc_id, own, idx, incident_map, now, days, entities, rules):
    start = now - datetime.timedelta(days=days)
    rows = []
    since = idx.earliest
    covered = days if (since is None or since <= start) else max(0, (now - since).days)
    for kind, v in list(entities)[:15] + [("rule", r) for r in rules][:3]:
        match = [a for a in idx.get(kind, v) if a["id"] not in own and (parse(a.get("received_at")) or now) >= start]
        match.sort(key=lambda a: a.get("received_at") or "")
        incs = sorted({incident_map[a["id"]] for a in match if a["id"] in incident_map} - {inc_id})
        c = Counter((a.get("disposition") or ("open" if a["status"] != "closed" else "closed")) for a in match)
        tp, noise = c.get("true-positive", 0), c.get("benign", 0) + c.get("false-positive", 0)
        open_ = sum(1 for a in match if a["status"] != "closed")
        if match:
            first, last = match[0]["received_at"], match[-1]["received_at"]
            text = (f"{len(match)} other alert(s) involve {kind} {v} in the last {days} days (first {first[:10]}, last {last[:10]}), in {len(incs)} other incident(s); "
                    f"{tp} closed as true positive, {noise} as benign or false positive, {open_} still open.")
            detail = f"{len(match)} stored alert(s) for {kind} {v} within {days} days: " + ", ".join(f"#{a['id']}" for a in match[:20])
        else:
            first = last = None
            text = f"None in {days} days: no other stored alert involves {kind} {v}" + (f" (Quanta holds alerts only since {since.strftime('%Y-%m-%d')}, so this covers {covered} day(s))." if covered < days else ".")
            detail = f"0 stored alerts for {kind} {v} within {days} days (stored alerts cover {covered} day(s))"
        ref = led.add("history", "count over stored alerts and incidents", detail, at=now_iso(now), key=("history", kind, _lc(v), days))
        rows.append({"kind": kind, "value": v, "look_back_days": days, "covered_days": covered, "alerts": len(match), "other_incidents": len(incs), "incident_ids": incs[:20],
                     "true_positive": tp, "noise": noise, "open": open_, "first_seen": first, "last_seen": last, "alert_ids": [a["id"] for a in match[:20]], "text": text, "evidence": [ref]})
    return rows


def reputation_for(led, iocs, lookup, lookup_name, stored_inv, pb_cfg, now):
    """{value: reputation dict}. A fresh lookup (only when `lookup` was supplied after a confirmation) wins over a stored one; neither is 'not looked up'."""
    rep_cfg = pb_cfg.get("reputation") or {}
    cap = int(rep_cfg.get("max_lookups", 15))
    stored = {}
    for sid, rec in stored_inv.items():
        for ind in (rec.get("investigation") or {}).get("indicators") or []:
            if ind.get("result") in ("seen", "unknown"):
                stored.setdefault(_lc(ind["value"]), (ind, rec))
    out, done, failed = {}, 0, None
    for kind, v in iocs:
        key = _lc(v)
        if kind == "address" and _internal(v):
            out[key] = {"status": "private-not-sent", "note": "An internal address is never sent to a reputation service."}
            continue
        ctype = reputation_connector.classify(v)[0]
        if not ctype:
            out[key] = {"status": "not-looked-up", "note": "Not a public indicator Quanta can look up."}
            continue
        if lookup and not failed and done < cap:
            try:
                r = lookup(v)
                done += 1
                out[key] = {"status": "looked-up", "source": f"reputation service ({lookup_name or 'connected'})", "at": now_iso(now),
                            **{k: r.get(k) for k in ("result", "malicious", "suspicious", "harmless", "undetected", "total")}}
                continue
            except Exception as exc:  # noqa: BLE001 - an unavailable service is reported, never guessed around
                failed = str(exc)[:120]
        if key in stored:
            ind, rec = stored[key]
            out[key] = {"status": "looked-up", "source": f"stored investigation #{rec['id']}", "at": rec.get("created_at"),
                        **{k: ind.get(k) for k in ("result", "malicious", "suspicious", "harmless", "undetected", "total")}}
            continue
        note = f"Reputation lookup was unavailable ({failed})." if failed else ("Not looked up: the lookup limit was reached." if lookup and done >= cap else "Not looked up.")
        out[key] = {"status": "lookup-failed" if failed else "not-looked-up", "note": note}
    for key, r in out.items():
        if r["status"] == "looked-up":
            r["evidence"] = led.add("reputation", r["source"], f"{key}: {r.get('malicious')} of {r.get('total')} engines flag it ({r.get('result')})", at=r.get("at"), key=("rep", key, r["source"]))
    return out, failed


def ioc_verdict(rep, malicious_min):
    if rep["status"] != "looked-up":
        return "unknown"
    m, s = rep.get("malicious") or 0, rep.get("suspicious") or 0
    if m >= malicious_min:
        return "malicious"
    if m > 0 or s > 0:
        return "suspicious"
    return "no-detections" if rep.get("result") == "seen" else "unknown"


def ioc_table(led, alert_rows, idx_all, incident_map, rep, pb_cfg, now):
    malicious_min = int((pb_cfg.get("reputation") or {}).get("malicious_min", 5))
    rows, seen = [], set()
    own = {a["id"]: a for a in alert_rows}
    for a in alert_rows:
        for kind, v in hunt_report._vals(a):
            if kind not in ("address", "domain", "hash", "url") or (kind, _lc(v)) in seen:
                continue
            seen.add((kind, _lc(v)))
            r = rep.get(_lc(v)) or {"status": "not-looked-up", "note": "Not looked up."}
            carry = idx_all.get(kind, v)
            hosts = sorted({_lc(x.get("asset")) for x in carry if x.get("asset")})
            users = sorted({_lc((x.get("entities") or {}).get("user")) for x in carry if (x.get("entities") or {}).get("user")})
            incs = sorted({incident_map[x["id"]] for x in carry if x["id"] in incident_map})
            ctx_alerts = [x for x in carry if x["id"] in own]
            sight = led.add("ioc-sightings", "count over stored alerts and incidents", f"{kind} {v} appears in {len(carry)} stored alert(s), {len(hosts)} host(s), {len(users)} user(s), {len(incs)} incident(s)",
                            at=now_iso(now), key=("sight", kind, _lc(v)))
            refs = [sight] + [_alert_evidence(led, x) for x in ctx_alerts[:5]] + ([r["evidence"]] if r.get("evidence") else [])
            rows.append({"value": v, "type": kind, "verdict": ioc_verdict(r, malicious_min), "reputation": {k: x for k, x in r.items() if k != "evidence"},
                         "context": [f"alert #{x['id']} '{_short(x['title'], 60)}'" for x in ctx_alerts[:5]],
                         "blast_radius": {"alerts": len(carry), "hosts": len(hosts), "users": len(users), "incidents": len(incs), "host_names": hosts[:20], "user_names": users[:20],
                                          "incident_ids": incs[:20], "alert_ids": [x["id"] for x in carry[:20]]}, "evidence": refs})
    rows.sort(key=lambda r: ({"malicious": 0, "suspicious": 1, "unknown": 2, "no-detections": 3}.get(r["verdict"], 4), -r["blast_radius"]["alerts"]))
    return rows[:50]


def entity_rows(led, alert_rows, ownership, owners, assets, identity, findings_by_host):
    out = []
    for kind, v in _entities_of(alert_rows)[:30]:
        carriers = [a for a in alert_rows if any(k == kind and _lc(x) == _lc(v) for k, x in hunt_report._vals(a))]
        refs = [_alert_evidence(led, a) for a in carriers[:5]]
        row = {"kind": kind, "value": v, "alerts": [a["id"] for a in carriers[:10]]}
        if kind == "host":
            h = _lc(v)
            own = (ownership.get(h) or {}) if ownership else {}
            owner = own.get("owner") or owners.get(h)
            team = own.get("team")
            asset = assets.get(h) or {}
            kev = findings_by_host.get(h, {"open": 0, "kev": 0})
            if owner or team:
                refs.append(led.add("asset-inventory", "asset ownership records", f"{v}: owner {owner or 'unknown'}, team {team or 'unknown'}", key=("own", h)))
            if asset.get("criticality") or asset.get("type"):
                refs.append(led.add("findings-queue", "live findings queue", f"{v}: type {asset.get('type') or 'unknown'}, criticality {asset.get('criticality') or 'unknown'}", key=("crit", h)))
            if kev["open"]:
                refs.append(led.add("findings-queue", "live findings queue", f"{v}: {kev['open']} open finding(s), {kev['kev']} known-exploited", key=("kev", h)))
            row.update({"owner": owner or "unknown", "team": team or "unknown", "criticality": asset.get("criticality") or "unknown", "asset_type": asset.get("type") or "unknown",
                        "open_findings": kev["open"], "kev_findings": kev["kev"], "privilege": None})
        elif kind == "user":
            who = (identity or {}).get(_lc(v)) if identity is not None else None
            if identity is None:
                priv, note = "unknown", "access records are not loaded"
            elif who is None:
                priv, note = "unknown", "the account is not in the access records Quanta holds"
            elif who["privileged"]:
                priv, note = "privileged", "holds privileged access on " + ", ".join(sorted(who["systems"])[:4])
                refs.append(led.add("access-records", "access governance entitlements", f"{v}: privileged on {', '.join(sorted(who['systems'])[:4])}", key=("iam", _lc(v))))
            else:
                priv, note = "not-privileged", "no privileged entitlement is recorded"
                refs.append(led.add("access-records", "access governance entitlements", f"{v}: no privileged entitlement recorded", key=("iam-np", _lc(v))))
            row.update({"privilege": priv, "privilege_detail": note, "owner": "unknown", "team": "unknown", "criticality": "unknown"})
        elif kind == "address":
            row.update({"scope": "internal" if _internal(v) else "public"})
        row["evidence"] = refs
        out.append(row)
    return out


def attack_rows(led, alert_rows, incident, books):
    out = []
    by_t = {}
    for a in alert_rows:
        t = _tech(a)
        if t:
            by_t.setdefault(t, []).append(a)
    for tid, carriers in by_t.items():
        g = hunt_report.technique_guidance(tid) or hunt_report.technique_info(tid)
        rb = hunt_triage.runbook_for(carriers[0], books)
        refs = [_alert_evidence(led, a) for a in carriers[:5]]
        nxt = (g or {}).get("what_to_check") if g else None
        if nxt or rb:
            refs.append(led.add("reference-data", "Quanta ATT&CK hunt library and runbooks", f"{tid} guidance" + (f"; runbook {rb['id']}" if rb else ""), key=("lib", tid, rb["id"] if rb else None)))
        step = nxt or ((rb or {}).get("steps") or [None])[0]
        out.append({"technique": tid, "name": (g or {}).get("name"), "tactics": (g or {}).get("tactics") or [], "tactic": (g or {}).get("tactic"),
                    "next_step": step or "Quanta's library has no guidance for this technique; follow your own procedure.",
                    "runbook": {"id": rb["id"], "title": rb["title"], "steps": rb["steps"][:4]} if rb else None,
                    "look_in": (g or {}).get("data_sources") or [], "mitigations": [m["name"] for m in (g or {}).get("mitigations") or []][:4],
                    "alerts": [a["id"] for a in carriers[:10]], "evidence": refs})
    out.sort(key=lambda r: (TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99, r["technique"]))
    return out


def attack_flow(led, alert_rows, ents):
    """Nodes (alerts and the entities they share), edges (the order of stages, and who is involved) and the stage labels, ready for the UI to draw."""
    real = [a for a in alert_rows if a.get("role") != "duplicate"][:40]
    stage_of = {}
    for a in real:
        info = hunt_report.technique_info(a.get("technique"))
        stage_of[a["id"]] = (info or {}).get("tactic")
    stages = sorted({s for s in stage_of.values() if s}, key=lambda s: TACTIC_ORDER.index(s) if s in TACTIC_ORDER else 99)
    if any(s is None for s in stage_of.values()):
        stages.append("Unmapped")
    order = sorted(real, key=lambda a: (stages.index(stage_of[a["id"]] or "Unmapped"), a.get("occurred_at") or a.get("received_at") or "", a["id"]))
    nodes, edges = [], []
    for a in order:
        info = hunt_report.technique_info(a.get("technique"))
        nodes.append({"id": f"a{a['id']}", "kind": "alert", "label": _short(a["title"], 70), "stage": stage_of[a["id"]] or "Unmapped", "technique": (info or {}).get("id"),
                      "technique_name": (info or {}).get("name"), "severity": a["severity"], "at": a.get("occurred_at") or a.get("received_at"), "host": a.get("asset"),
                      "evidence": [_alert_evidence(led, a)]})
    for i in range(len(order) - 1):
        a, b = order[i], order[i + 1]
        same = stage_of[a["id"]] == stage_of[b["id"]]
        edges.append({"from": f"a{a['id']}", "to": f"a{b['id']}", "kind": "same-stage" if same else "next-stage", "label": "then" if not same else "alongside"})
    ent_ids = {}
    for e in ents:
        if e["kind"] in ("host", "user", "address", "domain", "hash") and len(ent_ids) < 20:
            nid = f"e{len(ent_ids) + 1}"
            ent_ids[(e["kind"], _lc(e["value"]))] = nid
            nodes.append({"id": nid, "kind": "entity", "entity_kind": e["kind"], "label": e["value"], "stage": None, "evidence": e["evidence"][:3]})
            for aid in e["alerts"]:
                if f"a{aid}" in {n["id"] for n in nodes}:
                    edges.append({"from": f"a{aid}", "to": nid, "kind": "involves", "label": "involves"})
    return {"stages": stages, "nodes": nodes, "edges": edges,
            "note": "Stages follow the ATT&CK tactic Quanta tags on each alert; an alert with no technique sits under 'Unmapped'. Order inside a stage is by time. An edge between stages shows sequence in the tactic order, not proof of causation."}


def timeline_rows(led, alert_rows, events, stored_inv):
    rows = []
    for a in alert_rows:
        rows.append({"at": a.get("occurred_at") or a.get("received_at"), "event": f"Alert raised: {a['title']}" + (f" on {a['asset']}" if a.get("asset") else ""),
                     "alert_id": a["id"], "evidence": [_alert_evidence(led, a)]})
        if a.get("action_taken"):
            rows.append({"at": a.get("occurred_at") or a.get("received_at"), "event": f"The reporting tool says: {a['action_taken']}", "alert_id": a["id"], "evidence": [_alert_evidence(led, a)]})
    for sid, rec in stored_inv.items():
        rows.append({"at": rec.get("created_at"), "event": f"Quanta investigated alert #{sid}: {rec['investigation']['verdict']}", "alert_id": sid,
                     "evidence": [led.add("investigation", f"stored investigation #{rec['id']}", f"alert #{sid}: {rec['investigation']['verdict']} ({rec['investigation']['confidence']} confidence)", at=rec.get("created_at"), key=("inv", rec["id"]))]})
    for ev in events:
        if ev["kind"] in ("created", "accepted", "routed", "escalated", "resolved", "reopened", "ticket-comment", "followup"):
            rows.append({"at": ev["created_at"], "event": f"Incident {ev['kind']}" + (f": {_short(ev.get('body'), 100)}" if ev.get("body") else ""), "alert_id": None,
                         "evidence": [led.add("incident-event", f"incident timeline #{ev['id']}", f"{ev['kind']} by {ev.get('actor') or 'system'}", at=ev["created_at"], key=("ev", ev["id"]))]})
    rows.sort(key=lambda r: (r["at"] is None, r["at"] or ""))
    return rows[:60]


def tool_actions(led, alert_rows):
    out = []
    for a in alert_rows:
        t = hunt_report.tool_action(a)
        out.append({"alert_id": a["id"], "technology": a["source"], "action": t["text"] or "unknown", "state": t["state"], "advice": t["advice"], "evidence": [_alert_evidence(led, a)]})
    return out


def _signal_claims(led, a, rec, rows_by_id, all_by_id):
    """The stored investigation's signals for one alert, each tied to the records that made it fire. A signal whose records cannot be found yields no claim."""
    inv = rec["investigation"]
    sig, ref_a = inv.get("signals") or {}, _alert_evidence(led, a)
    ref_i = led.add("investigation", f"stored investigation #{rec['id']}", f"alert #{a['id']}: {inv['verdict']} ({inv['confidence']} confidence)", at=rec.get("created_at"), key=("inv", rec["id"]))
    out = []
    hist = inv.get("history") or {}
    if sig.get("ioc_malicious"):
        bad = [x for x in inv.get("indicators") or [] if (x.get("malicious") or 0) >= (inv.get("threshold") or 10)]
        refs = [led.add("reputation", f"stored investigation #{rec['id']}", f"{x['value']}: {x.get('malicious')} of {x.get('total')} engines flag it", at=rec.get("created_at"), key=("rep", _lc(x["value"]), f"stored investigation #{rec['id']}")) for x in bad]
        out.append(("tp", f"Alert #{a['id']}: indicator(s) flagged by the reputation service: " + ", ".join(f"{x['value']} ({x.get('malicious')} engines)" for x in bad) + ".", (refs + [ref_i]) if refs else []))
    if sig.get("kev_match"):
        kev = [f for f in (inv.get("host") or {}).get("findings") or [] if f.get("kev")]
        refs = [led.add("finding", f"findings queue, {f['id']}", f"{f['id']} {f.get('cve') or ''} on {a.get('asset')}, known-exploited", key=("finding", f["id"])) for f in kev]
        out.append(("tp", f"Alert #{a['id']}: a known-exploited vulnerability on {a.get('asset')} matches the alert's technique ({', '.join(f.get('cve') or f['id'] for f in kev)}).", (refs + [ref_i]) if refs else []))
    if sig.get("recurrence"):
        ids = hist.get("recent_true_positives") or []
        refs = [_alert_evidence(led, all_by_id[i]) for i in ids if i in all_by_id]
        out.append(("tp", f"Alert #{a['id']}: an earlier alert on the same host or rule was closed as a true positive recently (#{', #'.join(str(i) for i in ids)}).", (refs + [ref_i]) if refs else []))
    if sig.get("siem_corroboration"):
        hits = [q for q in inv.get("siem_evidence") or [] if q.get("kind") == "corroboration" and (q.get("count") or 0) > 0]
        refs = [led.add("siem", f"SIEM search recorded in investigation #{rec['id']}", f"{q['name']}: {q['count']} event(s) over {q.get('window')}", at=rec.get("created_at"), key=("siem-inv", rec["id"], q["name"])) for q in hits]
        out.append(("tp", f"Alert #{a['id']}: the SIEM showed matching events on the host (" + ", ".join(f"{q['name']}: {q['count']}" for q in hits) + ").", (refs + [ref_i]) if refs else []))
    if sig.get("critical_severity"):
        out.append(("tp", f"Alert #{a['id']} is Critical.", [ref_a]))
    if sig.get("rule_noise_history"):
        out.append(("fp", f"Alert #{a['id']}: the rule '{a.get('rule_name')}' was closed benign or as a false positive {round(100 * (hist.get('rule_noise_rate') or 0))}% of the time over {hist.get('rule_closed')} closed alerts.", [ref_i]))
    if sig.get("clean_indicators"):
        refs = [led.add("reputation", f"stored investigation #{rec['id']}", f"{x['value']}: known to the service, 0 engines flag it", at=rec.get("created_at"), key=("rep", _lc(x["value"]), f"stored investigation #{rec['id']}")) for x in inv.get("indicators") or [] if x.get("result") == "seen"]
        out.append(("fp", f"Alert #{a['id']}: every looked-up indicator is known to the reputation service and none is flagged.", (refs + [ref_i]) if refs else []))
    if sig.get("prior_benign_same_host"):
        ids = hist.get("prior_benign_same_host") or []
        refs = [_alert_evidence(led, all_by_id[i]) for i in ids if i in all_by_id]
        out.append(("fp", f"Alert #{a['id']}: the same rule was closed benign or as a false positive on this host before (#{', #'.join(str(i) for i in ids)}).", (refs + [ref_i]) if refs else []))
    return out


def verdict_block(led, incident, alert_rows, stored_inv, all_by_id, live_notes):
    real = [a for a in alert_rows if a.get("role") != "duplicate"] or alert_rows
    labels = []
    claims_tp, claims_fp = [], []
    for a in real:
        rec = stored_inv.get(a["id"])
        if not rec:
            continue
        labels.append(rec["investigation"]["verdict"])
        for side, text, refs in _signal_claims(led, a, rec, None, all_by_id):
            c = led.claim(text, refs)
            if c:
                (claims_tp if side == "tp" else claims_fp).append(c)
    resolved = incident.get("verdict") if incident.get("status") in ("resolved", "auto_closed") else None
    if resolved:
        label = "true-positive" if resolved == "true-positive" else "false-positive" if resolved in ("false-positive", "benign") else "action-needed"
        basis = "analyst-resolved"
    else:
        basis = "automated"
        if "likely-true-positive" in labels:
            label = "true-positive"
        elif labels and len(labels) == len(real) and all(x == "likely-false-positive" for x in labels):
            label = "false-positive"
        else:
            label = "action-needed"
    rationale = []
    if resolved:
        rationale.append(led.claim(f"An analyst resolved the incident as {resolved}.", [led.add("incident", f"incident #{incident['id']}", f"status {incident['status']}, verdict {resolved}", key=("incident", incident["id"]))]))
    pro, con = (claims_tp, claims_fp) if label != "false-positive" else (claims_fp, claims_tp)
    rationale += pro + con
    if not labels:
        rationale.append(led.claim("No investigation has been saved for this incident's alerts yet, so there is no automated verdict; it needs a person.", [_alert_evidence(led, a) for a in real[:3]]))
    elif not pro and not con:
        rationale.append(led.claim("The saved investigation found no signal either way, so it goes to a person.", [led.add("investigation", f"stored investigation #{stored_inv[a['id']]['id']}", f"alert #{a['id']}: {stored_inv[a['id']]['investigation']['verdict']}", at=stored_inv[a['id']].get("created_at"), key=("inv", stored_inv[a['id']]['id'])) for a in real if a["id"] in stored_inv][:3]))
    rationale += [c for c in live_notes if c]
    rationale = [r for r in rationale if r]
    conf = incident.get("confidence")
    return {"label": label, "basis": basis, "stored_verdicts": sorted(set(labels)), "confidence": (round(conf, 2) if conf is not None else "unknown"),
            "statement": {"true-positive": "True positive: the evidence indicates a real threat.", "false-positive": "False positive: the evidence indicates the alert is noise.",
                          "action-needed": "Action needed: the evidence is thin or mixed; a person should decide."}[label],
            "note": "A recommendation for a person to validate. Quanta has not closed or changed anything.", "rationale": rationale}


def root_cause(led, alert_rows, flow, tools, gaps, kinds_present, hist_hits):
    real = [a for a in alert_rows if a.get("role") != "duplicate"] or alert_rows
    if not real:
        return {"is_hypothesis": True, "text": None, "evidence": [], "gaps": gaps, "label": "No alerts, so no root cause can be proposed."}
    nodes = [n for n in flow["nodes"] if n["kind"] == "alert"]
    first = nodes[0] if nodes else None
    a0 = next((a for a in real if f"a{a['id']}" == (first or {}).get("id")), real[0])
    refs = [_alert_evidence(led, a0)]
    pieces = []
    if first and first["stage"] != "Unmapped":
        pieces.append(f"the earliest stage Quanta can place is {first['stage']} ({first.get('technique') or 'technique not named'}) on {a0.get('asset') or 'an unnamed host'}, from alert #{a0['id']} '{_short(a0['title'], 70)}'")
    else:
        pieces.append(f"the earliest alert is #{a0['id']} '{_short(a0['title'], 70)}' on {a0.get('asset') or 'an unnamed host'}, which carries no ATT&CK technique")
    first_stage = flow["stages"][0] if flow["stages"] else None
    if first_stage and first_stage not in ("Initial Access", "Reconnaissance", "Resource Development"):
        gaps.append(f"No Initial Access alert is present: the earliest stage seen is {first_stage}, so how it started is not evidenced.")
    strong = {"siem", "reputation", "finding", "findings-queue", "access-records"} & set(kinds_present)
    partial = bool(gaps) or len(strong) < 2
    prefix = "Hypothesis (the evidence is partial): " if partial else "Working explanation (several independent sources agree; still for a person to confirm): "
    return {"is_hypothesis": partial, "text": prefix + "; ".join(pieces) + ".", "evidence": refs, "gaps": gaps,
            "label": "hypothesis" if partial else "supported by several sources"}


def _needs_second(text):
    return any(w in (text or "").lower() for w in CHANGES_ENV)


def action_rows(led, incident, alert_rows, stored_inv, recommended, books_by_id, inc_ref):
    out, seen = [], set()

    def add(action, why, source, refs, second=None):
        k = _lc(action)
        if k in seen:
            return
        c = led.claim(action, refs)
        if not c:
            return
        seen.add(k)
        out.append({"action": action, "why": why, "source": source, "needs_second_person": _needs_second(action) if second is None else bool(second), "evidence": c["evidence"]})

    lead = next((a for a in alert_rows if a.get("role") != "duplicate" and a["id"] in stored_inv), None)
    if lead:
        rec = stored_inv[lead["id"]]
        iref = led.add("investigation", f"stored investigation #{rec['id']}", f"alert #{lead['id']}: {rec['investigation']['verdict']} ({rec['investigation']['confidence']} confidence)", at=rec.get("created_at"), key=("inv", rec["id"]))
        for x in ((rec["investigation"].get("report") or {}).get("actions") or [])[:6]:
            add(x["action"], x["why"], f"investigation #{rec['id']}", [iref])
    for rb in (recommended or {}).get("runbooks") or []:
        book = books_by_id.get(rb.get("id"))
        if book:
            ref = led.add("runbook", f"runbook {book['id']}", book["title"], key=("runbook", book["id"]))
            for i, s in enumerate(book["steps"][:4], 1):
                add(s, f"Runbook step {i}: {book['title']}", f"runbook {book['id']}", [ref])
    for p in (recommended or {}).get("playbooks") or []:
        ref = led.add("playbook-ranking", "SOAR recommendation", f"{p['name']}: basis {p.get('basis')}, {p.get('why') or ''}".strip(", "), key=("pb", p["playbook_id"]))
        add(f"Run playbook '{p['name']}' (dry run first)", p.get("why") or "Ranked for alerts like this one.", f"playbook {p['playbook_id']}", [ref], second=p.get("needs_second_person"))
    for s in (recommended or {}).get("next_steps") or []:
        add(s, "From the incident's current state.", "incident", [inc_ref])
    return out[:15]


def references_block(led, stored_inv, live, rep, lookup_name, pb_cfg, own_ids, window_days, now):
    refs = []
    for sid, rec in stored_inv.items():
        for q in (rec["investigation"].get("siem_evidence") or []):
            refs.append({"kind": "search", "name": q["name"], "query": q["query"], "source": f"SIEM, recorded in investigation #{rec['id']}", "at": rec.get("created_at"),
                         "look_back_days": q.get("lookback_days"), "result": (f"{q['count']} event(s)" if q.get("error") is None else f"failed: {q['error']}")})
    for q in (live or {}).get("results") or []:
        refs.append({"kind": "search", "name": q["name"], "query": q["query"], "source": f"SIEM, read-only search run for this report ({(live or {}).get('connection') or 'connection'})", "at": q["ran_at"],
                     "look_back_days": q["lookback_days"], "result": (f"{q['count']} event(s)" if q["error"] is None else f"failed: {q['error']}")})
    for v, r in rep.items():
        if r["status"] == "looked-up":
            refs.append({"kind": "reputation lookup", "name": v, "query": None, "source": r["source"], "at": r.get("at"), "look_back_days": None,
                         "result": f"{r.get('malicious')} of {r.get('total')} engines flag it ({r.get('result')})"})
    refs.append({"kind": "stored-data correlation", "name": "earlier alerts and incidents for the same entities", "query": f"GET /api/soc/alerts, matched on host, user, address, domain, hash, URL and rule, received within {window_days} days, excluding this incident's alerts",
                 "source": "Quanta's stored alerts and incidents", "at": now_iso(now), "look_back_days": window_days, "result": "see Historical correlation"})
    return refs


# ---------------------------------------------------------------- assembly
def build(incident, alert_rows, data, *, lookup=None, lookup_name=None, siem_run=None, siem_connected=False, siem_name=None, cap_days=None, followups=(), events=(),
          actor=None, now=None, live_requested=False):
    """The report as a dict. `data` carries everything read from storage, loaded once by the caller (see investigation_api.load_data)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    pb_cfg = data.get("pb_cfg") or qpb.load()
    books = data.get("books") or hunt_triage.runbooks()
    books_by_id = {b["id"]: b for b in books}
    led = Ledger()
    own = {a["id"] for a in alert_rows}
    real = [a for a in alert_rows if a.get("role") != "duplicate"] or alert_rows
    all_by_id = {a["id"]: a for a in data["alerts_all"]}
    idx = data.get("index") or _Index(data["alerts_all"])
    imap = data.get("incident_map") or {}
    stored_inv = {a["id"]: data["investigations"][a["id"]] for a in alert_rows if data.get("investigations", {}).get(a["id"])}
    days = int(cap_days or pb_cfg.get("max_lookback_days", 90))
    hist_days = int(pb_cfg.get("history_days", 90))

    # entities, history, reputation, indicators
    findings_by_host = {}
    for f in data.get("findings") or []:
        h = _lc((f.get("asset") or {}).get("name"))
        if h and f.get("status") not in ("resolved", "closed"):
            e = findings_by_host.setdefault(h, {"open": 0, "kev": 0})
            e["open"] += 1
            e["kev"] += 1 if (f.get("kev") or {}).get("listed") else 0
    ents = entity_rows(led, alert_rows, data.get("ownership") or {}, data.get("owners") or {}, data.get("assets") or {}, data.get("identity"), findings_by_host)
    hist = history_rows(led, incident["id"], own, idx, imap, now, hist_days, _entities_of(alert_rows), sorted({a["rule_name"] for a in real if a.get("rule_name")}))
    iocs_raw = [(k, v) for k, v in _entities_of(alert_rows) if k in ("address", "domain", "hash", "url")]
    rep, rep_failed = reputation_for(led, iocs_raw, lookup, lookup_name, stored_inv, pb_cfg, now)
    iocs = ioc_table(led, alert_rows, idx, imap, rep, pb_cfg, now)

    # live searches (only when the caller passes siem_run after a confirmation)
    live = {"requested": bool(live_requested), "connected": bool(siem_connected), "ran": False, "connection": siem_name, "look_back_cap_days": days, "stop_reason": None,
            "queries_run": 0, "rows_seen": 0, "elapsed_seconds": 0, "planned": [], "not_run": [], "skipped": [], "results": [], "budget": qpb.budget(pb_cfg)}
    live_notes = []
    if not siem_connected:
        live["note"] = "No read-only SIEM search connection is configured, so this report uses stored data only."
    elif not siem_run:
        live["note"] = "A SIEM connection exists but no live search was confirmed for this build; the report uses stored data and the searches recorded earlier."
    else:
        planned, skipped = qpb.plan(real, pb_cfg, days)
        res = qpb.run(planned, siem_run, live["budget"], now_fn=lambda: now_iso())
        live.update({"ran": True, "planned": [{"id": p["id"], "name": p["name"], "query": p["query"], "look_back_days": p["days"]} for p in planned], "skipped": skipped,
                     "stop_reason": res["stop_reason"], "queries_run": res["queries_run"], "rows_seen": res["rows_seen"], "elapsed_seconds": res["elapsed_seconds"],
                     "not_run": res["not_run"], "results": res["results"]})
        for q in res["results"]:
            ref = led.add("siem", f"SIEM search ({siem_name or 'connected'})", f"{q['name']}: " + (f"{q['count']} event(s) over {q['lookback_days']} days" if q["error"] is None else f"failed: {q['error']}"),
                          at=q["ran_at"], key=("siem-live", q["query"], q["ran_at"]))
            q["evidence"] = ref
            live_notes.append(led.claim(f"SIEM search '{q['name']}' " + (f"returned {q['count']} event(s) over {q['lookback_days']} days." if q["error"] is None else f"failed ({q['error']}), so it is evidence of nothing."), [ref]))
        if live["stop_reason"] != "completed":
            live_notes.append(led.claim(f"The search run {live['stop_reason']}: {len(res['not_run'])} planned search(es) were not run.", [led.add("siem", "query playbook", live["stop_reason"], at=now_iso(now), key=("stop", live["stop_reason"], now_iso(now)))]))

    verdict = verdict_block(led, incident, alert_rows, stored_inv, all_by_id, live_notes)
    inc_ref = led.add("incident", f"incident #{incident['id']}", f"{incident['severity']} incident, status {incident['status']}, {len(alert_rows)} alert(s)", at=incident.get("updated_at"), key=("incident", incident["id"]))
    attack = attack_rows(led, alert_rows, incident, books)
    flow = attack_flow(led, alert_rows, ents)
    tools = tool_actions(led, alert_rows)
    timeline = timeline_rows(led, alert_rows, events, stored_inv)

    # summary
    summ = []
    dups = len(alert_rows) - len([a for a in alert_rows if a.get("role") != "duplicate"])
    first = alert_rows[0] if alert_rows else None
    if first:
        led.add_claim(summ, f"{incident['severity']} incident of {len(alert_rows)} alert(s)" + (f" ({dups} duplicate)" if dups else "") + f", starting with '{_short(first['title'], 80)}' at {first.get('received_at') or 'an unknown time'}.", [_alert_evidence(led, first), inc_ref])
    if flow["stages"]:
        led.add_claim(summ, "Stages seen: " + " > ".join(flow["stages"]) + ".", [n["evidence"][0] for n in flow["nodes"] if n["kind"] == "alert"][:5])
    hosts = [e for e in ents if e["kind"] == "host"]
    users = [e for e in ents if e["kind"] == "user"]
    if hosts or users:
        led.add_claim(summ, "Involved: " + "; ".join(x for x in (("hosts " + ", ".join(e["value"] for e in hosts[:5])) if hosts else "", ("accounts " + ", ".join(e["value"] for e in users[:5])) if users else "") if x) + ".",
                      [r for e in (hosts + users)[:6] for r in e["evidence"][:1]])
    for h in hosts[:3]:
        if h.get("kev_findings"):
            led.add_claim(summ, f"{h['value']} has {h['kev_findings']} open known-exploited vulnerability(ies) among {h['open_findings']} open finding(s).", h["evidence"])
    for u in users[:2]:
        if u["privilege"] == "privileged":
            led.add_claim(summ, f"The account {u['value']} {u['privilege_detail']}.", u["evidence"])
    tp_stored = [x for x in verdict["rationale"] if x]
    if tp_stored:
        led.add_claim(summ, f"Verdict: {verdict['label']} ({verdict['basis']}).", tp_stored[0]["evidence"])
    dup_hist = [h for h in hist if h["alerts"] and h["kind"] != "rule"]
    if dup_hist:
        led.add_claim(summ, f"{len(dup_hist)} of {len([h for h in hist if h['kind'] != 'rule'])} entities appeared in earlier alerts within {hist_days} days.", [r for h in dup_hist[:5] for r in h["evidence"]])
    elif hist:
        led.add_claim(summ, f"None of the entities appears in an earlier stored alert within {hist_days} days.", [r for h in hist[:5] for r in h["evidence"]])

    gaps = []
    if not siem_connected:
        gaps.append("No SIEM connection: nothing outside Quanta's stored data was checked.")
    elif not live["ran"] and not any(q.get("siem_evidence") for q in [r["investigation"] for r in stored_inv.values()]):
        gaps.append("No SIEM search has been run for this incident.")
    if any(t["state"] == "unknown" for t in tools):
        gaps.append(f"The tools' action is unknown for {sum(1 for t in tools if t['state'] == 'unknown')} alert(s).")
    if any(i["reputation"]["status"] in ("not-looked-up", "lookup-failed") for i in iocs):
        gaps.append("Some indicators were not looked up, so their reputation is unknown (not clean).")
    rc = root_cause(led, alert_rows, flow, tools, gaps, led.kinds(), hist)
    acts = action_rows(led, incident, alert_rows, stored_inv, data.get("recommended"), books_by_id, inc_ref)

    merged = []
    for fu in followups:
        if not fu.get("merged"):
            continue
        refs = [led.add(e.get("kind", "follow-up"), e.get("source", "follow-up"), e.get("detail", ""), at=e.get("at"), key=("fu", fu["id"], e.get("detail"))) for e in fu.get("evidence") or []]
        c = led.claim(f"Q: {fu['question']} A: {fu['answer']}", refs)
        if c:
            merged.append({"id": fu["id"], "question": fu["question"], "answer": fu["answer"], "kind": fu["kind"], "evidence": c["evidence"], "asked_by": fu.get("asked_by"), "asked_at": fu.get("asked_at")})
    refs_block = references_block(led, stored_inv, live, rep, lookup_name, pb_cfg, own, hist_days, now)

    limits = ["Built only from data Quanta holds and the searches listed under References. Each statement cites its evidence; statements without evidence are dropped (counted below).",
              "A verdict is a recommendation for a person to validate. Nothing was closed, blocked or changed.",
              "Reputation results and SIEM searches have been built against public documentation and tested against fakes; they have not been run against a live service.",
              "Historical correlation counts only alerts and incidents stored in Quanta, within the look-back shown; older or never-ingested activity is not counted."]
    if rep_failed:
        limits.append(f"The reputation service was unavailable: {rep_failed}.")
    report = {
        "schema": SCHEMA, "incident_id": incident["id"], "generated_at": now_iso(now), "generated_by": actor, "look_back_days": hist_days,
        "incident": {"title": incident["title"], "severity": incident["severity"], "status": incident["status"], "tier": incident.get("tier"), "priority": incident.get("priority"), "assignee": incident.get("assignee")},
        "mode": {"siem": "ran" if live["ran"] else "connected-not-run" if siem_connected else "not-connected", "reputation": "ran" if lookup and not rep_failed else "failed" if rep_failed else "not-run",
                 "stored_data_only": not (live["ran"] or (lookup and not rep_failed))},
        "verdict": verdict, "summary": summ, "history": hist, "entities": ents, "iocs": iocs, "attack": attack, "attack_flow": flow, "timeline": timeline, "root_cause": rc,
        "tool_actions": tools, "recommended_actions": acts, "references": refs_block, "live_search": live, "followups": merged,
        "limits": limits, "gaps": gaps,
    }
    report["evidence"] = led.export()
    report["dropped_statements"] = len(led.dropped)
    return report


# ---------------------------------------------------------------- output
def to_markdown(r):
    L = [f"# Investigation report: incident #{r['incident_id']} {r['incident']['title']}", "", f"**{r['verdict']['statement']}** ({r['verdict']['basis']}; confidence {r['verdict']['confidence']})", "",
         f"Generated {r['generated_at']} (version {r.get('version', 1)}). Mode: SIEM {r['mode']['siem']}, reputation {r['mode']['reputation']}.", "", "## Why"]
    L += [f"- {c['text']} [{', '.join(c['evidence'])}]" for c in r["verdict"]["rationale"]] or ["- No evidenced rationale."]
    L += ["", "## Summary"] + [f"- {c['text']} [{', '.join(c['evidence'])}]" for c in r["summary"]]
    L += ["", "## Historical correlation"] + [f"- {h['text']} [{', '.join(h['evidence'])}]" for h in r["history"]]
    L += ["", "## Associated entities", "| Kind | Value | Privilege | Owner | Team | Criticality |", "|---|---|---|---|---|---|"]
    L += [f"| {e['kind']} | {e['value']} | {e.get('privilege') or '-'} | {e.get('owner', '-')} | {e.get('team', '-')} | {e.get('criticality', '-')} |" for e in r["entities"]]
    L += ["", "## Indicators", "| Indicator | Type | Verdict | Reputation | Hosts | Users | Alerts | Incidents |", "|---|---|---|---|---|---|---|---|"]
    for i in r["iocs"]:
        rp = i["reputation"]
        rs = f"{rp.get('malicious')} of {rp.get('total')} flag" if rp["status"] == "looked-up" else rp["status"].replace("-", " ")
        b = i["blast_radius"]
        L.append(f"| {i['value']} | {i['type']} | {i['verdict']} | {rs} | {b['hosts']} | {b['users']} | {b['alerts']} | {b['incidents']} |")
    L += ["", "## ATT&CK"] + [f"- {a['technique']} {a['name'] or ''} ({a['tactic'] or 'tactic unknown'}): next, {a['next_step']}" for a in r["attack"]]
    L += ["", "## Attack flow", "Stages: " + (" > ".join(r["attack_flow"]["stages"]) or "none mapped")]
    L += ["", "## Timeline"] + [f"- {t['at']}  {t['event']}" for t in r["timeline"]]
    rc = r["root_cause"]
    L += ["", "## Root cause", rc["text"] or rc["label"]] + [f"- Gap: {g}" for g in rc["gaps"]]
    L += ["", "## What the tools did"] + [f"- Alert #{t['alert_id']} ({t['technology']}): {t['action']}" for t in r["tool_actions"]]
    L += ["", "## Recommended actions"] + [f"- **{a['action']}**{' (needs a second person)' if a['needs_second_person'] else ''}: {a['why']}" for a in r["recommended_actions"]]
    L += ["", "## References"] + [f"- {x['kind']}: {x['name']} ({x['source']}, {x['at']}): {x['result']}" + (f"\n      {x['query']}" if x.get("query") else "") for x in r["references"]]
    if r["followups"]:
        L += ["", "## Follow-ups"] + [f"- Q: {f['question']}\n  A: {f['answer']}" for f in r["followups"]]
    L += ["", "## Evidence"] + [f"- {e['ref']} {e['kind']}: {e['source']}: {e['detail']}" for e in r["evidence"]]
    L += ["", "## Limits"] + [f"- {x}" for x in r["limits"]] + [f"- {r['dropped_statements']} statement(s) were dropped because no evidence supported them."]
    return "\n".join(L) + "\n"
