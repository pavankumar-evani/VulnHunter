"""
The detectors: pure functions `fn(snap, cfg) -> [insight]` over a snapshot of stored data (see loader.py for how the snapshot is built).

Each detector declares the snapshot keys it NEEDS. When a need is missing (None: that store is not available) the detector is skipped and a gap note is
reported, never an insight; when the data exists but is too short to judge ("not enough history") it reports that instead of guessing. A detector that
raises is reported as an error and never stops the others. Nothing here writes anywhere or calls a model.

Snapshot keys: now (datetime), findings, assets, exceptions, approvals, activity, alerts, hunts, cases, connections, api_keys, ai_events, grc_evidence,
grc_mappings, controls, license, baseline (what the previous refresh recorded, for exposure/control diffs).
"""
import collections
import datetime
import json

from remediation.insights import stats
from remediation.insights.model import make

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


# ---------------------------------------------------------------- helpers
def to_date(value):
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def today(snap):
    return snap["now"].date()


def _asset(f):
    return ((f.get("asset") or {}).get("name")) or None


def _kev(f):
    k = f.get("kev")
    return bool(k.get("listed")) if isinstance(k, dict) else bool(k)


def _is_urgent(f):
    return f.get("severity") in ("Critical", "High")


def _asset_team(snap):
    return {a.get("name"): a.get("team") for a in (snap.get("assets") or []) if a.get("team")}


def _teams_for(snap, *assets):
    m = _asset_team(snap)
    return [m[a] for a in assets if a in m]


def _json_list(text):
    if isinstance(text, list):
        return text
    try:
        v = json.loads(text or "[]")
        return v if isinstance(v, list) else []
    except (TypeError, ValueError):
        return []


def _norm_entity(x):
    if isinstance(x, dict):
        x = x.get("value") or x.get("name") or x.get("id") or ""
    return str(x).strip().lower()


def _asset_ev(name):
    return {"label": f"Asset {name}", "type": "asset", "ref": name, "page": f"/assets?highlight={name}"}


def _finding_ev(fid):
    return {"label": fid, "type": "finding", "ref": fid, "page": f"/queue?highlight={fid}"}


def _day_series(dates, today_, days):
    """Daily counts for the `days` days ending the day BEFORE today_ (today is incomplete). Oldest first."""
    c = collections.Counter(dates)
    return [c.get(today_ - datetime.timedelta(days=i), 0) for i in range(days, 0, -1)]


# ---------------------------------------------------------------- the detectors
def kev_week_over_week(snap, cfg):
    fs, t = snap["findings"], today(snap)
    if len(fs) < cfg.get("min_findings", 20):
        return []
    dated = [(f, to_date(f.get("first_seen"))) for f in fs if _kev(f)]
    this = [f for f, d in dated if d and t - datetime.timedelta(days=7) < d <= t]
    prev = [f for f, d in dated if d and t - datetime.timedelta(days=14) < d <= t - datetime.timedelta(days=7)]
    n, p = len(this), len(prev)
    if n < cfg.get("min_new", 3) or (p and n / p < cfg.get("ratio", 1.5)):
        return []
    total_kev = sum(1 for f in fs if _kev(f))
    return [make("kev_week_over_week", "kev-wow", "risk-change", "remediation",
                 f"{n} new known-exploited findings this week" + (f" (up from {p})" if p else ""),
                 f"{n} findings on the CISA KEV list first appeared in the last 7 days, against {p} the week before. {total_kev} KEV-listed findings are open in total.",
                 "KEV-listed vulnerabilities are being exploited in the wild now; a rising count means exposure is growing faster than it was.",
                 evidence=[_finding_ev(f["id"]) for f in this[:5]] + [{"label": "KEV findings in the queue", "type": "page", "ref": "queue", "page": "/queue?kev=true"}],
                 impact=min(1.0, 0.5 + n / 40), impact_text=f"{n} newly exploitable findings", confidence=stats.confidence_from_n(n + p, 4),
                 confidence_reason=f"Counted from first-seen dates: {n} this week vs {p} last week ({n + p} observations).",
                 action_label="Review the new KEV findings", action_page="/queue?kev=true", action_role="analyst",
                 roles={"admin": 0.8, "analyst": 1.0, "exec": 0.8, "appsec": 0.5}, urgency=0.85)]


def sla_trend(snap, cfg):
    fs, t = snap["findings"], today(snap)
    if len(fs) < cfg.get("min_findings", 20):
        return []
    urgent = [f for f in fs if _is_urgent(f)]
    breached = [f for f in urgent if (f.get("sla") or {}).get("breached")]

    def due(f):
        r = (f.get("sla") or {}).get("days_remaining")
        return None if r is None else t + datetime.timedelta(days=r)
    recent = [f for f in breached if (d := due(f)) and t - datetime.timedelta(days=7) <= d <= t]
    before = [f for f in breached if (d := due(f)) and t - datetime.timedelta(days=14) <= d < t - datetime.timedelta(days=7)]
    share = len(breached) / len(urgent) if urgent else 0
    if len(recent) < cfg.get("min_new", 3) or (before and len(recent) / len(before) < cfg.get("ratio", 1.5)) or share < cfg.get("breach_share", 0.2) / 2:
        return []
    return [make("sla_trend", "sla-breach", "deadline", "remediation",
                 f"{len(recent)} Critical/High findings passed their SLA this week",
                 f"{len(recent)} Critical/High findings went past their deadline in the last 7 days ({len(before)} the week before); {len(breached)} of {len(urgent)} ({share:.0%}) are now overdue.",
                 "Overdue findings stay exposed longer than policy allows and count against the patch-SLA control evidence.",
                 evidence=[_finding_ev(f["id"]) for f in recent[:5]] + [{"label": "Overdue findings", "type": "page", "ref": "queue", "page": "/queue?sla=breached"}],
                 impact=min(1.0, 0.4 + share), impact_text=f"{share:.0%} of Critical/High overdue", confidence=stats.confidence_from_n(len(recent) + len(before), 4),
                 confidence_reason="Deadlines are derived from each finding's days remaining; MTTR itself needs closed-finding history, which this check does not use.",
                 action_label="Work the overdue queue", action_page="/queue?sla=breached", action_role="analyst",
                 roles={"admin": 0.9, "analyst": 1.0, "exec": 0.9, "appsec": 0.5}, urgency=0.8)]


def finding_burst(snap, cfg):
    fs, t = snap["findings"], today(snap)
    win = cfg.get("window_days", 3)
    since = t - datetime.timedelta(days=win)
    per_asset = collections.Counter()
    for f in fs:
        d, a = to_date(f.get("first_seen")), _asset(f)
        if a and d and d > since:
            per_asset[a] += 1
    names = {a for a in (_asset(f) for f in fs) if a}
    if len(names) < cfg.get("min_entities", 10):
        snap.setdefault("_gaps", []).append("finding_burst: fewer assets than the minimum for a peer baseline")
        return []
    counts = [per_asset.get(a, 0) for a in names]
    out = []
    for a, c in per_asset.most_common(5):
        z = stats.robust_z(c, counts, min_n=cfg.get("min_entities", 10), floor=1.0)
        if z is not None and z >= cfg.get("z", 3.5) and c >= cfg.get("min_count", 5):
            out.append(make("finding_burst", f"asset:{a}", "anomaly", "infra", f"{c} new findings on {a} in {win} days",
                            f"{a} gained {c} findings in the last {win} days; the typical asset gained {stats.median(counts):.0f} (robust z = {z:.1f}).",
                            "A sudden cluster usually means a new scan scope, a new vulnerable component or a change on that host.",
                            evidence=[_asset_ev(a)], impact=min(1.0, 0.3 + c / 30), impact_text=f"{c} findings in {win} days",
                            confidence=min(0.9, 0.5 + z / 20), confidence_reason=f"Median/MAD z-score {z:.1f} against {len(counts)} assets (threshold {cfg.get('z', 3.5)}).",
                            action_label="Open the asset's findings", action_page=f"/queue?asset={a}", action_role="analyst",
                            roles={"admin": 0.7, "analyst": 1.0, "appsec": 0.6}, entities=[f"asset:{a}"], teams=_teams_for(snap, a), urgency=0.6))
    return out


def exposure_change(snap, cfg):
    prev = (snap.get("baseline") or {}).get("assets")
    if prev is None:
        snap.setdefault("_gaps", []).append("exposure_change: no earlier asset snapshot yet, so changes cannot be seen; this refresh records the first one")
        return []
    sev = collections.defaultdict(list)
    for f in snap["findings"]:
        if _is_urgent(f) and _asset(f):
            sev[_asset(f)].append(f)
    out = []
    for a in snap["assets"]:
        name, before = a.get("name"), prev.get(a.get("name"))
        if not before or name not in sev:
            continue
        newly_exposed = before.get("facing") != "internet" and a.get("facing") == "internet"
        lost_owner = bool(before.get("owner")) and not a.get("owner")
        if not (newly_exposed or lost_owner):
            continue
        what = ("became internet-facing" if newly_exposed else "lost its owner")
        out.append(make("exposure_change", f"{name}:{'exposed' if newly_exposed else 'unowned'}", "drift", "infra", f"{name} {what} with {len(sev[name])} Critical/High findings",
                        f"Since the last check, {name} {what}. It carries {len(sev[name])} Critical/High open findings.",
                        "An asset that is newly reachable from the internet, or has no one accountable, turns existing findings into exposure nobody is working.",
                        evidence=[_asset_ev(name)] + [_finding_ev(f["id"]) for f in sev[name][:3]], impact=0.9 if newly_exposed else 0.6,
                        impact_text=f"{len(sev[name])} urgent findings", confidence=0.85, confidence_reason="Compared with the previous recorded asset snapshot (facing and owner fields).",
                        action_label="Confirm exposure and owner", action_page=f"/ownership?asset={name}", action_role="admin",
                        roles={"admin": 1.0, "analyst": 0.7, "exec": 0.5}, entities=[f"asset:{name}"], teams=_teams_for(snap, name), urgency=0.85))
    return out


def unowned_critical(snap, cfg):
    owned = {a.get("name") for a in snap["assets"] if a.get("owner") or a.get("team")}
    by = collections.defaultdict(list)
    for f in snap["findings"]:
        a = _asset(f)
        if a and f.get("severity") == "Critical" and a not in owned:
            by[a].append(f)
    if len(by) < cfg.get("min_findings", 1):
        return []
    top = sorted(by.items(), key=lambda kv: -len(kv[1]))
    n = sum(len(v) for v in by.values())
    return [make("unowned_critical", "unowned-critical", "gap", "remediation", f"{len(by)} assets with Critical findings have no owner",
                 f"{n} Critical findings sit on {len(by)} assets that no person or team owns, for example {', '.join(a for a, _ in top[:3])}.",
                 "Nobody is routed these findings, so they wait. Ownership is the first step of every remediation.",
                 evidence=[_asset_ev(a) for a, _ in top[:5]] + [{"label": "Ownership page", "type": "page", "ref": "ownership", "page": "/ownership"}],
                 impact=min(1.0, 0.4 + n / 30), impact_text=f"{n} Critical findings unrouted", confidence=0.95,
                 confidence_reason="A direct count: the asset has no owner and no team in the inventory.", action_label="Assign owners", action_page="/ownership", action_role="admin",
                 roles={"admin": 1.0, "analyst": 0.6, "exec": 0.6}, entities=[f"asset:{a}" for a, _ in top[:5]], urgency=0.6)]


def control_disappeared(snap, cfg):
    prev = (snap.get("baseline") or {}).get("controls")
    cur = {(c["asset_name"], c["control_class"], c["name"]): c for c in snap["controls"]}
    urgent_assets = {_asset(f) for f in snap["findings"] if _is_urgent(f)}
    out, t = [], today(snap)
    gone = []
    if prev is not None:
        gone = [tuple(k) for k in prev if tuple(k) not in cur]
    stale = [k for k, c in cur.items() if (d := to_date(c.get("last_seen"))) and (t - d).days > cfg.get("stale_days", 30)]
    if prev is None:
        snap.setdefault("_gaps", []).append("control_disappeared: no earlier controls snapshot yet; only stale last-seen dates can be checked")
    for kind, keys in (("removed", gone), ("not re-verified", stale)):
        by = collections.defaultdict(list)
        for k in keys:
            if k[0] in urgent_assets:
                by[k[0]].append(k)
        for asset, ks in by.items():
            names = ", ".join(sorted({k[2] for k in ks})[:3])
            how = "no longer recorded since the last check" if kind == "removed" else "not seen for over %d days" % cfg.get("stale_days", 30)
            out.append(make("control_disappeared", f"{asset}:{kind}", "risk-change", "infra", f"{asset}: {len(ks)} compensating control(s) {kind}",
                            f"{names} on {asset} was {kind} ({how}), and the asset still has Critical/High findings.",
                            "Findings were being tolerated because a control covered them; without it the residual risk is higher than the queue shows.",
                            evidence=[_asset_ev(asset), {"label": "Controls inventory", "type": "page", "ref": "controls", "page": "/controls"}],
                            impact=0.7, impact_text="compensating cover lost", confidence=0.8 if kind == "removed" else 0.55,
                            confidence_reason="Compared with the previous controls snapshot." if kind == "removed" else "Based only on the last-seen date; the control may still exist.",
                            action_label="Re-verify the control", action_page="/controls", action_role="admin",
                            roles={"admin": 1.0, "analyst": 0.8, "exec": 0.4}, entities=[f"asset:{asset}"], teams=_teams_for(snap, asset), urgency=0.7))
    return out


def exception_expiring(snap, cfg):
    kev = {f["id"]: f for f in snap["findings"] if _kev(f)}
    t, within = today(snap), cfg.get("within_days", 14)
    out = []
    for e in snap["exceptions"]:
        d = to_date(e.get("expires_on"))
        if e.get("status", "active") != "active" or e.get("computed_status", "active") != "active" or d is None or e.get("finding_id") not in kev:
            continue
        left = (d - t).days
        if 0 <= left <= within:
            f = kev[e["finding_id"]]
            out.append(make("exception_expiring", e["finding_id"], "deadline", "remediation", f"Exception on KEV finding {f['id']} ends in {left} days",
                            f"The risk exception on {f['id']} ({f.get('title', '')}) on {_asset(f)} expires {d.isoformat()}. The vulnerability is on the CISA KEV list.",
                            "When the exception lapses the finding returns to the queue as exploited-in-the-wild with no fix recorded; renewing needs a fresh justification.",
                            evidence=[_finding_ev(f["id"]), {"label": "Exceptions", "type": "page", "ref": "exceptions", "page": "/exceptions"}],
                            impact=0.75, impact_text="known-exploited finding returns to the queue", confidence=0.95, confidence_reason="A date comparison on the stored exception.",
                            action_label="Fix it or renew the exception", action_page="/exceptions", action_role="admin",
                            roles={"admin": 1.0, "analyst": 0.7, "exec": 0.5}, entities=[f"asset:{_asset(f)}"] if _asset(f) else [], teams=_teams_for(snap, _asset(f)),
                            urgency=min(1.0, 1.0 - left / (within + 1) * 0.6)))
    return out


def approval_stalled(snap, cfg):
    t, days = snap["now"], cfg.get("stalled_days", 7)
    out = []
    for a in snap["approvals"]:
        if (a.get("computed_status") or a.get("status")) != "approved" or a.get("triggered_at"):
            continue
        at = to_date(a.get("approved_at"))
        if at and (t.date() - at).days >= days:
            fid = a.get("finding_id")
            out.append(make("approval_stalled", str(fid), "deadline", "remediation", f"Approved fix for {fid} not started after {(t.date() - at).days} days",
                            f"The remediation of {fid} was approved on {at.isoformat()} by {a.get('approved_by')} but has not been triggered.",
                            "An approved change that is not run leaves the finding exposed while looking handled.",
                            evidence=[_finding_ev(fid), {"label": "Approvals", "type": "page", "ref": "approvals", "page": "/remediation-approvals"}],
                            impact=0.55, impact_text="approved but exposed", confidence=0.9, confidence_reason="Approval timestamp with no trigger recorded.",
                            action_label="Trigger or withdraw the approval", action_page="/remediation-approvals", action_role="admin",
                            roles={"admin": 1.0, "analyst": 0.8}, urgency=0.55))
    return out


def same_cve_many_apps(snap, cfg):
    groups = collections.defaultdict(lambda: {"assets": set(), "ids": [], "fix": None, "sev": 0, "pkg": None})
    for f in snap["findings"]:
        dep = f.get("dependency") or {}
        if not f.get("cve") or not (dep.get("package") or (f.get("asset") or {}).get("type") == "application"):
            continue
        g = groups[(f["cve"], dep.get("package"))]
        if _asset(f):
            g["assets"].add(_asset(f))
        g["ids"].append(f["id"])
        g["fix"] = g["fix"] or dep.get("fixed_version")
        g["pkg"] = g["pkg"] or dep.get("package")
        g["sev"] = max(g["sev"], SEV_RANK.get(f.get("severity"), 0))
    out = []
    for (cve, pkg), g in groups.items():
        if len(g["assets"]) < cfg.get("min_assets", 3):
            continue
        n = len(g["assets"])
        fix = f" to {g['fix']}" if g["fix"] else ""
        out.append(make("same_cve_many_apps", f"{cve}:{pkg}", "opportunity", "appsec", f"One upgrade of {pkg or cve} closes {cve} in {n} applications",
                        f"{cve} affects {n} applications ({', '.join(sorted(g['assets'])[:4])}{'...' if n > 4 else ''}); upgrading {pkg or 'the component'}{fix} in each closes {len(g['ids'])} findings.",
                        "The same fix applied once as a coordinated change is cheaper than {n} separate tickets.".format(n=n),
                        evidence=[_finding_ev(i) for i in g["ids"][:4]] + [{"label": "Applications", "type": "page", "ref": "applications", "page": "/applications"}],
                        impact=min(1.0, 0.3 + g["sev"] / 8 + n / 20), impact_text=f"{len(g['ids'])} findings closed", confidence=0.85,
                        confidence_reason="Grouped by identical CVE and package across the queue.", action_label="Plan the upgrade", action_page="/fix-prs", action_role="appsec",
                        roles={"appsec": 1.0, "analyst": 0.7, "admin": 0.5}, entities=[f"cve:{cve}"] + [f"app:{a}" for a in sorted(g["assets"])[:6]], urgency=0.5))
    return out


def source_quiet(snap, cfg):
    t, out = snap["now"], []
    for c in snap["connections"]:
        if not c.get("enabled") or not c.get("schedule_minutes"):
            continue
        last = to_date(c.get("last_run_at"))
        limit = c["schedule_minutes"] * cfg.get("factor", 3) / 1440.0
        age = (t.date() - last).days if last else None
        if last is None or age > max(limit, 1):
            out.append(make("source_quiet", f"conn:{c['name']}", "anomaly", "admin", f"Connection {c['name']} has gone quiet",
                            f"{c['name']} is scheduled every {c['schedule_minutes']} minutes but " + ("has never run." if last is None else f"last ran {age} days ago."),
                            "Findings and alerts from this source are going stale, so every score built on them is out of date.",
                            evidence=[{"label": "Connections", "type": "page", "ref": "connections", "page": "/connections"}], impact=0.6, impact_text="stale source data",
                            confidence=0.9, confidence_reason="Last-run time against the schedule (allowed lateness: %dx the interval)." % cfg.get("factor", 3),
                            action_label="Check the connection", action_page="/connections", action_role="admin", roles={"admin": 1.0, "analyst": 0.6}, admin_only=True, urgency=0.65))
    dates = [d for d in (to_date(f.get("last_seen")) for f in snap["findings"]) if d]
    if dates:
        age = (t.date() - max(dates)).days
        if age > cfg.get("scan_max_age_days", 7):
            out.append(make("source_quiet", "scan-data", "anomaly", "admin", f"No finding refreshed in {age} days",
                            f"The newest last-seen date on any finding is {max(dates).isoformat()}, {age} days ago.",
                            "Risk scores assume the findings are current; a quiet scanner means closed issues look open and new ones are missing.",
                            evidence=[{"label": "Connections", "type": "page", "ref": "connections", "page": "/connections"}], impact=0.7, impact_text="all scores may be stale",
                            confidence=0.8, confidence_reason="Newest last_seen across the queue.", action_label="Check the scanners", action_page="/connections", action_role="admin",
                            roles={"admin": 1.0, "analyst": 0.8, "exec": 0.4}, urgency=0.7))
    return out


def noisy_rules(snap, cfg):
    by = collections.defaultdict(lambda: [0, 0])
    for a in snap["alerts"]:
        if not a.get("rule_name") or a.get("status") not in ("closed", "resolved") or not a.get("disposition"):
            continue
        by[a["rule_name"]][0] += 1
        by[a["rule_name"]][1] += a["disposition"] in ("false-positive", "benign")
    out = []
    for rule, (n, fp) in by.items():
        if n >= cfg.get("min_closed", 10) and fp / n >= cfg.get("fp_rate", 0.8):
            out.append(make("noisy_rules", rule, "anomaly", "soc", f"Detection rule '{rule}' is mostly noise",
                            f"{fp} of the last {n} closed alerts from '{rule}' were false positives or benign ({fp / n:.0%}).",
                            "A noisy rule trains analysts to ignore it and consumes triage time; tuning it protects the real alerts.",
                            evidence=[{"label": "Detection engineering", "type": "page", "ref": "detections", "page": "/soc"}], impact=0.5, impact_text=f"{fp} wasted triages",
                            confidence=stats.confidence_from_n(n, 10), confidence_reason=f"{n} closed alerts with a recorded disposition.", action_label="Tune or disable the rule",
                            action_page="/soc", action_role="analyst", roles={"analyst": 1.0, "admin": 0.6}, admin_only=True, urgency=0.4))
    return out


def alert_volume_anomaly(snap, cfg):
    t = today(snap)
    days = cfg.get("min_days", 14)
    ds = [d for d in (to_date(a.get("received_at") or a.get("occurred_at")) for a in snap["alerts"]) if d]
    if not ds or (t - min(ds)).days < days:
        snap.setdefault("_gaps", []).append(f"alert_volume_anomaly: needs {days} days of alert history (not enough history)")
        return []
    span = min(max((t - min(ds)).days, days), 56)
    series = _day_series(ds, t, span)
    value, history = series[-1], series[:-1]
    forecast, method = stats.baseline_forecast(history)
    z = stats.robust_z(value, history, min_n=days - 1, floor=1.0)
    if z is None or forecast is None or value < cfg.get("min_count", 10) or abs(z) < cfg.get("z", 3.5) or value < forecast:
        return []
    return [make("alert_volume_anomaly", "alert-volume", "anomaly", "soc", f"Alert volume spiked: {value} yesterday vs about {forecast:.0f} expected",
                 f"{value} alerts arrived yesterday. The {method} baseline expects about {forecast:.0f} (median {stats.median(history):.0f}; robust z = {z:.1f}).",
                 "A volume spike can mean an attack, a broken integration or a rule change; each needs a different response.",
                 evidence=[{"label": "SOC alerts", "type": "page", "ref": "soc", "page": "/soc"}], impact=min(1.0, 0.4 + z / 20), impact_text=f"{value - forecast:.0f} extra alerts",
                 confidence=min(0.9, 0.4 + len(history) / 100 + z / 30), confidence_reason=f"{len(history)} days of history, median/MAD z = {z:.1f}, baseline: {method}.",
                 action_label="Triage the spike", action_page="/soc", action_role="analyst", roles={"analyst": 1.0, "admin": 0.7}, admin_only=True, urgency=0.75)]


def entity_repeat(snap, cfg):
    t, win = today(snap), cfg.get("window_days", 14)
    since = t - datetime.timedelta(days=win)
    seen = collections.defaultdict(set)

    def add(entity, rec):
        e = _norm_entity(entity)
        if e:
            seen[e].add(rec)
    for a in snap["alerts"]:
        d = to_date(a.get("received_at") or a.get("occurred_at"))
        if d and d >= since:
            for e in [a.get("asset")] + _json_list(a.get("entities_json")):
                add(e, f"alert:{a.get('id')}")
    for h in snap["hunts"]:
        d = to_date(h.get("created_at"))
        if d and d >= since:
            for e in _json_list(h.get("assets_json")):
                add(e, f"hunt:{h.get('id')}")
    for c in snap["cases"]:
        d = to_date(c.get("created_at"))
        if d and d >= since:
            for e in _json_list(c.get("assets_json")) + _json_list(c.get("entities_json")):
                add(e, f"case:{c.get('id')}")
    out = []
    for e, recs in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        kinds = {r.split(":")[0] for r in recs}
        if len(recs) >= cfg.get("min_records", 3) and len(kinds) >= 1:
            out.append(make("entity_repeat", e, "correlation", "soc", f"{e} appears in {len(recs)} alerts, hunts or cases in {win} days",
                            f"'{e}' was touched by {len(recs)} separate records ({', '.join(sorted(kinds))}) in the last {win} days.",
                            "Repeated attention on one entity is a stronger signal than any one alert: it may be the same incident worked in pieces.",
                            evidence=[{"label": r, "type": r.split(':')[0], "ref": r.split(':')[1], "page": "/soc" if not r.startswith("hunt") else "/hunting"} for r in sorted(recs)[:6]],
                            impact=min(1.0, 0.35 + len(recs) / 12), impact_text=f"{len(recs)} related records", confidence=stats.confidence_from_n(len(recs), 3),
                            confidence_reason="Exact (case-insensitive) entity match across alerts, hunts and cases.", action_label="Review as one incident", action_page="/soc", action_role="analyst",
                            roles={"analyst": 1.0, "admin": 0.6}, entities=[f"asset:{e}"], admin_only=True, urgency=0.6))
    return out[:5]


def posture_drop(snap, cfg):
    rows, maps = snap["grc_evidence"], snap["grc_mappings"] or {}
    pts = cfg.get("min_points", 6)
    by_day = collections.defaultdict(lambda: collections.defaultdict(list))   # framework -> day -> [pass 0/1]
    for r in rows:
        d = to_date(r.get("collected_at"))
        if d is None or r.get("result") not in ("pass", "fail", "warn"):
            continue
        for fw in (maps.get(r.get("test_id")) or {}):
            by_day[fw][d].append(1.0 if r["result"] == "pass" else 0.0)
    out, short = [], 0
    for fw, days in by_day.items():
        series = [sum(v) / len(v) for _, v in sorted(days.items())]
        if len(series) < pts:
            short += 1
            continue
        cp = stats.change_point(series, min_seg=2, min_shift=1.5)
        drop = (cp["before"] - cp["after"]) if cp else 0
        if cp and drop >= cfg.get("min_drop", 0.15):
            out.append(make("posture_drop", fw, "risk-change", "grc", f"Control-test pass rate fell {drop:.0%} for {fw}",
                            f"The share of passing automated control tests for {fw} moved from {cp['before']:.0%} to {cp['after']:.0%} (a level shift {len(series) - cp['index']} collection(s) ago).",
                            "These tests are the evidence an assessor looks at; a drop is a compliance risk before it is an audit finding.",
                            evidence=[{"label": "Governance, risk and compliance", "type": "page", "ref": "grc", "page": "/grc"}], impact=min(1.0, 0.4 + drop), impact_text=f"-{drop:.0%} pass rate",
                            confidence=min(0.9, 0.4 + len(series) / 40 + cp["score"] / 20), confidence_reason=f"Change-point on {len(series)} daily pass rates (shift score {cp['score']:.1f}); 'na' results are excluded, never counted as passes.",
                            action_label="Open the failing tests", action_page="/grc", action_role="admin", roles={"admin": 1.0, "exec": 0.9, "analyst": 0.4}, admin_only=True, urgency=0.6))
    if short and not out:
        snap.setdefault("_gaps", []).append(f"posture_drop: {short} framework(s) have fewer than {pts} evidence collections (not enough history)")
    return out


def expiry(snap, cfg):
    out, t = [], today(snap)
    lic = snap.get("license") or {}
    if lic.get("state") in ("expiring", "grace", "expired"):
        out.append(make("expiry", "licence", "deadline", "admin", f"Licence {lic['state']}: {lic.get('message', '')}",
                        lic.get("message", ""), "When the licence lapses and grace ends, only the core platform remains available.", evidence=[{"label": "Licence", "type": "page", "ref": "license", "page": "/capabilities"}],
                        impact=0.9 if lic["state"] == "expired" else 0.6, impact_text="modules will lock", confidence=0.99, confidence_reason="Read from the verified licence.",
                        action_label="Renew the licence", action_page="/capabilities", action_role="admin", roles={"admin": 1.0, "exec": 0.7}, admin_only=True, urgency=0.9 if lic["state"] != "expiring" else 0.6))
    for k in snap["api_keys"]:
        d = to_date(k.get("expires_at"))
        if k.get("revoked_at") or d is None:
            continue
        left = (d - t).days
        if left <= cfg.get("key_within_days", 14):
            out.append(make("expiry", f"key:{k.get('prefix') or k.get('name')}", "deadline", "admin", f"API key '{k.get('name')}' " + (f"expires in {left} days" if left >= 0 else "has expired"),
                            f"The key {k.get('name')} (prefix {k.get('prefix')}) " + (f"expires {d.isoformat()}." if left >= 0 else f"expired {-left} days ago."),
                            "Integrations using it will start failing; CI uploads and scanner pushes stop silently.", evidence=[{"label": "API keys", "type": "page", "ref": "api-keys", "page": "/connections"}],
                            impact=0.5, impact_text="an integration will fail", confidence=0.99, confidence_reason="Expiry date on the stored key.", action_label="Rotate the key", action_page="/connections",
                            action_role="admin", roles={"admin": 1.0}, admin_only=True, urgency=0.8 if left < 3 else 0.5))
    return out


def ai_cost_spike(snap, cfg):
    by = collections.defaultdict(float)
    for e in snap["ai_events"]:
        d, c = to_date(e.get("ts")), e.get("cost_usd")
        if d is not None and c is not None:       # unknown cost is never counted as zero
            by[d] += float(c)
    t = today(snap)
    ds = sorted(by)
    if len(ds) < cfg.get("min_days", 10):
        snap.setdefault("_gaps", []).append("ai_cost_spike: not enough days of AI cost history")
        return []
    span = (t - ds[0]).days
    series = [by.get(t - datetime.timedelta(days=i), 0.0) for i in range(span, 0, -1)]
    value, history = series[-1], series[:-1]
    z = stats.robust_z(value, history, min_n=cfg.get("min_days", 10), floor=max(1.0, cfg.get("min_cost_usd", 5) / 5))
    if z is None or z < cfg.get("z", 3.5) or value < cfg.get("min_cost_usd", 5):
        return []
    return [make("ai_cost_spike", "ai-cost", "anomaly", "ai", f"AI spend jumped to ${value:,.2f} yesterday",
                 f"Recorded AI cost was ${value:,.2f} yesterday against a typical ${stats.median(history):,.2f} a day (robust z = {z:.1f}).",
                 "A cost spike usually means a runaway job, a new heavy user or a model change.",
                 evidence=[{"label": "AI usage", "type": "page", "ref": "ai-usage", "page": "/ai-usage"}], impact=min(1.0, 0.3 + z / 20), impact_text=f"${value:,.2f} in a day",
                 confidence=min(0.9, 0.4 + len(history) / 100 + z / 30), confidence_reason=f"Median/MAD z = {z:.1f} over {len(history)} days; days with unknown cost are excluded.",
                 action_label="See who and what", action_page="/ai-usage", action_role="admin", roles={"admin": 1.0, "exec": 0.7}, admin_only=True, urgency=0.6)]


def policy_drift(snap, cfg_all):
    cfg, drift = cfg_all["_own"], cfg_all["_drift"]
    prefixes, keys = tuple(drift.get("action_prefixes", [])), set(drift.get("approval_keys", []))
    since = today(snap) - datetime.timedelta(days=cfg.get("window_days", 14))
    hits = []
    for e in snap["activity"]:
        d = to_date(e.get("timestamp"))
        if d is None or d < since or not str(e.get("action", "")).startswith(prefixes):
            continue
        det = e.get("details")
        det = det if isinstance(det, dict) else {}
        if not (keys & set(det)):
            hits.append(e)
    if not hits:
        return []
    actors = sorted({h["actor"] for h in hits})
    return [make("policy_drift", "policy-drift", "drift", "admin", f"{len(hits)} configuration change(s) without a recorded approval",
                 f"In the last {cfg.get('window_days', 14)} days {len(hits)} change(s) to policy or configuration were made ({', '.join(sorted({h['action'] for h in hits})[:4])}) with no approval reference, by {', '.join(actors[:3])}.",
                 "Unreviewed policy changes are how scoring, gates and thresholds quietly drift away from what was agreed.",
                 evidence=[{"label": f"{h['action']} by {h['actor']}", "type": "activity", "ref": str(h.get("id")), "page": "/activity-log"} for h in hits[:5]],
                 impact=min(1.0, 0.4 + len(hits) / 15), impact_text=f"{len(hits)} unapproved changes", confidence=0.6,
                 confidence_reason="Matched on action names and the absence of an approval key in the logged details; a change may have been approved outside Quanta.",
                 action_label="Review the changes", action_page="/activity-log", action_role="admin", roles={"admin": 1.0, "exec": 0.5}, admin_only=True, urgency=0.5)]


# ---------------------------------------------------------------- registry
class Detector:
    def __init__(self, name, kind, module, needs, fn, doc):
        self.name, self.kind, self.module, self.needs, self.fn, self.doc = name, kind, module, tuple(needs), fn, doc


DETECTORS = [
    Detector("kev_week_over_week", "risk-change", "remediation", ("findings",), kev_week_over_week, "New KEV-listed findings this week vs last week"),
    Detector("sla_trend", "deadline", "remediation", ("findings",), sla_trend, "Critical/High findings newly past SLA"),
    Detector("finding_burst", "anomaly", "infra", ("findings", "assets"), finding_burst, "A burst of new findings on one asset (robust z vs peers)"),
    Detector("exposure_change", "drift", "infra", ("findings", "assets"), exposure_change, "Newly internet-facing or newly unowned assets with urgent findings"),
    Detector("unowned_critical", "gap", "remediation", ("findings", "assets"), unowned_critical, "Critical findings on assets with no owner"),
    Detector("control_disappeared", "risk-change", "infra", ("findings", "controls"), control_disappeared, "A compensating control disappeared or went stale"),
    Detector("exception_expiring", "deadline", "remediation", ("findings", "exceptions"), exception_expiring, "An exception on a KEV finding expires soon"),
    Detector("approval_stalled", "deadline", "remediation", ("approvals",), approval_stalled, "An approved remediation that has not been started"),
    Detector("same_cve_many_apps", "opportunity", "appsec", ("findings",), same_cve_many_apps, "One upgrade closes the same CVE in many applications"),
    Detector("source_quiet", "anomaly", "admin", ("findings", "connections"), source_quiet, "A connector or the scan data went quiet"),
    Detector("noisy_rules", "anomaly", "soc", ("alerts",), noisy_rules, "A detection rule that is mostly false positives"),
    Detector("alert_volume_anomaly", "anomaly", "soc", ("alerts",), alert_volume_anomaly, "Daily alert volume far above its baseline"),
    Detector("entity_repeat", "correlation", "soc", ("alerts", "hunts", "cases"), entity_repeat, "One entity repeatedly touched by alerts, hunts and cases"),
    Detector("posture_drop", "risk-change", "grc", ("grc_evidence", "grc_mappings"), posture_drop, "Control-test pass rate dropped for a framework"),
    Detector("expiry", "deadline", "admin", ("api_keys", "license"), expiry, "Licence or API key expiry"),
    Detector("ai_cost_spike", "anomaly", "ai", ("ai_events",), ai_cost_spike, "AI cost spike vs its daily baseline"),
    Detector("policy_drift", "drift", "admin", ("activity",), policy_drift, "Configuration changed without an approval reference"),
]
BY_NAME = {d.name: d for d in DETECTORS}


def capture_baselines(snap):
    """What the NEXT refresh compares against: asset facing/owner and the controls inventory. Only keys whose source was available are returned."""
    out = {}
    if snap.get("assets") is not None:
        out["assets"] = {a["name"]: {"facing": a.get("facing"), "owner": a.get("owner"), "team": a.get("team")} for a in snap["assets"] if a.get("name")}
    if snap.get("controls") is not None:
        out["controls"] = sorted([c["asset_name"], c["control_class"], c["name"]] for c in snap["controls"])
    return out


def run_all(snap, cfg):
    """-> (insights, gaps, errors). `cfg` is the loaded insights.yaml."""
    insights, gaps, errors = [], [], []
    snap["_gaps"] = []
    for d in DETECTORS:
        own = (cfg.get("detectors") or {}).get(d.name) or {}
        if own.get("enabled", True) is False:
            continue
        missing = [n for n in d.needs if snap.get(n) is None]
        if missing:
            gaps.append(f"{d.name}: needs {', '.join(missing)} (not available)")
            continue
        try:
            arg = {**own, "_own": own, "_drift": cfg.get("drift") or {}} if d.name == "policy_drift" else own
            insights.extend(d.fn(snap, arg))
        except Exception as exc:  # noqa: BLE001 - one broken detector must never stop the rest
            errors.append(f"{d.name}: {type(exc).__name__}")
    gaps.extend(snap.pop("_gaps", []))
    return insights, gaps, errors
