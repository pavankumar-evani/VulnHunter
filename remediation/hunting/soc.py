"""
L1 alert investigation: the work a first-line analyst does on every alert, done the same way every time and written up for them to check.

For one alert it (1) classifies it, (2) reads the history of the same rule and host, (3) pulls out the indicators and, if a reputation
connection is configured, looks the public ones up, (4) optionally asks the SIEM whether matching events exist on the host, (5) adds what
Quanta knows about the host (open and known-exploited vulnerabilities, owner), and (6) scores the signals into a verdict.

The verdict is a recommendation for a person to validate: likely-true-positive, likely-false-positive, or escalate-l2. It is a plain weighted
score of the signals in remediation/config/soc_triage.yaml, and the reasons it returns name every signal that fired. When the evidence is thin
or mixed the answer is escalate-l2, never a guess at closing the alert. A Critical alert is never called a likely false positive.

Nothing here closes or changes an alert; applying the verdict is a separate step a person takes.
"""
import datetime
from pathlib import Path

import yaml

from remediation.hunting import generate, triage

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "soc_triage.yaml"
VERDICTS = ("likely-true-positive", "likely-false-positive", "escalate-l2")


def config(path=None):
    with open(path or CONFIG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _parse(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def classify(alert, cfg=None):
    cfg = cfg or config()
    tech = (alert.get("technique") or "").upper().split(".")[0]
    if tech in (cfg.get("technique_categories") or {}):
        return cfg["technique_categories"][tech]
    title = (alert.get("title") or "").lower()
    for cat, words in (cfg.get("title_keywords") or {}).items():
        if any(w in title for w in words):
            return cat
    return "other"


def history(alert, alerts, cfg=None, now=None):
    """What earlier alerts say about this rule and this host."""
    cfg = cfg or config()
    h = cfg.get("history") or {}
    now = now or datetime.datetime.now(datetime.timezone.utc)
    window = now - datetime.timedelta(days=h.get("window_days", 30))
    recur = now - datetime.timedelta(days=h.get("recurrence_days", 7))
    rule, host = alert.get("rule_name"), (alert.get("asset") or "").lower()
    others = [a for a in alerts if a["id"] != alert["id"]]
    rule_closed = [a for a in others if rule and a.get("rule_name") == rule and a["status"] == "closed" and a.get("disposition") in ("true-positive", "benign", "false-positive")]
    noise = [a for a in rule_closed if a["disposition"] in ("false-positive", "benign")]
    same_host = [a for a in others if host and (a.get("asset") or "").lower() == host and (_parse(a.get("received_at")) or now) >= window]
    recent_tp = [a for a in others if a.get("disposition") == "true-positive" and (_parse(a.get("closed_at") or a.get("received_at")) or now) >= recur
                 and ((host and (a.get("asset") or "").lower() == host) or (rule and a.get("rule_name") == rule))]
    prior_benign_same_host = [a for a in rule_closed if host and (a.get("asset") or "").lower() == host and a["disposition"] in ("false-positive", "benign")]
    return {"rule_closed": len(rule_closed), "rule_noise": len(noise), "rule_noise_rate": round(len(noise) / len(rule_closed), 2) if rule_closed else None,
            "same_host_alerts": [{"id": a["id"], "title": a["title"], "status": a["status"], "disposition": a.get("disposition"), "received_at": a["received_at"]} for a in same_host[:10]],
            "recent_true_positives": [a["id"] for a in recent_tp], "prior_benign_same_host": [a["id"] for a in prior_benign_same_host]}


def indicators(alert):
    e = alert.get("entities") or {}
    return [{"type": t, "value": v} for t, key in (("ip", "ips"), ("domain", "domains"), ("hash", "hashes"), ("url", "urls")) for v in (e.get(key) or [])][:25]


def siem_evidence(alert, run, cfg=None):
    """Runs the library's host-scoped detections for the alert's technique through `run(query, earliest) -> {count, rows}`."""
    cfg = cfg or config()
    s = cfg.get("siem_evidence") or {}
    host = alert.get("asset")
    tech = (alert.get("technique") or "").upper().split(".")[0]
    if not host or not tech:
        return []
    out = []
    for q in generate.build_queries([tech], [host])[: s.get("max_queries", 3)]:
        try:
            r = run(q["query"], s.get("lookback", "-24h"))
            out.append({"name": q["name"], "technique": tech, "query": q["query"], "count": r["count"], "rows": r["rows"][:3], "error": None})
        except Exception as exc:  # noqa: BLE001 - a search failure is evidence of nothing, and is reported as such
            out.append({"name": q["name"], "technique": tech, "query": q["query"], "count": None, "rows": [], "error": str(exc)[:200]})
    return out


def score(signals, cfg, severity):
    w, v = cfg.get("weights") or {}, cfg.get("verdict") or {}
    tp = sum(w.get(k, 0) for k in ("ioc_malicious", "kev_match", "recurrence", "siem_corroboration", "critical_severity") if signals.get(k))
    fp = sum(w.get(k, 0) for k in ("rule_noise_history", "clean_indicators", "prior_benign_same_host") if signals.get(k))
    high = v.get("high_confidence_score", 5)
    if tp >= v.get("true_positive_min_score", 3) and tp > fp:
        return "likely-true-positive", "high" if tp >= high else "medium", tp, fp
    if fp >= v.get("false_positive_min_score", 3) and tp == 0 and not (v.get("critical_never_false_positive", True) and severity == "Critical"):
        return "likely-false-positive", "high" if fp >= high else "medium", tp, fp
    return "escalate-l2", "low" if (tp + fp) == 0 else "medium", tp, fp


def investigate(alert, alerts, findings, owners=None, lookup=None, siem_run=None, cfg=None, now=None):
    """Returns the investigation: classification, history, indicators with reputation, SIEM evidence, host context, signals, verdict, reasons, timeline.

    lookup(value) -> reputation dict (see ReputationConnector.lookup) or raises; siem_run(query, earliest) -> {count, rows}. Both are optional."""
    cfg = cfg or config()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    category = classify(alert, cfg)
    hist = history(alert, alerts, cfg, now)
    ctx = triage.enrich(alert, findings, owners or {})
    inds = indicators(alert)
    threshold = (cfg.get("reputation_thresholds") or {}).get(category, 10)
    looked, lookup_note = [], None
    if lookup and inds:
        for ind in inds:
            try:
                r = lookup(ind["value"])
            except Exception as exc:  # noqa: BLE001
                lookup_note = f"Reputation lookup was unavailable ({str(exc)[:120]}); indicators were not scored."
                looked = []
                break
            looked.append({**ind, **{k: r.get(k) for k in ("result", "malicious", "suspicious", "harmless", "undetected", "total", "reason")}})
    elif inds:
        lookup_note = "No reputation connection is configured, so indicators were not looked up."
    evidence = siem_evidence(alert, siem_run, cfg) if siem_run else []
    related_kev = [f for f in ctx["findings"] if f["kev"] and f["related_to_alert"]]
    signals = {
        "ioc_malicious": any((x.get("malicious") or 0) >= threshold for x in looked),
        "kev_match": bool(related_kev) or (ctx["kev_findings"] > 0 and any(f["related_to_alert"] for f in ctx["findings"])),
        "recurrence": bool(hist["recent_true_positives"]),
        "siem_corroboration": any((e.get("count") or 0) > 0 for e in evidence),
        "critical_severity": alert.get("severity") == "Critical",
        "rule_noise_history": (hist["rule_closed"] >= (cfg.get("history") or {}).get("rule_noise_min_closed", 10)
                               and (hist["rule_noise_rate"] or 0) >= (cfg.get("history") or {}).get("rule_noise_false_positive_rate", 0.9)),
        "clean_indicators": bool(looked) and all(x.get("result") == "seen" and (x.get("malicious") or 0) == 0 for x in looked),
        "prior_benign_same_host": bool(hist["prior_benign_same_host"]),
    }
    verdict, confidence, tp, fp = score(signals, cfg, alert.get("severity"))
    reasons = []
    if signals["ioc_malicious"]:
        bad = [x for x in looked if (x.get("malicious") or 0) >= threshold]
        reasons.append("Flagged indicator(s): " + ", ".join(f"{x['value']} ({x['malicious']} engines)" for x in bad) + f"; the {category} threshold is {threshold}.")
    if signals["kev_match"]:
        reasons.append("A known-exploited vulnerability on the host matches this alert's technique.")
    if signals["recurrence"]:
        reasons.append(f"An earlier true positive on the same host or rule within {(cfg.get('history') or {}).get('recurrence_days', 7)} days.")
    if signals["siem_corroboration"]:
        reasons.append("The SIEM shows matching events on the host.")
    if signals["critical_severity"]:
        reasons.append("The alert is Critical.")
    if signals["rule_noise_history"]:
        reasons.append(f"This rule's closed alerts are {round(100 * hist['rule_noise_rate'])}% false positive or benign over {hist['rule_closed']} alerts.")
    if signals["clean_indicators"]:
        reasons.append("Every looked-up indicator is known and none is flagged.")
    if signals["prior_benign_same_host"]:
        reasons.append("This rule was closed benign or as a false positive on this host before.")
    if not reasons:
        reasons.append("No signal either way, so it goes to a person.")
    if verdict == "escalate-l2" and tp and fp:
        reasons.append("Signals point both ways, so it goes to a person.")
    timeline = [{"at": alert.get("occurred_at") or alert.get("received_at"), "event": f"Alert raised: {alert['title']}"}]
    timeline += [{"at": a["received_at"], "event": f"Earlier alert #{a['id']} on the same host: {a['title']} ({a.get('disposition') or a['status']})"} for a in hist["same_host_alerts"][:5]]
    timeline.append({"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "Quanta investigation run"})
    timeline.sort(key=lambda x: x["at"] or "")
    return {"alert_id": alert["id"], "category": category, "threshold": threshold, "history": hist, "indicators": looked or inds, "lookup_note": lookup_note,
            "siem_evidence": evidence, "host": {"asset": alert.get("asset"), "owner": ctx["owner"], "open_findings": ctx["open_findings"], "kev_findings": ctx["kev_findings"],
                                                "findings": ctx["findings"]}, "signals": signals, "scores": {"true_positive": tp, "false_positive": fp},
            "verdict": verdict, "confidence": confidence, "reasons": reasons, "timeline": timeline, "runbook": ctx["runbook"]}


def render_markdown(alert, inv):
    L = [f"# Alert investigation: {alert['title']}", "",
         f"**Recommended verdict: {inv['verdict']}** (confidence {inv['confidence']}). A person validates this; Quanta has not closed or changed the alert.", "",
         "## Why", *[f"- {r}" for r in inv["reasons"]], "",
         "## Alert", f"- Source: {alert['source']} / {alert['external_id']}", f"- Severity: {alert['severity']}   Rule: {alert.get('rule_name') or 'not given'}   ATT&CK: {alert.get('technique') or 'not given'}",
         f"- Host: {alert.get('asset') or 'not given'}   Category: {inv['category']}"]
    ent = alert.get("entities") or {}
    if ent.get("user"):
        L.append(f"- User: {ent['user']}")
    L += ["", "## Indicators"]
    if inv["indicators"]:
        L += ["| Indicator | Type | Result | Flagged by |", "|---|---|---|---|"]
        for x in inv["indicators"]:
            L.append(f"| {x['value']} | {x['type']} | {x.get('result') or 'not looked up'} | {x.get('malicious') if x.get('malicious') is not None else '-'}{' of ' + str(x['total']) if x.get('total') else ''} |")
    else:
        L.append("None found in the alert.")
    if inv["lookup_note"]:
        L.append(f"\n{inv['lookup_note']}")
    h = inv["history"]
    L += ["", "## History", f"- Rule: {h['rule_closed']} closed alerts, {h['rule_noise']} benign or false positive" + (f" ({round(100 * h['rule_noise_rate'])}%)" if h["rule_noise_rate"] is not None else ""),
          f"- Same host in the last window: {len(h['same_host_alerts'])} alert(s)"]
    L += ["", "## Host context", f"- Owner: {inv['host']['owner'] or 'none recorded'}", f"- Open vulnerabilities: {inv['host']['open_findings']}, known-exploited: {inv['host']['kev_findings']}"]
    for f in inv["host"]["findings"][:5]:
        L.append(f"  - {f['id']} {f['title']} ({f['severity']}{', ' + f['cve'] if f.get('cve') else ''}){' KEV' if f['kev'] else ''}{' - matches this alert' if f['related_to_alert'] else ''}")
    L += ["", "## SIEM evidence"]
    if inv["siem_evidence"]:
        for e in inv["siem_evidence"]:
            L.append(f"- {e['name']}: " + (f"{e['count']} event(s)" if e["error"] is None else f"search failed ({e['error']})"))
    else:
        L.append("The SIEM was not searched for this investigation.")
    L += ["", "## Timeline", *[f"- {t['at']}  {t['event']}" for t in inv["timeline"]]]
    if inv.get("runbook"):
        L += ["", f"## Suggested steps: {inv['runbook']['title']}", *[f"{i}. {s}" for i, s in enumerate(inv["runbook"]["steps"], 1)]]
    return "\n".join(L) + "\n"
