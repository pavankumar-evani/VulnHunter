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
import ipaddress
import re
from pathlib import Path

import yaml

from remediation.hunting import generate, report, search_base, translate, triage

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
    rule_closed = [a for a in others if rule and a.get("rule_name") == rule and a["status"] == "closed" and a.get("disposition") in ("true-positive", "benign", "false-positive")
                   and a.get("action_taken") != "auto-closed"]   # an alert the system closed is not a person's judgement of the rule
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


SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.@:/-]{1,255}$")
LANG_KEY = {"splunk-spl": "spl"}   # the key a playbook template for a language is stored under (the language name itself, except SPL)
GOLDEN_PATH = Path(__file__).resolve().parent / "golden_playbook.yaml"


def golden_playbook(path=None):
    with open(path or GOLDEN_PATH, encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("queries") or []


def _fill(template, values):
    """Fills {placeholders} from the alert. Alert fields can be written by an attacker, so a value that is not plain host/user/address text is refused rather than escaped."""
    out = template
    for k, v in values.items():
        if "{" + k + "}" in out:
            if not v or not SAFE_VALUE.match(str(v)):
                return None
            out = out.replace("{" + k + "}", str(v))
    return None if re.search(r"\{[a-z]+\}", out) else out


def playbook_values(alert):
    e = alert.get("entities") or {}
    pub = [i for i in e.get("ips") or [] if not _private(i)]
    return {"host": alert.get("asset") or e.get("host"), "user": e.get("user"), "ip": (pub or (e.get("ips") or [None]))[0], "domain": (e.get("domains") or [None])[0],
            "hash": (e.get("hashes") or [None])[0], "url": (e.get("urls") or [None])[0]}


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def siem_evidence(alert, run, cfg=None, language=None):
    """Runs the golden playbook's searches for this alert, then the library searches that would corroborate its technique, through
    `run(query, earliest) -> {count, rows}`. Every look-back is capped at max_lookback_days. Returns one record per search."""
    cfg = cfg or config()
    language = language or getattr(run, "language", None) or "splunk-spl"
    key = LANG_KEY.get(language, language)
    cap = cfg.get("max_lookback_days", 90)
    limit = (cfg.get("siem_evidence") or {}).get("max_queries", 6)
    values = playbook_values(alert)
    category = classify(alert, cfg)
    tech = (alert.get("technique") or "").upper().split(".")[0]
    planned = []
    for q in golden_playbook():
        applies = q.get("for") or []
        if applies and category not in applies and tech not in applies:
            continue
        spl = _fill(q[key], values) if q.get(key) else None
        if spl and all(values.get(n) for n in q.get("needs") or []):
            planned.append({"name": q["name"], "kind": "context", "query": spl, "days": min(int(q.get("lookback_days", 7)), cap)})
    host = values["host"]
    if host and tech and SAFE_VALUE.match(str(host)):
        for q in generate.build_queries([tech], [host])[:2]:
            try:
                text = translate.render(language, q["selection"], [host]) if language != "splunk-spl" else q["query"]
            except translate.NotExpressible:
                continue   # not expressible in this connection's language: left out of the plan, never sent half-translated
            planned.append({"name": q["name"], "kind": "corroboration", "query": text, "days": min(7, cap)})
    out = []
    for q in planned[:limit]:
        base = {"name": q["name"], "technique": tech or None, "kind": q["kind"], "query": q["query"], "lookback_days": q["days"], "window": f"{q['days']} days"}
        try:
            r = run(q["query"], f"-{q['days']}d")
            out.append({**base, "count": r["count"], "rows": r["rows"][:3], "error": None})
        except Exception as exc:  # noqa: BLE001 - a search failure is evidence of nothing, and is reported as such
            out.append({**base, "count": None, "rows": [], "error": str(exc)[:200]})
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


def investigate(alert, alerts, findings, owners=None, lookup=None, siem_run=None, cfg=None, now=None, identity=None, playbooks=()):
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
    evidence = siem_evidence(alert, siem_run, cfg, getattr(siem_run, "language", None)) if siem_run else []
    related_kev = [f for f in ctx["findings"] if f["kev"] and f["related_to_alert"]]
    signals = {
        "ioc_malicious": any((x.get("malicious") or 0) >= threshold for x in looked),
        "kev_match": bool(related_kev) or (ctx["kev_findings"] > 0 and any(f["related_to_alert"] for f in ctx["findings"])),
        "recurrence": bool(hist["recent_true_positives"]),
        "siem_corroboration": any((e.get("count") or 0) > 0 for e in evidence if e.get("kind") == "corroboration"),
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
    inv = {"alert_id": alert["id"], "category": category, "threshold": threshold, "history": hist, "indicators": looked or inds, "lookup_note": lookup_note,
           "siem_evidence": evidence, "host": {"asset": alert.get("asset"), "owner": ctx["owner"], "open_findings": ctx["open_findings"], "kev_findings": ctx["kev_findings"],
                                               "findings": ctx["findings"]}, "signals": signals, "scores": {"true_positive": tp, "false_positive": fp},
           "verdict": verdict, "confidence": confidence, "reasons": reasons, "timeline": timeline, "runbook": ctx["runbook"]}
    inv["report"] = report.build(alert, alerts, inv, findings, identity, playbooks, cfg.get("max_lookback_days", 90))
    return inv


def render_markdown(alert, inv):
    return report.to_markdown(alert, inv)


def render_html(alert, inv):
    return report.to_html(alert, inv)


FOLLOWUP_KINDS = ("similar-alerts", "entity-history", "indicator-sightings")


def follow_up(alert, inv, kind, value, alerts, findings=(), siem_run=None, cfg=None):
    """Answers a question asked after the first report, from the same data, and returns {question, answer, data}. Nothing is sent anywhere unless siem_run is given."""
    cfg = cfg or config()
    value = (value or "").strip()
    if kind not in FOLLOWUP_KINDS:
        raise ValueError(f"kind must be one of {', '.join(FOLLOWUP_KINDS)}")
    if not value:
        raise ValueError("Give the host, user, address, domain or hash to ask about")
    others = [a for a in alerts if a["id"] != alert["id"]]
    match = [a for a in others if any(str(x).lower() == value.lower() for _, x in report._vals(a))]
    if kind == "similar-alerts":
        same_rule = [a for a in match if alert.get("rule_name") and a.get("rule_name") == alert["rule_name"]]
        q, ans = f"How many similar alerts involve {value}?", f"{len(match)} alert(s) involve {value}" + (f", {len(same_rule)} from the same rule" if alert.get("rule_name") else "") + "."
        data = [{"id": a["id"], "title": a["title"], "status": a["status"], "disposition": a.get("disposition")} for a in match[:20]]
    elif kind == "entity-history":
        q = f"What is the history of {value}?"
        tp, noise = sum(1 for a in match if a.get("disposition") == "true-positive"), sum(1 for a in match if a.get("disposition") in ("benign", "false-positive"))
        ans = (f"{len(match)} earlier alert(s): {tp} true positive, {noise} benign or false positive, {sum(1 for a in match if a['status'] != 'closed')} open; first on {min(a['received_at'] for a in match)[:10]}."
               if match else f"No earlier alert involves {value}.")
        data = [{"id": a["id"], "title": a["title"], "received_at": a["received_at"], "disposition": a.get("disposition")} for a in match[:20]]
    else:
        hosts = sorted({(a.get("asset") or "").lower() for a in match if a.get("asset")})
        q = f"Where else was {value} seen?"
        ans = f"In alerts on {len(hosts)} other host(s): {', '.join(hosts[:10])}." if hosts else f"{value} appears in no other alert Quanta holds."
        data = [{"host": h} for h in hosts[:20]]
    sq = search_base.sighting_query(getattr(siem_run, "language", "splunk-spl"), value) if siem_run is not None and SAFE_VALUE.match(value) else None
    if siem_run is not None and SAFE_VALUE.match(value) and not sq:
        ans += " This SIEM connection's query language has no free-text search, so no SIEM count was added."
    if sq:
        days = min(int(cfg.get("max_lookback_days", 90)), 90)
        try:
            r = siem_run(sq, f"-{days}d")
            h = (r["rows"][0].get("hosts") if r["rows"] else None)
            ans += f" SIEM, last {days} days: {r['count']} result row(s)" + (f", {h} host(s)" if h else "") + "."
        except Exception as exc:  # noqa: BLE001
            ans += f" The SIEM search failed ({str(exc)[:120]})."
    return {"question": q, "answer": ans, "data": data, "asked": kind}
