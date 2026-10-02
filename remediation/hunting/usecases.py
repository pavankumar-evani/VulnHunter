"""
Detection use cases: proposed new detections, each with a hypothesis, the evidence behind it, a draft rule and a test plan.

Four generators, all deterministic and all reading data Quanta already holds. A use case is a PROPOSAL for a detection engineer; nothing is deployed.

  coverage-gap     an ATT&CK technique that matters to this estate (tagged on its open findings, named in threat-intelligence reports, or hunted) and that no
                   enabled detection rule claims. Hypothesis: an adversary using it would go unnoticed. Draft rule: the hunt library's detection for that technique.
  hunt-promotion   a hunt whose leads were assessed suspicious or malicious. Hypothesis: what the hunt found should be caught continuously, not by hunting.
                   Draft rule: the lead's detection.
  sequence         a pair of tactics that follows each other on the same host within a time window across several hosts, mined from the alerts Quanta holds,
                   with the share of such sequences analysts closed as true positive. Hypothesis: the pair together is more telling than either alert alone.
                   Draft: a Sigma temporal-ordered correlation rule.
  ioc-watchlist    the public indicators in relevant threat-intelligence reports. Hypothesis: contact with them is worth an alert while they are current.
                   Draft rule: a Sigma rule matching the indicator lists, to be reviewed and expired.

Thresholds (minimum hosts for a sequence, minimum precision, window) are in remediation/config/detection_policy.yaml under `usecases`.

The mining is counting, not machine learning: a pattern is proposed when enough distinct hosts show it and enough of them turned out to be real. The report says
how many, so an engineer can judge the evidence. The Sigma drafts are starting points: the logsource and field names must be matched to the data model in use,
and the rule must be tested against real data before it is switched on.

Lifecycle: proposed -> accepted (an engineer will build it) -> implemented (it is live; Quanta then counts it as coverage) or rejected / deferred, each with a
note. A draft is never counted as coverage.
"""
import datetime
import hashlib
import uuid

import yaml

from remediation.hunting import generate, report

LOGSOURCE = {
    "T1190": {"category": "webserver"}, "T1499": {"category": "webserver"}, "T1059": {"category": "process_creation", "product": "windows"},
    "T1068": {"category": "process_creation", "product": "windows"}, "T1548": {"category": "process_creation"}, "T1552": {"category": "process_creation"},
    "T1195": {"category": "process_creation"}, "T1021": {"service": "security", "product": "windows"}, "T1210": {"category": "network_connection"},
    "T1556": {"category": "registry_set", "product": "windows"}, "T1600": {"category": "network_connection"},
}
DEFAULTS = {"sequence_window_hours": 24, "sequence_min_hosts": 3, "sequence_min_precision": 0.5, "max_use_cases": 50, "ioc_min_priority": "medium", "ioc_max_values": 50}
LEVEL = [(70, "high"), (50, "medium"), (0, "low")]
PRIO_ORDER = {"high": 2, "medium": 1, "low": 0}


def settings(policy):
    return {**DEFAULTS, **((policy or {}).get("usecases") or {})}


def _key(kind, subject):
    return f"{kind}-{hashlib.sha1(subject.encode()).hexdigest()[:10]}"


def _level(score):
    return next(name for floor, name in LEVEL if score >= floor)


def sigma_draft(key, title, hypothesis, techniques, selection, logsource, level, today, condition="selection", extra=None):
    doc = {"title": title, "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "quanta:" + key)), "status": "experimental", "description": hypothesis, "author": "Quanta (generated draft)",
           "date": today.isoformat(), "tags": [f"attack.{t.lower()}" for t in techniques], "logsource": logsource, "detection": {"selection": selection, "condition": condition},
           "falsepositives": ["Unknown until tested; run against recent data and list what it matches that is legitimate"], "level": level}
    if extra:
        doc.update(extra)
    return yaml.safe_dump(doc, sort_keys=False, width=140)


def test_plan(technique_name, lookback=30):
    return [f"Run the draft as a search over the last {lookback} days of the relevant log source and count what it matches.",
            "Review every match: list the legitimate causes and add them as exclusions, or note them as expected false positives.",
            f"Simulate {technique_name} safely in a test environment (an atomic test or a manual equivalent) and confirm the rule fires.",
            "Agree who receives the alert and what they should do, then enable it and watch its health under Detection engineering for the first month."]


def covered_techniques(rules):
    out = set()
    for r in rules:
        if r.get("enabled", True):
            out |= {t.split(".")[0] for t in r.get("techniques") or []}
    return out


def coverage_gaps(findings, intel_reports, hunts, rules, today, cfg):
    lib = generate.library()
    cov = covered_techniques(rules)
    evidence = {}
    for f in findings:
        if f.get("status") in ("resolved", "closed"):
            continue
        for t in f.get("attack_techniques") or []:
            e = evidence.setdefault(t["technique_id"], {"estate": 0, "kev": 0, "intel": [], "hunts": []})
            e["estate"] += 1
            e["kev"] += 1 if (f.get("kev") or {}).get("listed") else 0
    for r in intel_reports:
        for t in r["extracted"].get("techniques") or []:
            e = evidence.setdefault(t.split(".")[0], {"estate": 0, "kev": 0, "intel": [], "hunts": []})
            e["intel"].append(r["title"])
    for h in hunts:
        for t in h.get("techniques") or []:
            e = evidence.setdefault(t["technique_id"].split(".")[0], {"estate": 0, "kev": 0, "intel": [], "hunts": []})
            e["hunts"].append(h["id"])
    out = []
    for tid, ev in sorted(evidence.items()):
        entry = lib.get(tid)
        if tid in cov or not entry:
            continue
        info = report.technique_info(tid)
        key = _key("gap", tid)
        why = []
        if ev["estate"]:
            why.append(f"{ev['estate']} open finding(s) in your estate are tagged {tid}" + (f", {ev['kev']} known-exploited" if ev["kev"] else ""))
        if ev["intel"]:
            why.append(f"{len(set(ev['intel']))} threat-intelligence report(s) name it")
        if ev["hunts"]:
            why.append(f"{len(set(ev['hunts']))} hunt(s) cover it")
        score = min(100, 40 + (10 if ev["kev"] else 0) + (15 if ev["intel"] else 0) + (10 if ev["hunts"] else 0) + min(15, ev["estate"] // 10))
        name = (info and info["name"]) or entry["hunt"]
        d = entry["detections"][0]
        hyp = (f"If an adversary uses {name} ({tid}) against this environment, nothing would alert: no enabled detection rule claims it, and " + "; ".join(why) + ".")
        out.append({"key": key, "kind": "coverage-gap", "title": f"Detect: {entry['hunt']}", "hypothesis": hyp, "techniques": [tid], "data_sources": entry.get("data_sources") or [],
                    "evidence": {"estate_findings": ev["estate"], "known_exploited": ev["kev"], "intel_reports": sorted(set(ev["intel"]))[:5], "hunts": sorted(set(ev["hunts"]))[:5], "reasons": why},
                    "score": score, "sigma": sigma_draft(key, f"Quanta draft - {entry['hunt']}", hyp, [tid], d["selection"], LOGSOURCE.get(tid, {"category": "process_creation"}), _level(score), today),
                    "expected_false_positives": [entry.get("notes") or "Test against recent data to find them."], "test_plan": test_plan(name, 30)})
    return out


def hunt_promotions(hunts, rules, today):
    lib = generate.library()
    cov = covered_techniques(rules)
    out = []
    for h in hunts:
        if h.get("detection_created"):
            continue
        good = [q for q in h.get("queries") or [] if q.get("assessment") in ("suspicious", "malicious") and q.get("result") == "hits"]
        if not good:
            continue
        for q in good:
            tid = (q.get("technique") or "").split(".")[0]
            entry = lib.get(tid)
            det = next((d for d in (entry or {}).get("detections", []) if d["name"] == q.get("name")), None)
            if not det or tid in cov:
                continue
            key = _key("hunt", f"{h['id']}:{q['name']}")
            malicious = q.get("assessment") == "malicious"
            score = 60 + (20 if malicious else 0)
            hyp = (f"Hunt #{h['id']} ('{h['title']}') found {q.get('count')} result(s) for '{q['name']}' that an analyst judged {q['assessment']}. "
                   "What a hunt found once should be detected continuously, not rediscovered by hunting.")
            out.append({"key": key, "kind": "hunt-promotion", "title": f"Promote hunt lead: {q['name']}", "hypothesis": hyp, "techniques": [tid], "data_sources": (entry or {}).get("data_sources") or [],
                        "evidence": {"hunt_id": h["id"], "lead": q["name"], "hits": q.get("count"), "assessment": q["assessment"]}, "score": score,
                        "sigma": sigma_draft(key, f"Quanta draft - {q['name']}", hyp, [tid], det["selection"], LOGSOURCE.get(tid, {"category": "process_creation"}), _level(score), today),
                        "expected_false_positives": [(entry or {}).get("notes") or "Test against recent data."], "test_plan": test_plan(q["name"], 30)})
    return out


def sequences(alerts, rules, today, cfg):
    s = settings(cfg)
    window = datetime.timedelta(hours=s["sequence_window_hours"])
    by_host = {}
    for a in alerts:
        info = report.technique_info(a.get("technique"))
        host = (a.get("asset") or "").lower()
        if not (info and info["tactic"] and host):
            continue
        t = report._dt(a.get("occurred_at")) or report._dt(a.get("received_at"))
        if t:
            by_host.setdefault(host, []).append((t, info, a))
    pairs = {}
    for host, rows in by_host.items():
        rows.sort(key=lambda r: r[0])
        seen = set()
        for i, (t1, i1, a1) in enumerate(rows):
            for t2, i2, a2 in rows[i + 1:]:
                if t2 - t1 > window:
                    break
                if i1["tactic"] == i2["tactic"] or (i1["parent"], i2["parent"]) in seen:
                    continue
                seen.add((i1["parent"], i2["parent"]))
                p = pairs.setdefault((i1["parent"], i2["parent"]), {"hosts": set(), "tp_hosts": set(), "alerts": []})
                p["hosts"].add(host)
                p["alerts"] += [a1["id"], a2["id"]]
                if "true-positive" in (a1.get("disposition"), a2.get("disposition")):
                    p["tp_hosts"].add(host)
    out = []
    for (ta, tb), p in sorted(pairs.items(), key=lambda kv: -len(kv[1]["hosts"])):
        support, precision = len(p["hosts"]), len(p["tp_hosts"]) / len(p["hosts"])
        if support < s["sequence_min_hosts"] or precision < s["sequence_min_precision"]:
            continue
        ia, ib = report.technique_info(ta), report.technique_info(tb)
        key = _key("seq", f"{ta}>{tb}")
        score = int(min(100, 30 + 40 * precision + 5 * min(6, support)))
        hyp = (f"{ia['name']} ({ta}, {ia['tactic']}) followed by {ib['name']} ({tb}, {ib['tactic']}) on the same host within {s['sequence_window_hours']} hours is more telling than either alone: "
               f"it occurred on {support} hosts and analysts closed {len(p['tp_hosts'])} of them as true positive ({round(100 * precision)}%).")
        rule_names = {t: next((r["name"] for r in rules if r.get("enabled", True) and any(x.split(".")[0] == t for x in r.get("techniques") or [])), f"<a rule that detects {t}>") for t in (ta, tb)}
        extra_corr = {"correlation": {"type": "temporal_ordered", "rules": [rule_names[ta], rule_names[tb]], "group-by": ["host"], "timespan": f"{s['sequence_window_hours']}h"}}
        out.append({"key": key, "kind": "sequence", "title": f"Correlate: {ia['name']} then {ib['name']}", "hypothesis": hyp, "techniques": [ta, tb], "data_sources": ["Alerts from the two underlying detections"],
                    "evidence": {"hosts": support, "true_positive_hosts": len(p["tp_hosts"]), "precision": round(precision, 2), "example_alerts": sorted(set(p["alerts"]))[:8]}, "score": score,
                    "sigma": yaml.safe_dump({"title": f"Quanta draft - {ia['name']} then {ib['name']}", "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "quanta:" + key)), "status": "experimental", "description": hyp,
                                             "author": "Quanta (generated draft)", "date": today.isoformat(), "tags": [f"attack.{ta.lower()}", f"attack.{tb.lower()}"], **extra_corr, "level": _level(score)},
                                            sort_keys=False, width=140),
                    "expected_false_positives": ["Admin or deployment activity that legitimately produces both alerts in sequence; check the true-negative hosts"],
                    "test_plan": test_plan(f"{ia['name']} then {ib['name']}", 30)})
    return out


def ioc_watchlists(intel_reports, today, cfg):
    s = settings(cfg)
    floor = PRIO_ORDER.get(s["ioc_min_priority"], 1)
    out = []
    for r in intel_reports:
        if PRIO_ORDER.get(r["priority"], 0) < floor:
            continue
        ex = r["extracted"]
        sel = {}
        if ex.get("ips"):
            sel["DestinationIp"] = ex["ips"][:s["ioc_max_values"]]
        if ex.get("domains"):
            sel["QueryName|endswith"] = ex["domains"][:s["ioc_max_values"]]
        if ex.get("hashes"):
            sel["Hashes|contains"] = ex["hashes"][:s["ioc_max_values"]]
        if not sel:
            continue
        key = _key("ioc", str(r["id"]))
        score = min(100, 20 + r["relevance"] // 2)
        hyp = (f"Contact with the indicators in '{r['title']}' (relevance {r['relevance']} to this estate) is worth an alert while the report is current. "
               "Indicators age quickly; review this rule after 90 days and remove what no longer matters.")
        # Sigma matches any value in a list; the selection has one key per indicator type, combined with OR via separate selections.
        detection = {f"sel_{i}": {k: v} for i, (k, v) in enumerate(sel.items())}
        doc = {"title": f"Quanta draft - indicators from {r['title'][:60]}", "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "quanta:" + key)), "status": "experimental", "description": hyp,
               "author": "Quanta (generated draft)", "date": today.isoformat(), "tags": [f"attack.{t.split('.')[0].lower()}" for t in ex.get("techniques") or []][:6],
               "logsource": {"category": "network_connection"}, "detection": {**detection, "condition": " or ".join(detection)}, "falsepositives": ["Shared hosting or CDN addresses; check each before enabling"], "level": _level(score)}
        out.append({"key": key, "kind": "ioc-watchlist", "title": f"Watchlist: {r['title'][:80]}", "hypothesis": hyp, "techniques": sorted({t.split('.')[0] for t in ex.get("techniques") or []})[:6],
                    "data_sources": ["DNS and network connection logs", "EDR file hashes"], "evidence": {"intel_report": r["id"], "relevance": r["relevance"], "priority": r["priority"],
                                                                                                   "indicators": {k: len(v) for k, v in sel.items()}},
                    "score": score, "sigma": yaml.safe_dump(doc, sort_keys=False, width=140), "expected_false_positives": ["Shared infrastructure (CDNs, hosting) can share an address with a malicious host"],
                    "test_plan": test_plan("contact with the listed indicators", 30)})
    return out


def generate_all(findings, alerts, hunts, intel_reports, rules, policy=None, today=None):
    today = today or datetime.date.today()
    s = settings(policy)
    cases = coverage_gaps(findings, intel_reports, hunts, rules, today, policy) + hunt_promotions(hunts, rules, today) + sequences(alerts, rules, today, policy) + ioc_watchlists(intel_reports, today, policy)
    cases.sort(key=lambda c: -c["score"])
    for c in cases:
        c["level"] = _level(c["score"])
    return cases[: s["max_use_cases"]]
