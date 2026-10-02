"""
Detection engineering: how well each detection rule is working, which ATT&CK techniques nothing detects, and what to change.

Input is the alerts Quanta already holds (each carries the rule that raised it, and, once an analyst closes it, a disposition) and the rule
inventory (Sigma rules imported, or rules added by name). Everything here is arithmetic on those two things with the thresholds in
remediation/config/detection_policy.yaml; there is no model in the loop, and a rule with too few decided alerts is called Low Volume rather than judged.

Per rule, over the policy window:
  decided = true-positive + benign + false-positive (needs-data is left out)
  noise rate = (false-positive + benign) / decided          true-positive rate = true-positive / decided
Health tier, first match wins: Low Volume (decided < min), High Fidelity (tp rate high), Low Value (no true positives and mostly benign),
Critical Noise (very noisy and high volume), Noisy (noise above the healthy limit), Healthy.
Recommendation: Maintain / Tune / Disable from the tier. Evidence is the counts, the alert ids, and the entities that account for the noise.

A tuning suggestion for a Sigma rule is the rule's detection block before and after adding a filter that excludes the host(s) behind most of
the noise, with the estimated reduction taken from the data (the share of noise alerts those hosts produced). It is a suggestion for an
engineer to review and test; nothing is pushed to any SIEM.

Coverage compares the techniques your enabled rules claim with those tagged on the estate's open findings and those the hunt library knows.
"""
import copy
import datetime
import html
import json
import re
import statistics
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select, update

from remediation.hunting import generate
from remediation.utils import db as db_module

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "detection_policy.yaml"
TIERS = ("high_fidelity", "healthy", "noisy", "critical_noise", "low_value", "low_volume")
TIER_LABEL = {"high_fidelity": "High Fidelity", "healthy": "Healthy", "noisy": "Noisy", "critical_noise": "Critical Noise", "low_value": "Low Value", "low_volume": "Low Volume"}
_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _dt(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- rule inventory
def parse_sigma(text):
    """Sigma rules in a YAML file (several documents allowed) -> list of rule dicts. Raises ValueError for a document that is not a rule."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ValueError(f"Not valid YAML: {str(exc)[:120]}") from exc
    out = []
    for d in docs:
        if not isinstance(d, dict) or "detection" not in d or not (d.get("title") or d.get("id")):
            raise ValueError("Each Sigma rule needs a title and a detection section")
        techs = sorted({_TAG.match(str(t)).group(1).upper() for t in (d.get("tags") or []) if _TAG.match(str(t))})
        ls = d.get("logsource") or {}
        platform = "sigma" + (":" + "/".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)) if ls else "")
        out.append({"name": str(d.get("title") or d.get("id"))[:200], "platform": platform, "logic": yaml.safe_dump(d, sort_keys=False), "format": "sigma", "techniques": techs})
    return out


def upsert_rule(name, platform=None, logic=None, techniques=None, fmt="text", enabled=True, engine=None):
    name = (name or "").strip()
    if not name or len(name) > 200:
        raise ValueError("A rule name of 1 to 200 characters is required")
    techs = sorted({str(t).upper() for t in (techniques or []) if re.fullmatch(r"(?i)T\d{4}(\.\d{3})?", str(t))})
    engine, t, now = _engine(engine), db_module.detection_rules, _now()
    row = {"platform": (platform or None), "logic": logic, "format": fmt if fmt in ("sigma", "text") else "text", "techniques_json": json.dumps(techs), "enabled": 1 if enabled else 0,
           "updated_at": now}
    with engine.begin() as conn:
        cur = conn.execute(select(t.c.id).where(t.c.name == name)).first()
        if cur:
            conn.execute(update(t).where(t.c.id == cur[0]).values(**row))
            return get_rule(cur[0], engine)
        rid = conn.execute(insert(t), {"name": name, "created_at": now, **row}).inserted_primary_key[0]
    return get_rule(rid, engine)


def _rule(r):
    d = dict(r)
    d["techniques"] = json.loads(d.pop("techniques_json") or "[]")
    d["enabled"] = bool(d["enabled"])
    return d


def get_rule(rule_id, engine=None):
    engine, t = _engine(engine), db_module.detection_rules
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(rule_id))).mappings().first()
    return _rule(r) if r else None


def list_rules(engine=None):
    engine, t = _engine(engine), db_module.detection_rules
    with engine.connect() as conn:
        return [_rule(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def set_enabled(rule_id, enabled, engine=None):
    engine, t = _engine(engine), db_module.detection_rules
    with engine.begin() as conn:
        n = conn.execute(update(t).where(t.c.id == int(rule_id)).values(enabled=1 if enabled else 0, updated_at=_now())).rowcount
    if not n:
        raise KeyError("No such rule")
    return get_rule(rule_id, engine)


def delete_rule(rule_id, engine=None):
    engine, t = _engine(engine), db_module.detection_rules
    with engine.begin() as conn:
        return bool(conn.execute(delete(t).where(t.c.id == int(rule_id))).rowcount)


def import_sigma(text, engine=None):
    return [upsert_rule(r["name"], r["platform"], r["logic"], r["techniques"], "sigma", True, engine) for r in parse_sigma(text)]


# ---------------------------------------------------------------- metrics
def tier(m, pol):
    h = pol["health"]
    if m["decided"] < pol["min_decided"]:
        return "low_volume"
    if m["tp_rate"] >= h["high_fidelity_tp_rate"]:
        return "high_fidelity"
    if m["tp"] == 0 and m["benign"] / m["decided"] >= h["low_value_min_benign_share"]:
        return "low_value"
    if m["noise_rate"] >= h["critical_noise_min_rate"] and m["decided"] >= h["critical_noise_min_volume"]:
        return "critical_noise"
    if m["noise_rate"] > h["healthy_max_noise_rate"]:
        return "noisy"
    return "healthy"


def recommendation(t, m, pol):
    rec = pol["recommendation"][t]
    if t == "critical_noise" and pol.get("disable_critical_noise_without_true_positives") and m["tp"] == 0:
        return "disable"
    return rec


def _weekly(rule_alerts, now, weeks=8):
    out = []
    for i in range(weeks - 1, -1, -1):
        end, start = now - datetime.timedelta(days=7 * i), now - datetime.timedelta(days=7 * (i + 1))
        wk = [a for a in rule_alerts if a["status"] == "closed" and a.get("disposition") in ("true-positive", "benign", "false-positive")
              and start < (_dt(a.get("closed_at") or a["received_at"]) or now) <= end]
        noise = sum(a["disposition"] != "true-positive" for a in wk)
        out.append({"week_ending": end.strftime("%Y-%m-%d"), "decided": len(wk), "noise_rate": round(noise / len(wk), 2) if wk else None})
    return out


def rule_metrics(name, rule_alerts, pol, now):
    closed = [a for a in rule_alerts if a["status"] == "closed"]
    tp = [a for a in closed if a.get("disposition") == "true-positive"]
    benign = [a for a in closed if a.get("disposition") == "benign"]
    fp = [a for a in closed if a.get("disposition") == "false-positive"]
    decided = len(tp) + len(benign) + len(fp)
    m = {"alerts": len(rule_alerts), "open": len([a for a in rule_alerts if a["status"] != "closed"]), "decided": decided, "tp": len(tp), "benign": len(benign), "fp": len(fp),
         "needs_data": len([a for a in closed if a.get("disposition") == "needs-data"]),
         "tp_rate": round(len(tp) / decided, 3) if decided else 0.0, "noise_rate": round((len(benign) + len(fp)) / decided, 3) if decided else 0.0}
    hours = [(_dt(a["closed_at"]) - _dt(a["received_at"])).total_seconds() / 3600 for a in closed if _dt(a.get("closed_at")) and _dt(a.get("received_at"))]
    m["median_resolution_hours"] = round(statistics.median(hours), 1) if hours else None
    t = tier(m, pol)
    m["tier"], m["tier_label"], m["recommendation"] = t, TIER_LABEL[t], recommendation(t, m, pol)
    noise = benign + fp
    ents = {}
    for a in noise:
        e = a.get("entities") or {}
        for kind, val in (("host", a.get("asset") or e.get("host")), ("user", e.get("user"))):
            if val:
                ents.setdefault((kind, val), []).append(a["id"])
    top = sorted(((k, v) for k, v in ents.items()), key=lambda kv: -len(kv[1]))[:pol.get("max_exclusions", 5)]
    m["recurring_noise_entities"] = [{"kind": k[0], "value": k[1], "alerts": len(v), "share": round(len(v) / len(noise), 2)} for k, v in top]
    m["evidence_alert_ids"] = [a["id"] for a in noise][:15]
    m["trend"] = _weekly(rule_alerts, now)
    return m


def suggest_tuning(rule, m, pol):
    """The before/after for a Sigma rule: exclude the hosts behind most of the noise. Returns None when there is nothing worth excluding."""
    ex = [e for e in m["recurring_noise_entities"] if e["kind"] == "host" and e["alerts"] >= pol.get("exclusion_min_alerts", 3) and e["share"] >= pol.get("exclusion_min_share", 0.2)]
    if not ex:
        return None
    share = round(sum(e["share"] for e in ex), 2)
    out = {"exclude_hosts": [e["value"] for e in ex], "estimated_noise_reduction": share,
           "basis": f"{sum(e['alerts'] for e in ex)} of the rule's {m['fp'] + m['benign']} noise alerts came from these hosts."}
    if rule and rule.get("format") == "sigma" and rule.get("logic"):
        try:
            doc = yaml.safe_load(rule["logic"])
            before = copy.deepcopy(doc["detection"])
            after = copy.deepcopy(doc["detection"])
            after["filter_known_benign"] = {"Computer|contains": out["exclude_hosts"]}
            cond = after.get("condition", "selection")
            after["condition"] = f"({cond}) and not filter_known_benign" if isinstance(cond, str) else cond
            out["before"] = yaml.safe_dump({"detection": before}, sort_keys=False)
            out["after"] = yaml.safe_dump({"detection": after}, sort_keys=False)
            out["note"] = "Check the host field name against this rule's log source (Computer is the Windows convention) and test the change before deploying it."
        except (yaml.YAMLError, KeyError, TypeError, AttributeError):
            out["note"] = "The rule text could not be read as Sigma, so only the hosts to exclude are given."
    else:
        out["note"] = "Add an exclusion for these hosts in your SIEM's rule, then watch the false-positive rate."
    return out


def coverage(rules, findings, lib=None):
    lib = lib if lib is not None else generate.library()
    enabled = [r for r in rules if r["enabled"]]
    covered = {}
    for r in enabled:
        for t in r["techniques"]:
            covered.setdefault(t.split(".")[0], []).append(r["name"])
    estate = {}
    for f in findings:
        if f.get("status") in ("resolved", "closed"):
            continue
        for t in f.get("attack_techniques") or []:
            estate[t["technique_id"]] = t["technique_name"]
    gaps = [{"technique_id": t, "technique_name": n, "hunt_queries": t in lib} for t, n in sorted(estate.items()) if t not in covered]
    return {"covered": [{"technique_id": t, "rules": sorted(set(v))} for t, v in sorted(covered.items())], "estate_techniques": len(estate),
            "estate_covered": len(set(estate) & set(covered)), "gaps": gaps,
            "pct": round(100 * len(set(estate) & set(covered)) / len(estate)) if estate else None}


def assess(alerts, rules, findings, pol=None, now=None):
    pol = pol or policy()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=pol.get("window_days", 90))
    in_window = [a for a in alerts if (_dt(a["received_at"]) or now) >= cutoff]
    by_rule = {}
    for a in in_window:
        by_rule.setdefault(a.get("rule_name") or "(no rule named)", []).append(a)
    known = {r["name"]: r for r in rules}
    out = []
    for name in sorted(set(by_rule) | set(known)):
        ra = by_rule.get(name, [])
        m = rule_metrics(name, ra, pol, now)
        rule = known.get(name)
        out.append({"rule": name, "known": bool(rule), "enabled": rule["enabled"] if rule else None, "platform": rule["platform"] if rule else None,
                    "techniques": rule["techniques"] if rule else [], "rule_id": rule["id"] if rule else None, "metrics": m, "tuning": suggest_tuning(rule, m, pol)})
    order = {"critical_noise": 0, "noisy": 1, "low_value": 2, "healthy": 3, "high_fidelity": 4, "low_volume": 5}
    out.sort(key=lambda r: (order[r["metrics"]["tier"]], -r["metrics"]["alerts"]))
    counts = {t: sum(1 for r in out if r["metrics"]["tier"] == t) for t in TIERS}
    decided = sum(r["metrics"]["decided"] for r in out)
    noise = sum(r["metrics"]["fp"] + r["metrics"]["benign"] for r in out)
    return {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "window_days": pol.get("window_days", 90), "rules": out, "tier_counts": counts,
            "totals": {"rules": len(out), "alerts": len(in_window), "decided": decided, "noise_rate": round(noise / decided, 3) if decided else None},
            "coverage": coverage(rules, findings),
            "note": "Health is judged on closed alerts with a disposition. A rule with too few decided alerts is Low Volume, not good or bad."}


# ---------------------------------------------------------------- snapshots (so the trend between runs is real)
def save_assessment(result, actor, engine=None):
    engine, t = _engine(engine), db_module.detection_assessments
    with engine.begin() as conn:
        return conn.execute(insert(t), {"created_at": _now(), "created_by": actor, "window_days": result["window_days"], "result_json": json.dumps(result)}).inserted_primary_key[0]


def list_assessments(engine=None, limit=12):
    engine, t = _engine(engine), db_module.detection_assessments
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id.desc()).limit(limit)).mappings().all()
    return [{"id": r["id"], "created_at": r["created_at"], "created_by": r["created_by"], **{k: json.loads(r["result_json"])[k] for k in ("tier_counts", "totals")}} for r in rows]


def latest_assessment(engine=None):
    engine, t = _engine(engine), db_module.detection_assessments
    with engine.connect() as conn:
        r = conn.execute(select(t).order_by(t.c.id.desc()).limit(1)).mappings().first()
    return json.loads(r["result_json"]) if r else None


# ---------------------------------------------------------------- reports
def rule_report_md(r):
    m = r["metrics"]
    L = [f"# Detection tuning: {r['rule']}", "",
         f"**Health: {m['tier_label']}. Recommendation: {m['recommendation'].capitalize()}.**", "",
         "## Evidence", f"- Alerts in the window: {m['alerts']} ({m['open']} still open)", f"- Decided: {m['decided']} - true positive {m['tp']}, benign {m['benign']}, false positive {m['fp']}",
         f"- True-positive rate {round(100 * m['tp_rate'])}%, noise rate {round(100 * m['noise_rate'])}%",
         f"- Median time to close: {m['median_resolution_hours'] if m['median_resolution_hours'] is not None else 'n/a'} hours",
         f"- Example noise alerts: {', '.join('#' + str(i) for i in m['evidence_alert_ids']) or 'none'}"]
    if m["recurring_noise_entities"]:
        L += ["", "## What the noise has in common", *[f"- {e['kind']} {e['value']}: {e['alerts']} alert(s), {round(100 * e['share'])}% of the noise" for e in m["recurring_noise_entities"]]]
    tu = r.get("tuning")
    if tu:
        L += ["", "## Suggested change", f"Exclude {', '.join(tu['exclude_hosts'])}. {tu['basis']} Estimated noise reduction: {round(100 * tu['estimated_noise_reduction'])}%.", tu.get("note", "")]
        if tu.get("before"):
            L += ["", "Before:", "```yaml", tu["before"].rstrip(), "```", "", "After:", "```yaml", tu["after"].rstrip(), "```"]
    if r["techniques"]:
        L += ["", f"Techniques claimed: {', '.join(r['techniques'])}"]
    L += ["", "This is a suggestion for an engineer to review and test. Quanta has not changed any rule."]
    return "\n".join(L) + "\n"


def summary_md(a):
    L = [f"# Detection engineering summary", "", f"Window: {a['window_days']} days. {a['totals']['rules']} rules, {a['totals']['alerts']} alerts"
         + (f", overall noise rate {round(100 * a['totals']['noise_rate'])}%." if a["totals"]["noise_rate"] is not None else "."), "", "## Health", ""]
    L += [f"- {TIER_LABEL[t]}: {n}" for t, n in a["tier_counts"].items()]
    L += ["", "## Rules that need attention", "| Rule | Health | Recommendation | Decided | Noise |", "|---|---|---|---|---|"]
    for r in a["rules"]:
        m = r["metrics"]
        if m["recommendation"] != "maintain":
            L.append(f"| {r['rule']} | {m['tier_label']} | {m['recommendation']} | {m['decided']} | {round(100 * m['noise_rate'])}% |")
    c = a["coverage"]
    L += ["", "## ATT&CK coverage", f"{c['estate_covered']} of {c['estate_techniques']} techniques tagged on your open findings are claimed by an enabled rule."
          if c["estate_techniques"] else "No ATT&CK techniques are tagged on current findings."]
    L += [f"- Not covered: {g['technique_id']} {g['technique_name']}" + ("" if g["hunt_queries"] else " (no hunt queries either)") for g in c["gaps"]]
    return "\n".join(L) + "\n"


def to_html(markdown_text, title):
    body, in_code = [], False
    for line in markdown_text.splitlines():
        if line.startswith("```"):
            body.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
        elif in_code:
            body.append(html.escape(line))
        elif line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("- "):
            body.append(f"<p class='li'>{html.escape(line[2:])}</p>")
        elif line.startswith("|"):
            body.append(f"<p class='li'><code>{html.escape(line)}</code></p>")
        elif line.strip():
            body.append("<p>" + re.sub(r"\*\*(.+?)\*\*", lambda m: "<b>" + m.group(1) + "</b>", html.escape(line)) + "</p>")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>" + html.escape(title) + "</title><style>body{background:#0a0e1a;color:#eef1fb;"
            "font-family:'Chakra Petch',Segoe UI,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;line-height:1.5}h1,h2{color:#eef1fb}h2{border-bottom:1px solid #243152}"
            "pre{background:#0f1730;border:1px solid #243152;padding:10px;overflow-x:auto;color:#c3cbe6}.li{margin:2px 0 2px 16px}code{color:#c3cbe6}</style></head><body>"
            + "\n".join(body) + "</body></html>")
