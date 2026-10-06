"""Defence in depth: is each layer (perimeter, network, host, application, data, identity, monitoring, response) protected by more than one control that
Quanta has verified, and does the whole not hang on a single layer?

The control layers are judged from the controls inventory (verified vs claimed vs absent; remediation/controls), with the open findings on that layer's
assets shown beside it as the burden the layer is carrying. Monitoring and response are judged from alert intake, detection health, ATT&CK coverage,
SOAR playbooks and SOC cases. Nothing recorded means `unknown`, never a pass.
"""
import datetime

from remediation.posture import model

FRAMEWORK = {
    "id": "defence-in-depth",
    "title": "Defence in depth (layered controls)",
    "summary": "Whether each layer of the estate has independent, verified controls, whether any single layer is the only thing standing between an attacker and the estate, and whether the estate can detect and respond.",
    "areas": [("perimeter", "Perimeter"), ("network", "Network"), ("host", "Host"), ("application", "Application"), ("data", "Data"), ("identity", "Identity"),
              ("monitoring", "Monitoring"), ("response", "Response")],
    "refs": [{"label": "NIST SP 800-207 Zero Trust Architecture", "url": "https://csrc.nist.gov/pubs/sp/800/207/final"}],
}
FW = FRAMEWORK["id"]
CLOSED = {"resolved", "closed", "fixed", "remediated"}
LAYER_CLASSES = {
    "perimeter": ("network-filtering", "exploit-protection", "web-filtering"),
    "network": ("network-segmentation", "access-restriction"),
    "host": ("edr", "os-hardening", "patching", "app-control", "disable-feature", "vuln-scanning"),
    "application": ("secure-development", "sandboxing"),
    "data": ("encryption",),
    "identity": ("mfa", "least-privilege", "password-policy", "user-training"),
    "monitoring": ("audit-logging", "threat-intel"),
}
LAYER_TYPES = {
    "perimeter": ("network-security-device",),
    "network": ("network-routing-switching",),
    "host": ("windows-server", "windows-endpoint", "unix-server", "virtualization-host", "iot-ot-device", "mobile-device", "printer"),
    "application": ("application", "client-application", "code-repository", "container-runtime", "iac-resource", "ai-ml-system"),
}
CONTROL_LAYERS = ("perimeter", "network", "host", "application", "data", "identity")
LAYER_TITLES = dict(FRAMEWORK["areas"])
TIER_GOOD, TIER_BAD = ("healthy", "high_fidelity"), ("critical_noise", "noisy", "low_value")


def _chk(cid, area, title, status, **kw):
    return model.check(f"did-{cid}", FW, area, title, status, refs=FRAMEWORK["refs"], **kw)


def _unknown(cid, area, title, why, data_used, recommendation, weight=3, change=None, n=0):
    return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"{why} Records that could answer this: {n}."], recommendation=recommendation, data_used=data_used, change=change,
                detail="Quanta cannot answer this from what is recorded, so it is left out of the score.")


def _cov(ctx, ok, total):
    share = ok / total
    if share >= ctx.thr["coverage_good"]:
        return "pass", None
    if share >= ctx.thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _date(value):
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _age(ctx, value):
    d = _date(value)
    return (ctx.now.date() - d).days if d else None


def _controls(ctx):
    from remediation.controls import store
    return ctx.get("controls", lambda: store.list_controls(engine=ctx.engine))


def _open(ctx):
    return [f for f in ctx.findings if str(f.get("status") or "").lower() not in CLOSED]


def _burden(ctx, layer):
    types = LAYER_TYPES.get(layer)
    if not types:
        return None
    mine = [f for f in _open(ctx) if (f.get("asset") or {}).get("type") in types and f.get("severity") in ("Critical", "High")]
    assets = {(f["asset"].get("name") or f["asset"].get("hostname")) for f in mine}
    return f"{len(mine)} open Critical or High findings on {len(assets)} {layer} assets."


def _verified_by_layer(rows):
    out = {layer: {"verified": set(), "claimed": set(), "entries": 0} for layer in LAYER_CLASSES}
    for r in rows:
        for layer, classes in LAYER_CLASSES.items():
            if r["control_class"] in classes:
                if r["state"] == "verified":
                    out[layer]["verified"].add(r["control_class"])
                    out[layer]["entries"] += 1
                else:
                    out[layer]["claimed"].add(r["control_class"])
    return out


def _layer_check(ctx, layer, rows):
    classes = LAYER_CLASSES[layer]
    t = f"The {layer} layer has independent verified controls"
    rec_missing = "Record the controls that protect this layer on the Controls page, or push them from the tool that enforces them with a controls:write key."
    if not rows:
        return _unknown(f"{layer}-controls", layer, t, "No controls are recorded in the inventory.", ("asset_controls",), rec_missing, weight=4)
    info = _verified_by_layer(rows)[layer]
    v, c = len(info["verified"]), len(info["claimed"] - info["verified"])
    need = min(2, len(classes))
    absent = len(classes) - v - c
    ev = [f"{v} verified, {c} claimed only and {absent} absent of {len(classes)} control types ({', '.join(classes)}); {need} verified needed."]
    b = _burden(ctx, layer)
    if b:
        ev.append(b)
    if v >= need:
        st, sc = "pass", None
    elif v >= 1:
        st, sc = "partial", v / need
    else:
        st, sc = "fail", None
        ev.append("No verified control in this layer: an attacker meets nothing here that Quanta can show is working.")
    return _chk(f"{layer}-controls", layer, t, st, score=sc, weight=4, evidence=ev, data_used=("asset_controls", "findings"),
                detail="A layer defended by one control, or only by controls somebody claims, fails whenever that one control fails.",
                recommendation=f"Verify the {layer} controls automatically instead of by statement." if st != "pass" else "Keep the control feed running so verification stays current.",
                change=None if st == "pass" else {"kind": "page", "where": "/controls", "key": classes[0], "value": "verified", "effect": "Records the control as verified for the assets it protects."})


def _single_point(ctx, rows):
    t = "No layer is a single point of protection"
    if not rows:
        return _unknown("single-point", "perimeter", t, "No controls are recorded in the inventory.", ("asset_controls",), "Record controls on the Controls page.", weight=5)
    by = _verified_by_layer(rows)
    with_v = [layer for layer in CONTROL_LAYERS if by[layer]["verified"]]
    total = sum(by[layer]["entries"] for layer in CONTROL_LAYERS)
    top_layer = max(CONTROL_LAYERS, key=lambda layer: (by[layer]["entries"], layer))
    top = (by[top_layer]["entries"] / total) if total else 0
    ev = [f"{len(with_v)} of {len(CONTROL_LAYERS)} control layers have a verified control." + (f" {top_layer} holds {round(100 * top)}% of the {total} verified controls." if total else " No control is verified at all.")]
    missing = [layer for layer in CONTROL_LAYERS if layer not in with_v]
    if missing:
        ev.append("No verified control in: " + ", ".join(missing) + ".")
    if len(with_v) <= 1:
        st, sc = "fail", None
    elif len(with_v) >= 4 and top <= 0.5:
        st, sc = "pass", None
    else:
        st, sc = "partial", len(with_v) / len(CONTROL_LAYERS)
    return _chk("single-point", "perimeter", t, st, score=sc, weight=5, evidence=ev, data_used=("asset_controls",),
                detail="When one layer carries nearly everything, a single bypass reaches the estate.",
                recommendation="Add a verified control to each layer listed, starting with the host and identity layers." if st != "pass" else "Keep new controls spread across layers.",
                change=None if st == "pass" else {"kind": "page", "where": "/controls", "key": "state", "value": "verified", "effect": "Shows each layer's verified and claimed controls."})


def _monitoring(ctx, rows):
    out = [_layer_check(ctx, "monitoring", rows)]
    from remediation.hunting import detection, store
    alerts = ctx.get("alerts", lambda: store.list_alerts(ctx.engine))
    t = "Security alerts are being ingested"
    if not alerts:
        out.append(_unknown("mon-alerts", "monitoring", t, "No alert has ever been received.", ("soc_alerts",), "Point your SIEM or EDR at POST /api/ingest/alerts.", weight=4))
    else:
        ages = [a for a in (_age(ctx, x["received_at"]) for x in alerts) if a is not None]
        newest = min(ages) if ages else None
        ok = newest is not None and newest <= ctx.thr["stale_days"]
        out.append(_chk("mon-alerts", "monitoring", t, "pass" if ok else "fail", weight=4, data_used=("soc_alerts",),
                        evidence=[f"{len(alerts)} alerts recorded; the newest arrived {newest} days ago (limit {ctx.thr['stale_days']})."],
                        detail="A layer that cannot see cannot detect.", recommendation="Check the alert feed from your SIEM or EDR." if not ok else "Keep the alert feed monitored."))
    rules = ctx.get("rules", lambda: detection.list_rules(ctx.engine))

    def assess():
        if not rules and not alerts:
            return None
        findings = ctx.findings
        if findings and "attack_techniques" not in findings[0]:
            from remediation.enrichment import attack_mapping
            findings = attack_mapping.tag_findings(findings)
        return detection.assess(alerts or [], rules or [], findings, pol=detection.policy(), now=ctx.now)

    res = ctx.get("detection", assess)
    t = "Detection rules are healthy"
    known = [r for r in (res or {}).get("rules", []) if r["known"]]
    judged = [r for r in known if r["metrics"]["tier"] != "low_volume"]
    if not known:
        out.append(_unknown("mon-detection-health", "monitoring", t, "No detection rule is recorded.", ("detection_rules", "soc_alerts"), "Import detection rules on the Hunting page and close alerts with a disposition so health can be judged.", weight=3, n=len(rules or [])))
    elif not judged:
        out.append(_unknown("mon-detection-health", "monitoring", t, f"{len(known)} rules are recorded but none has enough closed alerts with a disposition to judge.", ("detection_rules", "soc_alerts"),
                            "Close alerts with a disposition so rule health can be judged.", weight=3, n=len(known)))
    else:
        good = sum(1 for r in judged if r["metrics"]["tier"] in TIER_GOOD)
        bad = [r["rule"] for r in judged if r["metrics"]["tier"] in TIER_BAD]
        st, sc = _cov(ctx, good, len(judged))
        out.append(_chk("mon-detection-health", "monitoring", t, st, score=sc, weight=3, data_used=("detection_rules", "soc_alerts"),
                        evidence=[f"{good} of {len(judged)} judged rules are healthy or high fidelity; {len(known) - len(judged)} have too few decided alerts."] + [f"Needs tuning: {n}" for n in bad[:3]],
                        detail="A noisy rule trains analysts to ignore it; a low-value rule detects nothing.",
                        recommendation="Tune or disable the rules listed." if bad else "Keep reviewing rule health.",
                        change=None if not bad else {"kind": "page", "where": "/soc", "key": "detection engineering", "value": "tune", "effect": "Shows each rule's tier and tuning suggestion."}))
    t = "Detection covers the techniques seen in the estate"
    cov = (res or {}).get("coverage")
    if not cov or cov["pct"] is None:
        out.append(_unknown("mon-attack-coverage", "monitoring", t, "No open finding carries an ATT&CK technique, or no detection rule is recorded.", ("detection_rules", "findings"),
                            "Enrich findings and import detection rules.", weight=3, n=(cov or {}).get("estate_techniques", 0)))
    else:
        share = cov["pct"] / 100
        st = "pass" if share >= ctx.thr["coverage_good"] else "partial" if share >= ctx.thr["coverage_partial"] else "fail"
        out.append(_chk("mon-attack-coverage", "monitoring", t, st, score=share if st == "partial" else None, weight=3, data_used=("detection_rules", "findings"),
                        evidence=[f"{cov['estate_covered']} of {cov['estate_techniques']} ATT&CK techniques in open findings have an enabled detection rule ({cov['pct']}%)."] + [f"No rule: {g['technique_id']} {g['technique_name']}" for g in cov["gaps"][:3]],
                        detail="A technique with no rule can be used without raising an alert.", recommendation="Write or import rules for the gaps listed." if cov["gaps"] else "Keep coverage current as findings change.",
                        change=None if not cov["gaps"] else {"kind": "page", "where": "/soc", "key": "use cases", "value": "promote", "effect": "Generates detection use cases for the gaps."}))
    return out


def _response(ctx):
    out = []
    from remediation.soar import playbooks
    from remediation.soc import cases
    pbs = ctx.get("playbooks", lambda: playbooks.list_all(ctx.engine))
    t = "Response playbooks are ready"
    if not pbs:
        out.append(_unknown("resp-playbooks", "response", t, "No response playbook is recorded.", ("soar_playbooks",), "Create a playbook on the SOAR page.", weight=3))
    else:
        on = [p for p in pbs if p["enabled"]]
        gated = sum(1 for p in on if any(s.get("type") == "request-approval" for s in p["steps"]))
        out.append(_chk("resp-playbooks", "response", t, "pass" if on else "fail", weight=3, data_used=("soar_playbooks",),
                        evidence=[f"{len(on)} of {len(pbs)} playbooks are enabled; {gated} include an approval step."],
                        detail="A response nobody has written down is improvised under pressure.", recommendation="Enable the playbooks you rely on." if not on else "Rehearse the playbooks.",
                        change=None if on else {"kind": "page", "where": "/soar", "key": "enabled", "value": "true", "effect": "Makes the playbook available to run."}))
    t = "SOC cases are inside their service levels"
    cs = ctx.get("cases", lambda: cases.list_cases(ctx.engine, now=ctx.now))
    if not cs:
        out.append(_unknown("resp-cases", "response", t, "No SOC case is recorded.", ("soc_cases",), "Cases open from investigated alerts on the SOC page.", weight=4))
    else:
        ok = sum(1 for c in cs if c["sla"]["worst"] != "breached")
        st, sc = _cov(ctx, ok, len(cs))
        out.append(_chk("resp-cases", "response", t, st, score=sc, weight=4, data_used=("soc_cases",),
                        evidence=[f"{ok} of {len(cs)} cases have no breached acknowledgement or resolution target."], detail="A breached target means the response did not happen in the time promised.",
                        recommendation="Add analysts or review priorities so targets are met." if st != "pass" else "Keep monitoring service levels.",
                        change=None if st == "pass" else {"kind": "yaml", "where": "remediation/config/soc_ops.yaml", "key": "targets", "value": "review", "effect": "Sets the acknowledgement and resolution targets per priority."}))
    t = "Every analyst tier is staffed for escalation"
    staff = ctx.get("analysts", lambda: cases.list_analysts(ctx.engine))
    if not staff:
        out.append(_unknown("resp-escalation", "response", t, "No SOC analyst is recorded.", ("soc_analysts",), "Add analysts per tier on the SOC page.", weight=3))
    else:
        tiers = {a["tier"] for a in staff}
        st = "pass" if tiers >= {1, 2, 3} else "partial" if len(tiers) >= 2 else "fail"
        out.append(_chk("resp-escalation", "response", t, st, score=len(tiers) / 3 if st == "partial" else None, weight=3, data_used=("soc_analysts",),
                        evidence=[f"{len(tiers)} of 3 analyst tiers have at least one analyst ({len(staff)} analysts)."], detail="A case that cannot be escalated waits.",
                        recommendation="Add an analyst to each tier." if st != "pass" else "Keep on-call cover current.",
                        change=None if st == "pass" else {"kind": "page", "where": "/soc", "key": "analysts", "value": "tiers 1 to 3", "effect": "Lets cases escalate to a person in the next tier."}))
    return out


def run(ctx):
    rows = _controls(ctx)
    out = [_layer_check(ctx, "perimeter", rows), _single_point(ctx, rows)]
    out += [_layer_check(ctx, layer, rows) for layer in ("network", "host", "application", "data", "identity")]
    out += _monitoring(ctx, rows)
    out += _response(ctx)
    return out
