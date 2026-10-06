"""
The hypothesis generators. Each is a pure function of a Context and returns (hypotheses, gaps): `gaps` is a list of plain sentences saying what data was missing, so
"nothing suggested" is never confused with "nothing to suggest". A generator never invents a fact: every `why_now` item names a record in the Context (the tests resolve
each one). Wording says what to LOOK for, never that anything happened.

  intel          reports and actors (hunting/intel.py, the threat-actor catalogue), CVD advisories, and known-exploited vulnerabilities, as post-exploitation behaviour
  coverage_gap   ATT&CK techniques the estate or alerts show that no enabled detection rule claims
  baseline       low-and-slow repeated alerts, alert bursts, off-hours privileged-account alerts (counting over stored alerts; no log text is stored)
  exposure       internet-facing assets carrying known-exploited or Critical findings: "has anyone already used this path?"
  identity       leavers, dormant privileged and ownerless shared accounts from Access Governance
  lessons        a technique confirmed as a true positive: where else could it have happened?
  darkweb        credential exposure for the organisation's domains
  model_assisted untagged alerts whose wording the TTP classifier places on one technique
"""
import datetime
import fnmatch

from remediation.enrichment import threat_actor_groups
from remediation.hunting import generate, ttp, usecases
from remediation.hunting.engine import model as m

SEV_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
PRIO_RANK = {"low": 0, "medium": 1, "high": 2}
CAP_EVIDENCE = 10


def _parent(tid):
    return str(tid).split(".")[0].upper()


def _tids(f):
    return [t["technique_id"] for t in f.get("attack_techniques") or [] if t.get("technique_id")]


def _asset(f):
    return (f.get("asset") or {}).get("name")


def _kev(f):
    return bool((f.get("kev") or {}).get("listed"))


def _finding_ev(f):
    bits = [f.get("title") or f.get("cve") or ""]
    if _kev(f):
        bits.append("KEV")
    return m.ev("finding", f["id"], f"{f['id']} on {_asset(f)}", ", ".join(b for b in bits if b), strong=_kev(f))


def _names(tids, lib):
    out = []
    for t in tids:
        e = m.technique_entry(t, lib)
        out.append(f"{e['technique_name']} ({t})")
    return ", ".join(out)


def _behaviour(tids, lib, fallback):
    hunts = [(lib.get(_parent(t)) or {}).get("hunt") for t in tids]
    hunts = [h for h in hunts if h]
    return "; ".join(h[0].lower() + h[1:] for h in dict.fromkeys(hunts)) or fallback


def _days(ctx, *dates):
    ds = [d for d in (ctx.days_since(x) for x in dates if x) if d is not None]
    return min(ds) if ds else None


# ---------------------------------------------------------------- intel-driven
def gen_intel(ctx, lib):
    out, gaps = [], []
    findings = ctx.open_findings()
    by_cve = {}
    for f in findings:
        if f.get("cve"):
            by_cve.setdefault(f["cve"].upper(), []).append(f)

    # 1. imported reports
    floor = PRIO_RANK.get(str(ctx.cfg.get("intel_min_priority") or "medium").lower(), 1)
    if ctx.intel is None or not ctx.intel:
        gaps.append("No threat-intelligence reports have been imported, so no report-driven hunts. Paste a report or send STIX on the Intel tab.")
    for r in ctx.intel or []:
        if PRIO_RANK.get(r.get("priority"), 0) < floor:
            continue
        x = r["extracted"]
        tids = sorted({_parent(t) for t in x.get("techniques") or []})
        cves = [c.upper() for c in x.get("cves") or []]
        fnd = [f for c in cves for f in by_cve.get(c, [])]
        hosts = sorted({_asset(f) for f in fnd if _asset(f)})
        if not tids and not (x.get("ips") or x.get("domains") or x.get("hashes")):
            gaps.append(f"Report '{r['title']}' names no technique or indicator, so no behaviour could be hypothesised from it.")
            continue
        who = (x["actors"][0] + f" (named in '{r['title']}')") if x.get("actors") else f"the activity described in '{r['title']}'"
        expect = _behaviour(tids, lib, "") or (f"activity matching {_names(tids, lib)}" if tids else "contact with the report's indicators")
        why = [m.ev("intel", r["id"], r["title"], "; ".join(r.get("reasons") or [])[:280], strong=r.get("priority") == "high")] + [_finding_ev(f) for f in fnd[:CAP_EVIDENCE]]
        sig = {"intel_relevance": r.get("relevance") or 0, "kev": any(_kev(f) for f in fnd), "blast": len(hosts), "freshness_days": _days(ctx, r.get("received_at")),
               "epss": max([(f.get("epss") or {}).get("score") or 0 for f in fnd] or [0])}
        out.append(m.build("intel-report", "intel-driven", r["content_hash"], tids[0] if tids else "indicators", f"Hunt for the activity in: {r['title']}"[:190], who, expect,
                           (f"{len(hosts)} host(s) carrying the report's CVEs" if hosts else "hosts the report's techniques and indicators would touch"), why, tids, assets=hosts,
                           signals=sig, malicious=["Behaviour matching the report's techniques on in-scope hosts", "Contact with the report's indicators (see the intel tab's indicator query)"],
                           benign=["Administrators or scanners using the same tools", "Indicators that are shared hosting or CDN addresses"],
                           scoping="Start from the report's date minus 30 days; limit to the in-scope hosts first, then widen if anything is found.",
                           next_step="Run the leads, record each result, then conclude.", soar={"suggested": "Enrich indicators and open a case", "note": "An enrich-indicators then add-note playbook; any containment needs an approval step."}))

    # 2. threat-actor groups relevant to the sector
    estate = {}
    for f in findings:
        for t in _tids(f):
            estate.setdefault(_parent(t), []).append(f)
    if not ctx.industry:
        gaps.append("No industry is set in remediation/config/hunt_engine.yaml, so threat-actor groups are not matched to your sector.")
    else:
        for g in threat_actor_groups.THREAT_ACTOR_GROUPS:
            if ctx.industry not in g["target_industries"] or g.get("status") != "active":
                continue
            matched = sorted(t for t in g["associated_technique_ids"] if t in estate)
            if not matched:
                continue
            fnd = [f for t in matched for f in estate[t]]
            hosts = sorted({_asset(f) for f in fnd if _asset(f)})
            why = [m.ev("actor", g["id"], f"{g['name']} targets {ctx.industry}", f"MITRE lists {', '.join(matched)} for this group; {g['most_recent_activity']}"[:290])]
            why += [_finding_ev(f) for f in fnd[:CAP_EVIDENCE]]
            out.append(m.build("threat-actor", "intel-driven", g["id"], matched[0], f"Is {g['name']} tradecraft present?", f"{g['name']} ({', '.join(g['aliases'][:2])})",
                               _behaviour(matched, lib, f"activity matching {_names(matched, lib)}"), f"{len(hosts)} host(s) tagged with those techniques", why, matched, assets=hosts,
                               signals={"kev": any(_kev(f) for f in fnd), "blast": len(hosts), "freshness_days": None},
                               malicious=[f"Behaviour for {_names(matched, lib)} on in-scope hosts"], benign=["Common administrative activity: these techniques are shared by many groups and by normal operations"],
                               scoping="Last 30 days on the hosts carrying the matching findings. This is a cross-reference to MITRE's catalogue, not an attribution.",
                               next_step="Run the leads for the matched techniques and record the results.", soar=None,
                               source_note="Illustrative cross-reference to MITRE ATT&CK's group page; re-check before citing."))

    # 3. coordinated vulnerability disclosure matches
    if ctx.cvd is None:
        gaps.append("The CVD feed could not be read, so no advisory-driven hunts.")
    elif not ctx.cvd:
        gaps.append("No CVD advisory matches the estate (or the CVD feed has not been refreshed).")
    for a in ctx.cvd or []:
        fnd = [f for f in findings if f["id"] in set(a.get("finding_ids") or [])]
        tids = sorted({_parent(t) for f in fnd for t in _tids(f)})
        hosts = sorted({_asset(f) for f in fnd if _asset(f)})
        exact = "cve" in (a.get("match_basis") or [])
        why = [m.ev("cvd", a["id"], a["title"] or a["id"], f"{a.get('vendor', '')} {a.get('product', '')} ({'CVE match' if exact else 'name match, not a version check'})".strip(), strong=exact)]
        why += [_finding_ev(f) for f in fnd[:CAP_EVIDENCE]]
        out.append(m.build("cvd-advisory", "intel-driven", f"{a.get('source')}:{a['id']}", tids[0] if tids else "none", f"Post-exploitation of {a.get('product') or a['id']} ({a['id']})"[:190],
                           f"an adversary exploiting {a.get('product') or 'the affected product'} ({', '.join(a.get('cves') or []) or a['id']})",
                           _behaviour(tids, lib, "unexpected child processes, new accounts, new scheduled tasks or unusual outbound connections from the product's host"),
                           (f"{len(hosts)} host(s) with matching findings" if hosts else "hosts that appear to run the product (a name match)"), why, tids, assets=hosts,
                           signals={"kev": any(_kev(f) for f in fnd), "blast": len(hosts), "freshness_days": _days(ctx, a.get("published")), "severity_critical": a.get("severity") == "Critical"},
                           malicious=["The product's process starting shells or writing executables", "New outbound connections from the product's host"],
                           benign=["Vendor update or maintenance tasks", "A name match on a version that is not affected"],
                           scoping="From the advisory's publication date to now, on the matching hosts.", next_step="Confirm the version is affected first, then run the leads.",
                           soar={"suggested": "Open a case and notify the owner", "note": "notify and add-note steps only."},
                           source_note="" if tids else "No ATT&CK technique is tagged on the matching findings, so no queries were generated."))

    # 4. known-exploited vulnerabilities, as behaviour (existing generate.py is the source of the candidates)
    recent = int(ctx.cfg.get("kev_recent_days") or 45)
    for cve, g in generate.candidates(ctx.findings or []).items():
        fnd = by_cve.get(cve.upper(), [])
        tids = sorted({_parent(t) for t in g["techniques"]})
        hosts = sorted(g["hosts"])
        dates = [((f.get("kev") or {}).get("date_added")) for f in fnd]
        fresh = _days(ctx, *dates)
        why = [_finding_ev(f) for f in fnd[:CAP_EVIDENCE]]
        if not why:
            continue
        out.append(m.build("kev-exposure", "hypothesis-driven", cve, tids[0] if tids else "none", f"Post-exploitation behaviour after {cve}", f"an adversary who exploited {cve} ({g['title']})",
                           _behaviour(tids, lib, "new processes, accounts, scheduled tasks or outbound connections on the exposed host after the exploit window"),
                           f"{len(hosts)} exposed host(s)", why, tids, assets=hosts,
                           signals={"kev": g["kev"], "ransomware": g["ransomware"], "epss": g["epss"], "blast": len(hosts), "freshness_days": fresh if fresh is not None and fresh <= recent else (fresh if fresh is not None else None),
                                    "internet_facing": any(ctx.facing(h) == "external" for h in hosts), "severity_critical": any(f.get("severity") == "Critical" for f in fnd)},
                           malicious=["A web or service process starting a shell", "New local accounts, services or scheduled tasks created after the vulnerability's first-seen date"],
                           benign=["Patch or configuration-management activity", "Vulnerability scanners generating exploit-shaped requests"],
                           scoping="From the earlier of the vulnerability's first-seen date and the KEV listing date, to now, on the exposed hosts.",
                           next_step="Run the leads; if the host is already patched, hunt only for what happened before the patch.",
                           soar={"suggested": "Isolate host after approval", "note": "A response-action step needs an approval step before it and a second person."}))
    return out, gaps


# ---------------------------------------------------------------- coverage gaps
def gen_coverage_gap(ctx, lib):
    if not ctx.rules:
        return [], ["No detection rules are recorded (Detection engineering tab), so coverage cannot be judged and no coverage-gap hunts were suggested."]
    cov = usecases.covered_techniques(ctx.rules)
    evidence = {}
    for f in ctx.open_findings():
        for t in _tids(f):
            e = evidence.setdefault(_parent(t), {"findings": [], "alerts": [], "intel": []})
            e["findings"].append(f)
    for a in ctx.alerts or []:
        if a.get("technique"):
            evidence.setdefault(_parent(a["technique"]), {"findings": [], "alerts": [], "intel": []})["alerts"].append(a)
    for r in ctx.intel or []:
        for t in r["extracted"].get("techniques") or []:
            evidence.setdefault(_parent(t), {"findings": [], "alerts": [], "intel": []})["intel"].append(r)
    out = []
    for tid, e in sorted(evidence.items(), key=lambda kv: -(len(kv[1]["findings"]) + 3 * len(kv[1]["alerts"]) + 3 * len(kv[1]["intel"]))):
        if tid in cov:
            continue
        te = m.technique_entry(tid, lib)
        hosts = sorted({_asset(f) for f in e["findings"] if _asset(f)} | {a["asset"] for a in e["alerts"] if a.get("asset")})
        why = [_finding_ev(f) for f in e["findings"][:CAP_EVIDENCE]] + [m.ev("alert", a["id"], a["title"], f"{a['severity']}, {a['status']}", strong=a.get("disposition") == "true-positive") for a in e["alerts"][:5]]
        why += [m.ev("intel", r["id"], r["title"]) for r in e["intel"][:3]]
        out.append(m.build("coverage-gap", "hypothesis-driven", tid, tid, f"Unwatched technique: {te['technique_name']} ({tid})", f"an adversary using {te['technique_name']} ({tid})",
                           _behaviour([tid], lib, f"activity matching {te['technique_name']}"), f"{len(hosts)} host(s) where it shows up in findings or alerts" if hosts else "the estate", why, [tid], assets=hosts,
                           signals={"coverage": "none", "kev": any(_kev(f) for f in e["findings"]), "blast": len(hosts), "tp_history": any(a.get("disposition") == "true-positive" for a in e["alerts"]),
                                    "freshness_days": _days(ctx, *[a.get("received_at") for a in e["alerts"]], *[r.get("received_at") for r in e["intel"]]), "severity_critical": any(f.get("severity") == "Critical" for f in e["findings"])},
                           malicious=[f"Any hit that matches {te['technique_name']} behaviour and is not explained by an administrator"],
                           benign=[(lib.get(tid) or {}).get("notes") or "Test against recent data to learn the legitimate causes."],
                           scoping="Last 30 days on the listed hosts; if hunting finds nothing, promote the lead to a detection so the gap is closed for good.",
                           next_step="Run the leads. When concluded, promote to a detection use case.", soar=None))
        if len(out) >= 15:
            break
    return out, []


# ---------------------------------------------------------------- baseline and anomaly
def _ts(a):
    for k in ("occurred_at", "received_at"):
        try:
            d = datetime.datetime.fromisoformat(str(a.get(k)).replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
        except (TypeError, ValueError):
            continue
    return None


def _entity(a):
    ent = a.get("entities") or {}
    return (a.get("asset") or ent.get("host") or "").strip().lower() or None


def gen_baseline(ctx, lib):
    gaps = ["Rare parent/child process pairs and first-seen administrative tools need process telemetry that Quanta does not store; hunt for them in your SIEM or EDR."]
    if not ctx.alerts:
        return [], ["No alerts are stored, so alert-based baseline hunts (low-and-slow, bursts, off-hours privileged use) could not be produced."] + gaps
    out = []
    cfg = ctx.cfg["low_and_slow"]
    maxrank = SEV_RANK.get(cfg["max_severity"], 2)
    by = {}
    for a in ctx.alerts:
        k = _entity(a)
        if k:
            by.setdefault(k, []).append(a)
    for ent, alerts in sorted(by.items()):
        if any(a.get("disposition") == "true-positive" for a in alerts):
            continue
        low = [a for a in alerts if SEV_RANK.get(a["severity"], 2) <= maxrank]
        days = {t.date() for t in (_ts(a) for a in low) if t}
        if len(low) >= cfg["min_alerts"] and len(days) >= cfg["min_days"]:
            tids = sorted({_parent(a["technique"]) for a in low if a.get("technique")})
            rules = sorted({a.get("rule_name") or a["title"] for a in low})[:4]
            out.append(m.build("low-and-slow", "baseline-anomaly", ent, tids[0] if tids else "untagged", f"Low-and-slow pattern on {ent}", "an intruder staying under alert thresholds",
                               f"the same host recurring in {len(low)} low-severity alerts over {len(days)} days ({'; '.join(rules)})", ent,
                               [m.ev("alert", a["id"], a["title"], f"{a['severity']} {a['status']}") for a in sorted(low, key=lambda x: x["id"], reverse=True)[:CAP_EVIDENCE]], tids, assets=[ent],
                               signals={"anomaly": True, "blast": 1, "freshness_days": _days(ctx, *[a.get("received_at") for a in low])},
                               malicious=["A rising or varied set of rules on one host", "Alerts that line up in time with new accounts, tools or outbound connections"],
                               benign=["A noisy rule firing on a legitimate scheduled job", "A host under routine scanning"],
                               scoping=f"Every alert and log source for {ent} across the last {max(len(days), 7)} days, ordered by time.",
                               next_step="Open the alerts together as one timeline; conclude benign only when each has an explanation.", soar={"suggested": "Open a case linking the alerts", "note": "add-note and update-alert (investigating) only."}))
    # bursts: the same rule on the same host many times inside an hour
    groups = {}
    for a in ctx.alerts:
        k, t = _entity(a), _ts(a)
        if k and t and a.get("rule_name"):
            groups.setdefault((a["rule_name"], k), []).append((t, a))
    for (rule, ent), items in sorted(groups.items()):
        items.sort(key=lambda x: x[0])
        best = []
        j = 0
        for i in range(len(items)):
            while items[i][0] - items[j][0] > datetime.timedelta(hours=1):
                j += 1
            if i - j + 1 > len(best):
                best = items[j:i + 1]
        if len(best) >= 8 and not any(a.get("disposition") == "true-positive" for _, a in best):
            tids = sorted({_parent(a["technique"]) for _, a in best if a.get("technique")})
            out.append(m.build("alert-burst", "baseline-anomaly", f"{rule}|{ent}", tids[0] if tids else "untagged", f"Burst of '{rule}' on {ent}", "automated tooling or an intruder working quickly",
                               f"{len(best)} alerts from one rule within an hour on one host", ent, [m.ev("alert", a["id"], a["title"], a["severity"]) for _, a in best[:CAP_EVIDENCE]], tids, assets=[ent],
                               signals={"anomaly": True, "blast": 1, "freshness_days": _days(ctx, *[a.get("received_at") for _, a in best])},
                               malicious=["The burst starts after a first successful or unusual event", "Targets or accounts widen during the burst"],
                               benign=["A deployment, backup or vulnerability scan", "A misconfigured rule"], scoping="The hour around the burst on that host and the hosts it talked to.",
                               next_step="Compare the burst with change records for the same hour.", soar=None))
    # off-hours privileged use (needs access-governance data)
    if not ctx.entitlements:
        gaps.append("Off-hours privileged-account hunts need Access Governance entitlements, which are not loaded.")
    else:
        priv = {str(e["user"]).lower() for e in ctx.entitlements if e["privileged"] and e["status"] != "disabled"} | {str(e["account"]).lower() for e in ctx.entitlements if e["privileged"] and e["status"] != "disabled"}
        lo, hi = ctx.cfg["business_hours_utc"]
        offs = {}
        for a in ctx.alerts:
            user, t = ((a.get("entities") or {}).get("user") or "").lower(), _ts(a)
            if user and user in priv and t and not (lo <= t.hour < hi):
                offs.setdefault(user, []).append(a)
        for user, alerts in sorted(offs.items()):
            if len(alerts) >= 2:
                out.append(m.build("off-hours-privileged", "baseline-anomaly", user, "T1078", f"Off-hours activity by privileged account {user}", f"misuse of the privileged account {user}",
                                   f"{len(alerts)} alerts outside {lo:02d}:00-{hi:02d}:00 UTC naming the account", f"systems where {user} holds privileged access", [m.ev("alert", a["id"], a["title"], a["severity"]) for a in alerts[:CAP_EVIDENCE]], ["T1078"],
                                   identities=[user], assets=sorted({a["asset"] for a in alerts if a.get("asset")}), signals={"anomaly": True, "crown_jewel": True, "blast": len({a.get("asset") for a in alerts}), "freshness_days": _days(ctx, *[a.get("received_at") for a in alerts])},
                                   malicious=["Sign-ins from a source the account has not used before", "Use of tools the account does not normally use"],
                                   benign=["On-call work or a different time zone (change business_hours_utc if your hours differ)", "Scheduled maintenance"],
                                   scoping=f"The account's sign-ins and actions for 14 days; compare off-hours with its own usual pattern.", next_step="Ask the account owner, then run the leads.",
                                   soar={"suggested": "Notify the account's manager", "note": "notify step only; disabling the account is a person's decision."}))
    return out, gaps


# ---------------------------------------------------------------- exposure
def gen_exposure(ctx, lib):
    ext = sorted(n for n in (ctx.ownership or {}) if ctx.facing(n) == "external")
    if not ext:
        return [], ["No asset is marked internet-facing (Assets/ownership 'facing'), so exposure-driven hunts could not be produced."]
    by = {}
    for f in ctx.open_findings():
        if _asset(f) in ext and (_kev(f) or f.get("severity") == "Critical"):
            by.setdefault(_asset(f), []).append(f)
    out = []
    team_sizes = {}
    for n in (ctx.ownership or {}):
        t = ctx.team(n)
        if t:
            team_sizes[t] = team_sizes.get(t, 0) + 1
    for asset, fnd in by.items():
        ctrls = [c for c in ctx.controls or [] if fnmatch.fnmatchcase(asset.lower(), c["asset_name"].lower())]
        verified = [c for c in ctrls if c["state"] == "verified"]
        tids = sorted({"T1190"} | {_parent(t) for f in fnd for t in _tids(f)})
        cves = sorted({f["cve"] for f in fnd if f.get("cve")})[:5]
        blast = 1 + team_sizes.get(ctx.team(asset), 1) - 1 if ctx.team(asset) else 1
        why = [_finding_ev(f) for f in fnd[:CAP_EVIDENCE]]
        why.append(m.ev("asset", asset, f"{asset} is marked internet-facing", f"controls recorded: {len(ctrls)} ({len(verified)} verified)" if ctrls else "no compensating control recorded (unknown, not absent)"))
        first = min([f.get("first_seen") or "9999" for f in fnd])
        out.append(m.build("exposed-asset", "hypothesis-driven", asset, "T1190", f"Has anyone already used the path into {asset}?", f"an adversary who reached {asset} from the internet through {', '.join(cves) or 'its critical findings'}",
                           _behaviour(tids, lib, "unexpected processes, new accounts or outbound connections"), asset, why, tids, assets=[asset],
                           signals={"internet_facing": True, "kev": any(_kev(f) for f in fnd), "severity_critical": any(f.get("severity") == "Critical" for f in fnd), "blast": blast,
                                    "epss": max([(f.get("epss") or {}).get("score") or 0 for f in fnd] or [0]), "freshness_days": _days(ctx, *[f.get("last_seen") for f in fnd]),
                                    "coverage": "partial" if verified else None},
                           malicious=["Requests to the vulnerable path followed by a process or file change on the host", "Outbound connections from the host that it does not normally make"],
                           benign=["Scanners and monitoring probes", "Patching and deployment activity"],
                           scoping=f"From {first if first != '9999' else 'the first date the weakness was reported'} to now on {asset}; widen to hosts it connects to only if something is found.",
                           next_step="Check the web or service logs for the vulnerable path first; then the host's process and network history.",
                           soar={"suggested": "Isolate host after approval", "note": "Needs an approval step and a second person."}))
    out.sort(key=lambda h: -h["signals"]["blast"])
    return out[: int(ctx.cfg["exposure"]["max_assets"])], ([] if by else ["Internet-facing assets exist but none carries a KEV or Critical open finding."])


# ---------------------------------------------------------------- identity
def gen_identity(ctx, lib):
    if not ctx.entitlements:
        return [], ["No Access Governance entitlements are loaded, so identity-misuse hunts could not be produced."]
    wanted = {"IAM001": ("has left the organisation", "sign-ins by the account after the leaving date", True), "IAM002": ("has not been used for a long time", "a first sign-in in months, from a new source or system", False),
              "IAM006": ("is shared or has no owner", "sign-ins from several sources, or at times no single person explains", False)}
    priv = {str(e["user"]).lower() for e in ctx.entitlements if e["privileged"] and e["status"] != "disabled"}
    out = []
    for f in ctx.iam_findings or []:
        if f["id"] not in wanted:
            continue
        why_txt, expect, strong = wanted[f["id"]]
        user = f["user"]
        out.append(m.build("identity-misuse", "hypothesis-driven", f"{f['id']}:{user}", "T1078", f"Could {user} be misused? ({f['id']})", f"someone using the credentials of {user}, an account that {why_txt}",
                           expect, f"{f.get('system') or 'the systems the account can reach'}", [m.ev("iam", f"{f['id']}:{user}", f["title"], f["detail"][:280], strong=strong)], ["T1078"], identities=[user],
                           assets=[f["system"]] if f.get("system") else [], signals={"crown_jewel": user.lower() in priv or f["severity"] in ("Critical", "High"), "blast": 1, "freshness_days": None,
                                                                                    "kev": False},
                           malicious=["Any successful sign-in by an account that should be inactive", "A sign-in from a source or country never seen for this account"],
                           benign=["A returning employee or contractor whose record is not yet updated", "An automation that uses the account"],
                           scoping="Every authentication event for the account since the date it should have been disabled (or the last 90 days).",
                           next_step="Run the sign-in lead; ask the identity team to disable the account regardless of the outcome.", soar={"suggested": "Notify the identity team", "note": "Disabling the account is the identity team's action; Quanta only records it."}))
    sev = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    order = {f["id"] + ":" + f["user"]: i for i, f in enumerate(sorted(ctx.iam_findings or [], key=lambda x: sev.get(x["severity"], 4)))}
    out.sort(key=lambda h: order.get(h["why_now"][0]["ref"], 99))
    return out[: int(ctx.cfg["identity"]["max_identities"])], []


# ---------------------------------------------------------------- lessons learned
def gen_lessons(ctx, lib):
    seeds = {}
    for a in ctx.alerts or []:
        if a.get("disposition") == "true-positive" and a.get("technique"):
            s = seeds.setdefault(_parent(a["technique"]), {"hosts": set(), "ev": []})
            if a.get("asset"):
                s["hosts"].add(a["asset"])
            s["ev"].append(m.ev("alert", a["id"], a["title"], "closed as a true positive", strong=True))
    for h in ctx.hunts or []:
        if h.get("outcome") == "confirmed":
            for t in h.get("techniques") or []:
                s = seeds.setdefault(_parent(t["technique_id"]), {"hosts": set(), "ev": []})
                s["hosts"] |= set(h.get("assets") or [])
                s["ev"].append(m.ev("hunt", h["id"], h["title"], "concluded as confirmed", strong=True))
    if not seeds:
        return [], ["No alert or hunt has been confirmed as a true positive yet, so there are no lessons-learned sweeps."]
    out = []
    for tid, s in sorted(seeds.items()):
        others = sorted({_asset(f) for f in ctx.open_findings() if tid in {_parent(t) for t in _tids(f)} and _asset(f) and _asset(f) not in s["hosts"]})
        if not others:
            continue
        te = m.technique_entry(tid, lib)
        out.append(m.build("lessons-learned", "hypothesis-driven", tid, tid, f"Where else did {te['technique_name']} ({tid}) happen?", f"the same {te['technique_name']} activity that was confirmed on {', '.join(sorted(s['hosts'])[:3]) or 'another system'}",
                           _behaviour([tid], lib, f"activity matching {te['technique_name']}"), f"{len(others)} other host(s) with findings tagged {tid}", s["ev"][:CAP_EVIDENCE], [tid], assets=others,
                           signals={"tp_history": True, "blast": len(others), "freshness_days": None},
                           malicious=["The same indicators and behaviour as the confirmed case"], benign=["The confirmed case's own benign look-alikes noted in its conclusion"],
                           scoping="Reuse the confirmed hunt's queries and time window, on the other hosts.", next_step="Run the confirmed case's leads against the listed hosts.", soar=None))
    return out[: int(ctx.cfg["lessons"]["max_per_run"])], []


# ---------------------------------------------------------------- dark web
def gen_darkweb(ctx, lib):
    if ctx.darkweb is None or not ctx.darkweb:
        return [], ["No dark-web credential-exposure hits are recorded, so no credential-stuffing hunts."]
    groups = {}
    for h in ctx.darkweb:
        if h["kind"] == "credential-exposure" and h["status"] in ("new", "reviewing"):
            groups.setdefault(h["term"], []).append(h)
    out = []
    for term, hits in sorted(groups.items()):
        users = sorted({str(e["user"]).lower() for e in ctx.entitlements or [] if str(e["user"]).lower().endswith("@" + term.lower())})
        out.append(m.build("credential-exposure", "intel-driven", term, "T1110", f"Credential stuffing against {term} accounts", f"someone using credentials exposed for {term}",
                           "password-spray or credential-stuffing attempts, and successful sign-ins from sources the accounts have not used before", f"accounts at {term}" + (f" ({len(users)} known)" if users else ""),
                           [m.ev("darkweb", h["id"], h["title"], f"{h['source']}, {h['severity']}", strong=True) for h in hits[:CAP_EVIDENCE]], ["T1110", "T1078"], identities=users or [], segments=[f"domain:{term}"],
                           signals={"crown_jewel": False, "blast": len(users), "freshness_days": _days(ctx, *[h.get("first_seen") for h in hits]), "internet_facing": True},
                           malicious=["Many accounts failing from one source, then a success", "A success from a new country or hosting provider"],
                           benign=["Users mistyping after a password rotation", "Single sign-on retries"],
                           scoping="Sign-in logs for the exposed domain since the exposure's first-seen date.", next_step="Run the sign-in leads; force a password reset for accounts shown in the exposure, whatever the hunt finds.",
                           soar={"suggested": "Notify the identity team", "note": "Forced reset is the identity team's action."}))
    return out, ([] if out else ["Credential-exposure hits exist but all are already actioned or dismissed."])


# ---------------------------------------------------------------- model-assisted
def gen_model_assisted(ctx, lib):
    untagged = [a for a in ctx.alerts or [] if not a.get("technique") and a["status"] != "closed"][:100]
    if not untagged:
        return [], []
    examples = [(f"{a['title']} {a.get('detail') or ''}", a["technique"]) for a in ctx.alerts if a.get("disposition") == "true-positive" and a.get("technique")][:500]
    groups = {}
    for a in untagged:
        r = ttp.classify(f"{a['title']} {a.get('detail') or ''}", examples, top=1)
        top = (r["techniques"] or [None])[0]
        if r["confident"] and top and top["source"] == "model":
            groups.setdefault(_parent(top["id"]), []).append((a, top))
    out = []
    for tid, items in sorted(groups.items()):
        if len(items) < 3:
            continue
        te = m.technique_entry(tid, lib)
        hosts = sorted({a["asset"] for a, _ in items if a.get("asset")})
        words = sorted({w for _, t in items for w in t["evidence"]})[:6]
        out.append(m.build("model-assisted", "model-assisted", tid, tid, f"Untagged alerts that read like {te['technique_name']} ({tid})", f"{te['technique_name']} activity that no rule has tagged",
                           _behaviour([tid], lib, f"activity matching {te['technique_name']}"), f"{len(hosts)} host(s) in {len(items)} untagged alerts",
                           [m.ev("alert", a["id"], a["title"], f"classifier {int(t['probability'] * 100)}% ({', '.join(t['evidence'][:3])})") for a, t in items[:CAP_EVIDENCE]], [tid], assets=hosts,
                           signals={"anomaly": False, "blast": len(hosts), "freshness_days": _days(ctx, *[a.get("received_at") for a, _ in items])},
                           malicious=["Alerts whose wording matches the technique AND whose host shows the behaviour in logs"], benign=[f"The classifier matched wording only ({', '.join(words)}); a benign command can share words"],
                           scoping="The hosts in the listed alerts, 7 days either side of each.", next_step="Tag the alerts if the wording is right; then run the leads.", soar=None,
                           source_note="A Naive Bayes wording classifier, not a behavioural model; treat as a lead."))
    return out, []


GENERATORS = (("intel", gen_intel), ("coverage_gap", gen_coverage_gap), ("baseline", gen_baseline), ("exposure", gen_exposure), ("identity", gen_identity),
              ("lessons", gen_lessons), ("darkweb", gen_darkweb), ("model_assisted", gen_model_assisted))
