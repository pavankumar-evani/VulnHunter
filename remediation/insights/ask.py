"""
Structured intent layer for the Ask box: a fixed, disclosed grammar that turns a sentence into a structured query, runs it against the existing read
data with the asker's own permissions, and returns the results AND the exact structured query it ran. Not a language model: a sentence that fits no
shape is not answered, it gets suggestions (and the caller may fall back to the older keyword search at /api/search/ask).

Safety: the text is data. It is length-capped, stripped of control characters and only ever matched against a fixed vocabulary; the few free parts
(an asset name, a package term, a technique id) are cut down to a strict identifier pattern and used only for in-memory comparison, never for a query
string, path, shell or SQL.
"""
import re

MAX_LEN = 300
IDENT = r"[A-Za-z0-9][A-Za-z0-9._\-]{0,63}"

SUGGESTIONS = [
    "critical KEV findings on internet-facing assets",
    "overdue high findings owned by team Platform",
    "what changed this week",
    "who owns host WIN-DC01",
    "open incidents assigned to me",
    "hunts for T1059",
    "show applications using log4j",
    "what should I do first",
]

_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
_KEV = re.compile(r"\b(kev|known[- ]exploited|actively exploited|exploited in the wild)\b")
_EXPOSED = re.compile(r"\b(internet[- ]facing|internet[- ]exposed|externally[- ]facing|external(?:ly)?|public(?:ly)? (?:facing|exposed))\b")
_SLA = [(re.compile(r"\b(overdue|breached|past (?:their |the )?sla|out of sla)\b"), "breached"), (re.compile(r"\b(at risk|about to breach|nearly overdue)\b"), "at_risk")]
_WORDS_FINDINGS = re.compile(r"\b(findings?|vulnerabilit(?:y|ies)|vulns?|issues?|cves?)\b")
_COUNT = re.compile(r"\b(how many|count|number of|total)\b")
_NEW = re.compile(r"\b(?:new|appeared|first seen)\b(?: in| since| this| last| the past| over)?(?: (\d{1,3}) days?| (today)| (week)| (yesterday))?")

R_CHANGED = re.compile(r"\bwhat(?:'s| is| has| have)? (?:changed|new)\b|\bchanges? (?:this|in the last|over the last|today)\b|\bsince (?:yesterday|last week)\b")
R_OWNER = re.compile(r"\b(?:who owns|who is the owner of|owner of|who looks after)\b (?:the )?(?:host |asset |server |machine |box |application |app )?(" + IDENT + ")", re.IGNORECASE)
R_MINE = re.compile(r"\b(?:(?:open |my )?(?:incidents?|cases?)\b.*\b(?:assigned to me|mine|i own|for me)|my (?:open )?(?:incidents?|cases?))\b")
R_HUNT = re.compile(r"\bhunts?\b.*?\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
R_APPS = re.compile(r"\bapplications?\b(?: that| which)? (?:using|use|uses|with|containing|running|affected by|depending on|that depend on) (?:the )?(" + IDENT + ")", re.IGNORECASE)
R_INSIGHTS = re.compile(r"\b(?:top |my )?(?:insights?|priorities)\b|\bwhat should i (?:do|work on|look at)\b|\bnext best action\b")
R_TEAM = re.compile(r"\b(?:owned by |team )(?:team )?(" + IDENT + ")", re.IGNORECASE)
R_ASSET = re.compile(r"\bon (?:the )?(?:host |asset |server )(" + IDENT + ")", re.IGNORECASE)
R_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)


def clean(text):
    t = "".join(ch for ch in str(text or "") if ch == " " or (ch.isprintable() and ch not in "`$;|<>\\{}"))
    return re.sub(r"\s+", " ", t).strip()[:MAX_LEN]


def parse(text):
    """-> {"ok": True, "intent", "params", "matched"[], "ignored"[]} or {"ok": False, "reason", "suggestions"[]}. Deterministic and side-effect free."""
    raw = clean(text)
    low = raw.lower()
    if not low:
        return {"ok": False, "reason": "Type a question.", "suggestions": SUGGESTIONS[:5]}

    def done(intent, params, matched):
        return {"ok": True, "intent": intent, "params": params, "matched": matched, "ignored": []}

    if R_CHANGED.search(low):
        days = 1 if re.search(r"\b(today|yesterday)\b", low) else 7
        return done("changes.period", {"days": days}, ["what changed"])
    if m := R_OWNER.search(raw):
        return done("asset.owner", {"asset": _ident(raw, m)}, ["who owns"])
    if R_MINE.search(low):
        return done("cases.mine", {"open_only": True}, ["incidents assigned to me"])
    if m := R_HUNT.search(raw):
        return done("hunts.technique", {"technique": m.group(1).upper()}, ["hunts for technique"])
    if m := R_APPS.search(raw):
        return done("apps.using", {"term": _ident(raw, m).lower()}, ["applications using"])
    if R_INSIGHTS.search(low) and not _WORDS_FINDINGS.search(low):
        return done("insights.top", {"limit": 5}, ["insights"])

    filters, matched = {}, []
    for word, sev in _SEV.items():
        if re.search(rf"\b{word}\b", low):
            filters.setdefault("severity", []).append(sev)
    if "severity" in filters:
        matched.append("severity")
    if _KEV.search(low):
        filters["kev"] = True
        matched.append("known exploited")
    if _EXPOSED.search(low):
        filters["internet_facing"] = True
        matched.append("internet-facing")
    for rx, v in _SLA:
        if rx.search(low):
            filters["sla"] = v
            matched.append("sla")
            break
    if m := R_TEAM.search(raw):
        filters["team"] = _ident(raw, m)
        matched.append("team")
    if m := R_ASSET.search(raw):
        filters["asset"] = _ident(raw, m)
        matched.append("asset")
    if m := R_CVE.search(raw):
        filters["cve"] = m.group(1).upper()
        matched.append("cve")
    if m := re.search(r"\bnew\b.*?\b(\d{1,3}) days?\b", low):
        filters["new_days"] = min(int(m.group(1)), 365)
        matched.append("new")
    elif re.search(r"\bnew (?:this week|findings this week)\b|\bnew\b.*\bweek\b", low):
        filters["new_days"] = 7
        matched.append("new")
    elif re.search(r"\bnew (?:today|yesterday)\b", low):
        filters["new_days"] = 1
        matched.append("new")
    if _WORDS_FINDINGS.search(low) or (filters and ("severity" in filters or "kev" in filters or "sla" in filters)):
        if filters or _WORDS_FINDINGS.search(low):
            mode = "count" if _COUNT.search(low) else "list"
            return done("findings.list", {"filters": filters, "mode": mode}, matched or ["findings"])
    return {"ok": False, "reason": "That does not match any question shape I understand.", "suggestions": SUGGESTIONS}


def _ident(raw, m):
    """The identifier from the match, in its original case, restricted to the strict identifier pattern."""
    return raw[m.start(1):m.end(1)][:64]


# ---------------------------------------------------------------- execution
class Context:
    """The data the intents read. Every callable is supplied by the caller, already scoped to the asker, so this module can never widen access.
    findings() -> scored queue list (team-scoped); assets() -> inventory rows; cases()/hunts() -> lists or None when the asker may not read them;
    sbom_components() -> [{application, name, version}]; insights(limit) -> ranked insights; activity(since_iso) -> count; user -> the asker."""

    def __init__(self, user=None, findings=None, assets=None, cases=None, hunts=None, sbom_components=None, insights=None, activity=None, today=None):
        self.user, self.findings, self.assets, self.cases, self.hunts = user, findings, assets, cases, hunts
        self.sbom_components, self.insights, self.activity, self.today = sbom_components, insights, activity, today


def _kev(f):
    k = f.get("kev")
    return bool(k.get("listed")) if isinstance(k, dict) else bool(k)


def _sla_state(f):
    s = f.get("sla") or {}
    if s.get("breached"):
        return "breached"
    r = s.get("days_remaining")
    return "at_risk" if r is not None and r <= 3 else "on_track"


def _row(f):
    return {"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"), "asset": (f.get("asset") or {}).get("name"), "cve": f.get("cve"),
            "kev": _kev(f), "sla": _sla_state(f), "page": f"/queue?highlight={f.get('id')}"}


def run_findings(params, ctx):
    fl, fs = params["filters"], ctx.findings() if ctx.findings else None
    if fs is None:
        return _unavailable("findings")
    facing = {a.get("name"): (a.get("facing") or "") for a in (ctx.assets() or [])} if ctx.assets else {}
    out = []
    t = ctx.today
    for f in fs:
        a = ((f.get("asset") or {}).get("name") or "")
        if fl.get("severity") and f.get("severity") not in fl["severity"]:
            continue
        if fl.get("kev") and not _kev(f):
            continue
        if fl.get("internet_facing") and facing.get(a) != "internet":
            continue
        if fl.get("sla") and _sla_state(f) != fl["sla"]:
            continue
        if fl.get("team") and (f.get("team") or "").lower() != fl["team"].lower():
            continue
        if fl.get("asset") and a.lower() != fl["asset"].lower():
            continue
        if fl.get("cve") and (f.get("cve") or "").upper() != fl["cve"]:
            continue
        if fl.get("new_days") and t:
            d = str(f.get("first_seen") or "")[:10]
            if not d or (t - _date(d)).days >= fl["new_days"]:
                continue
        out.append(f)
    out.sort(key=lambda f: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(f.get("severity"), 4), str(f.get("id"))))
    rows = [_row(f) for f in out[:50]]
    note = None
    if fl.get("internet_facing") and not any(v == "internet" for v in facing.values()):
        note = "No asset is marked internet-facing in the inventory, so this filter matches nothing; set exposure on the Ownership page."
    return {"summary": f"{len(out)} finding(s) match" + (f"; showing the top {len(rows)}" if len(out) > len(rows) else ""), "count": len(out),
            "rows": [] if params["mode"] == "count" else rows, "columns": ["id", "title", "severity", "asset", "cve"], "page": "/queue", "note": note}


def _date(s):
    import datetime
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return datetime.date.min


def run_changes(params, ctx):
    fs = ctx.findings() if ctx.findings else None
    if fs is None:
        return _unavailable("findings")
    t, days = ctx.today, params["days"]
    new = [f for f in fs if f.get("first_seen") and t and 0 <= (t - _date(str(f["first_seen"])[:10])).days < days]
    by = {s: sum(1 for f in new if f.get("severity") == s) for s in ("Critical", "High", "Medium", "Low")}
    kev = sum(1 for f in new if _kev(f))
    parts = [f"{len(new)} new finding(s) ({', '.join(f'{v} {k}' for k, v in by.items() if v) or 'none'})", f"{kev} of them known-exploited"]
    acts = ctx.activity((t.isoformat() if t else "")) if ctx.activity and t else None
    if acts is not None:
        parts.append(f"{acts} recorded change(s) in the activity log" + ("" if days > 1 else " since the start of the day"))
    ins = ctx.insights(3) if ctx.insights else []
    return {"summary": "In the last %d day(s): %s." % (days, "; ".join(parts)), "count": len(new), "rows": [_row(f) for f in new[:20]],
            "columns": ["id", "title", "severity", "asset", "cve"], "page": "/queue?new=true",
            "extra": {"top_insights": [{"id": i["id"], "title": i["title"], "score": i.get("score")} for i in ins]}}


def run_owner(params, ctx):
    assets = ctx.assets() if ctx.assets else None
    if assets is None:
        return _unavailable("assets")
    q = params["asset"].lower()
    hit = [a for a in assets if (a.get("name") or "").lower() == q] or [a for a in assets if q in (a.get("name") or "").lower()]
    rows = [{"name": a.get("name"), "owner": a.get("owner") or "(none recorded)", "team": a.get("team") or "(none recorded)", "facing": a.get("facing") or "unknown",
             "page": f"/ownership?asset={a.get('name')}"} for a in hit[:10]]
    return {"summary": (f"{rows[0]['name']} is owned by {rows[0]['owner']} (team {rows[0]['team']})." if len(rows) == 1 else f"{len(rows)} assets match '{params['asset']}'." if rows
                        else f"No asset named '{params['asset']}' in the inventory."), "count": len(rows), "rows": rows, "columns": ["name", "owner", "team", "facing"], "page": "/ownership"}


def run_cases(params, ctx):
    cases = ctx.cases() if ctx.cases else None
    if cases is None:
        return {"forbidden": "Incidents and cases are visible to administrators only."}
    me = (ctx.user or {}).get("email")
    mine = [c for c in cases if c.get("assignee") == me and c.get("status") in ("new", "in_progress", "pending", "escalated")]
    rows = [{"id": c["id"], "title": c.get("title"), "priority": c.get("priority"), "status": c.get("status"), "page": "/soc"} for c in mine[:25]]
    return {"summary": f"{len(mine)} open case(s) assigned to you.", "count": len(mine), "rows": rows, "columns": ["id", "title", "priority", "status"], "page": "/soc"}


def run_hunts(params, ctx):
    hunts = ctx.hunts() if ctx.hunts else None
    if hunts is None:
        return {"forbidden": "Hunts are visible to administrators only."}
    tq = params["technique"].upper()
    hit = [h for h in hunts if any(str(x).upper() == tq or str(x).upper().startswith(tq + ".") for x in (h.get("techniques") or h.get("techniques_json") or []))]
    rows = [{"id": h.get("id"), "title": h.get("title"), "status": h.get("status"), "page": "/hunting"} for h in hit[:25]]
    return {"summary": f"{len(hit)} hunt(s) cover {tq}.", "count": len(hit), "rows": rows, "columns": ["id", "title", "status"], "page": "/hunting"}


def run_apps(params, ctx):
    term = params["term"]
    comps = ctx.sbom_components() if ctx.sbom_components else None
    fs = ctx.findings() if ctx.findings else None
    if comps is None and fs is None:
        return _unavailable("SBOMs and findings")
    apps = {}
    for c in comps or []:
        if term in str(c.get("name", "")).lower():
            apps.setdefault(c["application"], set()).add(f"{c.get('name')} {c.get('version') or ''}".strip() + " (SBOM)")
    for f in fs or []:
        dep = f.get("dependency") or {}
        if term in str(dep.get("package", "")).lower() or term in str(f.get("title", "")).lower():
            a = (f.get("asset") or {}).get("name")
            if a and ((f.get("asset") or {}).get("type") == "application" or dep):
                apps.setdefault(a, set()).add(f"{f.get('id')} (finding)")
    rows = [{"application": a, "evidence": ", ".join(sorted(v)[:4]), "page": "/applications"} for a, v in sorted(apps.items())]
    note = None if comps else "No SBOM data was available; matches come from findings only."
    return {"summary": f"{len(rows)} application(s) match '{term}'.", "count": len(rows), "rows": rows[:50], "columns": ["application", "evidence"], "page": "/applications", "note": note}


def run_insights(params, ctx):
    ins = ctx.insights(params["limit"]) if ctx.insights else None
    if ins is None:
        return _unavailable("insights")
    rows = [{"id": i["id"], "title": i["title"], "score": i.get("score"), "action": i["action"]["label"], "page": i["action"]["page"]} for i in ins]
    return {"summary": f"{len(rows)} top insight(s) for you." if rows else "No open insights right now.", "count": len(rows), "rows": rows, "columns": ["title", "score", "action"], "page": "/"}


def _unavailable(what):
    return {"summary": f"The {what} data is not available, so this question cannot be answered.", "count": 0, "rows": [], "columns": [], "page": None}


RUNNERS = {"findings.list": run_findings, "changes.period": run_changes, "asset.owner": run_owner, "cases.mine": run_cases, "hunts.technique": run_hunts,
           "apps.using": run_apps, "insights.top": run_insights}


def ask(text, ctx):
    """-> {"parsed": bool, "query": {intent, params}, "result": {...}} (or "forbidden"), always echoing the exact structured query that ran."""
    p = parse(text)
    if not p["ok"]:
        return {"parsed": False, "query": None, "reason": p["reason"], "suggestions": p["suggestions"], "fallback": "/api/search/ask"}
    res = RUNNERS[p["intent"]](p["params"], ctx)
    q = {"intent": p["intent"], "params": p["params"], "matched": p["matched"]}
    if "forbidden" in res:
        return {"parsed": True, "query": q, "forbidden": res["forbidden"]}
    return {"parsed": True, "query": q, "result": res}
