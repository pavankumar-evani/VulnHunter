"""
The hunt report: the document a hunt ends in, built from the hunt, its trial hits (leads), what each returned and what the analysts decided.

A trial hit is one lead: one query for one attack step. For each the report shows its domain (endpoint, network or identity-email), the tool it ran in, whether it was run, how
many hits it returned, which entities those hits touched, and the query itself as Splunk SPL, a Sigma rule and Sentinel KQL so it can be run in whichever tool the analyst has.

Rules kept here:
  * Status is no-hit, needs-investigation or not-run. A hit nobody has assessed is needs-investigation, never benign. A lead that errored is not-run, with the error shown.
  * The allow-list is the analysts' recorded decision that a specific value (a scanner's address, a patch server) is benign for a given lead. It applies to every later run of
    that lead, removes matching rows from the sample, and the report shows how many rows it removed and why. If the sample is truncated, rows that were never seen cannot be
    checked, so the count after the allow-list is marked partial instead of guessed.
  * The overall verdict is no-ioc-match (every lead that ran had no hits or only benign ones), needs-investigation, confirmed (an analyst judged hits malicious) or not-run.
    A hunt where only some leads ran says so; its "no match" covers only those.
  * Quanta does not run a query on its own: leads run only after a person confirms in the SIEM connection, and results are the analysts' record.
"""
import datetime
import re

from remediation.hunting import detection, generate, usecases
from remediation.hunting.engine import render
from remediation.hunting.verdict import ENTITY_FIELDS
from remediation.investigation import playbook as qpb
from remediation.investigation import store as inv_store
from remediation.utils.digest import dedup_sha1

DOMAIN_MAP = {"endpoint": "endpoint", "network": "network", "identity": "identity-email", "identity-email": "identity-email", "email": "identity-email"}
STATUSES = ("no-hit", "needs-investigation", "not-run")
VERDICTS = ("no-ioc-match", "needs-investigation", "confirmed", "not-run")
ALLOW_FIELDS = tuple(sorted(set(ENTITY_FIELDS)))


def _dt(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def domain_of(q, lib=None):
    d = (q.get("domain") or "").lower()
    if d in DOMAIN_MAP:
        return DOMAIN_MAP[d]
    entry = (lib if lib is not None else generate.library()).get((q.get("technique") or "").split(".")[0]) or {}
    return DOMAIN_MAP.get((entry.get("domain") or "").lower(), entry.get("domain") or "endpoint")


def renderings(q, hunt, lib=None):
    """The query as SPL, Sigma and KQL. Uses what the lead already carries, else rebuilds Sigma and KQL from the library detection of the same name. Missing ones say why."""
    spl, sigma, kql = q.get("query"), q.get("sigma"), q.get("kql")
    why = None
    if not (sigma and kql):
        tid = (q.get("technique") or "").split(".")[0]
        entry = (lib if lib is not None else render.library()).get(tid) or {}
        det = next((d for d in entry.get("detections") or [] if d["name"] == q.get("name")), None)
        if det:
            try:
                hosts = sorted(hunt.get("assets") or [])[:50] or None
                kql = kql or render.to_kql(det["selection"], hosts)
                key = f"hunt-{tid}-{dedup_sha1(q['name'].encode()).hexdigest()[:8]}"
                sigma = sigma or usecases.sigma_draft(key, f"Quanta hunt - {det['name']}", hunt.get("hypothesis") or entry.get("hunt") or "", [tid], det["selection"],
                                                      usecases.LOGSOURCE.get(tid, {"category": "process_creation"}), "medium", datetime.date.today())
            except Exception as exc:  # noqa: BLE001
                why = f"could not be rendered ({str(exc)[:80]})"
        else:
            why = "this lead is not a library detection, so Sigma and KQL are not available for it"
    return {"spl": spl, "sigma": sigma, "kql": kql, "note": why if not (sigma and kql) else None}


def lead_key(q):
    return inv_store.lead_key(q)


def apply_allowlist(q, entries):
    """-> (kept_rows, suppressed_rows, used_entry_ids). Matching is exact, case-insensitive, on the recorded field."""
    kept, suppressed, used = [], [], set()
    for row in q.get("sample") or []:
        hit = next((e for e in entries if str(row.get(e["field"], "")).lower() == str(e["value"]).lower() and e["value"]), None)
        if hit:
            suppressed.append(row)
            used.add(hit["id"])
        else:
            kept.append(row)
    return kept, suppressed, used


def _entities(rows):
    ents = set()
    for row in rows:
        for f in ENTITY_FIELDS:
            if row.get(f):
                ents.add(str(row[f]))
    return sorted(ents)


def _lead_row(i, q, hunt, entries_by_lead, lib, render_lib, hunt_id):
    ran = q.get("result") in ("hits", "no-hits")
    allow = entries_by_lead.get(lead_key(q), [])
    kept, suppressed, used = apply_allowlist(q, allow) if ran else ([], [], set())
    raw = q.get("count") if ran else None
    after, partial = raw, False
    if ran and raw:
        after = max(0, raw - len(suppressed))
        partial = bool(suppressed) and (bool(q.get("truncated")) or raw > len(q.get("sample") or []))
    if not ran:
        status = "not-run"
    elif not after or (q.get("assessment") == "benign"):
        status = "no-hit"
    else:
        status = "needs-investigation"
    return {"n": i + 1, "index": i, "name": q.get("name"), "technique": q.get("technique"), "domain": domain_of(q, lib), "source_tool": q.get("source") or "SIEM", "status": status,
            "hits": raw, "hits_after_allowlist": after, "allowlisted_rows": len(suppressed), "allowlist_partial": partial, "assessment": q.get("assessment"),
            "entities": _entities(kept), "entities_all": _entities(q.get("sample") or []), "window": q.get("window"), "ran_at": q.get("ran_at"), "error": q.get("error"), "notes": q.get("notes") or "",
            "lead": {"hunt_id": hunt_id, "index": i, "path": f"/hunting?hunt={hunt_id}&lead={i}"}, "queries": renderings(q, hunt, render_lib),
            "allowlist_entries": sorted(used), "judged_benign": status == "no-hit" and bool(raw) and q.get("assessment") == "benign"}


def _verdict(rows, hunt):
    ran = [r for r in rows if r["status"] != "not-run"]
    needs = [r for r in rows if r["status"] == "needs-investigation"]
    confirmed = [r for r in needs if r["assessment"] == "malicious"]
    seen, shared = {}, set()
    for r in needs:
        for e in r["entities"]:
            if e in seen and seen[e] != r["n"]:
                shared.add(e)
            seen.setdefault(e, r["n"])
    if confirmed:
        label = "confirmed"
        why = f"An analyst judged the hits of trial hit(s) {', '.join(str(r['n']) for r in confirmed)} malicious."
    elif needs:
        label = "needs-investigation"
        why = f"Trial hit(s) {', '.join(str(r['n']) for r in needs)} returned hits that are not yet judged benign." + (f" The same entity appears in more than one: {', '.join(sorted(shared)[:5])}." if shared else "")
    elif ran:
        label = "no-ioc-match"
        why = f"{len(ran)} of {len(rows)} trial hit(s) ran and none has an unexplained hit." + (" The others were not run, so this covers only those that ran." if len(ran) < len(rows) else "")
    else:
        label = "not-run"
        why = "No trial hit has been run, so there is nothing to conclude."
    return {"label": label, "rationale": why, "correlated_entities": sorted(shared), "evidence": [r["n"] for r in (confirmed or needs or ran)][:20]}


def _detection_recs(hunt, rows, rules):
    covered = {t.split(".")[0] for r in rules if r.get("enabled", True) for t in r.get("techniques") or []}
    out = []
    for r in rows:
        tid = (r["technique"] or "").split(".")[0]
        if not tid or r["status"] == "not-run":
            continue
        if tid in covered:
            out.append({"trial_hit": r["n"], "technique": tid, "recommendation": "covered", "text": f"{tid} is already covered by an enabled detection rule; check it would have caught trial hit {r['n']} ('{r['name']}').", "priority": "low", "usecase_key": None})
            continue
        q = hunt["queries"][r["index"]]
        promotable = q.get("assessment") in ("suspicious", "malicious") and q.get("result") == "hits"
        key = usecases._key("hunt", f"{hunt['id']}:{q['name']}") if promotable else None
        if r["status"] == "needs-investigation":
            text = f"Promote '{r['name']}' to a detection use case: it had hits and no enabled rule covers {tid}." + ("" if promotable else " Record an analyst assessment (suspicious or malicious) on the lead first, so it appears as a promotion candidate.")
            out.append({"trial_hit": r["n"], "technique": tid, "recommendation": "promote" if promotable else "assess-then-promote", "text": text, "priority": "high", "usecase_key": key})
        else:
            out.append({"trial_hit": r["n"], "technique": tid, "recommendation": "consider", "text": f"No enabled rule covers {tid}. The hunt found nothing, but this lead could run continuously as a detection; review its false-positive rate before promoting.", "priority": "medium", "usecase_key": None})
    if hunt.get("detection_created"):
        out.append({"trial_hit": None, "technique": None, "recommendation": "done", "text": "A detection has already been created from this hunt.", "priority": "low", "usecase_key": None})
    return out


def timing(hunt, rows, cfg, boxes, now):
    hours = boxes.get(hunt["id"])
    default = (cfg.get("hunt_report") or {}).get("default_time_box_hours", 8)
    hours = hours or default
    created = _dt(hunt.get("created_at"))
    ran_all = bool(rows) and all(r["status"] != "not-run" for r in rows)
    ready = _dt(hunt.get("closed_at")) if hunt.get("status") == "closed" else (max((_dt(r["ran_at"]) for r in rows if r["ran_at"]), default=None) if ran_all else None)
    ttr = round((ready - created).total_seconds() / 3600, 1) if (ready and created) else None
    due = (created + datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ") if created else None
    if ready is not None and ttr is not None:
        state = "within-time-box" if ttr <= hours else "late"
    elif created and now > created + datetime.timedelta(hours=hours):
        state = "overdue"
    else:
        state = "open"
    return {"time_box_hours": hours, "time_box_source": "hunt" if hunt["id"] in boxes and boxes[hunt["id"]] else "default", "created_at": hunt.get("created_at"), "due_at": due,
            "report_ready_at": ready.strftime("%Y-%m-%dT%H:%M:%SZ") if ready else None, "time_to_report_hours": ttr, "state": state}


def build(hunt, rules=(), allow_entries=(), time_boxes=None, now=None, cfg=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cfg = cfg or qpb.load()
    lib, render_lib = generate.library(), render.library()
    by_lead = {}
    for e in allow_entries:
        by_lead.setdefault(e["lead_key"], []).append(e)
    qs = hunt.get("queries") or []
    rows = [_lead_row(i, q, hunt, by_lead, lib, render_lib, hunt["id"]) for i, q in enumerate(qs)]
    ran = [r for r in rows if r["status"] != "not-run"]
    with_hits = [r for r in rows if r["status"] == "needs-investigation"]
    raw_hits = [r for r in ran if r["hits"]]
    entities = sorted({e for r in with_hits for e in r["entities"]})
    windows = sorted({r["window"] for r in ran if r["window"]})
    days = [int(m.group(1)) for w in windows for m in [re.match(r"^-(\d+)d$", w or "")] if m]
    verdict = _verdict(rows, hunt)
    per_domain = {}
    for r in rows:
        d = per_domain.setdefault(r["domain"], {"trial_hits": 0, "run": 0, "no_hit": 0, "needs_investigation": 0, "not_run": 0, "hits": 0, "entities": []})
        d["trial_hits"] += 1
        d["run"] += r["status"] != "not-run"
        d["no_hit"] += r["status"] == "no-hit"
        d["needs_investigation"] += r["status"] == "needs-investigation"
        d["not_run"] += r["status"] == "not-run"
        d["hits"] += r["hits_after_allowlist"] or 0
        d["entities"] = sorted(set(d["entities"]) | set(r["entities"]))
    used_ids = {i for r in rows for i in r["allowlist_entries"]}
    allow_used = [e for e in allow_entries if e["id"] in used_ids]
    allow_all = [e for e in allow_entries if e["lead_key"] in {lead_key(q) for q in qs}]
    gist_src = (hunt.get("hypothesis") or "").strip()
    gist = re.split(r"(?<=[.!?])\s", gist_src, maxsplit=1)[0][:260]
    ex = [{"text": f"Hunt verdict: {verdict['label']}. {verdict['rationale']}", "trial_hits": verdict["evidence"]},
          {"text": f"{len(ran)} of {len(rows)} trial hits were run" + (f" over {', '.join(windows)}" if windows else "") + f"; {len(with_hits)} need investigation and {len(entities)} entit{'y' if len(entities) == 1 else 'ies'} appear in their results.",
           "trial_hits": [r["n"] for r in ran][:30]}]
    if any(r["allowlisted_rows"] for r in rows):
        n = sum(r["allowlisted_rows"] for r in rows)
        ex.append({"text": f"{n} result row(s) were set aside by {len(allow_used)} allow-list entr{'y' if len(allow_used) == 1 else 'ies'} analysts recorded as benign; see the allow-list section.", "trial_hits": [r["n"] for r in rows if r["allowlisted_rows"]]})
    if len(ran) < len(rows):
        ex.append({"text": f"{len(rows) - len(ran)} trial hit(s) were not run" + (" or errored" if any(r["error"] for r in rows) else "") + ", so the verdict does not cover them.", "trial_hits": [r["n"] for r in rows if r["status"] == "not-run"][:30]})
    recs = _detection_recs(hunt, rows, rules)
    t = timing(hunt, rows, cfg, time_boxes or {}, now)
    return {"schema": 1, "hunt_id": hunt["id"], "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "topic": hunt["title"], "gist": gist or "No hypothesis was recorded.",
            "hypothesis": hunt.get("hypothesis"), "source": hunt.get("source"), "status": hunt.get("status"), "outcome": hunt.get("outcome"),
            "scope": {"techniques": hunt.get("techniques") or [], "hosts": (hunt.get("assets") or [])[:50], "data_sources": hunt.get("data_sources") or []},
            "look_back": {"windows": windows, "days_max": max(days) if days else None, "text": (", ".join(windows) if windows else "not run yet")},
            "counts": {"trial_hits": len(rows), "run": len(ran), "no_hit": sum(1 for r in rows if r["status"] == "no-hit"), "needs_investigation": len(with_hits), "not_run": len(rows) - len(ran),
                       "leads_with_raw_hits": len(raw_hits), "hits": sum(r["hits_after_allowlist"] or 0 for r in rows), "entities": len(entities)},
            "entities_observed": entities, "verdict": verdict, "executive_summary": ex, "trial_hits": rows, "per_domain": per_domain,
            "allowlist": {"entries": allow_all, "applied_entries": allow_used, "rows_set_aside": sum(r["allowlisted_rows"] for r in rows),
                          "note": "An entry says an analyst judged this exact value benign for this lead; it applies to every later run of the lead. Rows it removes are counted, never hidden."},
            "detection_recommendations": recs, "timing": t, "analyst_notes": hunt.get("notes") or "", "follow_ups": hunt.get("follow_ups") or "",
            "limits": ["Quanta does not run queries by itself: a trial hit has results only if a person confirmed it in the SIEM connection, or recorded them by hand.",
                       "Sigma and KQL renderings use Sigma field names; map them to your data model before running.",
                       "The SIEM connection has been built against public documentation and tested against fakes; it has not been run against a live SIEM."]}


def metrics(hunts, boxes=None, now=None, cfg=None):
    """Time-to-report across hunts: how many have a report ready, the median and mean in hours, how many were within their time-box, how many are overdue."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cfg = cfg or qpb.load()
    rows = []
    for h in hunts:
        r = [_lead_row(i, q, h, {}, {}, {}, h["id"]) for i, q in enumerate(h.get("queries") or [])]
        rows.append(timing(h, r, cfg, boxes or {}, now) | {"hunt_id": h["id"], "title": h["title"]})
    ttr = sorted(x["time_to_report_hours"] for x in rows if x["time_to_report_hours"] is not None)
    med = (ttr[len(ttr) // 2] if len(ttr) % 2 else (ttr[len(ttr) // 2 - 1] + ttr[len(ttr) // 2]) / 2) if ttr else None
    return {"hunts": len(rows), "reports_ready": len(ttr), "median_hours": round(med, 1) if med is not None else None, "mean_hours": round(sum(ttr) / len(ttr), 1) if ttr else None,
            "within_time_box": sum(1 for x in rows if x["state"] == "within-time-box"), "late": sum(1 for x in rows if x["state"] == "late"), "overdue": sum(1 for x in rows if x["state"] == "overdue"),
            "open": sum(1 for x in rows if x["state"] == "open"), "per_hunt": rows[:200]}


# ---------------------------------------------------------------- export
def to_markdown(r):
    L = [f"# Hunt report: {r['topic']}", "", f"**Hunt verdict: {r['verdict']['label']}.** {r['verdict']['rationale']}", "", f"{r['gist']}", "",
         "## Executive summary"] + [f"- {x['text']}" for x in r["executive_summary"]]
    c, t = r["counts"], r["timing"]
    L += ["", "## At a glance", f"- Look-back: {r['look_back']['text']}", f"- Trial hits: {c['trial_hits']} planned, {c['run']} run, {c['no_hit']} no hit, {c['needs_investigation']} need investigation, {c['not_run']} not run",
          f"- Entities observed in results: {', '.join(r['entities_observed'][:15]) or 'none'}",
          f"- Time box: {t['time_box_hours']} h ({t['state']})" + (f"; time to report {t['time_to_report_hours']} h" if t["time_to_report_hours"] is not None else ""), "",
          "## Hypothesis", r["hypothesis"] or "none recorded", "", "## Trial hit execution summary", "| # | Trial hit | Domain | Source tool | Status | Hits | Affected entities |", "|---|---|---|---|---|---|---|"]
    for x in r["trial_hits"]:
        hits = "-" if x["hits"] is None else (str(x["hits_after_allowlist"]) + (f" (of {x['hits']} before allow-list)" if x["allowlisted_rows"] else "") + (", partial" if x["allowlist_partial"] else ""))
        L.append(f"| {x['n']} | {x['name']} ({x['technique'] or 'no technique'}) | {x['domain']} | {x['source_tool']} | {x['status']} | {hits} | {', '.join(x['entities'][:4]) or '-'} |")
    L += ["", "## Results by domain"]
    for dom, d in sorted(r["per_domain"].items()):
        L.append(f"- {dom}: {d['trial_hits']} trial hit(s), {d['run']} run, {d['no_hit']} no hit, {d['needs_investigation']} need investigation, {d['not_run']} not run")
    for dom in sorted(r["per_domain"]):
        L += ["", f"## {dom} trial hits"]
        for x in [y for y in r["trial_hits"] if y["domain"] == dom]:
            L += [f"### {x['n']}. {x['name']} [{x['status']}]", (f"- Ran {x['ran_at']} over {x['window']}" if x["ran_at"] else "- Not run")]
            if x["assessment"]:
                L.append(f"- Analyst assessment: {x['assessment']}")
            if x["allowlisted_rows"]:
                L.append(f"- {x['allowlisted_rows']} row(s) set aside by the allow-list" + (" (partial: the sample was truncated)" if x["allowlist_partial"] else ""))
            if x["error"]:
                L.append(f"- The search failed: {x['error']}")
            if x["notes"]:
                L.append(f"- Notes: {x['notes']}")
            for lang, key in (("Splunk SPL", "spl"), ("Sigma", "sigma"), ("Sentinel KQL", "kql")):
                if x["queries"].get(key):
                    L += ["", f"{lang}:", "```", str(x["queries"][key]), "```"]
            if x["queries"].get("note"):
                L.append(f"- {x['queries']['note']}")
    L += ["", "## Benign-activity allow-list"]
    al = r["allowlist"]
    L += [f"- {e['field']} = {e['value']} (lead {e['lead_key']}): {e['note']} ({e.get('created_by') or 'unknown'}, {e['created_at']})" for e in al["entries"]] or ["- No entries recorded for these leads."]
    L += ["", "## Detection recommendations"] + [f"- [{x['priority']}] {x['text']}" for x in r["detection_recommendations"]]
    if r["analyst_notes"]:
        L += ["", "## Analyst notes", r["analyst_notes"]]
    if r["follow_ups"]:
        L += ["", "## Follow-ups", r["follow_ups"]]
    L += ["", "## Limits"] + [f"- {x}" for x in r["limits"]]
    return "\n".join(L) + "\n"


def to_html(r):
    """A print-friendly standalone page built from the same Markdown. Everything is escaped; there is no script."""
    page = detection.to_html(to_markdown(r), f"Hunt report: {r['topic']}")
    return page.replace("</style>", "@media print{body{background:#fff;color:#000}h1,h2,h3{color:#000}pre{background:#f4f4f4;color:#000;border-color:#bbb}code{color:#000}}</style>", 1)

