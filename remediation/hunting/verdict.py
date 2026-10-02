"""
Hunt verdicts and hunt reports.

Each query in a hunt is a lead. After a lead runs, an analyst looks at the sample and records an assessment (benign, suspicious or malicious).
From those two facts the lead gets a verdict:

  not-run          the query has not been run (or errored), so there is nothing to say
  no-hits          it ran and returned nothing
  likely-fp        it returned results and the analyst judged them benign
  possible-tp      it returned results that are suspicious, or have not been assessed yet (unassessed hits are never assumed benign)
  confirmed-tp     it returned results and the analyst judged them malicious

The hunt's overall verdict is then:

  confirmed-compromise   any lead is confirmed-tp
  multi-hit-correlated   two or more leads are possible-tp, or the same host/entity appears in the results of two or more leads
  low-confidence         exactly one lead is possible-tp
  no-findings            every lead that ran is no-hits or likely-fp (and at least one ran)
  incomplete             nothing has run yet

The sample rows come from the SIEM; correlation looks for the same value in the host, user or IP fields of more than one lead's sample.
"""
import html
import re

ENTITY_FIELDS = ("host", "Computer", "ComputerName", "dest", "src", "src_ip", "dest_ip", "user", "User", "Image", "DestinationIp", "SourceIp")


def lead_verdict(q):
    res, assess = q.get("result"), q.get("assessment")
    if res in (None, "not-run", "error"):
        return "not-run"
    if res == "no-hits":
        return "no-hits"
    if assess == "malicious":
        return "confirmed-tp"
    if assess == "benign":
        return "likely-fp"
    return "possible-tp"


def _entities(q):
    vals = set()
    for row in q.get("sample") or []:
        for f in ENTITY_FIELDS:
            v = row.get(f)
            if v:
                vals.add(f"{f.lower().replace('computername', 'host').replace('computer', 'host')}:{str(v).lower()}")
    return vals


def correlated_entities(queries):
    seen, shared = {}, set()
    for i, q in enumerate(queries):
        if lead_verdict(q) not in ("possible-tp", "confirmed-tp"):
            continue
        for e in _entities(q):
            if e in seen and seen[e] != i:
                shared.add(e)
            seen.setdefault(e, i)
    return sorted(shared)


def hunt_verdict(hunt):
    qs = hunt.get("queries") or []
    vs = [lead_verdict(q) for q in qs]
    ran = [v for v in vs if v != "not-run"]
    shared = correlated_entities(qs)
    if "confirmed-tp" in vs:
        overall = "confirmed-compromise"
    elif vs.count("possible-tp") >= 2 or shared:
        overall = "multi-hit-correlated"
    elif vs.count("possible-tp") == 1:
        overall = "low-confidence"
    elif ran:
        overall = "no-findings"
    else:
        overall = "incomplete"
    return {"overall": overall, "leads": vs, "correlated_entities": shared, "ran": len(ran), "total": len(vs)}


STATUS_TEXT = {"not-run": "not run", "no-hits": "no hits", "likely-fp": "hits judged benign", "possible-tp": "hits, needs investigation", "confirmed-tp": "confirmed"}
OVERALL_TEXT = {
    "incomplete": "The hunt has not been run yet.",
    "no-findings": "No direct match was found. Everything that ran returned nothing, or hits an analyst judged benign.",
    "low-confidence": "One lead returned results that need investigation. There is no corroboration from other leads.",
    "multi-hit-correlated": "Several leads returned results, or the same host or user appears in more than one. Treat this as a probable compromise until shown otherwise.",
    "confirmed-compromise": "An analyst confirmed malicious activity in the results. This is an incident.",
}


def _affected(q):
    ents = set()
    for row in q.get("sample") or []:
        for f in ENTITY_FIELDS:
            if row.get(f):
                ents.add(str(row[f]))
    return sorted(ents)


def summary(hunt, rules=()):
    """The numbers and plain-language lines that head a hunt report: trial hits run, hits, entities, look-back, sources, verdict, detection coverage."""
    qs = hunt.get("queries") or []
    v = hunt_verdict(hunt)
    ran = [q for q, lv in zip(qs, v["leads"]) if lv != "not-run"]
    with_hits = [q for q in ran if q.get("result") == "hits"]
    entities = sorted({e for q in with_hits for e in _affected(q)})
    windows = sorted({q.get("window") for q in ran if q.get("window")})
    techs = {t["technique_id"].split(".")[0] for t in hunt.get("techniques") or [] if t.get("technique_id")}
    covered, gaps = {}, []
    for t in sorted(techs):
        names = [r["name"] for r in rules if r.get("enabled", True) and any(x.split(".")[0] == t for x in r.get("techniques") or [])]
        if names:
            covered[t] = names
        else:
            gaps.append(t)
    rows = []
    for i, (q, lv) in enumerate(zip(qs, v["leads"]), 1):
        rows.append({"n": i, "name": q.get("name"), "technique": q.get("technique"), "domain": q.get("domain") or "endpoint", "source": q.get("source") or "SIEM", "status": STATUS_TEXT[lv],
                     "verdict": lv, "hits": q.get("count"), "entities": _affected(q), "window": q.get("window"), "ran_at": q.get("ran_at"), "query": q.get("query")})
    sources = sorted({r["source"] for r in rows})
    head = (f"{len(ran)} of {len(qs)} trial hits run against {', '.join(sources) or 'the SIEM'}" + (f" over {', '.join(windows)}" if windows else "") + f": {len(with_hits)} returned results"
            f" and {len(entities)} entit{'y' if len(entities) == 1 else 'ies'} appear in them.")
    exec_ = [OVERALL_TEXT[v["overall"]]]
    if covered:
        exec_.append("Detection coverage: " + "; ".join(f"{t} is covered by {', '.join(n[:2])}" for t, n in covered.items()) + ".")
    if gaps:
        exec_.append("Not covered by an enabled detection rule: " + ", ".join(gaps) + ". Each is a candidate for a new detection" + ("." if not hunt.get("detection_created") else "; this hunt has already led to one."))
    return {"overall": v["overall"], "headline": head, "executive_summary": exec_, "trial_hits": rows, "run": len(ran), "total": len(qs), "with_hits": len(with_hits), "entities": entities,
            "sources": sources, "windows": windows, "covered": covered, "gaps": gaps, "correlated_entities": v["correlated_entities"]}


def to_markdown(hunt, rules=()):
    s = summary(hunt, rules)
    L = [f"# Hunt report: {hunt['title']}", "", f"**Hunt verdict: {s['overall']}.** {s['headline']}", "", "## Executive summary", *s["executive_summary"], "", "## Hypothesis", hunt["hypothesis"], "",
         "## Scope", f"- Techniques: {', '.join(t['technique_id'] + ' ' + t['technique_name'] for t in hunt['techniques']) or 'none tagged'}", f"- Hosts: {', '.join(hunt['assets'][:30]) or 'not scoped'}",
         f"- Data sources: {'; '.join(hunt['data_sources']) or 'not specified'}", f"- Status: {hunt['status']}" + (f", outcome: {hunt['outcome']}" if hunt.get("outcome") else ""), "",
         "## Trial hit execution summary", "| # | Trial hit | Domain | Source | Status | Hits | Affected entities |", "|---|---|---|---|---|---|---|"]
    for r in s["trial_hits"]:
        L.append(f"| {r['n']} | {r['name']} ({r['technique']}) | {r['domain']} | {r['source']} | {r['status']} | {r['hits'] if r['hits'] is not None else '-'} | {', '.join(r['entities'][:4]) or '-'} |")
    for dom in sorted({r["domain"] for r in s["trial_hits"]}):
        L += ["", f"## {dom.capitalize()} trial hits"]
        for r in [x for x in s["trial_hits"] if x["domain"] == dom]:
            q = hunt["queries"][r["n"] - 1]
            L.append(f"### {r['n']}. {r['name']} [{r['status']}]")
            L.append(f"- Ran {r['ran_at']} over {r['window']}" if r["ran_at"] else "- Not run")
            if q.get("assessment"):
                L.append(f"- Analyst assessment: {q['assessment']}")
            if q.get("notes"):
                L.append(f"- Notes: {q['notes']}")
            if q.get("error"):
                L.append(f"- The search failed: {q['error']}")
            L += ["", "```", q["query"], "```"]
    if s["correlated_entities"]:
        L += ["", "## Correlated entities", *[f"- {e}" for e in s["correlated_entities"]]]
    if hunt.get("notes"):
        L += ["", "## Analyst notes", hunt["notes"]]
    if hunt.get("follow_ups"):
        L += ["", "## Follow-ups", hunt["follow_ups"]]
    L += ["", f"Detection created from this hunt: {'yes' if hunt.get('detection_created') else 'no'}."]
    return "\n".join(L) + "\n"


def to_html(hunt, rules=()):
    """A standalone report page. Everything is escaped; there is no script."""
    v = hunt_verdict(hunt)
    md = to_markdown(hunt, rules)
    body = []
    in_code = False
    for line in md.splitlines():
        if line.startswith("```"):
            body.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
        elif in_code:
            body.append(html.escape(line))
        elif line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            body.append(f"<p class='li'>{html.escape(line[2:])}</p>")
        elif line.startswith("|"):
            body.append(f"<p class='li'><code>{html.escape(line)}</code></p>")
        elif line.strip():
            body.append("<p>" + re.sub(r"\*\*(.+?)\*\*", lambda m: "<b>" + m.group(1) + "</b>", html.escape(line)) + "</p>")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>" + html.escape(hunt["title"]) + "</title>"
            "<style>body{background:#0a0e1a;color:#eef1fb;font-family:'Chakra Petch',Segoe UI,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;line-height:1.5}"
            "h1,h2,h3{color:#eef1fb}h2{border-bottom:1px solid #243152;padding-bottom:4px}pre{background:#0f1730;border:1px solid #243152;padding:10px;overflow-x:auto;color:#c3cbe6}"
            ".li{margin:2px 0 2px 16px}code{color:#c3cbe6}.v{display:inline-block;padding:2px 10px;border:1px solid #6d97f7;border-radius:4px;color:#6d97f7}</style></head><body>"
            + f"<p class='v'>{html.escape(v['overall'])}</p>" + "\n".join(body) + "</body></html>")
