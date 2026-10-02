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


def to_markdown(hunt):
    v = hunt_verdict(hunt)
    L = [f"# Hunt report: {hunt['title']}", "", f"**Overall verdict: {v['overall']}** ({v['ran']} of {v['total']} leads run). Status: {hunt['status']}"
         + (f", outcome: {hunt['outcome']}" if hunt.get("outcome") else "") + ".", "",
         "## Hypothesis", hunt["hypothesis"], "",
         "## Scope", f"- Techniques: {', '.join(t['technique_id'] + ' ' + t['technique_name'] for t in hunt['techniques']) or 'none tagged'}",
         f"- Hosts: {', '.join(hunt['assets'][:30]) or 'not scoped'}", f"- Data sources: {'; '.join(hunt['data_sources']) or 'not specified'}", "", "## Leads"]
    for q, lv in zip(hunt["queries"], v["leads"]):
        L.append(f"### {q['technique']}: {q['name']}  [{lv}]")
        L.append(f"- Result: {q.get('result') or 'not run'}" + (f" ({q['count']} event(s))" if q.get("count") is not None else "")
                 + (f", assessed {q['assessment']}" if q.get("assessment") else ""))
        if q.get("notes"):
            L.append(f"- Notes: {q['notes']}")
        L += ["", "```", q["query"], "```"]
    if v["correlated_entities"]:
        L += ["", "## Correlated entities", *[f"- {e}" for e in v["correlated_entities"]]]
    if hunt.get("notes"):
        L += ["", "## Analyst notes", hunt["notes"]]
    if hunt.get("follow_ups"):
        L += ["", "## Follow-ups", hunt["follow_ups"]]
    L += ["", f"Detection created from this hunt: {'yes' if hunt.get('detection_created') else 'no'}."]
    return "\n".join(L) + "\n"


def to_html(hunt):
    """A standalone report page. Everything is escaped; there is no script."""
    v = hunt_verdict(hunt)
    md = to_markdown(hunt)
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
        elif line.strip():
            body.append("<p>" + re.sub(r"\*\*(.+?)\*\*", lambda m: "<b>" + m.group(1) + "</b>", html.escape(line)) + "</p>")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><title>" + html.escape(hunt["title"]) + "</title>"
            "<style>body{background:#0a0e1a;color:#eef1fb;font-family:'Chakra Petch',Segoe UI,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;line-height:1.5}"
            "h1,h2,h3{color:#eef1fb}h2{border-bottom:1px solid #243152;padding-bottom:4px}pre{background:#0f1730;border:1px solid #243152;padding:10px;overflow-x:auto;color:#c3cbe6}"
            ".li{margin:2px 0 2px 16px}.v{display:inline-block;padding:2px 10px;border:1px solid #6d97f7;border-radius:4px;color:#6d97f7}</style></head><body>"
            + f"<p class='v'>{html.escape(v['overall'])}</p>" + "\n".join(body) + "</body></html>")
