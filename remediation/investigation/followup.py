"""
Follow-up questions on an incident, answered from stored data.

An analyst asks "has this address shown up before?" or "what else did this account touch?". The answer is counted over the alerts and incidents Quanta holds, inside the
same bounded look-back as the report, and says exactly what it rests on (the matching records, or the count of zero). A question Quanta cannot tie to a host, user, address,
domain, hash or URL it knows is answered "cannot be answered from stored data", not guessed. One optional read-only SIEM search for the value is added only when the caller
passes a runner (the route does that after a confirmation). Nothing is changed by asking.
"""
import datetime
import ipaddress
import re
from collections import Counter

from remediation.hunting import report as hunt_report
from remediation.hunting import search_base
from remediation.hunting import soc as hunt_soc
from remediation.investigation.evidence import now_iso, parse
from remediation.investigation.incident_report import _Index

KINDS = ("similar-alerts", "entity-history", "indicator-sightings")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")


def infer_kind(question):
    q = (question or "").lower()
    if any(w in q for w in ("similar", "like this", "same rule", "how many")):
        return "similar-alerts"
    if any(w in q for w in ("where else", "other host", "seen on", "elsewhere", "spread")):
        return "indicator-sightings"
    return "entity-history"


def infer_value(question, known):
    """The value the question is about: a known entity named in it, else an address, hash or domain written in it. None when there is none."""
    q = (question or "").lower()
    for v in sorted(known, key=len, reverse=True):
        if v and v.lower() in q:
            return v
    for rx in (_IP, _HASH, _DOMAIN):
        m = rx.search(question or "")
        if m:
            if rx is _IP:
                try:
                    ipaddress.ip_address(m.group(0))
                except ValueError:
                    continue
            return m.group(0)
    return None


def _match(idx, value, own):
    seen, out = set(), []
    for kind in ("host", "user", "address", "domain", "hash", "url", "rule"):
        for a in idx.get(kind, value):
            if a["id"] not in own and a["id"] not in seen:
                seen.add(a["id"])
                out.append(a)
    out.sort(key=lambda a: a.get("received_at") or "")
    return out


def answer(incident, alert_rows, question, data, kind=None, value=None, window_days=90, siem_run=None, siem_name=None, now=None, max_days=90):
    """-> {kind, value, question, answer, data, evidence, answerable}. evidence items are {kind, source, detail, at}."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    question = (question or "").strip()
    if not question:
        raise ValueError("Ask a question")
    if kind and kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    known = [v for a in alert_rows for _, v in hunt_report._vals(a)]
    value = (value or "").strip() or infer_value(question, known)
    kind = kind or infer_kind(question)
    base = {"kind": kind, "value": value, "question": question}
    if not value:
        return {**base, "answer": "Cannot be answered from stored data: the question does not name a host, user, address, domain, hash or URL Quanta can look up. Name one and ask again.",
                "data": [], "evidence": [], "answerable": False}
    idx = data.get("index") or _Index(data["alerts_all"])
    imap = data.get("incident_map") or {}
    own = {a["id"] for a in alert_rows}
    start = now - datetime.timedelta(days=window_days)
    allm = _match(idx, value, own)
    match = [a for a in allm if (parse(a.get("received_at")) or now) >= start]
    incs = sorted({imap[a["id"]] for a in match if a["id"] in imap} - {incident["id"]})
    c = Counter((a.get("disposition") or ("open" if a["status"] != "closed" else "closed")) for a in match)
    ev = [{"kind": "history", "source": "count over stored alerts and incidents", "detail": f"{len(match)} stored alert(s) involve {value} within {window_days} days (excluding this incident's alerts)"
           + (": " + ", ".join(f"#{a['id']}" for a in match[:20]) if match else ""), "at": now_iso(now)}]
    ev += [{"kind": "alert", "source": f"stored alert #{a['id']}", "detail": f"{a['severity']}: {a['title']}", "at": a.get("received_at")} for a in match[:10]]
    if kind == "similar-alerts":
        rules = {a.get("rule_name") for a in alert_rows if a.get("rule_name")}
        same_rule = [a for a in match if a.get("rule_name") in rules]
        text = f"{len(match)} other alert(s) involve {value} in the last {window_days} days" + (f", {len(same_rule)} from the same rule" if rules else "") + (f", in {len(incs)} other incident(s)." if match else ".")
        data_out = [{"id": a["id"], "title": a["title"], "status": a["status"], "disposition": a.get("disposition"), "incident_id": imap.get(a["id"])} for a in match[:20]]
    elif kind == "entity-history":
        if match:
            text = (f"{len(match)} earlier alert(s) involve {value} in the last {window_days} days: {c.get('true-positive', 0)} closed as true positive, "
                    f"{c.get('benign', 0) + c.get('false-positive', 0)} as benign or false positive, {sum(1 for a in match if a['status'] != 'closed')} still open; "
                    f"first {match[0]['received_at'][:10]}, last {match[-1]['received_at'][:10]}.")
        else:
            text = f"None in {window_days} days: no other stored alert involves {value}."
        data_out = [{"id": a["id"], "title": a["title"], "received_at": a["received_at"], "disposition": a.get("disposition")} for a in match[:20]]
    else:
        hosts = sorted({(a.get("asset") or "").lower() for a in match if a.get("asset")} - {(x.get("asset") or "").lower() for x in alert_rows})
        text = (f"{value} also appears in alerts on {len(hosts)} other host(s): {', '.join(hosts[:10])}." if hosts else f"{value} appears in no alert on another host within {window_days} days.")
        data_out = [{"host": h} for h in hosts[:20]]
        ev.append({"kind": "history", "source": "count over stored alerts and incidents", "detail": f"{len(hosts)} other host(s) carry {value}", "at": now_iso(now)})
    q = search_base.sighting_query(getattr(siem_run, "language", "splunk-spl"), value) if siem_run is not None and re.match(r"^[A-Za-z0-9_.@:/-]{1,255}$", value) else None
    if siem_run is not None and not q and re.match(r"^[A-Za-z0-9_.@:/-]{1,255}$", value):
        text += " This SIEM connection's query language has no free-text search, so no SIEM count was added."
    if q:
        days = min(int(max_days), 90)
        try:
            r = siem_run(q, f"-{days}d", 10)
            h = (r["rows"][0].get("hosts") if r.get("rows") else None)
            text += f" SIEM, last {days} days: {r['count']} result row(s)" + (f", {h} host(s)" if h else "") + "."
            ev.append({"kind": "siem", "source": f"SIEM search ({siem_name or 'connected'})", "detail": f"{q} -> {r['count']} row(s) over {days} days", "at": now_iso(now)})
        except Exception as exc:  # noqa: BLE001
            text += f" The SIEM search failed ({str(exc)[:120]})."
            ev.append({"kind": "siem", "source": f"SIEM search ({siem_name or 'connected'})", "detail": f"{q} failed: {str(exc)[:120]}", "at": now_iso(now)})
    return {**base, "answer": text, "data": data_out, "evidence": ev, "answerable": True}
