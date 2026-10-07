"""
The ITSM side of an investigation: a ticket arriving becomes an alert, and a finished report can be posted back to the ticket as a comment.

Intake: a ticket-created event from ServiceNow, Jira or another system is mapped to the alert shape (alert_from_ticket); the route stores it, links the ticket id, and the
existing auto-investigate, incident and routing path takes over, so an analyst opens a ticket that is already investigated. Fields the ticket does not carry stay empty: a
severity the ticket does not give is Medium and the alert's detail says so, never an invented value.

Post-back: a concise comment (verdict, summary, recommended actions, link). It is a dry run unless confirmed, goes only to a ticket linked to this incident, is written as an
internal note where the system has one, and the same comment is never posted twice to the same ticket.
"""
import hashlib
import os
import re

from remediation.hunting import ocsf
from remediation.connections import links as conn_links

SYSTEMS = ("servicenow", "jira", "other")
_SNOW_PRIORITY = {"1": "Critical", "2": "High", "3": "Medium", "4": "Low", "5": "Informational"}
_WORDS = {"critical": "Critical", "highest": "Critical", "blocker": "Critical", "urgent": "Critical", "high": "High", "major": "High", "medium": "Medium", "moderate": "Medium",
          "normal": "Medium", "low": "Low", "minor": "Low", "lowest": "Informational", "trivial": "Informational", "informational": "Informational", "info": "Informational"}
_TICKET_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


def map_severity(system, value):
    """-> (severity, known). ServiceNow priority is 1-5; Jira priority is a name; anything else is matched by word. An unrecognised value is Medium, known False."""
    v = str(value if value is not None else "").strip().lower()
    if not v:
        return "Medium", False
    if system == "servicenow" and v[:1] in _SNOW_PRIORITY and (len(v) == 1 or v[1:2] in (" ", "-", ".")):
        return _SNOW_PRIORITY[v[0]], True
    return (_WORDS[v], True) if v in _WORDS else ("Medium", False)


def alert_from_ticket(body, source_name):
    """Maps a ticket-created event to an alert dict for hunting.store.receive_alert. Raises ValueError for a ticket that cannot be stored."""
    system = (body.get("system") or "other").lower()
    if system not in SYSTEMS:
        raise ValueError(f"system must be one of {', '.join(SYSTEMS)}")
    tid = str(body.get("ticket_id") or "").strip()
    if not _TICKET_ID.match(tid):
        raise ValueError("ticket_id is required and may use letters, digits and . _ : - only")
    title = (body.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    sev, known = map_severity(system, body.get("severity") if body.get("severity") is not None else body.get("priority"))
    desc = (body.get("description") or "").strip()
    note = "" if known else " [Quanta: the ticket gave no recognisable severity, so Medium was used.]"
    ent = ocsf.empty_entities()
    ocsf.scan_text(f"{title} {desc}", ent)
    ent["host"] = (body.get("asset") or "").strip() or None
    ent["user"] = (body.get("user") or "").strip() or None
    for key, field in (("ips", "ips"), ("domains", "domains"), ("hashes", "hashes"), ("urls", "urls")):
        for v in body.get(field) or []:
            v = str(v).strip()
            if v and v not in ent[key]:
                ent[key].append(v)
    for ip in (body.get("source_ip"), body.get("destination_ip")):
        if ip and str(ip).strip() not in ent["ips"]:
            ent["ips"].append(str(ip).strip())
    return {"external_id": f"{system}:{tid}", "title": title[:300], "severity": sev, "asset": ent["host"], "technique": (body.get("technique") or None),
            "detail": (desc + note)[:4000], "occurred_at": body.get("created_at"), "rule_name": body.get("rule_name"), "entities": ent, "source": source_name,
            "action_taken": body.get("action_taken")}


def link_ticket(alert_id, system, ticket_id, connection_id=None, engine=None):
    """Records which ticket an alert came from, in the same link table findings use (the finding id is `alert:<id>`)."""
    return conn_links.upsert(f"alert:{alert_id}", system if system in ("servicenow", "jira") else "other", ticket_id, "open", connection_id=connection_id, external_id=ticket_id, engine=engine)


def targets(incident_id, alert_ids, engine=None):
    """Tickets linked to this incident or any of its alerts, deduplicated by (system, ticket)."""
    out, seen = [], set()
    for fid in [f"incident:{incident_id}"] + [f"alert:{a}" for a in alert_ids]:
        for ln in conn_links.for_finding(fid, engine):
            if ln.get("external_ref") and (ln["system"], ln["external_ref"]) not in seen:
                seen.add((ln["system"], ln["external_ref"]))
                out.append(ln)
    return out


def compose_comment(report, max_actions=5, max_chars=3000):
    v = report["verdict"]
    lines = [f"Quanta investigation, incident #{report['incident_id']} (report v{report.get('version', 1)}, {report['generated_at']})",
             f"Verdict: {v['label']} ({v['basis']}; confidence {v['confidence']}). A recommendation for a person to validate.", ""]
    for c in report["summary"][:3]:
        lines.append(f"- {c['text']}")
    acts = report["recommended_actions"][:max_actions]
    if acts:
        lines += ["", "Recommended actions:"] + [f"- {a['action']}" + (" (needs a second person)" if a["needs_second_person"] else "") for a in acts]
    if report.get("gaps"):
        lines += ["", "Not known: " + "; ".join(report["gaps"][:3])]
    base = (os.environ.get("QUANTA_PUBLIC_URL") or "").rstrip("/")
    lines += ["", ("Full report: " + base + f"/soc?incident={report['incident_id']}") if base else f"Full report: incident #{report['incident_id']} in Quanta (SOC page)."]
    text = "\n".join(lines)
    return text if len(text) <= max_chars else text[: max_chars - 3].rstrip() + "..."


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def post(report, link_rows, make_connector, already_posted, confirm, comment=None):
    """Dry run unless confirm. -> list of {system, ticket, status, ...}. `make_connector(system, connection_id) -> (connector or None, name)`; `already_posted` is a set of
    (system, ticket, digest) already sent. A failure on one ticket does not stop the others, and a write is not retried."""
    text = comment or compose_comment(report)
    d = digest(text)
    out = []
    for ln in link_rows:
        row = {"system": ln["system"], "ticket": ln["external_ref"], "comment_digest": d}
        if ln["system"] not in ("servicenow", "jira"):
            out.append({**row, "status": "unsupported", "message": "Only ServiceNow and Jira tickets can be commented on."})
            continue
        conn, name = make_connector(ln["system"], ln.get("connection_id"))
        if conn is None:
            out.append({**row, "status": "no-connection", "message": f"No enabled {ln['system']} connection is configured, so nothing can be posted."})
            continue
        row["connection"] = name
        if (ln["system"], ln["external_ref"], d) in already_posted:
            out.append({**row, "status": "already-posted", "message": "This exact comment was already posted to this ticket."})
            continue
        if not confirm:
            out.append({**row, "status": "dry-run", "message": "Nothing was sent. Send confirm: true to post this comment."})
            continue
        try:
            conn.add_comment(ln["external_ref"], text)
            out.append({**row, "status": "posted"})
        except Exception as exc:  # noqa: BLE001 - reported on that ticket; the others still go
            out.append({**row, "status": "failed", "message": str(exc)[:200]})
    return out, text
