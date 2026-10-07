"""
Routes for investigation reports: the incident report, its follow-ups and live refresh, posting back to the ITSM ticket, ticket intake, and the hunt report.

Built by `build_router()` so this module needs nothing from app.py except what is handed in. Every route here needs an administrator, except ticket intake, which checks a
Quanta API key with the soc:write scope itself. What can reach outside Quanta, and how it is gated:
  * reputation lookups and SIEM searches (refresh, follow-up): a preview unless `confirm` is true; the SIEM runs only the query playbook, read-only, within its budget, and a
    look-back past the ceiling needs a written justification (the same `lookback_cfg` gate as the rest of the SOC);
  * posting the report to a ticket: a dry run unless `confirm` is true, only to a ticket linked to the incident, never twice with the same text.
Nothing here changes an alert, an incident's state or any customer system apart from that one comment.
"""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

import data as dashboard_data
from auth import rbac
from remediation.audit import activity_log
from remediation.connections import registry as conn_registry
from remediation.hunting import detection as hunt_detection, report as hunt_report, service as hunt_service, store as hunt_store, triage as hunt_triage
from remediation.hunting import hunt_report as hunt_report_mod, search_base
from remediation.inventory import asset_inventory
from remediation.investigation import followup as inv_followup, incident_report, itsm, playbook as qpb, store as inv_store
from remediation.investigation.incident_report import _Index
from remediation.soar import engine as soar_engine, playbooks as soar_playbooks
from remediation.soc.incidents import service as incident_service, store as incident_store


class RefreshBody(BaseModel):
    confirm: bool = False
    reputation: bool = False
    siem: bool = False
    reputation_connection_id: int | None = None
    siem_connection_id: int | None = None
    lookback_days: int | None = None
    justification: str | None = None


class IncidentFollowUpBody(BaseModel):
    question: str
    kind: str | None = None
    value: str | None = None
    siem: bool = False
    siem_connection_id: int | None = None
    confirm: bool = False
    lookback_days: int | None = None
    justification: str | None = None


class MergeBody(BaseModel):
    followup_ids: list[int]
    merged: bool = True


class PostBody(BaseModel):
    confirm: bool = False
    comment: str | None = None


class ItsmTicketBody(BaseModel):
    system: str = "servicenow"
    ticket_id: str
    title: str
    description: str | None = None
    severity: str | int | None = None
    priority: str | int | None = None
    asset: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    ips: list[str] = []
    domains: list[str] = []
    hashes: list[str] = []
    urls: list[str] = []
    technique: str | None = None
    rule_name: str | None = None
    created_at: str | None = None
    action_taken: str | None = None
    connection_id: int | None = None


class AllowBody(BaseModel):
    lead_index: int
    field: str
    value: str
    note: str


class TimeBoxBody(BaseModel):
    hours: int


def _404(msg):
    return HTTPException(status_code=404, detail=msg)


def build_router(*, require_api_key, identity_map, lookback_cfg, auto_investigator, soar_auto):
    router = APIRouter()
    admin = rbac.require_admin

    # ------------------------------------------------------------ shared plumbing
    def _incident(incident_id):
        inc = incident_store.get_incident(incident_id)
        if not inc:
            raise _404("No such incident")
        return inc

    def _recommended(incident_id):
        pbs = soar_playbooks.list_all()
        by_id = {p["id"]: p for p in pbs}
        past = []
        for run in soar_engine.list_runs(limit=300):
            a, p = hunt_store.get_alert(run["alert_id"]), by_id.get(run["playbook_id"])
            if a and p and not run["dry_run"]:
                past.append({"alert": a, "run": run, "playbook": p})
        return incident_service.recommended_actions(incident_id, pbs, past)

    def _data(incident_id, alert_rows):
        findings = dashboard_data.load_live_queue()
        alerts_all = hunt_store.list_alerts()
        own = asset_inventory.load_ownership()
        ownership = {k.lower(): v for k, v in own.items()}
        owners = {k: (v.get("owner") or v.get("team")) for k, v in ownership.items() if v.get("owner") or v.get("team")}
        return {"alerts_all": alerts_all, "index": _Index(alerts_all), "incident_map": inv_store.alert_incident_map(),
                "investigations": {a["id"]: hunt_service.latest_investigation(a["id"]) for a in alert_rows}, "findings": findings, "ownership": ownership, "owners": owners,
                "assets": incident_service.Context(findings, owners).assets, "identity": identity_map(), "recommended": _recommended(incident_id), "pb_cfg": qpb.load(),
                "books": hunt_triage.runbooks()}

    def _siem(connection_id, required):
        try:
            conn, public = hunt_service.search_connector(connection_id)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if required and not conn:
            raise HTTPException(status_code=400, detail="No read-only search connection (Splunk, Sentinel, Google SecOps, Elastic or CrowdStrike) is configured. Add one on the Connections page.")
        return conn, (public or {}).get("name")

    def _reputation(connection_id):
        try:
            conn, public = hunt_service.connector("reputation", connection_id)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not conn:
            raise HTTPException(status_code=400, detail="No reputation connection is configured. Add one on the Connections page.")
        return conn, public["name"]

    def _build(incident_id, actor, *, lookup=None, lookup_name=None, siem_run=None, siem_name=None, siem_connected=None, cap_days=None, live_requested=False, save=True):
        inc = _incident(incident_id)
        rows = incident_store.alert_rows(incident_id)
        if siem_connected is None:
            siem_connected = bool(hunt_service.find_search_connection())
        report = incident_report.build(inc, rows, _data(incident_id, rows), lookup=lookup, lookup_name=lookup_name, siem_run=siem_run, siem_connected=siem_connected, siem_name=siem_name,
                                       cap_days=cap_days, followups=inv_store.list_followups(incident_id), events=incident_store.events(incident_id), actor=actor, live_requested=live_requested)
        if save:
            report = inv_store.save_report(incident_id, report, actor, live=bool(lookup or siem_run))
            incident_store.add_event(incident_id, "report", actor, f"Investigation report v{report['version']} built" + (" with a confirmed live search or lookup" if (lookup or siem_run) else " from stored data"),
                                     {"version": report["version"], "live": bool(lookup or siem_run), "dropped": report["dropped_statements"]})
        return report

    def _current(incident_id, actor):
        _incident(incident_id)
        return inv_store.latest_report(incident_id) or _build(incident_id, actor)

    def _open_followups(incident_id):
        return [f for f in inv_store.list_followups(incident_id) if not f["merged"]]

    # ------------------------------------------------------------ incident report
    @router.get("/api/soc/incidents/{incident_id}/report")
    def api_incident_report(incident_id: int, format: str = "json", user: dict = Depends(admin)):
        report = _current(incident_id, user["email"])
        if format == "md":
            return PlainTextResponse(incident_report.to_markdown(report), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-report.md"'})
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be json or md")
        return {"report": report, "open_followups": _open_followups(incident_id), "versions": inv_store.report_versions(incident_id)}

    @router.post("/api/soc/incidents/{incident_id}/report/refresh")
    def api_incident_report_refresh(incident_id: int, body: RefreshBody, user: dict = Depends(admin)):
        """Rebuilds the report. From stored data it just runs. A reputation lookup or the query playbook's SIEM searches are previewed first and run only with confirm: true."""
        inc = _incident(incident_id)
        lookup = siem_run = None
        rep_name = siem_name = None
        if body.reputation:
            rconn, rep_name = _reputation(body.reputation_connection_id)
            lookup = rconn.lookup
        siem_conn = None
        if body.siem:
            siem_conn, siem_name = _siem(body.siem_connection_id, True)
        if (body.reputation or body.siem) and not body.confirm:
            rows = incident_store.alert_rows(incident_id)
            real = [a for a in rows if a.get("role") != "duplicate"] or rows
            pb = qpb.load()
            cap = body.lookback_days or int(pb.get("max_lookback_days", 90))
            planned, skipped = qpb.plan(real, pb, cap, hunt_service.language_of(siem_conn)) if body.siem else ([], [])
            bud = qpb.budget(pb)
            sendable = []
            if body.reputation:
                from remediation.connectors import reputation_connector
                sendable = sorted({v for a in rows for k, v in hunt_report._vals(a) if k in ("address", "domain", "hash", "url") and reputation_connector.classify(v)[0]})[: int((pb.get("reputation") or {}).get("max_lookups", 15))]
            return {"preview_only": True, "incident_id": inc["id"], "reputation_connection": rep_name, "indicators_that_would_be_sent": sendable, "siem_connection": siem_name,
                    "query_language": hunt_service.language_of(siem_conn), "searches_that_would_run": [{"name": p["name"], "query": p["query"], "look_back_days": p["days"]} for p in planned[: bud["max_queries"]]],
                    "planned_but_over_budget": max(0, len(planned) - bud["max_queries"]), "skipped": skipped, "budget": bud, "look_back_cap_days": cap,
                    "message": "Only public indicators are sent to the reputation service. The searches are read-only, bounded by the budget shown and stop at the first limit. Send confirm: true to run them."}
        cfg = lookback_cfg(body.lookback_days, body.justification, user["email"], f"incident {incident_id}") if body.siem else {"max_lookback_days": None}
        if siem_conn is not None:
            siem_run = search_base.Runner(siem_conn)
        report = _build(incident_id, user["email"], lookup=lookup, lookup_name=rep_name, siem_run=siem_run, siem_name=siem_name, siem_connected=bool(siem_conn) or None,
                        cap_days=cfg.get("max_lookback_days"), live_requested=bool(body.siem or body.reputation))
        activity_log.record_activity(user["email"], "soc.incident.report", str(incident_id), {"version": report["version"], "siem": bool(siem_run), "reputation": bool(lookup),
                                                                                           "stop_reason": report["live_search"]["stop_reason"]})
        return {"preview_only": False, "report": report, "open_followups": _open_followups(incident_id)}

    @router.post("/api/soc/incidents/{incident_id}/follow-up")
    def api_incident_follow_up(incident_id: int, body: IncidentFollowUpBody, user: dict = Depends(admin)):
        """A question about the incident, answered from stored data (and one read-only SIEM search for the value, only with confirm). Recorded on the incident; merge it into the report separately."""
        inc = _incident(incident_id)
        rows = incident_store.alert_rows(incident_id)
        siem_run = siem_name = None
        if body.siem:
            sconn, siem_name = _siem(body.siem_connection_id, True)
            if not body.confirm:
                return {"preview_only": True, "siem_connection": siem_name, "message": "One read-only search will run in your SIEM for this value. Send confirm: true to run it."}
            cfg = lookback_cfg(body.lookback_days, body.justification, user["email"], f"incident {incident_id}")
            siem_run = search_base.Runner(sconn)
        else:
            cfg = {"max_lookback_days": 90}
        pb = qpb.load()
        try:
            ans = inv_followup.answer(inc, rows, body.question, {"alerts_all": hunt_store.list_alerts(), "incident_map": inv_store.alert_incident_map()}, kind=body.kind, value=body.value,
                                      window_days=int(pb.get("history_days", 90)), siem_run=siem_run, siem_name=siem_name, max_days=cfg.get("max_lookback_days") or 90)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        fu = inv_store.add_followup(incident_id, ans["kind"], ans["value"], ans["question"], ans["answer"], ans["data"], ans["evidence"], ans["answerable"], user["email"])
        incident_store.add_event(incident_id, "followup", user["email"], ans["question"][:200], {"followup_id": fu["id"], "answerable": ans["answerable"]})
        activity_log.record_activity(user["email"], "soc.incident.follow_up", str(incident_id), {"kind": ans["kind"], "siem": bool(siem_run), "answerable": ans["answerable"]})
        return {"followup": fu, "merged": False, "message": "Recorded on the incident. Merge it into the report to include it." if ans["answerable"] else ans["answer"]}

    @router.get("/api/soc/incidents/{incident_id}/followups")
    def api_incident_followups(incident_id: int, user: dict = Depends(admin)):  # noqa: ARG001
        _incident(incident_id)
        return {"followups": inv_store.list_followups(incident_id)}

    @router.post("/api/soc/incidents/{incident_id}/report/merge-followups")
    def api_incident_merge_followups(incident_id: int, body: MergeBody, user: dict = Depends(admin)):
        """Marks the chosen follow-ups merged (or not) and rebuilds the report from stored data so they appear in it."""
        _incident(incident_id)
        changed = inv_store.set_merged(incident_id, body.followup_ids, body.merged, user["email"])
        if not changed:
            raise HTTPException(status_code=400, detail="None of those follow-ups belongs to this incident")
        report = _build(incident_id, user["email"])
        activity_log.record_activity(user["email"], "soc.incident.followups_merged", str(incident_id), {"ids": changed, "merged": body.merged})
        return {"merged_ids": changed, "report": report, "open_followups": _open_followups(incident_id)}

    @router.post("/api/soc/incidents/{incident_id}/report/post-to-ticket")
    def api_incident_post_to_ticket(incident_id: int, body: PostBody, user: dict = Depends(admin)):
        """Posts a concise comment (verdict, summary, recommended actions, link) to the ServiceNow or Jira ticket linked to this incident. A dry run unless confirm is true."""
        _incident(incident_id)
        report = _current(incident_id, user["email"])
        rows = incident_store.alert_rows(incident_id)
        links = itsm.targets(incident_id, [a["id"] for a in rows])
        if not links:
            raise HTTPException(status_code=400, detail="No ServiceNow or Jira ticket is linked to this incident. Tickets sent in through /api/ingest/itsm-ticket are linked automatically.")
        done = set()
        for ev in incident_store.events(incident_id):
            if ev["kind"] == "ticket-comment" and (ev.get("data") or {}).get("status") == "posted":
                done.add((ev["data"]["system"], ev["data"]["ticket"], ev["data"]["comment_digest"]))

        def make(system, connection_id):
            public, values = hunt_service.find_connection(system, connection_id)
            if not public:
                return None, None
            conn_registry.split_values(system, values)
            return conn_registry.SPECS[system]["make"](values), public["name"]

        results, text = itsm.post(report, links, make, done, body.confirm, comment=body.comment)
        if body.confirm:
            for r in results:
                if r["status"] in ("posted", "failed"):
                    incident_store.add_event(incident_id, "ticket-comment", user["email"], f"{r['system']} {r['ticket']}: {r['status']}", r)
            activity_log.record_activity(user["email"], "soc.incident.post_to_ticket", str(incident_id), {"posted": sum(1 for r in results if r["status"] == "posted"), "tickets": len(results)})
        return {"preview_only": not body.confirm, "comment": text, "results": results}

    # ------------------------------------------------------------ ITSM ticket intake
    @router.post("/api/ingest/itsm-ticket")
    def api_ingest_itsm_ticket(body: ItsmTicketBody, key: dict = Depends(require_api_key("soc:write"))):
        """A ticket-created event from ServiceNow, Jira or another ITSM tool. It becomes an alert (the ticket id linked), and the usual auto-investigation, incident grouping and
        routing follow, so the analyst opens a ticket that is already investigated. A repeat of the same ticket is ignored."""
        actor = f"apikey:{key['name']}"
        try:
            alert = itsm.alert_from_ticket(body.model_dump(), f"itsm:{(body.system or 'other').lower()}")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            row, new = hunt_store.receive_alert(alert)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        incident_id, version = incident_store.incident_for_alert(row["id"]), None
        if new:
            itsm.link_ticket(row["id"], body.system.lower(), body.ticket_id, body.connection_id)
            auto = auto_investigator()
            auto.run(row)
            soar_auto(row)
            incident_id = incident_store.incident_for_alert(row["id"])
            if incident_id:
                try:
                    version = _build(incident_id, actor)["version"]
                except Exception:  # noqa: BLE001 - the alert and incident are stored; the report can be built when opened
                    version = None
        activity_log.record_activity(actor, "soc.itsm.ingest", str(row["id"]), {"system": body.system, "created": new, "incident_id": incident_id})
        return {"created": new, "alert_id": row["id"], "incident_id": incident_id, "ticket": {"system": body.system.lower(), "ticket_id": body.ticket_id}, "severity": row["severity"],
                "report_version": version}

    # ------------------------------------------------------------ hunt report
    def _hunt(hunt_id):
        h = hunt_store.get_hunt(hunt_id)
        if not h:
            raise _404("No such hunt")
        return h

    def _hunt_report(hunt):
        keys = {hunt_report_mod.lead_key(q) for q in hunt.get("queries") or []}
        return hunt_report_mod.build(hunt_service.with_clock_start(hunt), hunt_detection.list_rules(), inv_store.list_allow(lead_keys=keys), inv_store.time_boxes())

    @router.get("/api/hunting/hunts/{hunt_id}/report")
    def api_hunt_report(hunt_id: int, format: str = "json", user: dict = Depends(admin)):  # noqa: ARG001
        r = _hunt_report(_hunt(hunt_id))
        if format == "md":
            return PlainTextResponse(hunt_report_mod.to_markdown(r), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="hunt-{hunt_id}.md"'})
        if format == "html":
            return HTMLResponse(hunt_report_mod.to_html(r), headers={"Content-Disposition": f'attachment; filename="hunt-{hunt_id}.html"'})
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be json, md or html")
        return r

    @router.get("/api/hunting/hunts/{hunt_id}/report.md")
    def api_hunt_report_md(hunt_id: int, user: dict = Depends(admin)):
        return api_hunt_report(hunt_id, "md", user)

    @router.get("/api/hunting/hunts/{hunt_id}/report.html")
    def api_hunt_report_html(hunt_id: int, user: dict = Depends(admin)):
        return api_hunt_report(hunt_id, "html", user)

    @router.get("/api/hunting/hunts/{hunt_id}/allowlist")
    def api_hunt_allowlist(hunt_id: int, user: dict = Depends(admin)):  # noqa: ARG001
        h = _hunt(hunt_id)
        return {"entries": inv_store.list_allow(lead_keys={hunt_report_mod.lead_key(q) for q in h["queries"]}), "fields": list(hunt_report_mod.ALLOW_FIELDS)}

    @router.post("/api/hunting/hunts/{hunt_id}/allowlist")
    def api_hunt_allowlist_add(hunt_id: int, body: AllowBody, user: dict = Depends(admin)):
        """Records that a value is benign for a lead. It applies to every later run of the same lead. A note saying why is required."""
        h = _hunt(hunt_id)
        if body.lead_index < 0 or body.lead_index >= len(h["queries"]):
            raise _404("No such trial hit")
        if body.field not in hunt_report_mod.ALLOW_FIELDS:
            raise HTTPException(status_code=400, detail=f"field must be one of {', '.join(hunt_report_mod.ALLOW_FIELDS)}")
        value, note = body.value.strip(), body.note.strip()
        if not value or len(value) > 255:
            raise HTTPException(status_code=400, detail="Give the exact value (1 to 255 characters); wildcards are not supported")
        if len(note) < 10:
            raise HTTPException(status_code=400, detail="Say why this value is benign (at least 10 characters); the report shows it")
        try:
            e = inv_store.add_allow(h["queries"][body.lead_index], hunt_id, body.field, value, note[:500], user["email"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        activity_log.record_activity(user["email"], "hunt.allowlist.add", str(hunt_id), {"lead": h["queries"][body.lead_index]["name"], "field": body.field})
        return {"entry": e, "report": _hunt_report(h)}

    @router.delete("/api/hunting/hunts/{hunt_id}/allowlist/{entry_id}")
    def api_hunt_allowlist_remove(hunt_id: int, entry_id: int, user: dict = Depends(admin)):
        h = _hunt(hunt_id)
        e = inv_store.get_allow(entry_id)
        if not e or e["lead_key"] not in {hunt_report_mod.lead_key(q) for q in h["queries"]}:
            raise _404("No such allow-list entry for this hunt")
        inv_store.remove_allow(entry_id)
        activity_log.record_activity(user["email"], "hunt.allowlist.remove", str(hunt_id), {"entry": entry_id})
        return {"removed": entry_id}

    @router.post("/api/hunting/hunts/{hunt_id}/time-box")
    def api_hunt_time_box(hunt_id: int, body: TimeBoxBody, user: dict = Depends(admin)):
        _hunt(hunt_id)
        top = int((qpb.load().get("hunt_report") or {}).get("max_time_box_hours", 168))
        if body.hours < 1 or body.hours > top:
            raise HTTPException(status_code=400, detail=f"The time box must be between 1 and {top} hours")
        inv_store.set_time_box(hunt_id, body.hours, user["email"])
        return {"time_box_hours": body.hours, "report": _hunt_report(_hunt(hunt_id))}

    @router.get("/api/hunting/report-metrics")
    def api_hunt_report_metrics(user: dict = Depends(admin)):  # noqa: ARG001
        return hunt_report_mod.metrics([hunt_service.with_clock_start(h) for h in hunt_store.list_hunts()], inv_store.time_boxes())

    return router
