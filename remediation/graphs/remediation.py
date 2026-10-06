"""
"Who owns the risk": teams, people and assets with open findings, with the waivers, fix approvals and tickets that cover them.

Everything is read from stored records, nothing is guessed:
  team -> person   'member of'   a user account whose team is that team
  team -> asset    'owns'        the asset's recorded team (asset ownership), or the team a finding on it was assigned to
  person -> asset  'assigned'    a finding on the asset is assigned to the person
  person -> asset  'owns'        the asset's recorded owner (only a name or email, as recorded)
  exception -> asset 'waives'    an active risk-acceptance waiver for a finding on the asset
  approval -> asset  'approves'  a pending / approved / triggered remediation approval for a finding on the asset
  ticket -> asset    'tracks'    an external ticket linked to a finding on the asset

An asset with open findings and no owning team, no owner and no assignment is still drawn (meta `unowned: true`) with no owner edge,
so it shows up as an isolated component: that is the point of the graph.
"""
import datetime

from sqlalchemy import select

from remediation.assignments import store as assignments_store
from remediation.exceptions import store as exceptions_store
from remediation.graphs.schema import SEVERITIES, GraphBuilder
from remediation.inventory import asset_inventory
from remediation.remediation_approvals import store as approvals_store
from remediation.utils import db as db_module

MODULE = "remediation"
TITLE = "Who owns the risk"
DESCRIPTION = ("Teams, people and assets with open findings, and the waivers, fix approvals and tickets that cover them. "
               "An asset with no owner edge is unowned: nothing is accountable for it.")
NOTE_EMPTY = ("No findings to show. Ingest scanner findings (Connections, or POST /api/ingest/findings), then record asset owners on Asset Inventory "
              "and assign findings on Assignments to see who owns the risk.")
CLOSED = {"resolved", "closed", "fixed", "remediated"}


def _sev(f):
    s = str(f.get("severity") or "").strip().lower()
    return s if s in SEVERITIES else None


def _asset_name(f):
    a = f.get("asset")
    name = a.get("name") if isinstance(a, dict) else a
    return (str(name).strip() if name else "") or str(f.get("hostname") or "").strip() or None


def _is_urgent(f):
    kev = f.get("kev")
    return _sev(f) in ("critical", "high") or bool(isinstance(kev, dict) and kev.get("listed"))


def _users(engine):
    """[{email, name, team}] from the local user store; empty when it cannot be read."""
    try:
        try:
            from auth import users
        except ImportError:
            from dashboard.auth import users
        return users.list_users(engine)
    except Exception:  # the user store is optional context for this graph
        with engine.connect() as conn:
            rows = conn.execute(select(db_module.users.c.email, db_module.users.c.name, db_module.users.c.team)).mappings().all()
        return [dict(r) for r in rows]


def _ticket_rows(engine):
    t = db_module.ticket_links
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).order_by(t.c.id)).mappings().all()]


def build(engine=None, findings=None, **context):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    as_of = context.get("as_of") or datetime.date.today()
    g = GraphBuilder(MODULE, TITLE, DESCRIPTION, directed=True)
    g.kind("team", "Team")
    g.kind("person", "Person")
    g.kind("asset", "Asset with open findings")
    g.kind("exception", "Exception (waiver)")
    g.kind("approval", "Remediation approval")
    g.kind("ticket", "Ticket")
    g.kind("member_of", "Member of")
    g.kind("assigned", "Assigned")
    g.kind("owns", "Owns")
    g.kind("waives", "Waives")
    g.kind("approves", "Approves fix for")
    g.kind("tracks", "Tracks")

    open_findings = [f for f in (findings or []) if f.get("id") and _asset_name(f)
                     and str(f.get("status") or "").lower() not in CLOSED]
    if not open_findings:
        return g.build(note=NOTE_EMPTY)

    by_id = {f["id"]: f for f in open_findings}
    by_asset = {}
    for f in open_findings:
        by_asset.setdefault(_asset_name(f), []).append(f)

    ownership = asset_inventory.load_ownership(engine)
    assignments = assignments_store.assignments_by_finding(engine)
    users = _users(engine)
    emails = {u["email"].lower(): u for u in users}
    owned = set()

    def team_node(name):
        return g.node("team:" + name.lower(), name, "team", href="/admin/people")

    def person_node(email, name=None):
        u = emails.get(email.lower())
        return g.node("person:" + email.lower(), (u or {}).get("name") or name or email, "person", href="/admin/people")

    # Assets: weight = open findings, severity = worst
    for name, fs in sorted(by_asset.items()):
        worst = None
        for f in fs:
            s = _sev(f)
            if s and (worst is None or SEVERITIES.index(s) < SEVERITIES.index(worst)):
                worst = s
        g.node("asset:" + name, name, "asset", weight=len(fs), sev=worst, href="/assets",
               meta={"open": len(fs), "urgent": sum(1 for f in fs if _is_urgent(f)),
                     "critical": sum(1 for f in fs if _sev(f) == "critical"), "unowned": False})

    # Teams that exist as records (so an empty team is still visible), and who is a member
    for t in assignments_store.load_teams(engine):
        g.node("team:" + t["name"].lower(), t["name"], "team", meta={"explicit": True, "manager": t.get("manager_email")}, href="/admin/people")
    for u in users:
        if u.get("team"):
            tn = team_node(u["team"])
            g.edge(tn, person_node(u["email"]), "member_of", "member of")

    # Asset ownership: team owns, recorded owner owns
    for name in by_asset:
        entry = ownership.get(name) or {}
        aid = "asset:" + name
        if (entry.get("team") or "").strip():
            g.edge(team_node(entry["team"].strip()), aid, "owns", "owns")
            owned.add(name)
        owner = (entry.get("owner") or "").strip()
        if owner:
            g.edge(person_node(owner) if owner.lower() in emails else g.node("person:" + owner.lower(), owner, "person", href="/admin/people"),
                   aid, "owns", "asset owner")
            owned.add(name)

    # Assignments: person assigned, or the team the finding was handed to
    for fid, a in sorted(assignments.items()):
        f = by_id.get(fid)
        if not f:
            continue
        name = _asset_name(f)
        aid = "asset:" + name
        if a.get("assignee_email"):
            g.edge(person_node(a["assignee_email"]), aid, "assigned", "assigned")
            owned.add(name)
        if a.get("assigned_team"):
            g.edge(team_node(a["assigned_team"]), aid, "owns", "owns")
            owned.add(name)

    # Waivers
    for e in exceptions_store.list_exceptions_with_status(engine, as_of=as_of):
        f = by_id.get(e.get("finding_id"))
        if not f or e.get("computed_status") != "active":
            continue
        xid = g.node("exception:" + str(e["id"]), str(e["id"]), "exception", meta={"status": "active", "expires_on": e.get("expires_on"), "finding": e["finding_id"]}, href="/exceptions")
        g.edge(xid, "asset:" + _asset_name(f), "waives", "waives")

    # Fix approvals
    for a in approvals_store.list_approvals_with_status(engine, as_of=as_of):
        f = by_id.get(a.get("finding_id"))
        status = a.get("computed_status")
        if not f or status not in ("pending", "approved", "remediation_triggered"):
            continue
        pid = g.node("approval:" + str(a["id"]), str(a["id"]), "approval", meta={"status": status, "finding": a["finding_id"]}, href="/remediation-approvals")
        g.edge(pid, "asset:" + _asset_name(f), "approves", "approves fix for")

    # Tickets
    for t in _ticket_rows(engine):
        f = by_id.get(t["finding_id"])
        if not f:
            continue
        ref = t.get("external_ref") or t.get("external_id")
        tid = g.node(f"ticket:{t['system']}:{ref or t['id']}", f"{t['system']} {ref}" if ref else f"{t['system']} ticket", "ticket",
                     meta={"system": t["system"], "state": t.get("state"), "finding": t["finding_id"]}, href="/assignments")
        g.edge(tid, "asset:" + _asset_name(f), "tracks", "tracks")

    # Mark the unowned ones (no team, owner or assignment): they get no owner edge, so they are isolated components
    for name in by_asset:
        if name not in owned:
            g.node("asset:" + name, name, "asset", weight=0, meta={"unowned": True})

    unowned = [n for n in by_asset if n not in owned]
    urgent_unowned = [n for n in unowned if any(_is_urgent(f) for f in by_asset[n])]
    note = (f"{len(unowned)} of {len(by_asset)} assets with open findings have no owner" +
            (f"; {len(urgent_unowned)} of them carry critical, high or known-exploited findings." if urgent_unowned else "."))
    return g.build(note=note)
