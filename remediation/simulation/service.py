"""
Loading and removing the demonstration data: one stored simulation connection per implemented renderer,
each run through the SAME sync.run path a live connection uses (connector -> its own parsing -> classify ->
merge -> enrich -> store). Shared by the dashboard route (dashboard/simulation_api.py) and the operator CLI
(`quanta_admin seed-demo`). Nothing here knows how a vendor responds; that is the renderers' job.
"""
from remediation.audit.activity_log import record_activity
from remediation.connections import store, sync
from remediation.ingest import merge
from remediation.simulation import estate as estate_mod
from remediation.simulation import renderers
from remediation.utils import environment


class SimulationNotAllowed(RuntimeError):
    pass


def connection_name(conn_type):
    return f"Simulated {renderers.LABELS.get(conn_type, conn_type)}"


def ensure_allowed(env=None):
    if not environment.simulation_allowed(env):
        raise SimulationNotAllowed("Simulation is not allowed in this environment (QUANTA_ENV=prod). "
                                   "Set QUANTA_ALLOW_SIMULATION=true only on a hosted demonstration site.")


def simulation_connections(engine=None):
    return [c for c in store.list_connections(engine) if c.get("mode") == "simulation"]


def plan(engine=None):
    """What load() would do, without doing it."""
    existing = {c["name"]: c for c in store.list_connections(engine)}
    e = estate_mod.build()
    return {"connections": [{"type": t, "name": connection_name(t), "exists": connection_name(t) in existing} for t in renderers.implemented()],
            "estate": {"hosts": len(e.hosts), "applications": len(e.applications), "detections": len(e.detections), "size": e.size},
            "note": "Recorded vendor-format responses are replayed through each connector's real code, then merged, enriched and stored like live data. "
                    "Every record is marked source_mode=simulation."}


def load(actor, engine=None, findings_path=None, enrich=True):
    ensure_allowed()
    existing = {c["name"]: c for c in store.list_connections(engine)}
    results = []
    for t in renderers.implemented():
        name = connection_name(t)
        conn = existing.get(name) or store.create(name, t, {"mode": "simulation"}, actor, engine=engine)
        r = sync.run(conn["id"], actor, engine, findings_path or merge.DEFAULT_PATH, enrich=enrich)
        results.append({"type": t, "name": name, "connection_id": conn["id"], "ok": r["ok"], "message": r["message"], "count": r["count"],
                        "added": (r.get("detail") or {}).get("added"), "updated": (r.get("detail") or {}).get("updated")})
    record_activity(actor, "simulation.load", None, {"connections": len(results), "ok": sum(1 for r in results if r["ok"])}, engine=engine)
    return {"results": results}


def remove(actor, engine=None, findings_path=None):
    ensure_allowed()
    conns = simulation_connections(engine)
    for c in conns:
        store.delete_connection(c["id"], actor, engine)
    removed = merge.remove_simulated(findings_path or merge.DEFAULT_PATH)
    record_activity(actor, "simulation.remove", None, {"connections": len(conns), "findings": removed}, engine=engine)
    return {"connections_removed": len(conns), "findings_removed": removed}


def status(engine=None, findings_path=None):
    rows = merge.load(findings_path or merge.DEFAULT_PATH)
    sim = sum(1 for f in rows if f.get("source_mode") == "simulation")
    return {"allowed": environment.simulation_allowed(), "environment": environment.name(), "types": renderers.implemented(),
            "connections": [{"id": c["id"], "name": c["name"], "type": c["type"], "last_status": c["last_status"], "last_run_at": c["last_run_at"],
                             "last_count": c["last_count"]} for c in simulation_connections(engine)],
            "simulated_findings": sim, "live_findings": len(rows) - sim}
