"""
Runs a stored connection: pull from the source, bring the data into Quanta, record the result.

Findings sources are merged into the system of record (remediation/ingest/merge.py) and then
enriched with CISA KEV and FIRST EPSS (best effort: an unreachable feed is reported, never
fatal). Asset sources reconcile ip/mac into the asset inventory. Every run is audited, the
outcome is stored on the connection (status, message, count), and a connection is never run
twice at once.
"""
import datetime

from remediation.audit.activity_log import record_activity
from remediation.connections import crypto, push, registry, store
from remediation.ingest import merge


def _reconcile_assets(assets, findings_path):
    from remediation.inventory import asset_inventory
    known = [a["name"] for a in asset_inventory.build_asset_inventory(merge.load(findings_path))]
    return asset_inventory.reconcile_pulled_assets(assets, known)


def test_connection(conn_type, values):
    spec = registry.SPECS[conn_type]
    spec["test"](values)


def run(connection_id, actor="scheduler", engine=None, findings_path=merge.DEFAULT_PATH, enrich=True, now=None):
    """Returns {ok, message, count, detail}. Never raises for a source/network failure: the
    failure is recorded on the connection and returned."""
    public, values = store.get_values(connection_id, engine)
    if not public:
        raise KeyError("No such connection")
    if not store.claim_run(connection_id, engine, now):
        return {"ok": False, "message": "A sync for this connection is already running.", "count": None, "detail": {}}
    name = public["name"]
    try:
        spec = registry.SPECS[public["type"]]
        # re-check the SSRF guard at run time: an edited config must never bypass it
        registry.split_values(public["type"], values)
        if spec.get("kind") == "push":
            r = push.push(spec["system"], spec["make"](values), connection_id, registry.rule_from(values), findings_path, engine, actor)
            detail = r
            message = (f"{r['matched']} matching finding(s): {r['sent']} sent, {r['errors']} failed"
                       + (f"; {r['refreshed']} ticket state(s) updated from {public['label']}" if r["refreshed"] else "") + ".")
            store.finish_run(connection_id, "ok" if not r["errors"] or r["sent"] else "error", message, r["sent"], engine, now)
            record_activity(actor, "connection.sync", name, {"ok": True, **r}, engine=engine)
            return {"ok": True, "message": message, "count": r["sent"], "detail": detail}
        pulled = spec["pull"](values)
        if pulled["kind"] == "findings":
            result = merge.merge(pulled["findings"], public["type"], findings_path, reconcile=pulled.get("reconcile", False))
            detail = {**result, "skipped": pulled.get("skipped") or {}, "fetched": len(pulled["findings"])}
            message = (f"Fetched {detail['fetched']} finding(s): {result['added']} new, {result['updated']} updated"
                       + (f", {result['removed']} no longer reported" if result["removed"] else "")
                       + (f"; skipped {sum(detail['skipped'].values())} informational/invalid row(s)" if detail["skipped"] else "") + ".")
            count = detail["fetched"]
            if enrich and (result["added"] or result["updated"]):
                try:
                    from remediation.enrichment import kev_epss
                    kev_epss.enrich_file(findings_path)
                    message += " Threat intel (KEV, EPSS) refreshed."
                except Exception as exc:  # noqa: BLE001 - enrichment is best effort
                    message += f" Threat-intel refresh failed ({type(exc).__name__}); retry from the Overview page."
        else:
            result = _reconcile_assets(pulled["assets"], findings_path)
            detail = {"fetched": len(pulled["assets"]), "matched": len(result["matched"]), "unmatched": len(result["unmatched"]), "skipped": len(result["skipped"])}
            message = (f"Fetched {detail['fetched']} asset(s): {detail['matched']} matched an existing asset, "
                       f"{detail['unmatched']} stored for when a finding appears, {detail['skipped']} skipped.")
            count = detail["fetched"]
        store.finish_run(connection_id, "ok", message, count, engine, now)
        record_activity(actor, "connection.sync", name, {"ok": True, **{k: v for k, v in detail.items() if not isinstance(v, dict)}}, engine=engine)
        return {"ok": True, "message": message, "count": count, "detail": detail}
    except (crypto.EncryptionNotConfigured, crypto.DecryptionFailed) as exc:
        message = str(exc)
    except Exception as exc:  # noqa: BLE001 - any source failure is recorded, not raised
        message = f"{type(exc).__name__}: {exc}"
    store.finish_run(connection_id, "error", message, None, engine, now)
    record_activity(actor, "connection.sync", name, {"ok": False, "error": message[:300]}, engine=engine)
    return {"ok": False, "message": message, "count": None, "detail": {}}


def enqueue_due(engine=None, now=None):
    """The scheduler tick for a multi-replica deployment: queues a sync job for every connection
    whose interval has elapsed and lets the workers run them. The dedupe key means a connection
    already queued or running is not queued again, so a slow sync or a double tick is harmless."""
    from remediation.coordination import jobs, worker
    out = []
    for c in store.due(engine, now):
        out.append({"id": c["id"], "name": c["name"],
                    "job": jobs.enqueue(worker.KIND_CONNECTION_SYNC, {"connection_id": c["id"], "actor": "scheduler"},
                                        dedupe_key=f"sync:{c['id']}", engine=engine)})
    return out


def run_due(engine=None, findings_path=merge.DEFAULT_PATH, now=None):
    """The scheduler tick: runs every connection whose interval has elapsed."""
    results = []
    for c in store.due(engine, now):
        results.append({"id": c["id"], "name": c["name"], **run(c["id"], "scheduler", engine, findings_path, now=now)})
    return results
