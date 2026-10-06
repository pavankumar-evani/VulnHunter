"""AppSec relationship graph: how APIs, data and models connect.

API services call other services (api_dependencies), serve endpoints (the inventory), and their endpoints return the data classes observed on them,
named only by the customer's own classification framework (anything else is "unclassified"). Threat-model components and the data flows between
them are added when a model exists. Shadow, zombie and unauthenticated endpoints are marked from the stored fields through the apisec view
function; nothing is recomputed here and nothing is invented.
"""
import datetime

from remediation.apisec import config as apisec_config
from remediation.apisec import rules as apisec_rules
from remediation.apisec import store as apisec_store
from remediation.graphs.schema import GraphBuilder, empty
from remediation.threatmodel import store as tm_store

TITLE = "API, data and model relationships"
DESCRIPTION = "API services, the endpoints they serve, the data classes those endpoints return, service-to-service calls and threat-model data flows."
_FIXED_DAY = datetime.date(2000, 1, 1)  # the view only uses 'today' for an age we do not show; a fixed day keeps the graph clock-free
UNCLASSIFIED = "unclassified"


def _endpoint_sev(v):
    """(sev, flags) from the endpoint view: shadow and unauthenticated-in-traffic are high, zombie and declared-open medium."""
    flags = []
    sev = None
    if v["state"] == "shadow":
        flags.append("shadow")
        sev = "high"
    if v["auth_state"] == "open-observed":
        flags.append("open-without-auth")
        sev = "high"
    elif v["auth_state"] == "open-declared":
        flags.append("declared-without-auth")
        sev = sev or "medium"
    if v["deprecated"] and v["observed"] and v["status"] != "decommissioning":
        flags.append("zombie")
        sev = sev or "medium"
    return sev, flags


def build(engine=None, findings=None, **context):
    endpoints = apisec_store.list_endpoints(engine)
    deps = apisec_store.dependencies(engine)
    models = [tm_store.get(m["id"], engine) for m in tm_store.list_models(engine)]
    if not (endpoints or deps or models):
        return empty("appsec", TITLE, DESCRIPTION,
                     "No APIs or threat models are recorded yet. Upload an OpenAPI file or import gateway or access logs on the API Security page "
                     "(POST /api/ingest/api-traffic), or describe a system on the Threat Models page, and the connections will appear here.")
    g = GraphBuilder("appsec", TITLE, DESCRIPTION)
    g.kind("service", "API service")
    g.kind("endpoint", "API endpoint")
    g.kind("data-class", "Data class")
    g.kind("component", "Model component")
    if endpoints:
        classes = apisec_store.list_classes(engine)
        specs = apisec_store.list_specs(engine)
        spec_services = {s["service"] for s in specs}
        cfg = apisec_config.load()
        per_service = {}
        for ep in endpoints:
            v = apisec_rules.view(ep, classes, ep["service"] in spec_services, cfg, (), _FIXED_DAY)
            sev, flags = _endpoint_sev(v)
            sid = f"service:{ep['service']}"
            eid = f"endpoint:{ep['service']}:{ep['method']} {ep['path_key']}"
            per_service[sid] = per_service.get(sid, 0) + 1
            g.node(sid, ep["service"], "service", href="/api-security")
            g.node(eid, f"{ep['method']} {ep['template']}", "endpoint", sev=sev, href="/api-security",
                   meta={"state": v["state"], "auth": v["auth_state"], "exposure": v["exposure"], "calls": ep["calls_total"], "status": ep["status"],
                         "flags": ", ".join(flags) if flags else "none"})
            g.edge(sid, eid, "serves")
            for c in v["data"]["classes"]:
                did = f"data-class:{c['name']}"
                g.node(did, c["name"], "data-class", meta={"priority": c["priority"]}, href="/api-security")
                g.edge(eid, did, "returns")
            if v["data"]["unclassified"]:
                g.node(f"data-class:{UNCLASSIFIED}", UNCLASSIFIED, "data-class", meta={"note": "seen in traffic, not mapped by your framework"}, href="/api-security")
                g.edge(eid, f"data-class:{UNCLASSIFIED}", "returns")
        for sid, n in per_service.items():
            g.node(sid, sid, "service", weight=n - 1, meta={"endpoints": n})
    for d in deps:
        for svc in (d["source_service"], d["dest_service"]):
            g.node(f"service:{svc}", svc, "service", weight=0, href="/api-security")
        g.node(f"service:{d['dest_service']}", d["dest_service"], "service", weight=0, meta={"exposure": d["dest_exposure"] or "unknown"})
        g.edge(f"service:{d['source_service']}", f"service:{d['dest_service']}", "calls", weight=max(1, int(d["calls"] or 1)))
    for m in models:
        mm = m["model"]
        names = {}
        for c in mm.get("components", []):
            nid = f"component:{m['id']}:{c['id']}"
            names[c["id"]] = nid
            g.node(nid, c["name"], "component", href="/threat-models",
                   meta={"model": m["name"], "type": c.get("type"), "zone": c.get("trust_zone") or "none",
                         "internet_facing": bool(c.get("internet_facing")), "handles": ", ".join(c.get("handles") or []) or "none"})
        for f in mm.get("data_flows", []):
            if f["from"] in names and f["to"] in names:
                g.edge(names[f["from"]], names[f["to"]], "flows to", label=", ".join(f.get("data") or []) or None)
    return g.build(note="Shadow, zombie and unauthenticated endpoints are marked on the endpoint; data classes are only those your framework maps.")
