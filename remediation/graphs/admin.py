"""Administration graph: what feeds Quanta and what it feeds.

Nodes: Quanta core (one node), stored connections (type, kind, enabled and last-sync status only; never credentials, URLs or messages),
the eight modules from capabilities.yaml, API-key scopes (a count of live keys per scope; never key material) and teams.
Edges: connection -> core (feeds; pull and tool connections), core -> connection (sends to; push connections), core -> module (serves),
connection -> module (feeds, where the module's connector list names the connection type or the type belongs to it), API-key scope ->
core (calls into) and -> module (ingests into), team -> core (works in).

A module nothing feeds is drawn with no connection edge, which is the honest picture of what is not yet connected.
"""
from remediation import capabilities
from remediation.apikeys import store as apikey_store
from remediation.assignments import store as assignment_store
from remediation.connections import registry
from remediation.connections import store as connection_store
from remediation.graphs.schema import GraphBuilder
from remediation.utils import db as db_module

CORE = "core:quanta"
# Connection types whose module cannot be read from a connector page path in capabilities.yaml.
_TYPE_MODULE = {"splunk-search": "soc", "reputation": "soc", "response-webhook": "soc", "notify-webhook": "soc",
                "intelx": "soc", "dehashed": "soc", "leakcheck": "soc", "snusbase": "soc",
                "api-policy-endpoint": "appsec", "github": "appsec", "gitlab": "appsec",
                "anthropic-usage": "ai", "openai-usage": "ai"}
# API key scope -> the modules it ingests into.
_SCOPE_MODULES = {"ingest:write": ["infra", "appsec"], "tickets:update": ["remediation"], "read:findings": ["remediation"],
                  "controls:write": ["infra"], "ai-usage:write": ["ai"], "soc:write": ["soc"], "darkweb:write": ["soc"], "api:write": ["appsec"]}
NOTE_EMPTY = ("Nothing is connected yet. Add a scanner or asset source on Connections (/connections), issue an API key for a scanner or CI job, "
              "and create teams on Users & Teams (/admin/people); each shows up here as something that feeds or uses Quanta.")


def _status_sev(c):
    if not c["enabled"]:
        return "low"
    if c["last_status"] == "error":
        return "high"
    return None


def build(engine=None, findings=None, **context):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    g = GraphBuilder("admin", "What feeds Quanta",
                     "Connections, API keys and teams around the Quanta core, and the modules the core serves.")
    for key, label in (("core", "Quanta core"), ("connection", "Connection"), ("module", "Module"), ("access", "Access"),
                       ("feeds", "feeds"), ("sends-to", "sends to"), ("serves", "serves"), ("ingests-into", "ingests into"),
                       ("calls-into", "calls into"), ("works-in", "works in")):
        g.kind(key, label)

    connections = connection_store.list_connections(engine)
    live_keys = [k for k in apikey_store.list_keys(engine) if not k.get("revoked_at")]
    teams = assignment_store.load_teams(engine)
    if not (connections or live_keys or teams):
        return g.build(note=NOTE_EMPTY)

    g.node(CORE, "Quanta", "core", weight=1, meta={"connections": len(connections), "api_keys": len(live_keys), "teams": len(teams)}, href="/admin")

    modules = [m for m in capabilities.catalog() if m.get("id")]
    path_modules = {}  # connector page path -> [module ids]
    for m in modules:
        g.node(f"module:{m['id']}", m.get("title") or m["id"], "module", meta={"number": m.get("number")}, href=f"/capabilities?area={m['id']}")
        g.edge(CORE, f"module:{m['id']}", "serves", "serves")
        for c in m.get("connectors") or []:
            path_modules.setdefault(c.get("path"), []).append(m["id"])

    for c in connections:
        cid = f"connection:{c['id']}"
        kind = (registry.SPECS.get(c["type"]) or {}).get("kind", "pull")
        status = "disabled" if not c["enabled"] else (c["last_status"] or "never run")
        g.node(cid, c["name"], "connection", sev=_status_sev(c), href="/connections",
               meta={"type": c["type"], "label": c["label"], "kind": kind, "enabled": c["enabled"], "status": status, "last_count": c["last_count"]})
        if kind == "push":
            g.edge(CORE, cid, "sends-to", "sends to")
        else:
            g.edge(cid, CORE, "feeds", "feeds")
        targets = set(path_modules.get(f"/{c['type']}", []))
        if _TYPE_MODULE.get(c["type"]):
            targets.add(_TYPE_MODULE[c["type"]])
        for mid in sorted(targets):
            if kind == "push":
                g.edge(f"module:{mid}", cid, "sends-to", "sends to")
            else:
                g.edge(cid, f"module:{mid}", "feeds", "feeds")

    scopes = {}
    for k in live_keys:
        for s in k["scopes"]:
            scopes[s] = scopes.get(s, 0) + 1
    for scope in sorted(scopes):
        sid = f"apikey:{scope}"
        g.node(sid, f"API keys: {scope}", "access", weight=scopes[scope], meta={"scope": scope, "live_keys": scopes[scope]}, href="/connections")
        g.edge(sid, CORE, "calls-into", "calls into")
        for mid in _SCOPE_MODULES.get(scope, []):
            g.edge(sid, f"module:{mid}", "ingests-into", "ingests into")

    for t in teams:
        g.node(f"team:{t['name']}", f"Team: {t['name']}", "access", meta={"team": t["name"], "has_manager": bool(t.get("manager_email"))}, href="/admin/people")
        g.edge(f"team:{t['name']}", CORE, "works-in", "works in")

    return g.build(note="A module with no connection edge has nothing feeding it yet. Credentials and URLs are never shown here.")
