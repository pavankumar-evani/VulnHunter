"""
"What each AI system depends on": the AI register, the models and providers it is recorded as using, and the AI applications nobody reviewed.

Only recorded facts become edges; a blank answer is a gap, never a guessed link:
  system -> model         'runs'       the register's vendor_model, or the model in recorded usage events for that application name
  system -> provider      'hosted by'  the provider in recorded usage events for that application name (or a `provider` on the record)
  system -> tool / mcp-server  'can call'   names recorded on the record (`tools`, `mcp_servers`) or passed as context `links`
  system -> data-source   'reads'      names recorded on the record (`data_sources`) or passed as context `links`
  shadow app -> provider  'talks to'   an unreviewed AI application found in proxy/DNS data (AI Usage page), joined to the provider by name or domain

A record carries `tools` (name, side effect, approval, optional `server` and `reads`), `mcp_servers` and `data_sources` (name, trusted), and the caller may also pass
`links={"<system name>": {"tools": [...], "mcp_servers": [...], "data_sources": [...], "provider": "..."}}` (plain names, or the same objects).

The path to look for is  untrusted content -> system -> tool that changes things with no approval:
  tool -> mcp-server   'served by'   the `server` named on the tool
  tool -> data-source  'reads'       the names in the tool's `reads`
A tool that changes things (write, external-send, destructive, financial) with `requires_approval` false is drawn high severity, and critical when the same
system takes untrusted input, retrieves from a store or reads a source recorded as untrusted (meta.untrusted_path), which is the prompt-injection-to-tool-call path. Registered plugins, MCP servers, vector
stores and datasets are always drawn as nodes (isolated when nothing links to them). A tool or data source many systems share is the blast radius.
"""
import datetime

from remediation.aisec import store as aisec_store
from remediation.aiusage import discovery
from remediation.aiusage import store as usage_store
from remediation.graphs.schema import SEVERITIES, GraphBuilder
from remediation.utils import db as db_module

MODULE = "ai"
TITLE = "AI dependencies"
DESCRIPTION = "What each AI system runs on, who hosts it, and which tools and data it can reach. A node many systems share is a single point of failure."
NOTE_EMPTY = ("No AI systems recorded. Add them on AI Security (or copy in the applications found on AI Usage), and connect an AI usage source "
              "or send events to /api/ingest/ai-usage so models and providers can be linked.")
SYSTEM_KINDS = ("application", "agent", "gateway")
SIDE_EFFECT_TOOLS = ("write", "external-send", "destructive", "financial")
# register kind -> graph node kind
OTHER_KINDS = {"model": "model", "mcp-server": "mcp-server", "plugin": "tool", "vector-db": "data-source", "dataset": "data-source"}
PAGE = {"system": "/ai-security", "model": "/ai-security", "provider": "/ai-usage", "tool": "/ai-security", "mcp-server": "/ai-security",
        "data-source": "/ai-security", "shadow": "/ai-usage"}


def _slug(v):
    return " ".join(str(v or "").lower().split())


def _names(v):
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in (v or []) if str(x or "").strip()]


def _entries(v):
    """Names or objects -> [{"name": ..., ...}], skipping blanks, so records and caller-supplied links share one path."""
    if isinstance(v, (str, dict)):
        v = [v]
    out = []
    for x in v or []:
        x = {"name": x} if isinstance(x, str) else dict(x or {})
        if str(x.get("name") or "").strip():
            x["name"] = str(x["name"]).strip()
            out.append(x)
    return out


def _worst(sevs):
    sevs = [s for s in sevs if s in SEVERITIES]
    return min(sevs, key=SEVERITIES.index) if sevs else None


def build(engine=None, findings=None, **context):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    g = GraphBuilder(MODULE, TITLE, DESCRIPTION, directed=True)
    for k, label in (("system", "AI system"), ("model", "Model"), ("provider", "Provider"), ("tool", "Tool or plugin"), ("mcp-server", "MCP server"),
                     ("data-source", "Data source"), ("shadow", "Unreviewed AI application"), ("runs", "Runs"), ("hosted_by", "Hosted by"),
                     ("can_call", "Can call"), ("reads", "Reads"), ("served_by", "Served by"), ("talks_to", "Talks to")):
        g.kind(k, label)

    assets = aisec_store.list_all(engine)
    shadows = [a for a in discovery.list_apps(engine) if a["status"] == "unreviewed"]
    if not assets and not shadows:
        return g.build(note=NOTE_EMPTY)

    today = context.get("today") or datetime.date.today()
    assessed = {a["id"]: a for a in aisec_store.assess(assets, today)["assets"]} if assets else {}
    ai_findings = {}
    for f in findings or []:
        a = f.get("asset")
        if isinstance(a, dict) and a.get("type") == "ai-ml-system" and a.get("name"):
            ai_findings.setdefault(_slug(a["name"]), []).append(f)
    links = {_slug(k): v for k, v in (context.get("links") or {}).items()}

    def meta_for(asset):
        info = assessed.get(asset["id"], {})
        fs = ai_findings.get(_slug(asset["name"]), [])
        sevs = [str(f.get("severity") or "").lower() for f in fs] + [str(info.get("worst") or "").lower()]
        m = {"kind": asset["kind"], "environment": asset.get("environment"), "owner": asset.get("owner"), "hosting": asset.get("hosting"),
             "register_findings": info.get("findings", 0), "queue_findings": len(fs), "gaps": len(info.get("unanswered", []))}
        return m, _worst(sevs)

    for a in assets:
        node_kind = OTHER_KINDS.get(a["kind"])
        if node_kind:
            m, sev = meta_for(a)
            g.node(f"{node_kind}:{_slug(a['name'])}", a["name"], node_kind, weight=0, sev=sev, meta=m, href=PAGE[node_kind])

    done = set()

    def link(src, dst, kind, label):
        """One edge per (source, target, kind); the target's weight counts how many systems use it."""
        if (src, dst, kind) not in done:
            done.add((src, dst, kind))
            g.edge(src, dst, kind, label)
            g.node(dst, "", "", weight=1)  # merged into the existing node: weight = number of systems that use it

    def used(kind, name, meta=None, sev=None):
        return g.node(f"{kind}:{_slug(name)}", name, kind, weight=0, sev=sev, meta=meta, href=PAGE[kind])

    systems = {}
    for a in assets:
        if a["kind"] in SYSTEM_KINDS:
            m, sev = meta_for(a)
            systems[_slug(a["name"])] = (g.node(f"system:{_slug(a['name'])}", a["name"], "system", sev=sev, meta=m, href=PAGE["system"]), a)

    providers = set()

    def provider(name):
        providers.add(_slug(name))
        return g.node(f"provider:{_slug(name)}", name, "provider", weight=0, href=PAGE["provider"])

    for key, (sid, a) in sorted(systems.items()):
        ln = links.get(key, {})
        if a.get("vendor_model"):
            link(sid, used("model", a["vendor_model"]), "runs", "runs")
        for name in _names(ln.get("provider") or a.get("provider")):
            link(sid, provider(name), "hosted_by", "hosted by")
        sources = _entries(ln.get("data_sources")) + _entries(a.get("data_sources"))
        tools = _entries(ln.get("tools")) + _entries(a.get("tools"))
        untrusted = a.get("untrusted_input") is True or a.get("uses_rag") is True or any(d.get("trusted") is False for d in sources)
        for srv in _entries(ln.get("mcp_servers")) + _entries(a.get("mcp_servers")):
            weak = srv.get("transport") == "http" and srv.get("auth") == "none"
            link(sid, used("mcp-server", srv["name"], {"transport": srv.get("transport"), "auth": srv.get("auth")}, "high" if weak else None), "can_call", "can call")
        for src in sources:
            link(sid, used("data-source", src["name"], {"trusted": src.get("trusted")}), "reads", "reads")
        for tool in tools:
            effect = tool.get("side_effect")
            bad = effect in SIDE_EFFECT_TOOLS and tool.get("requires_approval") is False
            tid = used("tool", tool["name"], {"side_effect": effect, "requires_approval": tool.get("requires_approval"), "scope": tool.get("scope")},
                       ("critical" if untrusted else "high") if bad else None)
            if bad and untrusted:
                g.node(tid, "", "", weight=0, meta={"untrusted_path": True})
                g.node(sid, "", "", weight=0, meta={"untrusted_path": True})
            link(sid, tid, "can_call", "can call")
            if tool.get("server"):
                link(tid, used("mcp-server", tool["server"]), "served_by", "served by")
            for name in _entries(tool.get("reads")):
                link(tid, used("data-source", name["name"]), "reads", "reads")

    # Recorded usage: the application name ties a system to the model and provider it was actually seen using
    seen = set()
    for ev in usage_store.fetch(engine=engine):
        key = _slug(ev.get("application"))
        if key not in systems:
            continue
        sid = systems[key][0]
        if ev.get("model") and (sid, "m", _slug(ev["model"])) not in seen:
            seen.add((sid, "m", _slug(ev["model"])))
            link(sid, used("model", ev["model"]), "runs", "runs")
        if ev.get("provider") and (sid, "p", _slug(ev["provider"])) not in seen:
            seen.add((sid, "p", _slug(ev["provider"])))
            link(sid, provider(ev["provider"]), "hosted_by", "hosted by")

    # Unreviewed applications found in traffic, joined to a provider already in the graph by name or domain, else to the service itself
    for app in shadows:
        hay = f"{app['name']} {app['domain']}".lower()
        match = next((p for p in sorted(providers) if p and p in hay), None)
        pid = f"provider:{match}" if match else provider(app["name"])
        sid = g.node(f"shadow:{_slug(app['domain'])}", app["name"], "shadow", weight=max(1, int(app.get("users_seen") or 0)),
                     meta={"domain": app["domain"], "status": app["status"], "users_seen": app.get("users_seen"), "requests_seen": app.get("requests_seen"), "owner": app.get("owner")},
                     href=PAGE["shadow"])
        link(sid, pid, "talks_to", "talks to")

    linked = {src for src, _, _ in done}
    unlinked = sum(1 for sid, _ in systems.values() if sid not in linked)
    note = (f"{len(systems)} AI systems, {len(shadows)} unreviewed applications. "
            + (f"{unlinked} systems have no recorded model, provider, tool or data source: those links are gaps in the record, not absences." if unlinked else ""))
    return g.build(note=note.strip())
