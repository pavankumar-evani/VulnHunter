"""
Routes for the read-only MCP endpoint: `POST /mcp` (the endpoint an AI assistant connects to) and `GET /api/mcp/status` (administrator).

`/mcp` is outside `/api/`, so the browser-login gate and the cookie session never apply to it: the ONLY way in is a Quanta API key (Authorization: Bearer) with the
`mcp:read` scope, checked in remediation/mcp/server.py on every request. It answers 404 unless QUANTA_MCP_ENABLED=true. Built by `build_router()` so this module needs
nothing from app.py except what is handed in.
"""
from collections import Counter

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from auth import rbac
from remediation.apikeys import store as apikey_store
from remediation.audit import activity_log
from remediation.licensing import license as licensing
from remediation.mcp import PROTOCOL_VERSION, SUPPORTED_VERSIONS, server as mcp_server
from remediation.mcp import policy as mcp_policy
from remediation.mcp import registry as mcp_registry
from remediation.mcp import tools as mcp_tools


def _reply(r):
    if r.body is None:
        return Response(status_code=r.status, headers=r.headers)
    return JSONResponse(r.body, status_code=r.status, headers=r.headers)


def build_router(*, load_findings, load_assets, scope_findings, scope_assets, attack_chains, posture):
    """load_findings()/load_assets() return everything; scope_*(rows, user) apply team scoping (user None = no narrowing); attack_chains(findings) and posture(findings)
    are the same functions the read routes call."""
    router = APIRouter()

    def licensed(path):
        return licensing.check(path)[0]

    deps = mcp_server.Deps(
        context_for=lambda key: _context(key),
        audit=lambda actor, action, target, details: activity_log.record_activity(actor, action, target, details),
        licensed=licensed)

    def _context(key):
        user = {"role": "user", "team": key["team"]} if key.get("team") else None
        return mcp_tools.Context(findings=lambda: scope_findings(load_findings(), user), assets=lambda: scope_assets(load_assets(), user),
                                 attack_chains=attack_chains, posture=posture, team=key.get("team"))

    @router.api_route("/mcp", methods=["POST", "GET", "DELETE", "PUT", "PATCH"], include_in_schema=False)
    async def mcp_endpoint(request: Request):
        deps.policy = mcp_policy.load()      # read fresh: an edited policy file applies on the next request
        headers = {k.lower(): v for k, v in request.headers.items()}
        refused = mcp_server.precheck(request.method, headers, request.url.query, deps)
        if refused:
            return _reply(refused)
        key, refused = mcp_server.authenticate(headers, request.client.host if request.client else "unknown", apikey_store.verify, deps)
        if refused:
            return _reply(refused)
        return _reply(mcp_server.handle_post(await request.body(), key, deps))

    @router.get("/api/mcp/status")
    def api_mcp_status(request: Request, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
        policy = mcp_policy.load()
        counts, per_tool = Counter(), Counter()
        for action in ("mcp.tool_call", "mcp.denied"):
            for e in activity_log.list_activity(action=action, limit=1000):
                counts[f"{action.split('.')[1]}:{(e['details'] or {}).get('outcome')}"] += 1
                if action == "mcp.tool_call":
                    per_tool[(e["details"] or {}).get("tool")] += 1
        return {"enabled": mcp_policy.endpoint_enabled(), "endpoint_url": str(request.base_url).rstrip("/") + "/mcp",
                "protocol_version": PROTOCOL_VERSION, "supported_versions": list(SUPPORTED_VERSIONS), "required_scope": "mcp:read",
                "side_effects": "none (every tool is read-only)",
                "tools": [{"name": t.name, "description": t.description, "extra_scopes": list(t.scopes), "team_bound_keys": not t.unscoped_only,
                           "enabled": mcp_policy.is_tool_enabled(t.name, policy)} for _, t in sorted(mcp_registry.TOOLS.items())],
                "limits": {k: policy[k] for k in ("max_result_bytes", "call_timeout_seconds", "rate_limit_calls", "rate_limit_window_seconds")},
                "recent_audit_counts": dict(counts), "recent_calls_by_tool": dict(per_tool), "audit_window": "the most recent 1000 entries of each kind"}

    return router
