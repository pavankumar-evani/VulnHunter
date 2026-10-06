# Read-only MCP endpoint

Quanta can expose a small, read-only [Model Context Protocol](https://modelcontextprotocol.io) endpoint so an AI assistant (Claude Desktop, Claude Code, any MCP client) can answer questions such as
"which KEV findings are still open on our payment servers?" from Quanta's own data. It is built to the six controls usually asked of an MCP server.

## Turn it on

1. Set `QUANTA_MCP_ENABLED=true` and restart. Until then `/mcp` answers 404.
2. Connections page, *Create an API key*: tick **`mcp:read`** and **`read:findings`**. Optionally limit the key to one team.
3. Point the client at `https://<your-quanta>/mcp` with `Authorization: Bearer <key>`:

```json
{ "mcpServers": { "quanta": { "type": "http", "url": "https://quanta.example.com/mcp", "headers": { "Authorization": "Bearer qk_YOUR_KEY_HERE" } } } }
```

## Protocol implemented

MCP **2025-11-25** over Streamable HTTP, answering `initialize`, `ping`, `tools/list` and `tools/call` (and accepting `notifications/*` with 202). It also answers `2025-06-18` and `2025-03-26` clients. Replies are always a single JSON
object (no SSE stream, no server-initiated messages), there are no sessions (no `MCP-Session-Id`), `GET`/`DELETE` answer 405, and JSON-RPC batches are refused as the spec requires from 2025-06-18. Tool input errors come back as
`isError: true` results; an unknown tool is a `-32602` protocol error. Written by hand from modelcontextprotocol.io (the official SDK would add a dependency for a four-method server).

Not implemented: the newer **2026-07-28** revision, which drops `initialize` for per-request `_meta` and adds `server/discover`. Clients that only speak it will not connect yet. Resources, prompts, logging, SSE, resumability and OAuth are not offered.

## The six controls

| Control | How |
|---|---|
| 1. Authentication | Only a Quanta API key (`qk_...`) in the `Authorization: Bearer` header, carrying the new `mcp:read` scope. No anonymous access: `/mcp` is outside `/api/`, so the "public reads" default never applies, and a browser session does not count. A query string (a token in a URL) is refused outright; `X-API-Key` is not accepted. A browser `Origin` is refused unless listed (`allowed_origins` / `QUANTA_MCP_ALLOWED_ORIGINS`). Repeated failures from one address are throttled. |
| 2. Authorization | Checked on **every** `tools/call`, not at connect time: `mcp:read` plus the tool's own scope (all today need `read:findings`). `tools/list` shows a key only the tools it may call. A key bound to a team (set when creating it) sees only that team's findings and assets, the same filter the dashboard applies to a team member. Keys with no team see the whole estate, exactly as an unscoped `read:findings` export does. `posture_summary` reads deployment settings (administrator-only in the dashboard), so it refuses team-bound keys. A tool whose module the licence does not cover is refused in enforce mode. |
| 3. Tool scoping | Allowlist of read tools: `search_findings`, `get_finding`, `list_assets`, `kev_open_findings`, `top_priorities`, `attack_paths_for_asset`, `posture_summary`. Strict closed JSON schemas (bounded strings, integers, enums; extra arguments rejected). Output is a whitelist projection of each record (no raw records, no connector settings, no credentials, no user emails; strings are shortened and anything shaped like a key or password is masked), capped in size. `remediation/config/mcp_policy.yaml` lists the enabled tools. There is no write tool, no pipeline trigger and no tool that fetches a URL (so no zero-day-watch tool: it needs to call out to CISA). |
| 4. Sandboxing | Tools call the same in-process functions as the dashboard's read routes. No subprocess, no filesystem path or URL from input, no network egress. Per-key rate limit (60 calls/60 s default), a per-call timeout (10 s) and an output cap (60 000 bytes; lists are trimmed and marked `truncated`). |
| 5. Auditing | Every call writes to the activity log: actor `mcp:qk_<prefix>`, action `mcp.tool_call` (outcome `ok`, `truncated`, `invalid_arguments`, `not_found`, `timeout`, `error`, `result_too_large`) or `mcp.denied` (`unauthenticated`, `missing_scope`, `unknown_tool`, `tool_disabled`, `team_bound_key`, `unlicensed`, `rate_limited`), with a hash of the arguments, sizes and duration. Never the arguments, never a result body. If the log cannot be written the call is refused. Rate-limit and failed-sign-in denials are recorded once a minute so a flood cannot fill the log; unusual volume shows in `GET /api/mcp/status` and the activity log. There is no separate pager: wire the activity-log insights to your alerting. |
| 6. Human approval | Nothing here changes anything, so there is nothing to approve. This is enforced, not promised: `remediation.mcp.registry.register` raises for any tool whose `side_effect` is not `read`, and a test asserts every registered tool is read-only. Clients should still show the user each tool call, as the spec advises. |

### Prompt injection

Findings carry text written by scanners and people (titles, descriptions, asset names). That text can contain instructions aimed at the assistant. Every result is therefore marked `"_untrusted": true` with a notice, the
server's `instructions` say the same, and tool descriptions call results data. This reduces the risk; it cannot remove it. Keep the assistant's other tools (anything that writes) behind its own approval prompts.

## Admin view

`GET /api/mcp/status` (administrator): enabled flag, endpoint URL, tools and their scopes, limits, and recent audit counts by outcome. The Connections page shows the same plus the client snippet (placeholder key only).

## Honest limits

Written against the public spec and tested against its message shapes with Python's `TestClient`; **not yet exercised with a real MCP client**. The rate limiter and failed-sign-in throttle are in-process (per replica, not shared). A timed-out call is abandoned,
not killed (Python cannot kill a thread), so a slow tool keeps a worker busy until it finishes (pool of 4). Team binding uses the same team field as the dashboard. Wire size is up to about twice the cap because the result is sent as both text and `structuredContent`.
