"""
Quanta's read-only MCP (Model Context Protocol) endpoint.

Lets an AI assistant query Quanta's data in natural language through a small allowlist of read tools. Designed against six controls:
authentication (Quanta API key with scope `mcp:read`, nothing else), authorization on every tool call (scope + per-tool extra scope + team binding),
tool scoping (read-only allowlist, strict input schemas, trimmed and size-capped output), sandboxing (in-process calls to the same functions the read routes
use; no subprocess, no path or URL from input, per-key rate limit, per-call timeout), auditing (every call, denied ones included, into the activity log; never
result bodies) and human approval (nothing here can change anything, so there is nothing to approve; `registry.register` refuses any non-read tool).

Protocol: MCP revision 2025-11-25 over Streamable HTTP (JSON replies, no SSE, no sessions), also answering the two earlier revisions in `SUPPORTED_VERSIONS`.
See docs/MCP_ENDPOINT.md.
"""
PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
SERVER_NAME = "quanta"
