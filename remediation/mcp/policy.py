"""MCP policy: whether the endpoint is on (env QUANTA_MCP_ENABLED, default off), which tools are enabled and the limits (remediation/config/mcp_policy.yaml)."""
import os
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "mcp_policy.yaml"
DEFAULTS = {"enabled_tools": "all", "max_result_bytes": 60000, "max_request_bytes": 65536, "call_timeout_seconds": 10,
            "rate_limit_calls": 60, "rate_limit_window_seconds": 60, "allowed_origins": []}


def endpoint_enabled():
    return os.environ.get("QUANTA_MCP_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def load(path=None):
    p = Path(path or POLICY_PATH)
    data = {}
    if p.exists():
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out = {**DEFAULTS, **{k: v for k, v in data.items() if k in DEFAULTS}}
    for k in ("max_result_bytes", "max_request_bytes", "call_timeout_seconds", "rate_limit_calls", "rate_limit_window_seconds"):
        out[k] = max(1, int(out[k]))
    extra = os.environ.get("QUANTA_MCP_ALLOWED_ORIGINS", "").split(",")
    out["allowed_origins"] = [o.strip().rstrip("/") for o in list(out["allowed_origins"] or []) + extra if o.strip()]
    return out


def is_tool_enabled(name, policy):
    enabled = policy["enabled_tools"]
    return enabled == "all" or name in (enabled or [])
