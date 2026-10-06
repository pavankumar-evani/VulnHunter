"""The tool registry. The one rule enforced at registration: a tool's `side_effect` must be "read". Anything else raises, so a write-capable tool cannot be added by accident."""
from dataclasses import dataclass
from typing import Callable

from remediation.mcp import schema as schema_mod

TOOLS = {}


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable
    scopes: tuple = ()               # extra API-key scopes needed on top of mcp:read
    side_effect: str = "read"
    list_keys: tuple = ("items",)    # result lists that may be trimmed to fit the size cap
    unscoped_only: bool = False      # refused for a key bound to a team (the data cannot be team-scoped)
    license_path: str = "/api/findings"
    title: str = ""


def register(tool, registry=None):
    registry = TOOLS if registry is None else registry
    if tool.side_effect != "read":
        raise ValueError(f"tool '{tool.name}': only read tools may be registered (side_effect={tool.side_effect!r})")
    if not tool.name.replace("_", "").isalnum() or len(tool.name) > 64:
        raise ValueError("invalid tool name")
    if tool.name in registry:
        raise ValueError(f"tool '{tool.name}' is already registered")
    schema_mod.check_schema(tool.input_schema)
    registry[tool.name] = tool
    return tool


def descriptor(tool):
    """The tools/list entry for a tool."""
    return {"name": tool.name, "title": tool.title or tool.name, "description": tool.description, "inputSchema": tool.input_schema,
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}}
