"""
Agent, MCP and AI-lifecycle rules.

Same finding shape as remediation/aisec/rules.py ({asset_id, asset, rule, owasp, severity, title, why, fix}, plus `atlas`), and the same discipline: a rule
fires on an explicit "no" recorded for the asset, never on a blank. A blank on a field a rule needs is listed by `unanswered()` as a gap.

  MCP001 authentication   MCP002 per-tool authorization   MCP003 tool scoping   MCP004 sandboxing   MCP005 secrets handling
  MCP006 audit log not immutable   MCP007 secrets in logs   MCP008 side-effect tool without human approval        (the six MCP controls)
  AGT001 unbounded loop   AGT002 persistent memory without provenance or poisoning controls
  AGT003 untrusted content can reach a side-effect tool with no approval (the prompt-injection-to-tool-call path)   AGT004 no observability
  AIDLC001 no prompt versioning   AIDLC002 no evaluation suite   AIDLC003 no rollback path   AIDLC004 big-bang rollout

Thresholds live in remediation/config/ai_security_rules.yaml. This module reads only what is recorded; it does not connect to a server or probe an agent.
"""
from pathlib import Path

import yaml

TRANSPORTS = ("stdio", "http")
AUTH = ("none", "api-key", "oauth2.1", "mtls")
SIDE_EFFECTS = ("read", "write", "external-send", "destructive", "financial")
CATEGORIES = ("code", "shell", "file", "network", "database", "other")
MEMORY = ("none", "session", "persistent")
EVAL_SUITES = ("none", "offline", "online", "both")
SERVER_TRI = ("token_audience_validated", "per_tool_authorization", "allowlisted_tools", "sandboxed", "egress_restricted", "secrets_mounted")
RELEASE_TRI = ("rollback_path", "canary", "shadow")
OBS_TRI = ("traces", "cost", "latency", "tool_failures")
AUDIT_TRI = ("immutable", "redacts_secrets")
AGENT_KINDS = ("agent", "application", "gateway")
CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "ai_security_rules.yaml"
DEFAULTS = {"max_exposed_tools": 10, "side_effects_requiring_approval": ["write", "external-send", "destructive", "financial"], "severe_side_effects": ["destructive", "financial"],
            "sandbox_categories": ["code", "shell", "file"],
            "sandbox_name_keywords": ["shell", "bash", "exec", "eval", "python", "code_interpreter", "terminal", "filesystem", "file_write", "write_file", "run_command"],
            "production_environments": ["production"], "max_steps_ceiling": 100}
SERVER_QUESTIONS = {
    "auth": "How does this MCP server authenticate callers (none, api-key, oauth2.1, mtls)?",
    "token_audience_validated": "Does this MCP server check that each token was issued for it (audience)?",
    "per_tool_authorization": "Does this MCP server authorise each tool call, not just the connection?",
    "allowlisted_tools": "Is the set of tools it exposes fixed by an allowlist?",
    "sandboxed": "Does this MCP server run in a sandbox (container, restricted user, no host access)?",
    "egress_restricted": "Is its outbound network access restricted to what it needs?",
    "secrets_mounted": "Are its credentials delivered as mounted secrets rather than in its arguments, config file or environment?"}
TOOL_QUESTIONS = {"side_effect": "What is the strongest effect of this tool (read, write, external-send, destructive, financial)?", "requires_approval": "Does a person approve each call of this tool?"}
ASSET_QUESTIONS = {
    "memory": "Does the agent keep memory (none, session, persistent)?", "memory_provenance": "Does persistent memory record where each entry came from?",
    "memory_poisoning_controls": "Is persistent memory validated, reviewable and expiring, so a poisoned entry can be found and removed?",
    "max_steps": "What is the most steps one agent run may take (0 for no limit)?", "budget_cap": "Is there a token or cost cap per run?",
    "prompt_versioning": "Are system prompts kept in version control with a recorded version per release?", "eval_suite": "Is there an evaluation suite (none, offline, online, both)?",
    "release.rollback_path": "Can a release be rolled back (prompt, model and tool configuration)?", "release.canary": "Are changes released to a small share of traffic first?",
    "release.shadow": "Are changes run in shadow mode against live traffic before release?",
    "audit_log.immutable": "Is the audit log append-only (cannot be edited or deleted by the agent's operators)?", "audit_log.redacts_secrets": "Does the audit log redact secrets and tokens?",
    "observability.traces": "Are agent runs traced step by step?", "observability.cost": "Is cost tracked per run?", "observability.latency": "Is latency tracked?",
    "observability.tool_failures": "Are tool failures tracked?"}
OWASP_AGENCY = "LLM06:2025 Excessive Agency"


def config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        loaded = {}
    return {**DEFAULTS, **{k: v for k, v in loaded.items() if k in DEFAULTS and v is not None}}


def server_tools(asset):
    """{server name: tools recorded for it}. A tool names its server in `server`; a tool naming none belongs to the one server when the asset has exactly one."""
    servers, tools = asset.get("mcp_servers") or [], asset.get("tools") or []
    out = {s["name"]: [t for t in tools if (t.get("server") or "").lower() == s["name"].lower()] for s in servers}
    if len(servers) == 1 and not out[servers[0]["name"]]:
        out[servers[0]["name"]] = [t for t in tools if not t.get("server")]
    return out


def is_exec_tool(tool, cfg=None):
    """A tool that runs code, a shell or touches files: by its recorded category, or (no category) by a keyword in its name."""
    cfg = cfg or config()
    cat = tool.get("category")
    if cat:
        return cat in cfg["sandbox_categories"]
    name = (tool.get("name") or "").lower()
    return any(k in name for k in cfg["sandbox_name_keywords"])


def _names(items, limit=5):
    names = [i if isinstance(i, str) else i["name"] for i in items]
    return ", ".join(names[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


def evaluate(asset, today=None, cfg=None):  # noqa: ARG001 - same signature as rules.evaluate
    cfg = cfg or config()
    a = asset
    tools, servers = a.get("tools") or [], a.get("mcp_servers") or []
    by_server = server_tools(a)
    sensitive = bool(set(a.get("data_classes") or []) & {"pii", "phi", "pci", "secrets", "proprietary"})
    prod = a.get("environment") in cfg["production_environments"]
    kind = a.get("kind")
    out = []

    def add(rule, owasp, atlas, sev, title, why, fix):
        out.append({"asset_id": a.get("id"), "asset": a["name"], "rule": rule, "owasp": owasp, "atlas": atlas, "severity": sev, "title": title, "why": why, "fix": fix})

    need_appr = cfg["side_effects_requiring_approval"]
    severe_fx = cfg["severe_side_effects"]
    side = [t for t in tools if t.get("side_effect") in need_appr]

    # ---- the six MCP controls
    remote = [s for s in servers if s.get("transport") == "http"]
    weak = [s for s in remote if s.get("auth") == "none"]
    if weak:
        add("MCP001", f"MCP control 1, authentication; {OWASP_AGENCY}", "AML.T0053", "High", "Remote MCP server without authentication",
            f"{_names(weak)} is reached over HTTP with no authentication, so anything that can reach it can call its tools.",
            "Set auth to oauth2.1 (or mtls) on each remote MCP server: require a bearer token on every request and reject requests with none.")
    noaud = [s for s in remote if s.get("auth") == "oauth2.1" and s.get("token_audience_validated") is False]
    if noaud:
        add("MCP001", f"MCP control 1, authentication; {OWASP_AGENCY}", "AML.T0053", "High", "MCP server accepts tokens not issued for it",
            f"{_names(noaud)} uses OAuth but does not check the token's audience, so a token stolen from or issued for another service works here (confused deputy).",
            "Validate the audience (resource) claim on every token and refuse tokens meant for another service; never pass a client's token on to another API.")
    keyed = [s for s in remote if s.get("auth") == "api-key"]
    if keyed:
        add("MCP001", "MCP control 1, authentication", "AML.T0053", "Medium", "Remote MCP server protected only by a static API key",
            f"{_names(keyed)} relies on a long-lived shared key: it cannot say which user a call is for, is not scoped, and a leaked key works until someone notices.",
            "Move to oauth2.1 with short-lived, audience-bound tokens, or mtls between a gateway and the server.")
    noauthz = [s for s in servers if s.get("per_tool_authorization") is False]
    if noauthz:
        risky = any(t.get("side_effect") in need_appr for s in noauthz for t in by_server[s["name"]]) or any(not by_server[s["name"]] for s in noauthz) and bool(side)
        add("MCP002", f"MCP control 2, per-tool authorization; {OWASP_AGENCY}", "AML.T0053", "High" if risky else "Medium", "MCP tool calls are not authorised one by one",
            f"{_names(noauthz)} checks who connected but not whether that caller may use each tool, so a client that can connect can call everything.",
            "Check the caller's scope against the tool on every call, and give each tool its own scope (read tools separate from write tools).")
    crowded = [(s, max(int(s.get("tool_count") or 0), len(by_server[s["name"]]))) for s in servers]
    crowded = [(s, n) for s, n in crowded if n > cfg["max_exposed_tools"]]
    if crowded:
        add("MCP003", f"MCP control 3, tool scoping; {OWASP_AGENCY}", "AML.T0053", "Medium", "MCP server exposes many tools",
            "; ".join(f"{s['name']} exposes {n} tools" for s, n in crowded) + f" (limit {cfg['max_exposed_tools']}). Each one is something a steered model can call, and a long tool list also makes the model choose worse.",
            "Expose only the tools this agent needs: split the server or filter its tool list, and set allowlisted_tools to true once the list is fixed.")
    loose = [s for s in servers if s.get("allowlisted_tools") is False and any(t.get("side_effect") in severe_fx for t in by_server[s["name"]])]
    if loose:
        add("MCP003", f"MCP control 3, tool scoping; {OWASP_AGENCY}", "AML.T0053", "High", "Destructive or financial tool exposed with no allowlist",
            f"{_names(loose)} exposes destructive or financial tools and its tool list is not fixed, so a new or renamed tool is available to the model the moment the server changes.",
            "Fix the tool list with an allowlist enforced at the gateway or client, and review any change to it.")
    unboxed = []
    for s in servers:
        execs = [t for t in by_server[s["name"]] if is_exec_tool(t, cfg)]
        if s.get("sandboxed") is False and (execs or s.get("transport") == "stdio"):
            unboxed.append(f"{s['name']} (no sandbox)")
        elif s.get("egress_restricted") is False and (execs or s.get("sandboxed") is False):
            unboxed.append(f"{s['name']} (unrestricted outbound network)")
    if unboxed:
        add("MCP004", f"MCP control 4, sandboxing; {OWASP_AGENCY}", "AML.T0053", "High", "MCP server that runs code or touches files is not isolated",
            "; ".join(unboxed) + ". Code, shell and file tools run with the server's own rights, so injected instructions become commands on that host, and open egress lets data leave.",
            "Run the server in a container or VM with a non-root user, a read-only file system except a scratch directory, no host mounts, and an egress allowlist; set sandboxed and egress_restricted to true.")
    unmounted = [s for s in servers if s.get("secrets_mounted") is False]
    if unmounted:
        add("MCP005", "MCP control 4, secrets handling; LLM07:2025 System Prompt Leakage", "AML.T0053", "Medium", "MCP server credentials are not mounted as secrets",
            f"{_names(unmounted)} receives its credentials in arguments, config files or the environment, where process listings, logs and the model's own context can reveal them.",
            "Deliver credentials as mounted secret files or from a vault the server reads at start, never in command-line arguments or the prompt; set secrets_mounted to true.")
    audit = a.get("audit_log") or {}
    has_tools = bool(tools or servers or a.get("can_take_actions") is True)
    if has_tools and audit.get("immutable") is False:
        add("MCP006", f"MCP control 5, auditing; {OWASP_AGENCY}", "AML.T0053", "High" if (prod and side) else "Medium", "Tool-call audit log can be altered",
            "An audit log that the people or the agent operating the system can edit cannot be relied on after an incident.",
            "Send tool calls and decisions to an append-only store (object-lock bucket, WORM storage or a separate log account) and set audit_log.immutable to true.")
    if has_tools and audit.get("redacts_secrets") is False:
        add("MCP007", "MCP control 5, auditing; LLM02:2025 Sensitive Information Disclosure", "AML.T0057", "High", "Secrets and tokens appear in the audit log",
            "Logs of prompts and tool arguments copy API keys, tokens and personal data into a place with wider access and longer retention than the secret itself.",
            "Redact tokens, keys and the data classes the system handles before a record is written, and set audit_log.redacts_secrets to true.")
    noappr = [t for t in side if t.get("requires_approval") is False]
    if noappr:
        add("MCP008", f"MCP control 6, human approval; {OWASP_AGENCY}", "AML.T0053", "Critical" if any(t["side_effect"] in severe_fx for t in noappr) else "High", "Tool that changes things runs without a person's approval",
            f"{_names(noappr)} can write, send data out, delete or move money, and a call is made without anyone confirming it, so one steered step is a completed action.",
            "Set requires_approval to true on each of these tools and have the client show the person the exact call before it runs; keep approval-free tools read-only.")

    # ---- agent harness
    if kind == "agent" or (kind in AGENT_KINDS and a.get("can_take_actions") is True):
        ms, cap = a.get("max_steps"), a.get("budget_cap")
        if ms == 0 and cap is False:
            add("AGT001", f"LLM10:2025 Unbounded Consumption; {OWASP_AGENCY}", "AML.T0034", "High", "Agent loop has no step limit and no budget",
                "A loop that can run until it decides to stop can run forever on a confused or manipulated goal, spending without limit and repeating an action many times.",
                "Set max_steps to a small number the task needs (and stop with a clear message when it is reached) and set a per-run token or cost cap.")
        elif (ms == 0 and cap is not True) or (cap is False and ms is None):
            add("AGT001", f"LLM10:2025 Unbounded Consumption; {OWASP_AGENCY}", "AML.T0034", "Medium", "Agent loop is missing a step limit or a budget",
                "One of the two limits on a run is recorded as absent and the other is not recorded as in place, so a run can still grow without bound.", "Record and enforce both: max_steps for the run and a budget cap per run.")
        elif isinstance(ms, int) and ms > cfg["max_steps_ceiling"]:
            add("AGT001", "LLM10:2025 Unbounded Consumption", "AML.T0034", "Low", "Agent step limit is very high", f"{ms} steps per run is above the {cfg['max_steps_ceiling']} the policy treats as bounded.", "Lower max_steps to what the task needs.")
    if a.get("memory") == "persistent" and (a.get("memory_provenance") is False or a.get("memory_poisoning_controls") is False):
        miss = [lbl for f, lbl in (("memory_provenance", "does not record where entries came from"), ("memory_poisoning_controls", "has no validation, review or expiry")) if a.get(f) is False]
        add("AGT002", "LLM04:2025 Data and Model Poisoning; LLM01:2025 Prompt Injection", "AML.T0051", "High" if (a.get("can_take_actions") is True or bool(tools)) else "Medium",
            "Persistent agent memory can be poisoned", "Persistent memory " + " and ".join(miss) + ". One injected instruction saved to memory is read back as trusted on every later run, and nobody can tell which entry to remove.",
            "Store the source and time with each memory entry, never write instructions from untrusted content into memory, review or expire entries, and set memory_provenance and memory_poisoning_controls to true.")
    untrusted = [src for src in ("untrusted_input", "uses_rag") if a.get(src) is True] + (["a data source recorded as untrusted"] if any(d.get("trusted") is False for d in a.get("data_sources") or []) else [])
    if untrusted and noappr:
        exfil = any(t["side_effect"] == "external-send" for t in noappr)
        sev = "Critical" if any(t["side_effect"] in severe_fx or t["side_effect"] == "external-send" for t in noappr) else "High"
        add("AGT003", f"LLM01:2025 Prompt Injection; {OWASP_AGENCY}", "AML.T0051", sev, "Untrusted content can drive a side-effect tool with no approval",
            f"Content from outside your control ({', '.join(u.replace('_', ' ') for u in untrusted)}) reaches an agent that can call {_names(noappr)} without a person's approval. "
            "Text hidden in a page, document or email can tell the model to call the tool, and nothing stops it." + (" The tool sends data out, so with sensitive data in reach this is a data-theft path." if exfil and sensitive else ""),
            "Require approval on each side-effect tool this agent can call (requires_approval true), or take the tool away from agents that read untrusted content; keep the reader of outside content and the agent that acts on your systems separate.")
    obs = a.get("observability") or {}
    blind = [k.replace("_", " ") for k in OBS_TRI if obs.get(k) is False]
    if blind and kind in AGENT_KINDS and (kind == "agent" or has_tools):
        add("AGT004", f"LLM10:2025 Unbounded Consumption; {OWASP_AGENCY}", "AML.T0034", "Medium" if prod else "Low", "Agent runs are not fully observable",
            f"Not tracked: {', '.join(blind)}. Without step traces, cost and tool-failure tracking, a looping, manipulated or failing agent is found by the bill or a user complaint.",
            "Trace every run step by step, and track cost, latency and tool failures per run with an alert; set the observability fields to true once they are.")

    # ---- AI development lifecycle in production
    if kind in AGENT_KINDS:
        sev_p = "Medium" if prod else "Low"
        if a.get("prompt_versioning") is False:
            add("AIDLC001", "NIST SP 800-218A PW.1; LLM07:2025 System Prompt Leakage", "AML.T0051", sev_p, "System prompts are not versioned",
                "A prompt edited in place cannot be reviewed, compared or restored, and a behaviour change cannot be tied to the change that caused it.", "Keep prompts in version control, review changes like code and record the prompt version with each release.")
        if a.get("eval_suite") == "none":
            add("AIDLC002", "NIST SP 800-218A PW.8; LLM09:2025 Misinformation", "AML.T0051", "High" if (prod and (a.get("can_take_actions") is True or a.get("high_stakes_use") is True)) else "Medium",
                "No evaluation suite", "Without tests for quality and for injection and misuse cases, a prompt, model or tool change is released on hope.",
                "Build an offline suite that runs on every change (include injection and tool-misuse cases), then add online sampling; set eval_suite to offline, online or both.")
        rel = a.get("release") or {}
        if rel.get("rollback_path") is False:
            add("AIDLC003", f"NIST SP 800-218A PW.9; {OWASP_AGENCY}", "AML.T0053", "High" if prod else "Medium", "No way to roll back a release",
                "If a prompt, model or tool change misbehaves in production there is no quick, tested way to return to the last good version.", "Keep the previous prompt, model id and tool configuration deployable, and rehearse switching back.")
        if rel.get("canary") is False and rel.get("shadow") is False:
            add("AIDLC004", "NIST SP 800-218A PW.9", "AML.T0051", sev_p, "Changes go out to everyone at once",
                "Neither canary nor shadow release is used, so a regression reaches all users and all tool calls at the same moment.",
                "Release to a small share first (canary) or run the new version beside the old one without acting (shadow), and widen only after the evals and traces look right.")
    return out


def unanswered(asset):
    """Gaps for the new fields, only for what the record has begun to describe, so existing records do not suddenly list questions that were never asked. [(field, question)]"""
    a = asset
    gaps = []
    for s in a.get("mcp_servers") or []:
        if s.get("auth") is None:
            gaps.append((f"mcp_servers.{s['name']}.auth", f"{s['name']}: {SERVER_QUESTIONS['auth']}"))
        for f in SERVER_TRI:
            if s.get(f) is None and (f != "token_audience_validated" or (s.get("transport") == "http" and s.get("auth") == "oauth2.1")):
                gaps.append((f"mcp_servers.{s['name']}.{f}", f"{s['name']}: {SERVER_QUESTIONS[f]}"))
    for t in a.get("tools") or []:
        for f in ("side_effect", "requires_approval"):
            if t.get(f) is None:
                gaps.append((f"tools.{t['name']}.{f}", f"{t['name']}: {TOOL_QUESTIONS[f]}"))
    if a.get("tools") or a.get("mcp_servers"):
        for k in AUDIT_TRI:
            if (a.get("audit_log") or {}).get(k) is None:
                gaps.append((f"audit_log.{k}", ASSET_QUESTIONS[f"audit_log.{k}"]))
    if a.get("kind") == "agent" and (a.get("tools") or a.get("mcp_servers") or a.get("memory")):
        for f in ("max_steps", "budget_cap"):
            if a.get(f) is None:
                gaps.append((f, ASSET_QUESTIONS[f]))
    if a.get("memory") == "persistent":
        for f in ("memory_provenance", "memory_poisoning_controls"):
            if a.get(f) is None:
                gaps.append((f, ASSET_QUESTIONS[f]))
    return gaps
