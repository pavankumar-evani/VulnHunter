"""
AI security posture: the OWASP Top 10 for LLM Applications (2025) and agent/MCP hygiene, applied to what you record about each AI system.

This does not probe a model or an endpoint. It reads the facts you record about each AI asset (what it can do, what it is exposed to, which defences
are in place, where the model came from) and applies explicit rules. A fact you have not answered is "unknown", never assumed safe or unsafe: a
rule fires on an explicit "no", and the unanswered questions that would let a rule decide are listed as gaps so the record can be completed.

Rule ids follow the OWASP LLM Top 10 (2025) numbering:
  LLM01 Prompt injection        LLM02 Sensitive information disclosure   LLM03 Supply chain          LLM04 Data and model poisoning
  LLM05 Improper output handling   LLM06 Excessive agency   LLM07 System prompt leakage   LLM08 Vector and embedding weaknesses
  LLM09 Misinformation          LLM10 Unbounded consumption
plus MCP (Model Context Protocol server) exposure and governance (owner, review, logging, approved models).
"""
import datetime
from pathlib import Path

import yaml

from remediation.aisec import rules_mcp

KINDS = ("application", "agent", "model", "mcp-server", "vector-db", "dataset", "gateway", "plugin")
ENVIRONMENTS = ("production", "staging", "development")
HOSTING = ("vendor-api", "self-hosted", "on-device", "unknown")
SCOPES = ("none", "read", "write", "admin")
PROVENANCE = ("verified", "unverified", "unknown", "not-applicable")
SERIALIZATION = ("safetensors", "gguf", "onnx", "pickle", "unknown", "not-applicable")
DATA_CLASSES = ("pii", "phi", "pci", "secrets", "proprietary", "public")
SENSITIVE = {"pii", "phi", "pci", "secrets", "proprietary"}
TRI = ("untrusted_input", "internet_facing", "auth_required", "can_take_actions", "human_in_loop", "high_stakes_use", "downstream_trusts_output", "input_guardrails", "output_filtering",
       "rate_limited", "logging", "secrets_in_prompt", "plugins_reviewed", "training_data_validated", "fine_tuned", "uses_rag", "rag_access_control")
QUESTIONS = {
    "untrusted_input": "Does it process input from outside your control (users, web pages, documents, email)?",
    "internet_facing": "Can it be reached from the internet?", "auth_required": "Does it require authentication?",
    "can_take_actions": "Can it take actions (call tools, change data, send messages)?", "human_in_loop": "Does a person approve its consequential actions?",
    "high_stakes_use": "Is its output used for decisions with legal, financial, safety or medical consequences?", "downstream_trusts_output": "Is its output passed to other systems or code without being validated?",
    "input_guardrails": "Is there input filtering or prompt-injection defence?", "output_filtering": "Is its output filtered for sensitive data?", "rate_limited": "Are requests rate limited or budgeted?",
    "logging": "Are prompts and actions logged for audit?", "secrets_in_prompt": "Do system prompts or tool configuration contain secrets?", "plugins_reviewed": "Were its plugins and tools reviewed?",
    "training_data_validated": "Is training or fine-tuning data validated?", "fine_tuned": "Is it fine-tuned or trained on your data?", "uses_rag": "Does it retrieve from a document or vector store?",
    "rag_access_control": "Does retrieval respect each user's access to the documents?"}
SEV_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
POLICY = Path(__file__).resolve().parent.parent / "config" / "ai_usage_policy.yaml"


def approved_models():
    try:
        with open(POLICY, encoding="utf-8") as fh:
            return [m.lower() for m in ((yaml.safe_load(fh) or {}).get("allowed_models") or [])]
    except OSError:
        return []


def _days_since(d, today):
    try:
        return (today - datetime.date.fromisoformat(str(d)[:10])).days
    except ValueError:
        return None


def evaluate(asset, today=None, approved=None):
    """Findings for one asset: [{rule, owasp, severity, title, why, fix}]."""
    today = today or datetime.date.today()
    a = asset
    classes = set(a.get("data_classes") or [])
    sensitive = bool(classes & SENSITIVE)
    out = []

    def add(rule, owasp, sev, title, why, fix):
        out.append({"asset_id": a.get("id"), "asset": a["name"], "rule": rule, "owasp": owasp, "severity": sev, "title": title, "why": why, "fix": fix})

    kind = a.get("kind")
    acts, hil, scope = a.get("can_take_actions"), a.get("human_in_loop"), a.get("permissions_scope")
    if kind in ("application", "agent", "gateway") and a.get("untrusted_input") is True and a.get("input_guardrails") is False:
        add("LLM01", "LLM01:2025 Prompt Injection", "High" if (acts is True or sensitive) else "Medium", "Untrusted input reaches the model with no injection defence",
            "Text from users, pages or documents can carry instructions the model follows, redirecting it or exfiltrating data.",
            "Treat all model input as untrusted: separate instructions from data, filter and constrain input, and never let the model's output authorise an action by itself.")
    if sensitive and a.get("output_filtering") is False:
        add("LLM02", "LLM02:2025 Sensitive Information Disclosure", "Critical" if (a.get("internet_facing") is True and a.get("auth_required") is False) else "High",
            "Sensitive data can leave through the model's output", f"It handles {', '.join(sorted(classes & SENSITIVE))} and its output is not filtered.",
            "Filter outputs for the data classes involved, minimise what reaches the model, and require authentication.")
    if a.get("provenance") == "unverified":
        add("LLM03", "LLM03:2025 Supply Chain", "High", "Model or component of unverified origin", "A model or package fetched without a checked source or hash can carry a backdoor.",
            "Pull models from a registry you control, pin and verify hashes or signatures, and record the source.")
    if a.get("serialization") == "pickle":
        add("LLM03", "LLM03:2025 Supply Chain", "High", "Model stored in pickle format", "Loading a pickle file can run arbitrary code.", "Convert to safetensors (or another non-executable format) and load only from trusted sources.")
    if a.get("plugins_reviewed") is False:
        add("LLM03", "LLM03:2025 Supply Chain", "Medium", "Plugins or tools were not reviewed", "Each tool is code and permissions the model can use.", "Review each plugin's code, permissions and publisher before enabling it.")
    if (a.get("fine_tuned") is True or kind == "dataset") and a.get("training_data_validated") is False:
        add("LLM04", "LLM04:2025 Data and Model Poisoning", "Medium", "Training or fine-tuning data is not validated", "Poisoned examples change what the model does and are hard to spot afterwards.",
            "Track data lineage, validate and sample what goes in, and test the model for behaviour changes before release.")
    if a.get("downstream_trusts_output") is True:
        add("LLM05", "LLM05:2025 Improper Output Handling", "High" if acts is True else "Medium", "Output is trusted by other systems without validation",
            "Model output used as code, queries or commands is an injection path.", "Validate and encode output for where it goes (parameterised queries, schemas, allow-lists); never execute it directly.")
    if acts is True and hil is False:
        sev = "Critical" if scope == "admin" else "High" if scope == "write" else "Medium"
        add("LLM06", "LLM06:2025 Excessive Agency", sev, "Acts without a person's approval" + (f" with {scope} permissions" if scope in ("write", "admin") else ""),
            "A model that can act and is steered wrongly acts wrongly at machine speed.", "Give it the narrowest permissions, require approval for consequential or irreversible actions, and log every action.")
    if a.get("secrets_in_prompt") is True:
        add("LLM07", "LLM07:2025 System Prompt Leakage", "High", "Secrets are placed in prompts or tool configuration", "System prompts can be extracted, and everything in them with them.",
            "Move secrets to a vault the tool code reads; assume the prompt is public.")
    if a.get("uses_rag") is True and a.get("rag_access_control") is False:
        add("LLM08", "LLM08:2025 Vector and Embedding Weaknesses", "High" if sensitive else "Medium", "Retrieval ignores who may see each document",
            "Anyone who can ask can be answered from documents they could not open.", "Enforce per-document permissions at retrieval time and keep tenants in separate indexes.")
    if kind == "vector-db" and a.get("auth_required") is False:
        add("LLM08", "LLM08:2025 Vector and Embedding Weaknesses", "High", "Vector store without authentication", "Embeddings can be read back into the text they came from.", "Require authentication and network restriction on the store.")
    if a.get("high_stakes_use") is True and hil is False:
        add("LLM09", "LLM09:2025 Misinformation", "Medium", "High-stakes use with no human review", "Models state wrong things confidently.", "Require review of outputs used for consequential decisions and cite sources.")
    if a.get("internet_facing") is True and a.get("rate_limited") is False:
        add("LLM10", "LLM10:2025 Unbounded Consumption", "Medium", "No rate limit or budget on an exposed endpoint", "Unbounded use means unbounded cost, denial of service and model extraction.", "Rate limit per identity, cap tokens per request, and set spend alerts.")
    if kind == "mcp-server":
        if a.get("auth_required") is False:
            add("MCP", "MCP server exposure", "Critical" if a.get("internet_facing") is True else "High", "MCP server without authentication", "Any client that can reach it can call its tools.", "Require authentication and authorisation per tool, and bind it to localhost or a private network unless it must be remote.")
        elif a.get("internet_facing") is True:
            add("MCP", "MCP server exposure", "High", "MCP server reachable from the internet", "Tools exposed to the internet widen what a stolen token can do.", "Keep it on a private network or behind a gateway with strong authentication and per-tool scopes.")
    if not a.get("owner"):
        add("GOV", "Governance", "Medium", "No owner recorded", "Nobody is accountable for reviewing or retiring it.", "Name an owner.")
    rev = _days_since(a.get("last_reviewed"), today)
    if rev is None or rev > 180:
        add("GOV", "Governance", "Low", "Not reviewed in the last 180 days" if rev is not None else "Never reviewed", "Capabilities and exposure drift.", "Review it and record the date.")
    if a.get("logging") is False and a.get("environment") == "production":
        add("GOV", "Governance", "Medium", "No audit logging in production", "Without logs, misuse cannot be investigated.", "Log prompts, tool calls and decisions (mind retention of personal data).")
    allowed = approved if approved is not None else approved_models()
    vm = (a.get("vendor_model") or "").lower()
    if allowed and vm and kind in ("application", "agent", "model", "gateway") and not any(m in vm or vm in m for m in allowed):
        add("GOV", "Governance", "Medium", "Model is not on the approved list", f"'{a.get('vendor_model')}' is not in ai_usage_policy.yaml's allowed_models.", "Move to an approved model or have this one reviewed and added.")
    out += rules_mcp.evaluate(a, today)
    return out


def unanswered(asset):
    """Questions whose answers would let a rule decide, that are still unknown. [(field, question)]"""
    a, kind = asset, asset.get("kind")
    relevant = {"application": ["untrusted_input", "can_take_actions", "human_in_loop", "input_guardrails", "output_filtering", "rate_limited", "logging", "internet_facing", "auth_required", "uses_rag"],
                "agent": ["untrusted_input", "can_take_actions", "human_in_loop", "input_guardrails", "output_filtering", "logging", "downstream_trusts_output", "secrets_in_prompt", "plugins_reviewed"],
                "model": ["fine_tuned", "training_data_validated"], "mcp-server": ["auth_required", "internet_facing", "human_in_loop", "can_take_actions", "logging"],
                "vector-db": ["auth_required", "internet_facing"], "dataset": ["training_data_validated"], "gateway": ["rate_limited", "logging", "input_guardrails", "output_filtering", "internet_facing", "auth_required"],
                "plugin": ["plugins_reviewed"]}.get(kind, [])
    if a.get("uses_rag") is True:
        relevant = relevant + ["rag_access_control"]
    if a.get("fine_tuned") is True:
        relevant = relevant + ["training_data_validated"]
    return [(f, QUESTIONS[f]) for f in dict.fromkeys(relevant) if a.get(f) is None] + rules_mcp.unanswered(a)


def score(findings):
    return sum(SEV_WEIGHT[f["severity"]] for f in findings)
