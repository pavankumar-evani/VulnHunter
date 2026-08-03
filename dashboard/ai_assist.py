"""
AI-assist prompt construction for the dashboard's /api/ai-assist endpoint.

Deliberately has no subprocess/network code of its own - dashboard/app.py owns actually
invoking the real `claude` CLI (reusing cli/vulnhunter.py's binary-discovery logic), the
same dry-run-preview-by-default / explicit-confirm-to-spend pattern as /api/run and
/api/servicenow/send. This module only builds the prompt text, so it's testable without
ever touching a subprocess or spending API usage.
"""

ACTIONS = ("explain", "remediate", "summarize")

_ASK_BY_ACTION = {
    "explain": (
        "Explain, in plain English for a non-security-expert stakeholder, what this "
        "vulnerability means and what an attacker could actually do with it."
    ),
    "remediate": (
        "Suggest concrete, specific remediation steps for this finding, ordered by "
        "priority, suitable for an infrastructure engineer to follow."
    ),
    "summarize": (
        "Write a 2-3 sentence executive summary of this finding suitable for a status "
        "report."
    ),
}


def build_ai_assist_prompt(finding, action):
    """Builds the exact prompt text that would be sent to `claude -p`. Pure function -
    same finding + action always produces the same prompt, no side effects."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown action: {action!r} (must be one of {ACTIONS})")

    asset = finding.get("asset") or {}
    context_lines = [
        f"Finding {finding.get('id', 'unknown')}: {finding.get('title', 'untitled')}",
        f"Asset: {asset.get('name', 'unknown')} ({asset.get('type', 'unknown')})",
        f"CVE: {finding.get('cve') or 'N/A'}",
        f"Severity: {finding.get('severity', 'unknown')}",
    ]
    if finding.get("description"):
        context_lines.append(f"Description: {finding['description']}")

    context = "\n".join(context_lines)
    ask = _ASK_BY_ACTION[action]
    return (
        f"{context}\n\n{ask}\n\n"
        "Respond with plain text only, no markdown headers or bullet asterisks, "
        "concise (under 150 words)."
    )
