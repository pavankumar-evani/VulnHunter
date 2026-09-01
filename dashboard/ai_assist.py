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


def build_trend_analysis_prompt(scope, stats):
    """Builds the prompt for /api/ai-trend-analysis - same pure-function, no-side-effect
    contract as build_ai_assist_prompt() above. `stats` is a flat dict of REAL,
    already-computed numbers the calling dashboard page passes in (severity/team/
    priority breakdowns, KPI totals, month-over-month first-seen counts, etc.) - this
    function only formats them into a prompt, it never invents or looks up data of its
    own. The instruction explicitly tells the model not to fabricate numbers beyond what
    was given, since a real, already-computed snapshot is genuinely all the grounding
    this call has - there is no live database/API access from inside the `claude -p`
    call this feeds into."""
    lines = [
        f"You are a security operations analyst reviewing a real, current snapshot of "
        f"{scope} security findings data from a vulnerability management dashboard "
        f"(not simulated, not historical - this is what the data looks like right now):",
        "",
    ]
    for key, value in stats.items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append(
        "Based ONLY on the real numbers above, write a concise (4-6 sentence) trend "
        "analysis: what stands out, which team/priority combination needs the most "
        "attention right now, and one concrete, specific recommendation. Do not invent "
        "any number not listed above. If asked to comment on a trend over time, use "
        "only whatever month-over-month figures were actually given, and say "
        "explicitly if the data provided doesn't support a longer-term trend claim - "
        "do not imply a trend the numbers don't actually show."
    )
    return "\n".join(lines)


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
