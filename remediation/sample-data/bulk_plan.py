#!/usr/bin/env python3
"""
Regenerates REMEDIATION_PLAN.md from remediation/output/normalized-findings.json at
the ~2,400-finding scale the bulk real-CVE data brings - the real remediation-planner
subagent took ~9.5 minutes of LLM reasoning for the original 15 findings; at 160x that
volume, an LLM-subagent pass is not tractable (time and context both), so this applies
remediation-planner.md's own documented decision rules (automation_target strictly from
remediation_domain, priority from severity+KEV+EPSS, risk_tier from asset criticality)
as a deterministic script instead.

Honesty note: action_type and risk_tier for the ORIGINAL 15 hand-curated findings (see
git history before this file existed) were individually reasoned about by a real
subagent - "service-disable" for EternalBlue because disabling SMBv1 is literally the
fix, not just "patch" as a generic default. This script cannot replicate that per-CVE
judgment across 2,400 bulk-sourced findings, and does not pretend to - it applies one
documented, disclosed heuristic uniformly (see ACTION_TYPE_RULES below), which is a
different, coarser thing than individual research. Said heuristic is disclosed at the
top of the generated plan, not hidden.

The full per-finding prose section only makes sense for a human to read at a much
smaller scale than 2,400 entries (each entry in the existing plan runs ~5-8 lines) - so
this script keeps that section to the top N findings by priority (configurable,
default 60) with an explicit note, while the compact queue table - the only part
dashboard/data.py's load_remediation_plan() actually parses - covers every finding.
"""
import argparse
import datetime
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FINDINGS_PATH = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
PLAN_PATH = REPO_ROOT / "REMEDIATION_PLAN.md"

AUTOMATION_SUPPORTED = {"windows-server": "ansible-windows", "unix-server": "ansible-unix"}

# Criticality keywords mirror remediation/config/priority_rules.yaml's own
# asset_criticality_keywords list, reused here so "risky asset -> more conservative
# risk tier" stays consistent between the live queue's priority score and this plan.
CRITICALITY_KEYWORDS = ("dc", "auth", "core", "bastion", "db")


def action_type_for(f):
    asset_type = (f.get("asset") or {}).get("type", "")
    has_cve = bool(f.get("cve"))
    if asset_type in ("windows-server", "unix-server"):
        return "patch" if has_cve else "config-change"
    if asset_type == "certificate":
        return "config-change"
    if asset_type == "application":
        return "patch" if has_cve else "config-change"  # SCA (has CVE) vs DAST (doesn't)
    if asset_type in ("network-routing-switching", "network-security-device", "cloud-infrastructure"):
        return "firmware-update" if has_cve else "config-change"
    if asset_type == "iot-ot-device":
        return "firmware-update" if has_cve else "manual-investigation"
    if asset_type == "client-application":
        return "patch" if has_cve else "manual-investigation"
    if asset_type == "iac-resource":
        return "config-change"  # a Terraform/CloudFormation attribute fix, not a patch
    if asset_type == "code-repository":
        return "patch" if has_cve else "config-change"  # dependency bump vs. credential rotation
    if asset_type == "container-runtime":
        return "manual-investigation"  # a behavioral detection alert, not a patchable CVE
    if asset_type == "ai-ml-system":
        return "manual-investigation"  # a prompt-injection/agent-design-shaped finding, not a patchable CVE
    if asset_type == "windows-endpoint":
        return "patch" if has_cve else "config-change"  # SCCM's own real job: OS/app patch deployment
    if asset_type == "mobile-device":
        return "patch" if has_cve else "manual-investigation"  # MDM-pushed OS update vs. a device-config review
    if asset_type == "printer":
        return "firmware-update"  # same physical-device convention as iot-ot-device/network gear
    if asset_type == "virtualization-host":
        return "patch" if has_cve else "config-change"  # hypervisor patch vs. host/vSwitch config hardening
    return "manual-investigation"


def automation_target_for(f):
    asset_type = (f.get("asset") or {}).get("type", "")
    return AUTOMATION_SUPPORTED.get(asset_type, "manual-only")


def risk_tier_for(f, automation_target):
    if automation_target == "manual-only":
        return "manual-only"
    asset_name = ((f.get("asset") or {}).get("name") or "").lower()
    if any(kw in asset_name for kw in CRITICALITY_KEYWORDS):
        return "needs-change-approval"
    return "auto-approvable"


def priority_for(f):
    """remediation-planner's OWN 3-tier High/Medium/Low scale - distinct from the live
    dashboard queue's Critical/High/Medium/Low (see remediation/config/priority_engine.py's
    module docstring for why these are two related but separate things)."""
    kev = f.get("kev")
    epss = f.get("epss")
    if kev and kev.get("listed"):
        return "High"
    if epss and epss.get("score", 0) >= 0.5:
        return "High"
    severity = f.get("severity", "Low")
    if severity in ("Critical", "High"):
        return "High"
    if severity == "Medium":
        return "Medium"
    return "Low"


def rationale_for(f, action_type, automation_target, risk_tier, priority):
    parts = []
    if priority == "High":
        kev = f.get("kev")
        epss = f.get("epss")
        if kev and kev.get("listed"):
            parts.append(f"escalated to High priority: actively exploited per CISA KEV since {kev.get('date_added')}")
        elif epss and epss.get("score", 0) >= 0.5:
            parts.append(f"escalated to High priority: EPSS {epss['score']:.1%} (near-term exploitation likelihood)")
        else:
            parts.append(f"High priority: {f.get('severity')} severity")
    else:
        parts.append(f"{priority} priority: {f.get('severity')} severity, no KEV/high-EPSS escalation")
    if automation_target == "manual-only":
        parts.append(f"manual-only: no remediation-fixer subagent exists yet for `{(f.get('asset') or {}).get('type')}`")
    elif risk_tier == "auto-approvable":
        parts.append("auto-approvable: well-understood single-finding fix on a non-critical-named asset")
    else:
        parts.append("needs-change-approval: asset name matches a criticality keyword (domain controller/auth/core/bastion/db-style)")
    return "; ".join(parts)


PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def build_plan(findings, detail_limit):
    planned = []
    for f in findings:
        action_type = action_type_for(f)
        automation_target = automation_target_for(f)
        risk_tier = risk_tier_for(f, automation_target)
        priority = priority_for(f)
        planned.append({
            **f,
            "action_type": action_type,
            "automation_target": automation_target,
            "risk_tier": risk_tier,
            "priority": priority,
            "rationale": rationale_for(f, action_type, automation_target, risk_tier, priority),
        })
    planned.sort(key=lambda f: (PRIORITY_ORDER.get(f["priority"], 3), -(f.get("cvss") or 0)))

    total = len(planned)
    automatable = [f for f in planned if f["automation_target"] != "manual-only"]
    manual_only = [f for f in planned if f["automation_target"] == "manual-only"]
    risk_counts = {}
    for f in planned:
        risk_counts[f["risk_tier"]] = risk_counts.get(f["risk_tier"], 0) + 1
    kev_count = sum(1 for f in planned if f.get("kev") and f["kev"].get("listed"))
    high_epss_count = sum(1 for f in planned if f.get("epss") and f["epss"].get("score", 0) >= 0.5)

    lines = []
    lines.append(f"# Remediation Plan — {total} findings")
    lines.append("")
    lines.append(f"**Automated remediation available today:** {len(automatable)} findings (windows-server + unix-server)")
    lines.append(f"**Manual-only (no fixer for this asset class yet):** {len(manual_only)} findings")
    lines.append("")
    lines.append(f"**Risk tier split:** {risk_counts.get('auto-approvable', 0)} auto-approvable · "
                 f"{risk_counts.get('needs-change-approval', 0)} needs-change-approval · "
                 f"{risk_counts.get('manual-only', 0)} manual-only")
    lines.append("")
    lines.append(f"**Threat intel:** {kev_count} findings are KEV-listed (confirmed actively exploited) and "
                 f"{high_epss_count} have an EPSS score ≥ 50%.")
    lines.append("")
    lines.append(f"**Scale note:** this plan now covers {total} findings ({total - 15} added via real-CVE bulk "
                 f"sourcing from NVD, see `remediation/sample-data/generate_bulk_findings.py`). `action_type` and "
                 f"`risk_tier` for the bulk-sourced majority come from one disclosed, uniform heuristic "
                 f"(`remediation/sample-data/bulk_plan.py`) rather than individual per-finding research - see that "
                 f"script's module docstring. The live, re-scored view at `/queue` remains the authoritative, "
                 f"always-current source; this file is the point-in-time snapshot `/remediate` shows.")
    lines.append("")
    lines.append("## Remediation queue (priority order)")
    lines.append("")
    lines.append("| ID | Asset | Title | CVE | Severity | Action Type | Automation Target | Risk Tier | KEV | EPSS |")
    lines.append("|----|-------|-------|-----|----------|-------------|--------------------|-----------|-----|------|")
    for f in planned:
        cve = f.get("cve") or "—"
        kev_cell = "Yes" if (f.get("kev") and f["kev"].get("listed")) else ("No" if f.get("cve") else "—")
        epss_cell = f"{f['epss']['score']:.1%}" if f.get("epss") else "—"
        title = (f.get("title") or "").replace("|", "\\|")
        asset_name = (f.get("asset") or {}).get("name", "")
        lines.append(f"| {f['id']} | {asset_name} | {title} | {cve} | {f.get('severity')} | "
                     f"{f['action_type']} | {f['automation_target']} | {f['risk_tier']} | {kev_cell} | {epss_cell} |")
    lines.append("")

    lines.append(f"## Per-finding detail (top {min(detail_limit, total)} by priority)")
    lines.append("")
    lines.append(f"Showing the {min(detail_limit, total)} highest-priority findings of {total} total - full detail "
                 f"for every finding at this scale would not be practically readable as a document; every finding "
                 f"is still in the queue table above, and in full (with live SLA/KEV/EPSS) at `/queue`.")
    lines.append("")
    for f in planned[:detail_limit]:
        asset = f.get("asset") or {}
        lines.append(f"### {f['id']} — {f.get('title')} — **{f.get('severity', '').upper()}**"
                     + (f" ({f['cve']})" if f.get("cve") else ""))
        lines.append(f"- Asset: {asset.get('name')} ({asset.get('type')})")
        lines.append(f"- Action: {f['action_type']} | Automation: {f['automation_target']} | Risk tier: {f['risk_tier']}")
        lines.append(f"- Rationale: {f['rationale']}")
        lines.append("")

    lines.append("## Findings with no automated remediation path today")
    lines.append("")
    by_type = {}
    for f in manual_only:
        t = (f.get("asset") or {}).get("type", "unknown")
        by_type.setdefault(t, []).append(f["id"])
    notes = {
        "network-routing-switching": "needs a `remediation-fixer-network` subagent generating vendor CLI config diffs",
        "network-security-device": "needs a `remediation-fixer-network` subagent generating vendor CLI config diffs",
        "iot-ot-device": "needs vendor-specific firmware tooling - no general-purpose fixer exists across IoT/OT vendors",
        "application": "needs a `remediation-fixer-application` subagent for library/dependency upgrades (SCA) or a code fix (DAST) - a different mechanism per language/package manager, unlike the OS-level fixers",
        "certificate": "needs integration with the org's CA/ACME tooling for renewal, and a TLS-config fixer for protocol/cipher hardening",
        "cloud-infrastructure": "needs a `remediation-fixer-cloud` subagent generating Terraform/CloudFormation/ARM diffs per provider",
        "client-application": "needs an endpoint-management/patch-deployment integration (e.g. Intune, SCCM, Jamf) to push app updates - different from the OS-level Ansible fixers",
        "iac-resource": "needs a `remediation-fixer-iac` subagent generating Terraform/CloudFormation diffs to correct the flagged resource attribute",
        "code-repository": "needs a `remediation-fixer-repo` subagent - bump the flagged dependency version via a PR for CVE-bearing (Dependabot-style) alerts, or purge history and rotate the credential for secret-scanning alerts; two different fix mechanisms under one asset type, same split `application`'s SCA/DAST distinction already documents",
        "container-runtime": "needs security-team triage - a runtime detection alert (Falco-style) flags anomalous in-container behavior, not a patchable CVE or a config drift; response is investigative, not automatable",
        "ai-ml-system": "needs AI/ML security team triage - a prompt-injection, agent-design, or model-supply-chain finding requires a design/code change specific to that system, not a general-purpose patch or config diff",
        "windows-endpoint": "needs a real SCCM/Microsoft Configuration Manager API integration to push the patch - `remediation_mechanism` names the real tool, but no working integration exists in this app yet",
        "mobile-device": "needs a real MDM API integration (e.g. Microsoft Intune) to push the OS/app update - `remediation_mechanism` names the real tool, but no working integration exists in this app yet",
        "printer": "needs vendor-specific firmware tooling (HP/Xerox/Canon/Lexmark/Ricoh each ship their own) - no general-purpose fixer exists across printer vendors, same reasoning as `iot-ot-device`",
        "virtualization-host": "needs a real vendor hypervisor-patching integration (e.g. VMware Update Manager's API) - `remediation_mechanism` names the real tool, but no working integration exists in this app yet",
    }
    for t, ids in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        note = notes.get(t, "no fixer subagent exists yet for this asset class")
        lines.append(f"- **{t}** ({len(ids)} findings) — {note}")
    lines.append("")

    return "\n".join(lines), {
        "total": total, "automatable": len(automatable), "manual_only": len(manual_only),
        "kev_count": kev_count, "high_epss_count": high_epss_count, "risk_counts": risk_counts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detail-limit", type=int, default=60)
    args = parser.parse_args()

    findings = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))
    plan_text, summary = build_plan(findings, args.detail_limit)
    PLAN_PATH.write_text(plan_text, encoding="utf-8")

    print(f"Planned {summary['total']} findings.")
    print(f"  Auto-remediable today: {summary['automatable']}  |  Manual-only: {summary['manual_only']}")
    print(f"  Risk tiers: {summary['risk_counts']}")
    print(f"  KEV-listed: {summary['kev_count']}  |  EPSS >= 50%: {summary['high_epss_count']}")
    print(f"Written to: {PLAN_PATH}")


if __name__ == "__main__":
    main()
