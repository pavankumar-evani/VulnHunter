"""
Closed-loop verification for the /remediate side: did a triggered remediation actually
close the finding?

Until now the only loop-closing check was the code-scan one (vuln-verifier). For
infrastructure findings an approval stopped at "remediation_triggered" - the honest
ceiling of what the app knows, because Quanta never executes a fix itself. This module
adds the missing second half by reading the next scan: after a remediation is triggered,
the finding either keeps being reported (the fix did not hold, or has not been applied),
stops being reported (very likely fixed), or has simply not been rescanned yet.

States, per triggered approval:
  verified            - finding no longer present in the latest scan
  still-present       - finding present and last seen ON/AFTER the trigger date
                        (a scan ran after the fix was due and still saw it)
  awaiting-rescan     - finding present but last seen BEFORE the trigger date
                        (no scan has run since; nothing can be concluded)
  not-triggered       - approval has not reached remediation_triggered

Honest limits, stated rather than hidden: "verified" means "no longer reported", which
also happens if the asset left scan scope or the finding id was renumbered by a later
ingest - so it is evidence, not proof, and is labelled that way in the UI. A finding id
that vanished is matched by id only (the approvals table stores no fingerprint).
"""
import datetime


def _date(value):
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def verify_approval(approval, findings_by_id):
    if approval.get("status") != "remediation_triggered":
        return {"state": "not-triggered", "detail": "Remediation has not been triggered yet."}
    triggered = _date(approval.get("triggered_at"))
    finding = findings_by_id.get(approval.get("finding_id"))
    if finding is None:
        return {"state": "verified", "detail": "No longer reported in the latest scan. Evidence the fix held; "
                                               "also consistent with the asset leaving scan scope."}
    last_seen = _date(finding.get("last_seen"))
    if triggered and last_seen and last_seen >= triggered:
        return {"state": "still-present", "last_seen": finding.get("last_seen"),
                "detail": f"Still reported (last seen {finding.get('last_seen')}) after the fix was triggered "
                          f"on {approval.get('triggered_at')}."}
    return {"state": "awaiting-rescan", "last_seen": finding.get("last_seen"),
            "detail": "No scan has run since the fix was triggered; nothing can be concluded yet."}


def verify_all(approvals, findings):
    by_id = {f.get("id"): f for f in findings}
    out = []
    for a in approvals:
        v = verify_approval(a, by_id)
        out.append({"approval_id": a["id"], "finding_id": a["finding_id"], **v})
    summary = {s: 0 for s in ("verified", "still-present", "awaiting-rescan", "not-triggered")}
    for v in out:
        summary[v["state"]] += 1
    return {"results": out, "summary": summary}


def evidence_pack(approval, finding, playbook_content, lint, verification):
    """One self-contained, audit-ready record of a remediation: what was found, what was
    approved, the artifact that was reviewed, whether it passed lint, and the outcome."""
    return {
        "approval": {k: approval.get(k) for k in (
            "id", "finding_id", "status", "requested_by", "approved_by", "approved_at", "triggered_by",
            "triggered_at", "decision_reason", "staging_validated_by")},
        "finding": ({k: finding.get(k) for k in ("id", "title", "cve", "severity", "asset", "first_seen", "last_seen")}
                    if finding else None),
        "playbook": {"content": playbook_content, "lint": lint} if playbook_content is not None else None,
        "verification": verification,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _days(a, b):
    a, b = _date(a), _date(b)
    return (b - a).days if a and b else None


def outcome_metrics(approvals, verification_results):
    """Baseline-first outcome metrics from real approval history: how long a request took
    to reach each stage, and how often a triggered fix held. Every figure is None when
    there is no data behind it - never a modelled or invented number."""
    def avg(vals):
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    decided = [a for a in approvals if a.get("approved_at")]
    triggered = [a for a in approvals if a.get("triggered_at")]
    by_state = {v["approval_id"]: v["state"] for v in verification_results}
    assessed = [a for a in triggered if by_state.get(a["id"]) in ("verified", "still-present")]
    held = [a for a in assessed if by_state[a["id"]] == "verified"]
    return {
        "requests": len(approvals),
        "approved": len(decided),
        "triggered": len(triggered),
        "avg_days_request_to_approval": avg([_days(a.get("created_on"), a.get("approved_at")) for a in decided]),
        "avg_days_request_to_trigger": avg([_days(a.get("created_on"), a.get("triggered_at")) for a in triggered]),
        "assessed_after_rescan": len(assessed),
        "fix_hold_rate": round(len(held) / len(assessed), 2) if assessed else None,
    }
