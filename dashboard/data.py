"""
Reads VulnHunter's real generated artifacts (git history for /vulnhunt, files under
remediation/ for /remediate) and shapes them for the dashboard templates.

Deliberately has no pipeline logic of its own - it only parses what vuln-triage-reporter
and remediation-planner already produced. If a number shown here disagrees with the
source file, the source file is right and this parser has a bug.
"""
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_BRANCH_PREFIX = "vulnhunter/auto-fixes-"

sys.path.insert(0, str(REPO_ROOT))
from remediation.config import priority_engine  # noqa: E402
from remediation.enrichment.attack_mapping import tag_findings  # noqa: E402
from remediation.enrichment.compensating_controls import tag_compensating_controls  # noqa: E402
from remediation.enrichment.infra_classification import tag_infra_categories  # noqa: E402
from remediation.enrichment.scan_type_mapping import tag_scan_types  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402


def _git_show(ref, path):
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def _find_fix_branch():
    result = subprocess.run(
        ["git", "branch", "--list", "-a", f"*{FIX_BRANCH_PREFIX}*"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    branches = [b.strip().lstrip("* ").strip() for b in result.stdout.splitlines() if b.strip()]
    if not branches:
        return None
    # Prefer a local branch name over a remotes/origin/... ref if both exist.
    local = [b for b in branches if not b.startswith("remotes/")]
    return (local or branches)[0]


def parse_markdown_table(markdown_text, heading):
    """Extract rows from the first markdown table following a given '## heading' line.
    Returns (header: list[str], rows: list[list[str]])."""
    lines = markdown_text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip().lstrip("#").strip() == heading)
    except StopIteration:
        start = 0
    table_lines = []
    in_table = False
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("|"):
            in_table = True
            table_lines.append(stripped)
        elif in_table:
            break
    if not table_lines:
        return [], []
    header = [c.strip() for c in table_lines[0].strip("|").split("|")]
    rows = []
    for line in table_lines[2:]:  # skip header + separator row
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == len(header):
            rows.append(cells)
    return header, rows


def load_vulnhunt_data():
    branch = _find_fix_branch()
    if not branch:
        return {"available": False}

    report = _git_show(branch, "vulnerable-demo-app/SECURITY_REPORT.md")
    if not report:
        return {"available": False}

    header, rows = parse_markdown_table(report, "Summary")
    findings = [dict(zip(header, row)) for row in rows]

    title_line = next((l for l in report.splitlines() if l.startswith("# ")), "")
    return {
        "available": True,
        "branch": branch,
        "title": title_line.lstrip("# ").strip(),
        "findings": findings,
        "total": len(findings),
        "auto_fixable": sum(1 for f in findings if f.get("Auto-fixable?", "").strip().lower() == "yes"),
    }


def load_remediation_findings():
    path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def count_kev_listed(findings):
    return sum(1 for f in findings if f.get("kev") and f["kev"].get("listed"))


def count_high_epss(findings, threshold=0.5):
    return sum(1 for f in findings if f.get("epss") and f["epss"].get("score", 0) >= threshold)


def asset_type_breakdown(findings):
    """Returns {asset_type: count}, ordered by count descending - used to show the
    breadth of coverage (OS/infra/network/IoT/application/certificate), not just a
    single 'code scan' story."""
    counts = {}
    for f in findings:
        t = f.get("asset", {}).get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def load_priority_rules_text():
    """Raw YAML text for the config editor form - preserves comments/formatting,
    unlike round-tripping through a parsed dict."""
    return priority_engine.DEFAULT_RULES_PATH.read_text(encoding="utf-8")


def save_priority_rules_text(text):
    """Validates the YAML parses before writing - never save a broken config file
    that would take down every page reading it on the next request."""
    import yaml
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    priority_engine.DEFAULT_RULES_PATH.write_text(text, encoding="utf-8")


def sla_and_priority_definitions():
    """A display-ready summary of the CURRENTLY CONFIGURED SLA windows and priority
    thresholds, for the Overview page's reference panel - reads the same
    priority_rules.yaml load_live_queue() itself uses, so an admin who retunes
    weights on /priority-rules sees this panel update too, rather than a hardcoded
    snapshot that could silently drift out of sync with the real config."""
    rules = priority_engine.load_rules()
    return {
        "sla_days": rules["sla_days"],
        "priority_thresholds": rules["priority_thresholds"],
        "kev_override": rules["kev_override"],
        "epss_escalation": rules["epss_escalation"],
    }


def load_live_queue():
    """The LIVE, re-scored, threat-intel-tagged remediation queue - computed fresh on
    every request from normalized-findings.json + whatever priority_rules.yaml
    currently says, unlike REMEDIATION_PLAN.md which is a point-in-time snapshot
    written by the remediation-planner subagent. This is what an admin editing the
    priority rules form actually sees change."""
    findings = load_remediation_findings()
    findings = tag_findings(findings)
    findings = tag_scan_types(findings)
    findings = tag_infra_categories(findings)
    findings = tag_compensating_controls(findings)
    active_exceptions = exceptions_store.active_exceptions_by_finding()
    findings = [{**f, "exception": active_exceptions.get(f["id"])} for f in findings]
    rules = priority_engine.load_rules()
    return priority_engine.score_findings(findings, rules=rules)


GENERIC_INGESTED_PATH = REPO_ROOT / "remediation" / "live-data" / "generic-ingested.json"
EXCEPTION_EXPIRY_WARNING_DAYS = 14
MAX_SLA_BREACH_NOTIFICATIONS = 10


def build_notifications(scored_findings):
    """Real, system-generated notifications derived entirely from live data already
    computed elsewhere on this page (the live queue, the exceptions store, the generic
    ingestion adapter's output file) - deliberately NOT person-to-person messaging
    (there's no user/auth system yet for that to mean anything - see
    KNOWLEDGE_TRANSFER.md). Every notification here is a fact about current state, not
    a message someone typed. Read/dismissed tracking is client-side only (localStorage),
    since there's no per-user server-side state to track it against."""
    notifications = []
    today = datetime.date.today()

    breached = [f for f in scored_findings if (f.get("sla") or {}).get("breached")]
    for f in breached[:MAX_SLA_BREACH_NOTIFICATIONS]:
        asset_name = (f.get("asset") or {}).get("name", "?")
        due_date = (f.get("sla") or {}).get("due_date", "?")
        notifications.append({
            "id": f"sla-{f['id']}",
            "severity": "danger",
            "category": "SLA",
            "message": f"SLA breached: {f['id']} on {asset_name} — was due {due_date}.",
            "date": due_date,
            "link": f"/queue?highlight={f['id']}",
        })
    if len(breached) > MAX_SLA_BREACH_NOTIFICATIONS:
        notifications.append({
            "id": f"sla-overflow-{len(breached)}",
            "severity": "danger",
            "category": "SLA",
            "message": f"...and {len(breached) - MAX_SLA_BREACH_NOTIFICATIONS} more SLA-breached finding(s) - see the Remediation Queue.",
            "date": None,
            "link": "/queue",
        })

    # KEV-listed findings that haven't already breached SLA - avoids repeating the same
    # finding twice when it's both breached AND KEV-listed (the SLA notification above
    # already flags it as urgent).
    for f in scored_findings:
        if (f.get("kev") or {}).get("listed") and not (f.get("sla") or {}).get("breached"):
            asset_name = (f.get("asset") or {}).get("name", "?")
            notifications.append({
                "id": f"kev-{f['id']}",
                "severity": "warn",
                "category": "Threat intel",
                "message": f"{f['id']} on {asset_name} is CISA KEV-listed (actively exploited) - not yet SLA-breached.",
                "date": (f.get("kev") or {}).get("date_added"),
                "link": f"/queue?highlight={f['id']}",
            })

    for e in exceptions_store.list_exceptions_with_status():
        if e["computed_status"] != "active":
            continue
        days_left = (datetime.date.fromisoformat(e["expires_on"]) - today).days
        if days_left <= EXCEPTION_EXPIRY_WARNING_DAYS:
            notifications.append({
                "id": f"exc-{e['id']}",
                "severity": "danger" if days_left < 0 else "warn",
                "category": "Exception",
                "message": f"Exception {e['id']} for {e['finding_id']} "
                           f"{'expired' if days_left < 0 else 'expires'} on {e['expires_on']}.",
                "date": e["expires_on"],
                "link": "/exceptions",
            })

    if GENERIC_INGESTED_PATH.exists():
        try:
            ingested = json.loads(GENERIC_INGESTED_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            ingested = []
        if ingested:
            mtime = GENERIC_INGESTED_PATH.stat().st_mtime_ns
            notifications.append({
                "id": f"ingest-{mtime}",
                "severity": "info",
                "category": "Ingestion",
                "message": f"{len(ingested)} finding(s) ingested via the generic webhook adapter are "
                           f"pending review (not yet merged into the live queue - see docs/INTEGRATIONS.md).",
                "date": None,
                "link": None,
            })

    severity_rank = {"danger": 0, "warn": 1, "info": 2}
    notifications.sort(key=lambda n: severity_rank.get(n["severity"], 3))
    return notifications


def sla_summary(scored_findings):
    """Returns {breached, at_risk, on_track} counts - at_risk means due within 3 days
    but not yet breached."""
    breached = at_risk = on_track = 0
    for f in scored_findings:
        sla = f.get("sla", {})
        if sla.get("breached"):
            breached += 1
        elif sla.get("days_remaining") is not None and sla["days_remaining"] <= 3:
            at_risk += 1
        else:
            on_track += 1
    return {"breached": breached, "at_risk": at_risk, "on_track": on_track}


def load_remediation_plan():
    path = REPO_ROOT / "REMEDIATION_PLAN.md"
    if not path.exists():
        return {"available": False}
    text = path.read_text(encoding="utf-8")

    title_line = next((l for l in text.splitlines() if l.startswith("# ")), "")
    header, rows = parse_markdown_table(text, "Remediation queue (priority order)")
    queue = [dict(zip(header, row)) for row in rows]

    risk_tier_counts = {}
    for row in queue:
        tier = row.get("Risk Tier", "unknown")
        risk_tier_counts[tier] = risk_tier_counts.get(tier, 0) + 1

    return {
        "available": True,
        "title": title_line.lstrip("# ").strip(),
        "queue": queue,
        "risk_tier_counts": risk_tier_counts,
    }


def load_playbooks():
    output_dir = REPO_ROOT / "remediation" / "output"
    if not output_dir.exists():
        return []
    playbooks = []
    for path in sorted(output_dir.glob("FIND-*.yml")):
        content = path.read_text(encoding="utf-8")
        finding_id_match = re.match(r"(FIND-\d+)", path.name)
        needs_approval = "CHANGE APPROVAL REQUIRED" in content
        playbooks.append({
            "filename": path.name,
            "finding_id": finding_id_match.group(1) if finding_id_match else None,
            "needs_approval": needs_approval,
            "content": content,
            "line_count": len(content.splitlines()),
        })
    return playbooks


def load_cli_audit_log_summaries():
    """Recent runs of cli/vulnhunter.py, if any have been run for real (dry-run doesn't
    write logs). Returns newest-first, summary fields only (not full stdout/stderr)."""
    log_dir = REPO_ROOT / ".vulnhunter" / "logs"
    if not log_dir.exists():
        return []
    entries = []
    for path in sorted(log_dir.glob("*.json"), reverse=True):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        entries.append({
            "timestamp": record.get("timestamp"),
            "pipeline": record.get("pipeline"),
            "returncode": record.get("returncode"),
            "command": " ".join(record.get("command", [])),
        })
    return entries
