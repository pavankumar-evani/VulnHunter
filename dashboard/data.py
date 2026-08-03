"""
Reads VulnHunter's real generated artifacts (git history for /vulnhunt, files under
remediation/ for /remediate) and shapes them for the dashboard templates.

Deliberately has no pipeline logic of its own - it only parses what vuln-triage-reporter
and remediation-planner already produced. If a number shown here disagrees with the
source file, the source file is right and this parser has a bug.
"""
import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_BRANCH_PREFIX = "vulnhunter/auto-fixes-"


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
