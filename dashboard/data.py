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
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_BRANCH_PREFIX = "vulnhunter/auto-fixes-"

sys.path.insert(0, str(REPO_ROOT))
from remediation.config import priority_engine  # noqa: E402
from remediation.config import remediation_policy_engine  # noqa: E402
from remediation.enrichment.attack_mapping import tag_findings  # noqa: E402
from remediation.enrichment.compensating_controls import tag_compensating_controls  # noqa: E402
from remediation.enrichment.eol_lookup import tag_eol_eos  # noqa: E402
from remediation.enrichment import exploit_criteria  # noqa: E402
from remediation.enrichment.exploit_criteria import tag_exploit_criteria  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.enrichment.infra_classification import tag_infra_categories  # noqa: E402
from remediation.enrichment import activity_insights  # noqa: E402
from remediation.enrichment import ml_insights  # noqa: E402
from remediation.enrichment import risk_scoring  # noqa: E402
from remediation.enrichment.quantum_readiness import tag_quantum_readiness  # noqa: E402
from remediation.enrichment.cloud_provider import tag_cloud_provider  # noqa: E402
from remediation.enrichment.dedup import dedup_findings  # noqa: E402
from remediation.enrichment.scan_type_mapping import tag_scan_types  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.inventory import asset_inventory, asset_policy  # noqa: E402
from remediation.remediation_approvals import store as remediation_approvals_store  # noqa: E402
from remediation.connectors import live_data_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


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


def _split_markdown_table_row(line):
    """Splits a '| a | b | c |' row on unescaped '|' only - a literal pipe inside a
    cell (e.g. a real CVE description naming a "Plugin A | Plugin B" product) is
    written as '\\|' by bulk_plan.py's table generator, so a naive line.split("|")
    would over-split that one row and silently drop it (len(cells) would never match
    the header again). Splits on a '|' not preceded by a backslash, then unescapes
    '\\|' back to a literal '|' in each cell."""
    raw_cells = re.split(r"(?<!\\)\|", line.strip("|"))
    return [c.strip().replace("\\|", "|") for c in raw_cells]


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
    header = _split_markdown_table_row(table_lines[0])
    rows = []
    for line in table_lines[2:]:  # skip header + separator row
        cells = _split_markdown_table_row(line)
        if len(cells) == len(header):
            rows.append(cells)
    return header, rows


_VULNHUNT_DATA_CACHE = {"data": None, "expires_at": 0.0}
_VULNHUNT_DATA_CACHE_TTL_SECONDS = 10  # see load_vulnhunt_data()'s own docstring for why

_SCORED_ASSETS_CACHE = {"key": None, "assets": None, "expires_at": 0.0}
# Both TTLs below are backstops only, not the correctness mechanism - each cache key
# already covers every real file's mtime that can change its output (see each cache
# key function's own docstring), so a real edit is reflected on the very next call
# regardless of TTL. 30s (up from an initial, over-cautious 5s) means clicking through
# several pages in a normal browsing session actually benefits from the cache instead
# of re-paying the ~4-5s cold cost (measured at ~9,400 real findings) on nearly every
# navigation - profiled speedup on a cache hit: ~18x for load_live_queue() alone.
_SCORED_ASSETS_CACHE_TTL_SECONDS = 30

_LIVE_QUEUE_CACHE = {"key": None, "queue": None, "expires_at": 0.0}
_LIVE_QUEUE_CACHE_TTL_SECONDS = 30


def _compute_vulnhunt_data():
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


def load_vulnhunt_data():
    """Cached for a short TTL (in-process, not persisted) - profiled at ~0.4s per call
    (two `git` subprocess spawns: branch discovery + `git show`), and now several
    dashboard pages call this on every navigation (Overview, AppSec), not just
    /vulnhunt itself. The underlying data only changes when a new commit lands on the
    real fix branch - a rare event in a demo - so a few seconds of staleness is a
    non-issue, and it makes repeat navigation genuinely fast instead of re-spawning
    git on every click."""
    now = time.monotonic()
    if _VULNHUNT_DATA_CACHE["data"] is not None and now < _VULNHUNT_DATA_CACHE["expires_at"]:
        return _VULNHUNT_DATA_CACHE["data"]
    data = _compute_vulnhunt_data()
    _VULNHUNT_DATA_CACHE["data"] = data
    _VULNHUNT_DATA_CACHE["expires_at"] = now + _VULNHUNT_DATA_CACHE_TTL_SECONDS
    return data


def load_remediation_findings():
    path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def load_threat_intel_freshness():
    """How stale is our real CISA KEV/FIRST.org EPSS data? The honest signal is the
    real last-modified time of normalized-findings.json itself - that file only
    changes when /remediate's enrichment stage runs, or when POST
    /api/threat-intel/refresh-now (see remediation/enrichment/kev_epss.py) re-fetches
    both feeds on demand. Not a separately tracked timestamp - the file's own real
    mtime IS the fact being reported, same "the filesystem is the source of truth"
    convention _load_content_enriched_findings()'s own cache-key already uses."""
    path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    if not path.exists():
        return {"available": False}
    findings = load_remediation_findings()
    return {
        "available": True,
        "last_refreshed": datetime.datetime.fromtimestamp(
            path.stat().st_mtime, tz=datetime.timezone.utc,
        ).isoformat(),
        "cve_count": sum(1 for f in findings if f.get("cve")),
    }


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


def load_exploit_criteria_rules_text():
    from remediation.enrichment import exploit_criteria
    return exploit_criteria.DEFAULT_RULES_PATH.read_text(encoding="utf-8")


def save_exploit_criteria_rules_text(text):
    """Validates the YAML parses before writing - same guardrail as
    save_priority_rules_text."""
    import yaml
    from remediation.enrichment import exploit_criteria
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    exploit_criteria.DEFAULT_RULES_PATH.write_text(text, encoding="utf-8")


REPORT_SCHEDULE_RULES_PATH = REPO_ROOT / "remediation" / "config" / "report_schedule_rules.yaml"
ALERT_RULES_PATH = REPO_ROOT / "remediation" / "config" / "alert_rules.yaml"


def load_report_schedule_text():
    return REPORT_SCHEDULE_RULES_PATH.read_text(encoding="utf-8")


def save_report_schedule_text(text):
    import yaml
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    REPORT_SCHEDULE_RULES_PATH.write_text(text, encoding="utf-8")


def load_report_schedule_rules():
    import yaml
    return yaml.safe_load(REPORT_SCHEDULE_RULES_PATH.read_text(encoding="utf-8")) or {"subscriptions": []}


def load_alert_rules_text():
    return ALERT_RULES_PATH.read_text(encoding="utf-8")


def save_alert_rules_text(text):
    import yaml
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    ALERT_RULES_PATH.write_text(text, encoding="utf-8")


def load_alert_rules():
    import yaml
    return yaml.safe_load(ALERT_RULES_PATH.read_text(encoding="utf-8")) or {"subscriptions": []}


def load_remediation_policy_text():
    return remediation_policy_engine.DEFAULT_RULES_PATH.read_text(encoding="utf-8")


def save_remediation_policy_text(text):
    """Validates the YAML parses before writing - same guardrail as
    save_priority_rules_text."""
    import yaml
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    remediation_policy_engine.DEFAULT_RULES_PATH.write_text(text, encoding="utf-8")


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
        "asset_criticality_keywords": rules["asset_criticality_keywords"],
        "asset_type_weights": rules["asset_type_weights"],
    }


_ENRICHED_FINDINGS_CACHE = {"key": None, "findings": None}


def _load_content_enriched_findings():
    """The slow part of load_live_queue(), profiled directly: tag_findings (MITRE
    ATT&CK keyword matching) and tag_compensating_controls (keyword matching) together
    take ~1.8s across ~8,000 findings just from running ~14 regex patterns per finding
    twice over - real cost, not a bug, but one worth not paying on every single page
    load now that Overview/Infrastructure/AppSec/Risk all fetch the live queue too.
    Unlike priority scoring and exploit-criteria matching (which read rules files an
    admin can edit and must reflect "immediately", per those pages' own promise), every
    tag_* call here is a pure function of the finding's own content (title/description/
    asset) plus eol_lookup's date-relative EOL_REFERENCE table - nothing a user action
    can change without a full pipeline re-run. Cached in-process, keyed on the
    findings file's own mtime (a re-run changes it) plus today's date (so an EOL/EOS
    status that flips at midnight isn't pinned to a stale cache) - either changing
    invalidates it automatically, nothing else can leave it stale.

    dedup_findings() runs first, deliberately before every tag_* call - it only reads
    cve/asset/title/first_seen/id, none of which any tag_* call adds or changes, so
    ordering relative to them doesn't affect correctness, but running it first keeps
    the "identify duplicates" step conceptually separate from "annotate content" -
    see remediation/enrichment/dedup.py for what it tags and why (cross-scanner
    deduplication - the gap named in docs/VR_PLATFORM_COMPARISON.md)."""
    path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    mtime = path.stat().st_mtime if path.exists() else None
    cache_key = (mtime, datetime.date.today().isoformat())

    if _ENRICHED_FINDINGS_CACHE["key"] == cache_key:
        return _ENRICHED_FINDINGS_CACHE["findings"]

    findings = load_remediation_findings()
    findings = dedup_findings(findings)
    findings = tag_findings(findings)
    findings = tag_scan_types(findings)
    findings = tag_infra_categories(findings)
    findings = tag_compensating_controls(findings)
    findings = tag_eol_eos(findings)
    findings = tag_quantum_readiness(findings)
    findings = tag_cloud_provider(findings)

    _ENRICHED_FINDINGS_CACHE["key"] = cache_key
    _ENRICHED_FINDINGS_CACHE["findings"] = findings
    return findings


def _scored_assets_cache_key():
    """Every real, editable file/store whose content actually changes
    _load_scored_assets()'s output - findings, asset ownership (owner/team/environment/
    facing/remediation schedule - read by build_asset_inventory()), and the two rules
    files score_assets() itself loads when not passed explicitly. Keying on each one's
    own mtime means an edit to ANY of them invalidates the cache the instant it
    happens, not just after the TTL below expires - that TTL is only a backstop for
    rapid repeat calls within the same file state, never the mechanism a real edit
    relies on to be seen.

    Asset ownership now lives in the shared SQLite DB (see remediation/utils/db.py) -
    its path is read off the real engine (`engine.url.database`), not a separate
    DEFAULT_OWNERSHIP_PATH constant, so this stays correct when tests patch
    db_module.get_engine() to an isolated file (see _live_queue_cache_key()'s own
    identical reasoning, right below)."""
    db_path = Path(db_module.get_engine().url.database)
    risk_rules_path = risk_scoring.DEFAULT_RULES_PATH
    priority_rules_path = priority_engine.DEFAULT_RULES_PATH
    return (
        _findings_file_mtime(),
        db_path.stat().st_mtime if db_path.exists() else None,
        risk_rules_path.stat().st_mtime if risk_rules_path.exists() else None,
        priority_rules_path.stat().st_mtime if priority_rules_path.exists() else None,
    )


def _load_scored_assets():
    """Real per-asset Impact/Likelihood/Risk scoring (remediation/enrichment/
    risk_scoring.py) - shared across load_live_queue(), /api/overview, and /api/assets,
    which each previously computed this independently (measured ~0.25s each, so a
    single Overview page load - which fetches all three - paid for it 2-3x
    redundantly). Content-enrichment tagging (ATT&CK/scan-type/infra-category/
    compensating-controls/EOL/quantum-readiness) doesn't feed risk_scoring.py at all
    (it reads eol_status off the ASSET row, which build_asset_inventory() computes
    itself), so using the plain, un-content-enriched findings here produces identical
    scores while staying cheap and cacheable. Cache key covers every file that can
    actually change the output (see _scored_assets_cache_key()); the short TTL is only
    a backstop within one unchanged file state, never load-bearing for correctness.
    Returns (exploit-criteria-tagged findings, scored asset rows) - most callers only
    need the second element."""
    findings = load_remediation_findings()
    findings = tag_exploit_criteria(findings)
    cache_key = _scored_assets_cache_key()
    now = time.monotonic()
    if (_SCORED_ASSETS_CACHE["key"] == cache_key and _SCORED_ASSETS_CACHE["assets"] is not None
            and now < _SCORED_ASSETS_CACHE["expires_at"]):
        return findings, _SCORED_ASSETS_CACHE["assets"]
    asset_rows = asset_inventory.build_asset_inventory(findings)
    scored_assets = risk_scoring.score_assets(asset_rows, findings)
    _SCORED_ASSETS_CACHE["key"] = cache_key
    _SCORED_ASSETS_CACHE["assets"] = scored_assets
    _SCORED_ASSETS_CACHE["expires_at"] = now + _SCORED_ASSETS_CACHE_TTL_SECONDS
    return findings, scored_assets


def _live_queue_cache_key():
    """Every real, editable file/store whose content actually changes
    load_live_queue()'s output, on top of _scored_assets_cache_key()'s own four
    (findings, ownership, risk-rules, priority-rules): the exploit-criteria rules,
    active exceptions, remediation policy rules, and approval decisions - each can
    genuinely change between requests via a real admin action (editing a rules form,
    requesting/approving/rejecting an approval, revoking an exception), so each one's
    mtime is part of the key, same "an edit invalidates the instant it happens, not
    just after a TTL" reasoning as that function's own docstring.

    Exceptions and approvals now live in the shared SQLite DB (see
    remediation/utils/db.py), not separate files - both tables are in the SAME
    physical file, so its one mtime stands in for both. This over-invalidates very
    slightly (a write to activity_log or ai_usage_log, which share that file too, also
    bumps it) rather than under-invalidating, which is the safe direction for a cache.

    The path is read off the real engine (`engine.url.database`), not the separate
    db_module.DEFAULT_DB_PATH constant - tests patch db_module.get_engine() to an
    isolated file for isolation, and reading DEFAULT_DB_PATH here directly would
    silently drift from whatever get_engine() actually returns in that case (the
    cache would then key off a file nothing is writing to, and never invalidate)."""
    exploit_rules_path = exploit_criteria.DEFAULT_RULES_PATH
    policy_rules_path = remediation_policy_engine.DEFAULT_RULES_PATH
    db_path = Path(db_module.get_engine().url.database)
    return (
        _scored_assets_cache_key(),
        exploit_rules_path.stat().st_mtime if exploit_rules_path.exists() else None,
        db_path.stat().st_mtime if db_path.exists() else None,
        policy_rules_path.stat().st_mtime if policy_rules_path.exists() else None,
    )


def load_live_queue():
    """The LIVE, re-scored, threat-intel-tagged remediation queue - reflects
    normalized-findings.json + whatever priority_rules.yaml/remediation_policy.yaml/
    exceptions.json/remediation_approvals.json currently say, unlike
    REMEDIATION_PLAN.md which is a point-in-time snapshot written by the
    remediation-planner subagent. This is what an admin editing the priority rules form
    actually sees change - real-time, not stale, just not recomputed from scratch on
    every single call now that the real sample dataset has grown past ~9,000 findings
    (measured ~2-5s per cold computation, dominated by priority_engine.score_findings()
    - a real, user-visible page-load lag this cache exists specifically to remove).
    Cache key covers every file that can actually change the output (see
    _live_queue_cache_key()); the short TTL is only a backstop within one unchanged
    file state, never load-bearing for correctness - a real edit to any of those files
    is reflected on the very next call, cache or not."""
    cache_key = _live_queue_cache_key()
    now = time.monotonic()
    if (_LIVE_QUEUE_CACHE["key"] == cache_key and _LIVE_QUEUE_CACHE["queue"] is not None
            and now < _LIVE_QUEUE_CACHE["expires_at"]):
        # Shallow-copy every row before handing it back - callers across this app
        # mutate a finding dict in place (e.g. /api/assets' own suggestion field did,
        # caught and fixed earlier this session for _load_scored_assets()'s cache); a
        # shared cached list must never let one caller's mutation leak into another's
        # or corrupt what's served from cache next.
        return [dict(f) for f in _LIVE_QUEUE_CACHE["queue"]]

    findings = _load_content_enriched_findings()
    findings = tag_exploit_criteria(findings)
    active_exceptions = exceptions_store.active_exceptions_by_finding()
    findings = [{**f, "exception": active_exceptions.get(f["id"])} for f in findings]
    rules = priority_engine.load_rules()
    # Real asset risk_tier (remediation/enrichment/risk_scoring.py), keyed by asset
    # name, feeds score_findings()'s asset-criticality-tiered SLA multiplier (CIS
    # Controls v8 §7.2) - see _load_scored_assets()'s own docstring for why sharing its
    # short-TTL-cached result here is safe (content-enrichment doesn't feed risk scoring).
    _, scored_assets = _load_scored_assets()
    risk_tier_by_asset = {row["name"]: row.get("risk_tier") for row in scored_assets}
    scored = priority_engine.score_findings(findings, rules=rules, risk_tier_by_asset=risk_tier_by_asset)

    ownership = asset_inventory.load_ownership()
    policy_rules = remediation_policy_engine.load_rules()
    approvals_by_finding = remediation_approvals_store.approvals_by_finding()
    for f in scored:
        asset_name = (f.get("asset") or {}).get("name")
        asset_ownership_entry = ownership.get(asset_name) or {}
        environment = asset_ownership_entry.get("environment")
        asset_schedule = asset_ownership_entry.get("remediation_schedule")
        policy = remediation_policy_engine.policy_for_finding(
            f, rules=policy_rules, environment=environment, asset_remediation_schedule=asset_schedule,
        )
        f["remediation_policy"] = policy
        f["remediation_policy"]["next_window"] = remediation_policy_engine.next_maintenance_window(
            policy["maintenance_window"],
        )
        approval = approvals_by_finding.get(f["id"])
        f["remediation_approval"] = approval
        approved_by = approval["approved_by"] if approval and approval.get("status") == "approved" else None
        f["remediation_policy"]["rendered_communication"] = remediation_policy_engine.render_communication(
            policy["communication_template"], f, f["remediation_policy"]["next_window"], approved_by=approved_by,
        )
    _LIVE_QUEUE_CACHE["key"] = cache_key
    _LIVE_QUEUE_CACHE["queue"] = scored
    _LIVE_QUEUE_CACHE["expires_at"] = now + _LIVE_QUEUE_CACHE_TTL_SECONDS
    return [dict(f) for f in scored]


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

    ingested_count = live_data_store.count(live_data_store.SOURCE_GENERIC_INGEST)
    if ingested_count:
        # The notification id includes the shared DB file's own mtime (not a
        # per-source one - all sources share one physical file, see
        # remediation/utils/db.py) so it changes whenever new data is ingested,
        # keeping a client's localStorage dismissal-tracking from treating a stale
        # id as "already seen" once fresh findings arrive.
        db_path = Path(db_module.get_engine().url.database)
        mtime = db_path.stat().st_mtime_ns if db_path.exists() else 0
        notifications.append({
            "id": f"ingest-{mtime}",
            "severity": "info",
            "category": "Ingestion",
            "message": f"{ingested_count} finding(s) ingested via the generic webhook adapter are "
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


def _parse_rollback_plan(playbook_text):
    """Extracts the real, human-written "# Rollback: ..." comment from a generated
    playbook's header - every remediation-fixer-windows/-unix subagent is instructed to
    include one (see those agents' own docs), so this is genuine per-fix guidance, not
    a fabricated summary. Handles the comment wrapping onto following '#'-prefixed
    lines (including an indented follow-up command, e.g. FIND-2's playbook), stopping
    at the first blank '#' line or non-comment line. Returns None if a playbook somehow
    has no such comment (a hand-edited or older playbook) - stays honest about that
    rather than guessing at a rollback procedure that isn't actually written down."""
    lines = playbook_text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip().startswith("# Rollback:")), None)
    if start is None:
        return None
    collected = [lines[start].split("# Rollback:", 1)[1].strip()]
    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped == "#" or not stripped.startswith("#"):
            break
        collected.append(stripped[1:].strip())
    return "\n".join(collected).strip() or None


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
            "rollback_plan": _parse_rollback_plan(content),
        })
    return playbooks


_ML_ASSET_ANOMALIES_CACHE = {"key": None, "rows": None}
_ML_FINDING_CLUSTERS_CACHE = {"key": None, "tagged": None, "summaries": None}


def _findings_file_mtime():
    path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
    return path.stat().st_mtime if path.exists() else None


def load_asset_anomalies():
    """Real IsolationForest anomaly detection (remediation/enrichment/ml_insights.py) -
    genuinely fit per asset type against the live asset population, not a canned
    lookup. Profiled at ~2.6s across ~8,500 assets/16 types with contamination=0.05,
    so cached in-process keyed on the findings file's own mtime (same convention as
    _load_content_enriched_findings()) rather than re-fit on every /ml-insights page
    load - a re-run of the pipeline changes the mtime and invalidates it
    automatically."""
    cache_key = _findings_file_mtime()
    if _ML_ASSET_ANOMALIES_CACHE["key"] == cache_key:
        return _ML_ASSET_ANOMALIES_CACHE["rows"]

    findings, rows = _load_scored_assets()
    rows = ml_insights.detect_asset_anomalies(rows, findings)

    _ML_ASSET_ANOMALIES_CACHE["key"] = cache_key
    _ML_ASSET_ANOMALIES_CACHE["rows"] = rows
    return rows


def load_finding_clusters():
    """Real KMeans risk-archetype clustering (ml_insights.cluster_findings) - fit
    fresh against the live finding population, profiled at ~2.4s across ~9,400
    findings. Cached the same way as load_asset_anomalies(). Returns
    (tagged_findings, cluster_summaries)."""
    cache_key = _findings_file_mtime()
    if _ML_FINDING_CLUSTERS_CACHE["key"] == cache_key:
        return _ML_FINDING_CLUSTERS_CACHE["tagged"], _ML_FINDING_CLUSTERS_CACHE["summaries"]

    findings = load_remediation_findings()
    tagged, summaries = ml_insights.cluster_findings(findings)

    _ML_FINDING_CLUSTERS_CACHE["key"] = cache_key
    _ML_FINDING_CLUSTERS_CACHE["tagged"] = tagged
    _ML_FINDING_CLUSTERS_CACHE["summaries"] = summaries
    return tagged, summaries


def load_finding_cluster_members(cluster_id, limit=25):
    """Just the findings in one discovered cluster (for the /ml-insights page's "View
    members" expand) - reuses the same cached, already-tagged findings
    load_finding_clusters() computed rather than re-running KMeans."""
    tagged, _summaries = load_finding_clusters()
    members = [f for f in tagged if f.get("risk_cluster") == cluster_id]
    return members[:limit], len(members)


def find_similar_findings(finding_id, top_n=5):
    """Real TF-IDF + cosine-similarity search (ml_insights.find_similar_findings)
    against the live finding population - cheap enough (~0.8s across ~9,400
    findings) that it isn't cached; only runs when a user opens a finding's detail
    view, not on every page load."""
    findings = load_remediation_findings()
    return ml_insights.find_similar_findings(findings, finding_id, top_n=top_n)


def load_asset_policy_text():
    return asset_policy.DEFAULT_RULES_PATH.read_text(encoding="utf-8")


def save_asset_policy_text(text):
    """Validates the YAML parses before writing - same guardrail as
    save_priority_rules_text."""
    import yaml
    yaml.safe_load(text)  # raises yaml.YAMLError if invalid; caller should catch it
    asset_policy.DEFAULT_RULES_PATH.write_text(text, encoding="utf-8")


def _current_asset_rows():
    findings = load_remediation_findings()
    return asset_inventory.build_asset_inventory(findings)


def preview_asset_policy(rules_text):
    """Real, read-only preview against the CURRENT real asset inventory - `rules_text`
    is raw YAML (possibly not yet saved) so a caller can preview an edit before
    committing it, same pattern as exploit_criteria's own preview route."""
    import yaml
    rules = yaml.safe_load(rules_text) or {"rules": []}
    return asset_policy.preview_matches(_current_asset_rows(), rules)


def apply_asset_policy(actor=None):
    """Applies the real, currently-SAVED asset_policy_rules.yaml against the current
    real asset inventory - unlike preview_asset_policy(), this always uses the saved
    file (never an unsaved edit), so what gets applied is exactly what an admin
    reviewed and saved first."""
    rules = asset_policy.load_rules()
    return asset_policy.apply_rules(_current_asset_rows(), rules, actor=actor)


def load_activity_insights():
    """Real, non-ML summary of remediation/audit/activity_log.py's current contents
    (works at any volume, including zero) plus real IsolationForest anomaly detection
    over per-actor behavior once there's enough real history to fit on honestly - see
    activity_insights.py's module docstring for exactly why a fresh checkout starts
    with none of that yet, by design, not as a bug."""
    entries = activity_log.list_activity()
    return {
        "summary": activity_insights.summarize_activity(entries),
        "unusual_actors": activity_insights.detect_unusual_actors(entries),
    }


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
