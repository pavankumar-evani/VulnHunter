"""
The catalogue of pull connectors that can be stored and synced on a schedule: what each one
needs, how to build it, and how to turn a pull into data for the dashboard.

Every `pull` returns one of:
  {"kind": "findings", "findings": [...], "reconcile": bool, "skipped": {...}}
  {"kind": "assets",   "assets": [...]}
`reconcile` is True only when the pull is a COMPLETE export (see remediation/ingest/merge.py).
Hosts and URLs are checked with the SSRF guard (remediation/connectors/url_safety.py) before a
connector is ever built, at save time and again at run time.

OpenVAS/GVM is not listed: it launches a scan and polls for minutes to hours, so it keeps its
own start / status / import page rather than a scheduled one-shot pull.
"""
import os
import tempfile
from pathlib import Path

from remediation.connectors import url_safety
from remediation.connectors.active_directory_connector import ActiveDirectoryConnector
from remediation.connectors.ai_usage_connector import AnthropicUsageConnector, OpenAIUsageConnector
from remediation.connectors.axonius_connector import AxoniusConnector
from remediation.connectors import darkweb_connector
from remediation.connectors.cortex_xsiam_connector import CortexXsiamConnector
from remediation.connectors import git_host_connector
from remediation.connectors.infoblox_connector import InfobloxConnector
from remediation.connectors.prismacloud_connector import PrismaCloudConnector
from remediation.connectors.jira_connector import JiraConnector
from remediation.connectors.qualys_connector import QualysConnector
from remediation.connectors.reputation_connector import ReputationConnector
from remediation.connectors.servicenow_connector import ServiceNowConnector
from remediation.connectors.siem_search_connector import SplunkSearchConnector
from remediation.connectors.splunk_connector import SplunkConnector
from remediation.connectors.webhook_connector import NotifyWebhook, ResponseWebhook
from remediation.connectors.tenable_connector import TenableConnector
from remediation.connections import push as push_mod
from remediation.ingest import scanner_csv


def _f(name, label, secret=False, required=True, kind="text", placeholder="", help="", options=None):
    f = {"name": name, "label": label, "secret": secret, "required": required, "type": kind, "placeholder": placeholder, "help": help}
    if options:
        f["options"] = options
    return f


def _rule_fields():
    return [
        _f("min_severity", "Send findings at or above", required=False, kind="select", options=["Critical", "High", "Medium", "Low"],
           help="Default High"),
        _f("kev_only", "Only findings on the CISA KEV list", required=False, kind="checkbox"),
        _f("min_epss", "Minimum EPSS exploit probability, 0 to 1 (optional)", required=False, placeholder="0.5"),
        _f("max_per_run", "Most tickets per run", required=False, placeholder="50"),
    ]


def rule_from(values):
    """The push rule held in a connection's settings."""
    return {k: values.get(k) for k in ("min_severity", "kev_only", "min_epss", "max_per_run") if values.get(k) not in (None, "")}


def _validate_push(values):
    push_mod.normalise_rule(rule_from(values))


_INSTANCE = __import__("re").compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _validate_snow(values):
    if not _INSTANCE.match(str(values.get("instance", ""))):
        raise ValueError("instance must be just your ServiceNow instance name, for example 'acme' for acme.service-now.com")
    _validate_push(values)


def _csv_pull(connector, source, reconcile):
    fd, tmp = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        connector.fetch_and_write_csv(Path(tmp))
        findings, skipped = scanner_csv.parse_csv(tmp, source)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {"kind": "findings", "findings": findings, "reconcile": reconcile, "skipped": skipped}


def _tenable(c):
    return TenableConnector(c["access_key"], c["secret_key"])


def _qualys(c):
    return QualysConnector(c["username"], c["password"], platform_url=c["platform_url"])


SPECS = {
    "tenable": {
        "label": "Tenable.io", "category": "Vulnerability scanner", "output": "findings",
        "fields": [_f("access_key", "Access key", secret=True), _f("secret_key", "Secret key", secret=True)],
        "docs": "Tenable.io > Settings > My Account > API Keys.",
        "build": _tenable, "pull": lambda c: _csv_pull(_tenable(c), "tenable", reconcile=True),
        "test": lambda c: _tenable(c).test_connection(),
        "note": "A full export: vulnerabilities no longer reported are removed from the queue on each sync.",
    },
    "qualys": {
        "label": "Qualys VMDR", "category": "Vulnerability scanner", "output": "findings",
        "fields": [_f("platform_url", "Platform URL", placeholder="https://qualysapi.qualys.com"), _f("username", "Username"),
                   _f("password", "Password", secret=True)],
        "safe_targets": ["platform_url"], "docs": "Use the API base URL for your Qualys platform/region.",
        "build": _qualys, "pull": lambda c: _csv_pull(_qualys(c), "qualys", reconcile=False),
        "test": lambda c: _qualys(c).test_connection(),
        "note": "Host detections can be truncated for very large tenants, so findings are added and refreshed but never auto-removed.",
    },
    "prismacloud": {
        "label": "Prisma Cloud", "category": "Cloud posture", "output": "findings",
        "fields": [_f("base_url", "API base URL", placeholder="https://api.prismacloud.io"), _f("access_key_id", "Access key ID", secret=True),
                   _f("secret_key", "Secret key", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]),
        "pull": lambda c: {"kind": "findings", "findings": PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]).fetch_and_normalize_alerts(),
                           "reconcile": False, "skipped": {}},
        "test": lambda c: PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]).test_connection(),
    },
    "cortex-xsiam": {
        "label": "Cortex XSIAM", "category": "Detection and response", "output": "findings",
        "fields": [_f("base_url", "API base URL"), _f("api_key_id", "API key ID", secret=True), _f("api_key", "API key", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]),
        "pull": lambda c: {"kind": "findings", "findings": CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]).fetch_and_normalize_incidents(),
                           "reconcile": False, "skipped": {}},
        "test": lambda c: CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]).test_connection(),
    },
    "infoblox": {
        "label": "Infoblox", "category": "Asset discovery", "output": "assets",
        "fields": [_f("grid_master", "Grid master host"), _f("username", "Username"), _f("password", "Password", secret=True)],
        "safe_targets": ["grid_master"],
        "build": lambda c: InfobloxConnector(c["grid_master"], c["username"], c["password"]),
        "pull": lambda c: {"kind": "assets", "assets": InfobloxConnector(c["grid_master"], c["username"], c["password"]).fetch_and_normalize_hosts()},
        "test": lambda c: InfobloxConnector(c["grid_master"], c["username"], c["password"]).test_connection(),
    },
    "axonius": {
        "label": "Axonius", "category": "Asset discovery", "output": "assets",
        "fields": [_f("base_url", "Base URL"), _f("api_key", "API key", secret=True), _f("api_secret", "API secret", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]),
        "pull": lambda c: {"kind": "assets", "assets": AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]).fetch_and_normalize_devices()},
        "test": lambda c: AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]).test_connection(),
    },
    "active-directory": {
        "label": "Active Directory", "category": "Asset discovery", "output": "assets",
        "fields": [_f("server", "Server"), _f("base_dn", "Base DN"), _f("bind_dn", "Bind DN", required=False),
                   _f("bind_password", "Bind password", secret=True, required=False), _f("use_ssl", "Use LDAPS", required=False, kind="checkbox")],
        "safe_targets": ["server"],
        "build": lambda c: ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                    bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))),
        "pull": lambda c: {"kind": "assets", "assets": ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                                                bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))).fetch_and_normalize_computers()},
        "test": lambda c: ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                   bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))).test_connection(),
    },
}


def _days(values):
    try:
        return max(1, min(int(values.get("days") or 7), 31))
    except (TypeError, ValueError):
        raise ValueError("days must be a whole number from 1 to 31") from None


SPECS.update({
    "anthropic-usage": {
        "label": "Anthropic usage (AI spend)", "category": "AI usage", "output": "ai-usage",
        "fields": [_f("admin_key", "Admin API key", secret=True, placeholder="sk-ant-admin..."),
                   _f("days", "Days to pull each time (1 to 31)", required=False, placeholder="7")],
        "docs": "Claude Console > Settings > Admin keys. A workspace API key does not work. Pulls daily token counts by model and workspace.",
        "note": "Aggregated daily buckets; a re-pull updates them. Cost is estimated only if you enter prices in ai_pricing.yaml.",
        "validate": _days,
        "build": lambda c: AnthropicUsageConnector(c["admin_key"], days=_days(c)),
        "pull": lambda c: {"kind": "ai_usage", "events": AnthropicUsageConnector(c["admin_key"], days=_days(c)).fetch_events()},
        "test": lambda c: AnthropicUsageConnector(c["admin_key"], days=_days(c)).test_connection(),
    },
    "openai-usage": {
        "label": "OpenAI usage (AI spend)", "category": "AI usage", "output": "ai-usage",
        "fields": [_f("admin_key", "Admin key", secret=True, placeholder="sk-admin-..."),
                   _f("days", "Days to pull each time (1 to 31)", required=False, placeholder="7")],
        "docs": "OpenAI platform > Organization settings > Admin keys. A project API key does not work. Pulls daily token counts by model and project.",
        "note": "Aggregated daily buckets; a re-pull updates them. Cost is estimated only if you enter prices in ai_pricing.yaml.",
        "validate": _days,
        "build": lambda c: OpenAIUsageConnector(c["admin_key"], days=_days(c)),
        "pull": lambda c: {"kind": "ai_usage", "events": OpenAIUsageConnector(c["admin_key"], days=_days(c)).fetch_events()},
        "test": lambda c: OpenAIUsageConnector(c["admin_key"], days=_days(c)).test_connection(),
    },
})


SPECS.update({
    "servicenow": {
        "label": "ServiceNow", "category": "Ticketing", "output": "tickets", "kind": "push", "system": "servicenow",
        "fields": [_f("instance", "Instance name", placeholder="acme  (for acme.service-now.com)"), _f("username", "Integration user"),
                   _f("password", "Password", secret=True), _f("table", "Table", required=False, placeholder="incident")] + _rule_fields(),
        "docs": "Create an integration user that can create and read incidents. Quanta sets correlation_id to the finding id, so a re-run never duplicates a ticket, and reads incident state back.",
        "note": "State comes back by polling on each run; you can also have ServiceNow call Quanta's inbound API on update (see docs/INTEGRATION_API.md).",
        "validate": _validate_snow,
        "make": lambda c: ServiceNowConnector(c["instance"], c["username"], c["password"], table=c.get("table") or "incident"),
        "test": lambda c: ServiceNowConnector(c["instance"], c["username"], c["password"], table=c.get("table") or "incident").find_existing_incident("QUANTA-CONNECTION-TEST"),
    },
    "jira": {
        "label": "Jira Cloud", "category": "Ticketing", "output": "tickets", "kind": "push", "system": "jira",
        "fields": [_f("base_url", "Site URL", placeholder="https://acme.atlassian.net"), _f("email", "Account email"),
                   _f("api_token", "API token", secret=True), _f("project_key", "Project key", placeholder="SEC")] + _rule_fields(),
        "safe_targets": ["base_url"], "validate": _validate_push,
        "docs": "Atlassian account settings > Security > API tokens. Issues are labelled quanta-<finding id> so a re-run never duplicates one.",
        "make": lambda c: JiraConnector(c["base_url"], c["email"], c["api_token"], c["project_key"]),
        "test": lambda c: JiraConnector(c["base_url"], c["email"], c["api_token"], c["project_key"]).find_existing_issue("QUANTA-CONNECTION-TEST"),
    },
    "splunk": {
        "label": "Splunk HEC", "category": "SIEM / logging", "output": "events", "kind": "push", "system": "splunk",
        "fields": [_f("hec_url", "HEC endpoint URL", placeholder="https://splunk.acme.com:8088/services/collector/event"),
                   _f("hec_token", "HEC token", secret=True)] + _rule_fields(),
        "safe_targets": ["hec_url"], "validate": _validate_push,
        "docs": "Splunk > Settings > Data inputs > HTTP Event Collector. Each finding is sent once as an event (an append-only stream, so no duplicate check).",
        "make": lambda c: SplunkConnector(c["hec_url"], c["hec_token"]),
        "test": lambda c: SplunkConnector(c["hec_url"], c["hec_token"]).session.get(c["hec_url"].rsplit("/services/", 1)[0] + "/services/collector/health", timeout=15).raise_for_status(),
    },
})


def _validate_splunk_search(values):
    if not values.get("token") and not (values.get("username") and values.get("password")):
        raise ValueError("Give a Splunk token, or a username and password")


def _splunk_search(c):
    return SplunkSearchConnector(c["base_url"], token=c.get("token") or None, username=c.get("username") or None,
                                 password=c.get("password") or None, verify_tls=not c.get("skip_tls_verify"))


SPECS.update({
    "splunk-search": {
        "label": "Splunk search (hunting and triage)", "category": "SIEM / logging", "output": "searches", "kind": "tool",
        "fields": [_f("base_url", "Management URL", placeholder="https://splunk.acme.com:8089"),
                   _f("token", "Authentication token", secret=True, required=False),
                   _f("username", "Username (if no token)", required=False), _f("password", "Password (if no token)", secret=True, required=False),
                   _f("skip_tls_verify", "Skip TLS certificate verification (self-signed lab only)", required=False, kind="checkbox")],
        "safe_targets": ["base_url"], "validate": _validate_splunk_search,
        "docs": "Splunk > Settings > Tokens. Use an account that can run searches on the indexes you hunt in and nothing else. Quanta only sends read-only "
                "searches, from a hunt or an alert investigation, after an administrator confirms; it caps the rows it keeps and cancels a slow search.",
        "note": "Not synced on a schedule. Used on demand from Hunting & SOC.",
        "build": _splunk_search, "test": lambda c: _splunk_search(c).test_connection(),
    },
    "reputation": {
        "label": "Indicator reputation (VirusTotal)", "category": "Threat intelligence", "output": "reputation", "kind": "tool",
        "fields": [_f("api_key", "API key", secret=True)],
        "docs": "VirusTotal > your profile > API key. Only the indicator value (IP, domain, hash or URL) is sent, never the alert; private addresses are never sent. "
                "The public key is rate limited.",
        "note": "Not synced on a schedule. Used on demand when an alert is investigated.",
        "build": lambda c: ReputationConnector(c["api_key"]), "test": lambda c: ReputationConnector(c["api_key"]).test_connection(),
    },
})


def _response_webhook(c):
    allowed = [a.strip() for a in str(c.get("allowed_actions") or "").split(",") if a.strip()]
    return ResponseWebhook(c["url"], c["signing_secret"], allowed_actions=allowed or None)


SPECS.update({
    "response-webhook": {
        "label": "Response endpoint (SOAR, EDR or firewall automation)", "category": "Response", "output": "response", "kind": "tool",
        "fields": [_f("url", "Endpoint URL", placeholder="https://soar.acme.com/hooks/quanta"), _f("signing_secret", "Signing secret", secret=True),
                   _f("allowed_actions", "Allowed actions (comma separated, blank for all the policy allows)", required=False,
                      placeholder="create-ticket, isolate-host, block-ip")],
        "safe_targets": ["url"],
        "docs": "A URL you own. Quanta never acts on your systems itself: a playbook step sends a signed request (HMAC-SHA256 over timestamp.body in X-Quanta-Signature) and your "
                "automation decides. Verify the signature and the timestamp before acting. Actions that change something need an approval step in the playbook.",
        "note": "Not synced on a schedule. Used by SOAR playbooks. Testing sends a harmless enrich-asset request.",
        "build": _response_webhook, "test": lambda c: _response_webhook(c).test_connection(),
    },
    "notify-webhook": {
        "label": "Notification webhook (Slack, Teams)", "category": "Response", "output": "notifications", "kind": "tool",
        "fields": [_f("url", "Incoming webhook URL", secret=True)],
        "safe_targets": ["url"],
        "docs": "A Slack or Microsoft Teams incoming webhook. A playbook's notify step posts a short text message to it.",
        "note": "Not synced on a schedule. Used by SOAR playbooks. Testing posts a short test message.",
        "build": lambda c: NotifyWebhook(c["url"]), "test": lambda c: NotifyWebhook(c["url"]).test_connection(),
    },
})


def _dw(label, cls, site, help_text):
    return {"label": label, "category": "Threat intelligence", "output": "darkweb", "kind": "tool",
            "fields": [_f("api_key", "API key", secret=True)],
            "docs": f"{help_text} Only your own domains from the Dark Web Watch terms are sent. Identifiers are masked and passwords are never kept. Account: {site}.",
            "note": "Not synced like a scanner. Run from Dark Web Watch, on demand or on its daily schedule once switched on.",
            "build": lambda c: cls(c["api_key"]), "test": lambda c: cls(c["api_key"]).test_connection()}


SPECS.update({
    "intelx": _dw("IntelligenceX (breach and paste search)", darkweb_connector.IntelX, "intelx.io", "Searches leaks, pastes and dark-web indexes for your domain."),
    "dehashed": _dw("DeHashed (credential search)", darkweb_connector.DeHashed, "dehashed.com", "Searches breach data for your domain; needs API credits."),
    "leakcheck": _dw("LeakCheck (credential search)", darkweb_connector.LeakCheck, "leakcheck.io", "Domain search needs a plan that includes it."),
    "snusbase": _dw("Snusbase (breach compilations)", darkweb_connector.Snusbase, "snusbase.com", "Searches breach compilations by domain."),
})


def _git_spec(provider, label, default_url, token_help):
    return {
        "label": label, "category": "Source control", "output": "pull-requests", "kind": "tool",
        "fields": [_f("base_url", "API base URL (leave blank for the hosted service)", required=False, placeholder=default_url), _f("token", "Access token", secret=True)],
        "safe_targets": ["base_url"],
        "docs": token_help + " Quanta uses it to read dependency files, create a branch of its own, commit to that branch and open a pull request, only after an administrator "
                "confirms. It never merges and never writes to the default branch. Give the token access to the repositories you list on the Applications page and nothing else.",
        "note": "Not synced on a schedule. Used by the Fix pull requests page. Testing only checks that the token is valid.",
        "build": lambda c: git_host_connector.build(provider, c["token"], c.get("base_url")),
        "test": lambda c: git_host_connector.build(provider, c["token"], c.get("base_url")).whoami(),
    }


SPECS.update({
    "github": _git_spec("github", "GitHub (pull requests)", "https://api.github.com   (GitHub Enterprise Server: https://HOST/api/v3)",
                        "Use a fine-grained personal access token or a GitHub App installation token with Contents and Pull requests read/write on the repositories."),
    "gitlab": _git_spec("gitlab", "GitLab (merge requests)", "https://gitlab.com   (self-managed: https://gitlab.example.com)",
                        "Use a project or group access token with the api scope and the Developer role."),
})


def public_catalog():
    """What the UI needs: the types and their fields, never the callables."""
    return [{"type": t, **{k: v for k, v in s.items() if k in ("label", "category", "output", "fields", "docs", "note")}, "kind": s.get("kind", "pull")} for t, s in SPECS.items()]


def split_values(conn_type, values):
    """Splits submitted field values into (config, secrets) per the spec; validates required
    fields and the SSRF guard. Raises ValueError with a readable message."""
    spec = SPECS.get(conn_type)
    if not spec:
        raise ValueError(f"Unknown connector type {conn_type!r}")
    config, secrets = {}, {}
    for f in spec["fields"]:
        v = values.get(f["name"])
        if f["type"] == "checkbox":
            v = bool(v)
        elif f["type"] == "select" and v and v not in f.get("options", []):
            raise ValueError(f"{f['label']} must be one of {', '.join(f['options'])}")
        elif isinstance(v, str):
            v = v.strip()
        if f["required"] and (v is None or v == ""):
            raise ValueError(f"{f['label']} is required")
        if v in (None, ""):
            continue
        (secrets if f["secret"] else config)[f["name"]] = v
    for name in spec.get("safe_targets", []):
        target = config.get(name)
        if target:
            try:
                url_safety.assert_safe_target(target)
            except url_safety.UnsafeTargetError as exc:
                raise ValueError(f"{name}: {exc}") from exc
    if spec.get("validate"):
        spec["validate"]({**config, **secrets})
    return config, secrets
