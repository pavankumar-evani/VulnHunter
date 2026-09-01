"""
Configurable remediation policy engine.

Loads remediation/config/remediation_policy.yaml and resolves, for any normalized
finding, the real operational policy that should govern how it gets remediated: change
type (ITIL 4: standard/normal/emergency), patch cadence, maintenance window, whether it
can go through without a per-instance approval click, an AD approval-group name, a
downtime communication template, and which real PAM backend's Ansible lookup snippet a
generated playbook should reference.

This is deliberately separate from priority_engine.py (severity/SLA scoring) and from
bulk_plan.py's action_type/automation_target/risk_tier classification (what KIND of
change this is) - this module answers a different question: given what kind of finding
this already is, WHEN and HOW should it be remediated, and who can sign off on it. It
reads the same real, already-computed fields (`infra_category`, `scan_type`, `kev`) those
other modules produce rather than re-deriving asset classification.

Nothing in this module ever opens a network connection, executes a command, or touches
real infrastructure - `pam_vars_snippet()` returns plain text (a documented Ansible
snippet for a human/change-management process to include in a playbook); the actual
credential broker call happens later, on whatever machine runs that playbook, using your
organization's own real Vault/CyberArk connection.
"""
import datetime
from pathlib import Path
from string import Template

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "remediation_policy.yaml"

_DAY_NAMES = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


def load_rules(path=DEFAULT_RULES_PATH):
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _domain_for_finding(finding, environment, rules):
    """Resolution order: an explicit "dev" environment tag (if a dev policy exists)
    wins first, since a dev/staging override is meant to cut across normal asset-type
    classification; then a real quantum_readiness classification (see
    remediation/enrichment/quantum_readiness.py) - migrating off classical RSA/ECDSA/DH
    is a fundamentally different action from a routine patch, so it also cuts across
    normal classification, same reasoning as the dev override just above it; then
    infra_category (the 11-category infra taxonomy); then scan_type (for non-infra
    findings: sca/dast/cert-mgmt/iac/secrets/runtime/ai-ml); then "default"."""
    policies = rules.get("policies", {})
    if environment == "dev" and "dev" in policies:
        return "dev"
    quantum_readiness = finding.get("quantum_readiness")
    if quantum_readiness and quantum_readiness.get("category") and "quantum-crypto" in policies:
        return "quantum-crypto"
    infra_category = finding.get("infra_category")
    if infra_category and infra_category in policies:
        return infra_category
    scan_type = finding.get("scan_type")
    if scan_type and scan_type in policies:
        return scan_type
    return "default"


def policy_for_finding(finding, rules=None, environment=None, asset_remediation_schedule=None):
    """Returns {domain, change_type, cadence, maintenance_window, auto_remediate,
    restart_required, requires_approval_group, downtime_expected,
    communication_template, pam_backend, pam_credential_path, emergency_override,
    schedule_override}. `environment` is the finding's asset's environment tag
    (prod/staging/dev/unknown, or None if not looked up) - injected rather than looked
    up here so this stays a pure function; callers (dashboard/data.py) own fetching
    real ownership data. `asset_remediation_schedule` is that same asset's real,
    optional per-asset schedule override (remediation/inventory/asset_inventory.py's
    set_remediation_schedule(), stored in asset_ownership.json) - {"cadence":
    <VALID_CADENCE_VALUES str>, "maintenance_window": {...}} or None."""
    rules = rules or load_rules()
    policies = rules.get("policies", {})
    domain = _domain_for_finding(finding, environment, rules)
    policy = dict(policies.get(domain) or policies["default"])
    policy["domain"] = domain
    policy["emergency_override"] = False

    # An asset-level schedule override (set via /asset-policy or the per-asset editor)
    # wins over the domain's own default cadence/maintenance window - same
    # override-precedence pattern already proven for environment=="dev" above, just at
    # the individual-asset level rather than a whole domain.
    policy["schedule_override"] = False
    if asset_remediation_schedule:
        if asset_remediation_schedule.get("cadence"):
            policy["cadence"] = asset_remediation_schedule["cadence"]
            policy["schedule_override"] = True
        if asset_remediation_schedule.get("maintenance_window"):
            policy["maintenance_window"] = asset_remediation_schedule["maintenance_window"]
            policy["schedule_override"] = True

    kev_rule = rules.get("kev_emergency_override", {})
    kev = finding.get("kev")
    if kev_rule.get("enabled") and kev and kev.get("listed") and policy["change_type"] != "emergency":
        policy["change_type"] = "emergency"
        policy["auto_remediate"] = False
        policy["emergency_override"] = True

    return policy


def _next_weekday(as_of, day_of_week):
    """Returns the next date (today included) whose weekday matches `day_of_week`
    (a name from _DAY_NAMES, or "daily" meaning every day)."""
    if day_of_week == "daily":
        return as_of
    target = _DAY_NAMES.index(day_of_week.lower())
    days_ahead = (target - as_of.weekday()) % 7
    return as_of + datetime.timedelta(days=days_ahead)


def next_maintenance_window(window, as_of=None):
    """Returns {date, start_time, end_time, timezone, day_of_week} for the next real
    calendar occurrence of a policy's maintenance_window config - pure date math, no
    network/system-clock side effects beyond the injectable `as_of`."""
    as_of = as_of or datetime.date.today()
    day_of_week = window.get("day_of_week", "daily")
    next_date = _next_weekday(as_of, day_of_week)
    return {
        "date": next_date.isoformat(),
        "day_of_week": day_of_week,
        "start_time": window.get("start_time"),
        "end_time": window.get("end_time"),
        "timezone": window.get("timezone", "UTC"),
    }


def render_communication(template, finding, window, approved_by=None):
    """Safe templating via string.Template.safe_substitute() - an admin-authored
    template referencing an unknown placeholder is left as literal text rather than
    raising and breaking the page, since this text is user-edited config, not trusted
    code. Never uses str.format/eval on admin input."""
    asset = finding.get("asset") or {}
    context = {
        "asset_name": asset.get("name", "unknown asset"),
        "title": finding.get("title", ""),
        "cve": finding.get("cve") or "N/A",
        "window_day": window.get("day_of_week", ""),
        "window_start": window.get("start_time", ""),
        "window_end": window.get("end_time", ""),
        "timezone": window.get("timezone", "UTC"),
        "approved_by": approved_by or "pending approval",
    }
    return Template(template).safe_substitute(context)


# Real, current Ansible collection/lookup-plugin names (independently verified, not
# recalled from memory): community.hashi_vault.vault_kv2_get (HashiCorp Vault KV v2
# lookup), cyberark.pas.cyberark_credential (CyberArk Central Credential Provider
# module), cyberark.conjur.conjur_variable (CyberArk Conjur lookup), amazon.aws.
# sts_assume_role (AWS STS AssumeRole module), azure.azcollection's managed-identity
# auth (no lookup plugin needed - it's a connection-level auth mode), and GCP Workload
# Identity Federation (external credential-config file, no service-account key). Each
# snippet only names which real collection/auth mode to install/configure - the
# connection details (Vault address, CyberArk CCP URL, AWS role ARN, Azure/GCP identity
# config) are your organization's own, supplied wherever the playbook actually runs,
# never by this application. The three cloud backends are the same "just-in-time,
# keyless, short-lived" posture as Vault/CyberArk, just for cloud IAM instead of an
# on-prem PAM vault - see remediation_policy.yaml's pam_backend field docs.
def pam_vars_snippet(pam_backend, credential_path):
    if pam_backend == "vault":
        return (
            "# Requires: ansible-galaxy collection install community.hashi_vault\n"
            "# Configure VAULT_ADDR / your organization's real auth method separately.\n"
            "vars:\n"
            f"  admin_credential: \"{{{{ lookup('community.hashi_vault.vault_kv2_get', "
            f"'{credential_path}').secret }}}}\"\n"
        )
    if pam_backend == "cyberark-pas":
        return (
            "# Requires: ansible-galaxy collection install cyberark.pas\n"
            "# Configure your organization's real CyberArk CCP URL/app ID separately.\n"
            "tasks:\n"
            "  - name: Retrieve admin credential from CyberArk Central Credential Provider\n"
            "    cyberark.pas.cyberark_credential:\n"
            "      api_base_url: \"{{ cyberark_ccp_url }}\"\n"
            "      app_id: \"{{ cyberark_app_id }}\"\n"
            f"      query: \"Safe={credential_path}\"\n"
            "    register: cyberark_credential\n"
            "    no_log: true\n"
        )
    if pam_backend == "cyberark-conjur":
        return (
            "# Requires: ansible-galaxy collection install cyberark.conjur\n"
            "# Requires this playbook's runner to have a real Conjur identity configured separately.\n"
            "vars:\n"
            f"  admin_credential: \"{{{{ lookup('cyberark.conjur.conjur_variable', '{credential_path}') }}}}\"\n"
        )
    if pam_backend == "aws-sts-assume-role":
        return (
            "# Requires: ansible-galaxy collection install amazon.aws\n"
            "# The runner's own base AWS credentials (never this application's) assume this role -\n"
            "# temporary, short-lived STS credentials only, no standing secret.\n"
            "tasks:\n"
            "  - name: Assume the remediation role via AWS STS\n"
            "    amazon.aws.sts_assume_role:\n"
            f"      role_arn: \"{credential_path}\"\n"
            "      role_session_name: \"vulnhunter-remediation\"\n"
            "    register: assumed_role\n"
            "    no_log: true\n"
        )
    if pam_backend == "azure-managed-identity":
        return (
            "# Requires: ansible-galaxy collection install azure.azcollection\n"
            "# Managed identity is the production-recommended azure.azcollection auth mode -\n"
            "# no stored secret; the runner's own Azure-assigned identity is used directly.\n"
            "vars:\n"
            "  ansible_connection: azure_managed_identity\n"
            f"  azure_target_resource: \"{credential_path}\"\n"
        )
    if pam_backend == "gcp-workload-identity":
        return (
            "# Requires: ansible-galaxy collection install google.cloud\n"
            "# Workload Identity Federation exchanges the runner's own external identity for a\n"
            "# short-lived GCP access token - no service-account key file ever stored.\n"
            "vars:\n"
            "  gcp_auth_kind: \"application\"\n"
            f"  gcp_service_account: \"{credential_path}\"\n"
        )
    return None
