"""
Tests for remediation/config/remediation_policy_engine.py.

Uses an in-memory rules dict for domain-resolution/override/date-math tests (not the
real remediation_policy.yaml) so tests stay independent of that file's actual tuning - a
handful of tests specifically load the real file to make sure it's valid YAML matching
the expected shape, same split as test_priority_engine.py.
"""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.config.remediation_policy_engine import (  # noqa: E402
    policy_for_finding, next_maintenance_window, render_communication, pam_vars_snippet,
    load_rules, DEFAULT_RULES_PATH,
)

BASE_RULES = {
    "kev_emergency_override": {"enabled": True},
    "policies": {
        "endpoint": {
            "change_type": "standard", "cadence": "weekly",
            "maintenance_window": {"day_of_week": "tuesday", "start_time": "02:00", "end_time": "04:00", "timezone": "UTC"},
            "auto_remediate": True, "restart_required": True, "requires_approval_group": None,
            "downtime_expected": False, "communication_template": "Patch for $asset_name",
            "pam_backend": "none", "pam_credential_path": None,
        },
        "os": {
            "change_type": "normal", "cadence": "monthly",
            "maintenance_window": {"day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"},
            "auto_remediate": False, "restart_required": True, "requires_approval_group": "IT-Change-Approvers",
            "downtime_expected": True, "communication_template": "Maintenance for $asset_name: $title ($cve) $window_day $window_start-$window_end $timezone, approved by $approved_by",
            "pam_backend": "vault", "pam_credential_path": "secret/servers/admin-credentials",
        },
        "dev": {
            "change_type": "standard", "cadence": "weekly",
            "maintenance_window": {"day_of_week": "daily", "start_time": "01:00", "end_time": "05:00", "timezone": "UTC"},
            "auto_remediate": True, "restart_required": False, "requires_approval_group": None,
            "downtime_expected": False, "communication_template": "Dev auto-update for $asset_name",
            "pam_backend": "vault", "pam_credential_path": "secret/dev/admin-credentials",
        },
        "sca": {
            "change_type": "standard", "cadence": "on-demand",
            "maintenance_window": {"day_of_week": "daily", "start_time": "00:00", "end_time": "23:59", "timezone": "UTC"},
            "auto_remediate": True, "restart_required": False, "requires_approval_group": None,
            "downtime_expected": False, "communication_template": "Dependency update for $asset_name",
            "pam_backend": "none", "pam_credential_path": None,
        },
        "quantum-crypto": {
            "change_type": "normal", "cadence": "on-demand",
            "maintenance_window": {"day_of_week": "daily", "start_time": "00:00", "end_time": "23:59", "timezone": "UTC"},
            "auto_remediate": False, "restart_required": True, "requires_approval_group": "Security-Architecture-Review",
            "downtime_expected": False, "communication_template": "Post-quantum crypto review for $asset_name",
            "pam_backend": "none", "pam_credential_path": None,
        },
        "default": {
            "change_type": "normal", "cadence": "quarterly",
            "maintenance_window": {"day_of_week": "saturday", "start_time": "22:00", "end_time": "23:59", "timezone": "UTC"},
            "auto_remediate": False, "restart_required": False, "requires_approval_group": "IT-Change-Approvers",
            "downtime_expected": False, "communication_template": "Scheduled remediation for $asset_name",
            "pam_backend": "none", "pam_credential_path": None,
        },
    },
}


def finding(**overrides):
    base = {
        "id": "FIND-TEST",
        "asset": {"name": "SOME-HOST", "type": "windows-server"},
        "infra_category": "os",
        "scan_type": None,
        "kev": None,
        "title": "Some Vulnerability",
        "cve": "CVE-2026-0001",
    }
    base.update(overrides)
    return base


class DomainResolution(unittest.TestCase):
    def test_infra_category_resolves_to_matching_domain(self):
        f = finding(infra_category="endpoint")
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "endpoint")
        self.assertEqual(policy["change_type"], "standard")

    def test_scan_type_used_when_infra_category_absent(self):
        f = finding(infra_category=None, scan_type="os")
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "os")

    def test_unknown_domain_falls_back_to_default(self):
        f = finding(infra_category="something-unmapped", scan_type=None)
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "default")

    def test_dev_environment_tag_wins_over_infra_category(self):
        f = finding(infra_category="os")
        policy = policy_for_finding(f, BASE_RULES, environment="dev")
        self.assertEqual(policy["domain"], "dev")

    def test_non_dev_environment_does_not_override_infra_category(self):
        f = finding(infra_category="endpoint")
        policy = policy_for_finding(f, BASE_RULES, environment="prod")
        self.assertEqual(policy["domain"], "endpoint")

    def test_dev_environment_without_a_dev_policy_falls_through_normally(self):
        rules = {**BASE_RULES, "policies": {k: v for k, v in BASE_RULES["policies"].items() if k != "dev"}}
        f = finding(infra_category="endpoint")
        policy = policy_for_finding(f, rules, environment="dev")
        self.assertEqual(policy["domain"], "endpoint")

    def test_dev_environment_tag_wins_over_scan_type_too(self):
        """The dev override is checked before infra_category OR scan_type - this is the
        exact path an application/code-repository finding takes (no infra_category, a
        scan_type like "sca" instead), so a dev-tagged application asset must route to
        the dev policy domain exactly like a dev-tagged server does. Previously only
        the infra_category path was covered by a test - this closes that gap."""
        f = finding(infra_category=None, scan_type="sca", asset={"name": "APP-DEV01", "type": "application"})
        policy = policy_for_finding(f, BASE_RULES, environment="dev")
        self.assertEqual(policy["domain"], "dev")

    def test_non_dev_environment_does_not_override_scan_type_either(self):
        f = finding(infra_category=None, scan_type="sca", asset={"name": "APP-PROD01", "type": "application"})
        policy = policy_for_finding(f, BASE_RULES, environment="prod")
        self.assertEqual(policy["domain"], "sca")


class QuantumCryptoDomainOverride(unittest.TestCase):
    """A real quantum_readiness classification (remediation/enrichment/
    quantum_readiness.py) cuts across normal infra_category/scan_type classification,
    same override-precedence pattern already proven for the "dev" environment tag."""

    def test_asymmetric_crypto_wins_over_infra_category(self):
        f = finding(infra_category="os", quantum_readiness={"category": "asymmetric-crypto"})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "quantum-crypto")
        self.assertEqual(policy["requires_approval_group"], "Security-Architecture-Review")

    def test_asymmetric_crypto_wins_over_scan_type(self):
        f = finding(infra_category=None, scan_type="sca", quantum_readiness={"category": "asymmetric-crypto"})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "quantum-crypto")

    def test_legacy_protocol_category_also_routes_to_quantum_crypto_domain(self):
        """Both quantum_readiness categories (see that module's own docstring on why
        they're distinct) share the same real operational treatment - a legacy TLS
        stack needs the same security-architecture review as bare RSA/ECDSA usage,
        not a routine patch cadence."""
        f = finding(infra_category="os", quantum_readiness={"category": "legacy-protocol"})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "quantum-crypto")

    def test_no_quantum_readiness_falls_through_to_infra_category_normally(self):
        f = finding(infra_category="os", quantum_readiness=None)
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["domain"], "os")

    def test_dev_environment_still_wins_over_quantum_readiness(self):
        f = finding(infra_category="os", quantum_readiness={"category": "asymmetric-crypto"})
        policy = policy_for_finding(f, BASE_RULES, environment="dev")
        self.assertEqual(policy["domain"], "dev")

    def test_quantum_readiness_present_but_no_quantum_crypto_policy_falls_through(self):
        rules = {**BASE_RULES, "policies": {k: v for k, v in BASE_RULES["policies"].items() if k != "quantum-crypto"}}
        f = finding(infra_category="os", quantum_readiness={"category": "asymmetric-crypto"})
        policy = policy_for_finding(f, rules)
        self.assertEqual(policy["domain"], "os")


class AssetScheduleOverride(unittest.TestCase):
    """Per-asset remediation_schedule (remediation/inventory/asset_inventory.py's
    set_remediation_schedule(), threaded through by dashboard/data.py) wins over the
    resolved domain's own default cadence/maintenance window - same
    override-precedence shape already proven for environment=='dev', just scoped to
    one asset instead of a whole domain."""

    def test_no_override_uses_domain_default(self):
        f = finding(infra_category="os")
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["cadence"], "monthly")
        self.assertFalse(policy["schedule_override"])

    def test_cadence_override_wins_over_domain_default(self):
        f = finding(infra_category="os")
        policy = policy_for_finding(f, BASE_RULES, asset_remediation_schedule={"cadence": "weekly", "maintenance_window": None})
        self.assertEqual(policy["cadence"], "weekly")
        self.assertTrue(policy["schedule_override"])
        # Maintenance window untouched since the override didn't set one.
        self.assertEqual(policy["maintenance_window"], BASE_RULES["policies"]["os"]["maintenance_window"])

    def test_maintenance_window_override_wins_over_domain_default(self):
        f = finding(infra_category="os")
        custom_window = {"day_of_week": "sunday", "start_time": "01:00", "end_time": "02:00", "timezone": "UTC"}
        policy = policy_for_finding(f, BASE_RULES, asset_remediation_schedule={"cadence": None, "maintenance_window": custom_window})
        self.assertEqual(policy["maintenance_window"], custom_window)
        self.assertTrue(policy["schedule_override"])
        # Cadence untouched since the override didn't set one.
        self.assertEqual(policy["cadence"], BASE_RULES["policies"]["os"]["cadence"])

    def test_none_asset_schedule_behaves_identically_to_no_argument(self):
        f = finding(infra_category="os")
        policy = policy_for_finding(f, BASE_RULES, asset_remediation_schedule=None)
        self.assertFalse(policy["schedule_override"])
        self.assertEqual(policy["cadence"], "monthly")


class KevEmergencyOverride(unittest.TestCase):
    def test_kev_listed_finding_escalates_to_emergency(self):
        f = finding(infra_category="endpoint", kev={"listed": True})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["change_type"], "emergency")
        self.assertTrue(policy["emergency_override"])

    def test_non_kev_finding_keeps_domain_default_change_type(self):
        f = finding(infra_category="endpoint", kev={"listed": False})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertEqual(policy["change_type"], "standard")
        self.assertFalse(policy["emergency_override"])

    def test_override_disabled_does_not_escalate(self):
        rules = {**BASE_RULES, "kev_emergency_override": {"enabled": False}}
        f = finding(infra_category="endpoint", kev={"listed": True})
        policy = policy_for_finding(f, rules)
        self.assertEqual(policy["change_type"], "standard")

    def test_already_emergency_domain_is_not_double_flagged(self):
        rules = {**BASE_RULES}
        rules["policies"] = {**BASE_RULES["policies"], "endpoint": {**BASE_RULES["policies"]["endpoint"], "change_type": "emergency"}}
        f = finding(infra_category="endpoint", kev={"listed": True})
        policy = policy_for_finding(f, rules)
        self.assertEqual(policy["change_type"], "emergency")
        self.assertFalse(policy["emergency_override"])  # already emergency on its own, not because of KEV

    def test_kev_override_forces_auto_remediate_off_even_if_domain_default_is_on(self):
        """The endpoint domain defaults to auto_remediate: True, but a KEV-listed finding
        escalated to emergency must never keep auto_remediate: True too - an emergency
        change is still a human-approved change (see docs/REMEDIATION_WORKFLOWS.md), and
        the Queue table would otherwise show contradictory Change Type/Auto-Remediate
        values on the same row (e.g. FIND-12, Log4Shell on a dev-tagged asset)."""
        f = finding(infra_category="endpoint", kev={"listed": True})
        policy = policy_for_finding(f, BASE_RULES)
        self.assertTrue(BASE_RULES["policies"]["endpoint"]["auto_remediate"])  # sanity: domain default is True
        self.assertEqual(policy["change_type"], "emergency")
        self.assertFalse(policy["auto_remediate"])


class NextMaintenanceWindow(unittest.TestCase):
    def test_daily_window_returns_as_of_date(self):
        window = {"day_of_week": "daily", "start_time": "01:00", "end_time": "05:00", "timezone": "UTC"}
        result = next_maintenance_window(window, as_of=datetime.date(2026, 8, 5))  # a Wednesday
        self.assertEqual(result["date"], "2026-08-05")

    def test_specific_weekday_rolls_forward_to_next_occurrence(self):
        window = {"day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}
        result = next_maintenance_window(window, as_of=datetime.date(2026, 8, 5))  # Wednesday -> next Saturday
        self.assertEqual(result["date"], "2026-08-08")
        self.assertEqual(result["day_of_week"], "saturday")

    def test_as_of_date_that_already_is_the_target_weekday_returns_today(self):
        window = {"day_of_week": "wednesday", "start_time": "02:00", "end_time": "04:00", "timezone": "UTC"}
        result = next_maintenance_window(window, as_of=datetime.date(2026, 8, 5))  # itself a Wednesday
        self.assertEqual(result["date"], "2026-08-05")


class CommunicationRendering(unittest.TestCase):
    def test_known_placeholders_are_substituted(self):
        window = {"day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}
        f = finding(asset={"name": "WIN-DC01", "type": "windows-server"}, title="PrintNightmare", cve="CVE-2021-34527")
        rendered = render_communication(
            "Maintenance for $asset_name: $title ($cve) $window_day $window_start-$window_end $timezone, approved by $approved_by",
            f, window, approved_by="alice@example.com",
        )
        self.assertIn("WIN-DC01", rendered)
        self.assertIn("PrintNightmare", rendered)
        self.assertIn("CVE-2021-34527", rendered)
        self.assertIn("alice@example.com", rendered)

    def test_missing_approver_defaults_to_pending(self):
        window = {"day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}
        rendered = render_communication("Approved by $approved_by", finding(), window)
        self.assertIn("pending approval", rendered)

    def test_unknown_placeholder_is_left_literal_instead_of_raising(self):
        window = {"day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}
        rendered = render_communication("Value: $not_a_real_placeholder", finding(), window)
        self.assertEqual(rendered, "Value: $not_a_real_placeholder")


class PamVarsSnippet(unittest.TestCase):
    def test_vault_backend_references_real_collection_and_path(self):
        snippet = pam_vars_snippet("vault", "secret/servers/admin-credentials")
        self.assertIn("community.hashi_vault.vault_kv2_get", snippet)
        self.assertIn("secret/servers/admin-credentials", snippet)

    def test_cyberark_pas_backend_references_real_collection_and_path(self):
        snippet = pam_vars_snippet("cyberark-pas", "ServersSafe")
        self.assertIn("cyberark.pas.cyberark_credential", snippet)
        self.assertIn("ServersSafe", snippet)

    def test_cyberark_conjur_backend_references_real_collection_and_path(self):
        snippet = pam_vars_snippet("cyberark-conjur", "servers/admin-credentials")
        self.assertIn("cyberark.conjur.conjur_variable", snippet)
        self.assertIn("servers/admin-credentials", snippet)

    def test_none_backend_returns_none(self):
        self.assertIsNone(pam_vars_snippet("none", None))

    def test_aws_sts_assume_role_backend_references_real_module_and_role_arn(self):
        snippet = pam_vars_snippet("aws-sts-assume-role", "arn:aws:iam::123456789012:role/VulnHunterRemediationRole")
        self.assertIn("amazon.aws.sts_assume_role", snippet)
        self.assertIn("arn:aws:iam::123456789012:role/VulnHunterRemediationRole", snippet)

    def test_azure_managed_identity_backend_references_real_collection_and_target(self):
        snippet = pam_vars_snippet("azure-managed-identity", "/subscriptions/xxx/resourceGroups/rg1")
        self.assertIn("azure.azcollection", snippet)
        self.assertIn("azure_managed_identity", snippet)
        self.assertIn("/subscriptions/xxx/resourceGroups/rg1", snippet)

    def test_gcp_workload_identity_backend_references_real_collection_and_service_account(self):
        snippet = pam_vars_snippet("gcp-workload-identity", "vulnhunter@project.iam.gserviceaccount.com")
        self.assertIn("google.cloud", snippet)
        self.assertIn("vulnhunter@project.iam.gserviceaccount.com", snippet)


# Every real infra_category/scan_type value this app's own taxonomy produces (see
# remediation/enrichment/infra_classification.py and scan_type_mapping.py) - the full
# taxonomy expansion this round added a tuned domain for, so 0 real findings should ever
# fall through to "default" anymore.
ALL_REAL_DOMAINS = (
    "endpoint", "os", "dev", "network", "network-security", "ot", "virtualization",
    "cloud", "apps", "printer", "iac", "runtime", "sca", "dast", "cert-mgmt", "secrets",
    "ai-ml", "quantum-crypto", "default",
)


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_rules_file_loads_and_has_expected_top_level_keys(self):
        rules = load_rules(DEFAULT_RULES_PATH)
        self.assertIn("kev_emergency_override", rules)
        self.assertIn("policies", rules)
        for domain in ALL_REAL_DOMAINS:
            self.assertIn(domain, rules["policies"], f"remediation_policy.yaml missing domain '{domain}'")
        for domain, policy in rules["policies"].items():
            for field in ("change_type", "cadence", "maintenance_window", "auto_remediate",
                          "requires_approval_group", "downtime_expected", "communication_template",
                          "pam_backend", "pam_credential_path"):
                self.assertIn(field, policy, f"domain '{domain}' missing field '{field}'")
            self.assertIn(policy["change_type"], ("standard", "normal", "emergency"),
                          f"domain '{domain}' has an invalid change_type")

    def test_real_rules_file_resolves_a_known_finding_as_expected(self):
        """Regression guard using our own real sample data - PrintNightmare (KEV-listed,
        windows-server/infra-vm) should always come out change_type emergency against
        the real shipped policy file via the KEV override, however else it's tuned."""
        import json
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        by_id = {f["id"]: f for f in findings}
        rules = load_rules(DEFAULT_RULES_PATH)
        policy = policy_for_finding(by_id["FIND-1"], rules)  # PrintNightmare on WIN-DC01
        self.assertEqual(policy["change_type"], "emergency")
        self.assertTrue(policy["emergency_override"])

    def test_real_diffie_hellman_finding_resolves_to_the_quantum_crypto_domain(self):
        """Regression guard using our own real sample data - CVE-2011-5095 (a real,
        already-shipped Diffie-Hellman finding) should route to the quantum-crypto
        domain against the real shipped policy file once tagged, cutting across
        whatever its own infra_category/scan_type would otherwise resolve to."""
        import json
        from remediation.enrichment.quantum_readiness import tag_quantum_readiness

        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        tagged = tag_quantum_readiness(findings)
        by_cve = {f["cve"]: f for f in tagged if f.get("cve")}
        rules = load_rules(DEFAULT_RULES_PATH)
        policy = policy_for_finding(by_cve["CVE-2011-5095"], rules)
        self.assertEqual(policy["domain"], "quantum-crypto")
        self.assertEqual(policy["requires_approval_group"], "Security-Architecture-Review")

    def test_secrets_domain_is_emergency_by_default_not_via_kev_override(self):
        """A leaked-credential finding is treated as an assumed compromise regardless of
        KEV status - the secrets domain's own change_type is emergency, independent of
        the kev_emergency_override mechanism (which only escalates non-emergency domains)."""
        rules = load_rules(DEFAULT_RULES_PATH)
        f = finding(infra_category=None, scan_type="secrets", kev=None)
        policy = policy_for_finding(f, rules)
        self.assertEqual(policy["domain"], "secrets")
        self.assertEqual(policy["change_type"], "emergency")
        self.assertFalse(policy["emergency_override"])  # emergency on its own, not because of KEV

    def test_every_real_domain_resolves_via_the_real_shipped_file(self):
        """Every one of this app's own real infra_category/scan_type values (the full
        taxonomy this round added a domain for) must resolve to its own named domain
        against the real shipped policy file, not silently fall through to 'default'."""
        rules = load_rules(DEFAULT_RULES_PATH)
        real_category_domains = ("network", "network-security", "ot", "virtualization", "cloud",
                                  "apps", "printer", "iac", "runtime", "sca", "dast", "cert-mgmt",
                                  "secrets", "ai-ml")
        for domain in real_category_domains:
            f = finding(infra_category=domain, scan_type=None, kev=None)
            policy = policy_for_finding(f, rules)
            self.assertEqual(policy["domain"], domain, f"{domain} unexpectedly fell through to {policy['domain']!r}")


if __name__ == "__main__":
    unittest.main()
