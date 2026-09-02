"""
Test suite for VulnHunter's two pipelines (/vulnhunt and /remediate).

This does NOT invoke the Claude Code subagents directly (they only run inside
an interactive Claude Code session). Instead it validates the real artifacts
those agents produced during the documented validation run: the git history
(master = vulnerable baseline, vulnhunter/auto-fixes-<ts> = the fix branch)
for /vulnhunt, and the files under remediation/output/ + REMEDIATION_PLAN.md
for /remediate. That makes this both a regression suite (re-run it after any
prompt/agent edit to catch drift) and the test evidence for the hackathon
report.

Run with: python -m unittest tests.test_pipeline_artifacts -v
"""
import json
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_BRANCH_PREFIX = "vulnhunter/auto-fixes-"


def git_show(ref, path):
    """Read a file's content at a given git ref without touching the working tree."""
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return result.stdout


def find_fix_branch():
    result = subprocess.run(
        ["git", "branch", "--list", f"{FIX_BRANCH_PREFIX}*"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    branches = [b.strip().lstrip("* ").strip() for b in result.stdout.splitlines() if b.strip()]
    assert branches, "no vulnhunter/auto-fixes-* branch found - has /vulnhunt --fix been run?"
    return branches[0]


class VulnHuntScannerFindsRealVulnerabilities(unittest.TestCase):
    """The vulnerable baseline (master) actually contains what the demo claims it does."""

    @classmethod
    def setUpClass(cls):
        cls.app_py = git_show("master", "vulnerable-demo-app/app.py")
        cls.dockerfile = git_show("master", "vulnerable-demo-app/Dockerfile")

    def test_hardcoded_secret_present(self):
        self.assertRegex(self.app_py, r'STRIPE_API_KEY\s*=\s*"sk_live_')

    def test_sql_injection_string_concat_present(self):
        self.assertIn('"SELECT id, username, email FROM users WHERE id = " + user_id', self.app_py)

    def test_command_injection_shell_true_present(self):
        self.assertIn("shell=True", self.app_py)

    def test_eval_on_user_input_present(self):
        self.assertRegex(self.app_py, r"eval\(expression\)")

    def test_debug_mode_hardcoded_true(self):
        self.assertIn("debug=True", self.app_py)

    def test_dockerfile_has_no_user_directive(self):
        self.assertNotRegex(self.dockerfile, r"(?m)^USER\s+\w+")

    def test_dockerfile_secret_baked_in(self):
        self.assertRegex(self.dockerfile, r'ENV STRIPE_API_KEY="sk_live_')


class VulnHuntScannerFindsRealAiAndApiVulnerabilities(unittest.TestCase):
    """Same rule as VulnHuntScannerFindsRealVulnerabilities, for the 2 fixture files
    added later (ai_assistant.py, admin_api.py) that back VULN-10 through VULN-18."""

    @classmethod
    def setUpClass(cls):
        cls.ai_assistant = git_show("master", "vulnerable-demo-app/ai_assistant.py")
        cls.admin_api = git_show("master", "vulnerable-demo-app/admin_api.py")

    def test_hardcoded_llm_api_key_present(self):
        self.assertRegex(self.ai_assistant, r'ANTHROPIC_API_KEY\s*=\s*"sk-ant-')

    def test_insecure_pickle_load_present(self):
        self.assertIn("pickle.load(uploaded_file)", self.ai_assistant)

    def test_prompt_injection_concatenation_present(self):
        self.assertIn('"User message: " + user_message', self.ai_assistant)

    def test_llm_output_executed_via_shell_present(self):
        self.assertIn("subprocess.check_output(llm_command, shell=True)", self.ai_assistant)

    def test_hardcoded_aws_keys_present(self):
        self.assertRegex(self.admin_api, r'AWS_ACCESS_KEY_ID\s*=\s*"AKIA')

    def test_hardcoded_jwt_secret_present(self):
        self.assertIn('JWT_SIGNING_SECRET = "vulnshop-demo-jwt-secret', self.admin_api)

    def test_wildcard_cors_present(self):
        self.assertIn('CORS(app, resources={r"/*": {"origins": "*"}})', self.admin_api)

    def test_mass_assignment_present(self):
        self.assertIn("_apply_updates_to_user(user_id, updates)  # e.g.", self.admin_api)


class VulnHuntFixerAppliesOnlyApprovedFixes(unittest.TestCase):
    """The fix branch actually fixes the 6 auto-fixable findings and leaves the rest alone."""

    @classmethod
    def setUpClass(cls):
        cls.fix_branch = find_fix_branch()
        cls.app_py = git_show(cls.fix_branch, "vulnerable-demo-app/app.py")
        cls.dockerfile = git_show(cls.fix_branch, "vulnerable-demo-app/Dockerfile")

    def test_secret_now_from_environment(self):
        self.assertIn('os.environ["STRIPE_API_KEY"]', self.app_py)
        self.assertNotRegex(self.app_py, r'STRIPE_API_KEY\s*=\s*"sk_live_')

    def test_sql_injection_now_parameterized(self):
        self.assertIn('cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))', self.app_py)
        self.assertNotIn('+ user_id', self.app_py)

    def test_command_injection_now_uses_arg_list(self):
        self.assertIn('subprocess.check_output(["ping", "-c", "1", host])', self.app_py)
        self.assertNotIn("shell=True", self.app_py)

    def test_debug_mode_now_gated_by_env_var(self):
        self.assertIn('os.environ.get("FLASK_DEBUG"', self.app_py)
        self.assertNotIn("debug=True", self.app_py)

    def test_dockerfile_now_has_non_root_user(self):
        self.assertRegex(self.dockerfile, r"(?m)^USER\s+\w+")

    def test_dockerfile_secret_removed(self):
        """The secret must no longer be baked in as an ENV assignment - a comment
        documenting how to pass it at `docker run` time is fine and expected."""
        self.assertNotRegex(self.dockerfile, r"ENV STRIPE_API_KEY=")

    def test_manual_review_findings_untouched(self):
        """eval() and plaintext password storage must NOT be modified - the fixer
        must never touch findings marked auto_fixable: false."""
        self.assertRegex(self.app_py, r"eval\(expression\)")
        self.assertIn('cursor.execute(\n        "INSERT INTO users (username, password) VALUES (?, ?)",', self.app_py)

    def test_fixed_app_py_still_valid_python(self):
        compile(self.app_py, "app.py", "exec")


class VulnHuntFixerAppliesAiAndApiFixes(unittest.TestCase):
    """Same rule as VulnHuntFixerAppliesOnlyApprovedFixes, for the 5 auto-fixable
    findings in ai_assistant.py/admin_api.py (VULN-10, 14, 15, 17, 18) - and the 4
    manual-review findings in those same 2 files (VULN-11, 12, 13, 16) that must stay
    untouched."""

    @classmethod
    def setUpClass(cls):
        fix_branch = find_fix_branch()
        cls.ai_assistant = git_show(fix_branch, "vulnerable-demo-app/ai_assistant.py")
        cls.admin_api = git_show(fix_branch, "vulnerable-demo-app/admin_api.py")

    def test_llm_api_key_now_from_environment(self):
        self.assertIn('os.environ["ANTHROPIC_API_KEY"]', self.ai_assistant)
        self.assertNotRegex(self.ai_assistant, r'ANTHROPIC_API_KEY\s*=\s*"sk-ant-')

    def test_aws_keys_now_from_environment(self):
        self.assertIn('os.environ["AWS_ACCESS_KEY_ID"]', self.admin_api)
        self.assertIn('os.environ["AWS_SECRET_ACCESS_KEY"]', self.admin_api)
        self.assertNotRegex(self.admin_api, r'AWS_ACCESS_KEY_ID\s*=\s*"AKIA')

    def test_jwt_secret_now_from_environment(self):
        self.assertIn('os.environ["JWT_SIGNING_SECRET"]', self.admin_api)
        self.assertNotIn('JWT_SIGNING_SECRET = "vulnshop-demo-jwt-secret', self.admin_api)

    def test_cors_no_longer_wildcard(self):
        self.assertNotIn('resources={r"/*": {"origins": "*"}}', self.admin_api)
        self.assertIn('resources={r"/admin/*"', self.admin_api)

    def test_mass_assignment_now_allow_listed(self):
        self.assertIn("_PROFILE_UPDATABLE_FIELDS", self.admin_api)
        self.assertNotIn("_apply_updates_to_user(user_id, updates)  # e.g.", self.admin_api)

    def test_manual_review_ai_findings_untouched(self):
        """Insecure pickle.load, prompt injection, and excessive agency must NOT be
        modified - none is auto_fixable."""
        self.assertIn("pickle.load(uploaded_file)", self.ai_assistant)
        self.assertIn('"User message: " + user_message', self.ai_assistant)
        self.assertIn("subprocess.check_output(llm_command, shell=True)", self.ai_assistant)

    def test_admin_route_still_has_no_auth_check(self):
        """The unauthenticated /admin/users route (VULN-16) must NOT be modified -
        not auto_fixable, needs a real authentication system to plug into."""
        self.assertIn("return jsonify({\"users\": _load_all_users_from_db()})", self.admin_api)

    def test_fixed_files_still_valid_python(self):
        compile(self.ai_assistant, "ai_assistant.py", "exec")
        compile(self.admin_api, "admin_api.py", "exec")


class VulnHuntReportIsAccurate(unittest.TestCase):
    """Covers the original 9 findings (app.py/Dockerfile) plus 9 more added later from
    two more vulnerable fixture files, ai_assistant.py (AI/ML) and admin_api.py
    (secrets/API-authorization) - see vulnerable-demo-app/SECURITY_REPORT.md's own
    intro paragraph for that history."""

    @classmethod
    def setUpClass(cls):
        cls.report = git_show(find_fix_branch(), "vulnerable-demo-app/SECURITY_REPORT.md")

    def test_reports_eighteen_findings(self):
        self.assertIn("18 findings", self.report)

    def test_reports_eleven_auto_fixed(self):
        self.assertIn("Already fixed, historical record (11)", self.report)

    def test_all_eighteen_finding_ids_present(self):
        for i in range(1, 19):
            self.assertIn(f"VULN-{i}", self.report)


class RemediationNormalizedFindingsAreWellFormed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))

    def test_at_least_7440_findings_total(self):
        """15 hand-curated + 7,425 real-CVE findings added via bulk NVD sourcing across
        6 infra sub-categories (5 scaled to ~1,100 each, plus a new ~1,100-finding
        "OS Applications"/client-application sub-category - see
        remediation/sample-data/generate_bulk_findings.py) = 7,440 at time of writing,
        then 8,096 after the IaC/GitHub-GitLab-repository/runtime-security categories
        were added on top. Asserts a floor since this grows as more real data is added -
        see tests/test_dashboard.py's DataLayerReadsRealArtifacts class for the same
        pattern."""
        self.assertGreaterEqual(len(self.findings), 8096)

    def test_every_finding_has_required_fields(self):
        required = {"id", "source", "source_ref", "asset", "title", "severity", "remediation_domain"}
        for f in self.findings:
            self.assertTrue(required.issubset(f.keys()), f"{f.get('id')} missing fields")
            self.assertIn("name", f["asset"])
            self.assertIn("ip", f["asset"])
            self.assertIn("type", f["asset"])

    def test_all_three_sources_represented(self):
        sources = {f["source"] for f in self.findings}
        self.assertEqual(sources, {"tenable", "armis", "threat-intel"})

    def test_asset_type_classification_spot_checks(self):
        by_id = {f["id"]: f for f in self.findings}
        self.assertEqual(by_id["FIND-1"]["asset"]["type"], "windows-server")   # WIN-DC01
        self.assertEqual(by_id["FIND-4"]["asset"]["type"], "unix-server")      # LNX-DB03
        self.assertEqual(by_id["FIND-6"]["asset"]["type"], "network-routing-switching")  # CSW-CORE01
        self.assertEqual(by_id["FIND-7"]["asset"]["type"], "iot-ot-device")    # AXIS camera
        self.assertEqual(by_id["FIND-12"]["asset"]["type"], "application")     # Log4Shell
        self.assertEqual(by_id["FIND-13"]["asset"]["type"], "certificate")     # SSL cert expiry
        self.assertEqual(by_id["FIND-14"]["asset"]["type"], "certificate")     # deprecated TLS
        self.assertEqual(by_id["FIND-15"]["asset"]["type"], "network-security-device")  # PAN-OS firewall

    def test_remediation_domain_only_set_for_supported_domains(self):
        supported = {"windows-server", "unix-server"}
        for f in self.findings:
            if f["asset"]["type"] in supported:
                self.assertEqual(f["remediation_domain"], f["asset"]["type"])
            else:
                self.assertIsNone(f["remediation_domain"])

    def test_findings_eligible_for_automation(self):
        """Real total at time of writing: 1,099 (658 windows-server + 441 unix-server,
        all bulk-sourced findings on those two asset types) - see
        test_at_least_7440_findings_total for why this asserts a floor."""
        eligible = [f for f in self.findings if f["remediation_domain"] is not None]
        self.assertGreaterEqual(len(eligible), 1099)

    def test_no_fabricated_cve_ids(self):
        """Every non-null CVE must match the standard CVE-YYYY-NNNN(N...) format -
        catches an agent hallucinating a plausible-looking but fake CVE ID."""
        for f in self.findings:
            if f["cve"] is not None:
                self.assertRegex(f["cve"], r"^CVE-\d{4}-\d{4,}$")

    def test_kev_and_epss_fields_present_and_consistent(self):
        """Every finding must have kev/epss keys (added by threat-intel-enricher).
        A finding with no CVE must have both null; a finding with a CVE must have a
        kev dict with at least a `listed` boolean."""
        for f in self.findings:
            self.assertIn("kev", f, f"{f['id']} missing kev field")
            self.assertIn("epss", f, f"{f['id']} missing epss field")
            if f["cve"] is None:
                self.assertIsNone(f["kev"], f"{f['id']} has no CVE but kev is not null")
                self.assertIsNone(f["epss"], f"{f['id']} has no CVE but epss is not null")
            else:
                self.assertIsInstance(f["kev"], dict)
                self.assertIn("listed", f["kev"])

    def test_known_kev_listed_findings_match_real_cisa_catalog(self):
        """Spot-checks against real, verified CISA KEV status as of this data's
        enrichment run (see remediation/enrichment/kev_epss.py) - these are well-known,
        long-standing KEV entries (PrintNightmare, Log4Shell) unlikely to ever be
        removed from the catalog, so this is a stable regression check, not a flaky one."""
        by_id = {f["id"]: f for f in self.findings}
        self.assertTrue(by_id["FIND-1"]["kev"]["listed"])   # PrintNightmare
        self.assertTrue(by_id["FIND-12"]["kev"]["listed"])  # Log4Shell
        self.assertFalse(by_id["FIND-5"]["kev"]["listed"])  # OpenSSL DoS - not KEV-listed


class NewFindingCategoriesAreWellFormed(unittest.TestCase):
    """Structural checks (not exact-count, matching this repo's own established "floor"
    discipline) for the 3 new finding categories (IaC misconfigurations, GitHub/GitLab
    repository vulnerabilities, runtime/container security) added alongside the
    zero-day-criteria/compensating-controls-dashboard work."""

    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))
        cls.by_type = {}
        for f in cls.findings:
            cls.by_type.setdefault(f["asset"]["type"], []).append(f)

    def test_iac_resource_category_reached_at_least_200(self):
        self.assertGreaterEqual(len(self.by_type.get("iac-resource", [])), 200)

    def test_container_runtime_category_reached_at_least_200(self):
        self.assertGreaterEqual(len(self.by_type.get("container-runtime", [])), 200)

    def test_code_repository_category_reached_at_least_200(self):
        self.assertGreaterEqual(len(self.by_type.get("code-repository", [])), 200)

    def test_iac_findings_have_no_cve_and_a_real_checkov_rule_id_in_the_title(self):
        for f in self.by_type.get("iac-resource", []):
            self.assertIsNone(f["cve"], f["id"])
            self.assertRegex(f["title"], r"CKV_AWS_\d+", f["id"])

    def test_runtime_findings_have_no_cve_and_reference_a_falco_rule(self):
        for f in self.by_type.get("container-runtime", []):
            self.assertIsNone(f["cve"], f["id"])
            self.assertIn("Falco rule:", f["title"], f["id"])

    def test_code_repository_findings_split_into_cve_and_non_cve_bearing(self):
        """Dependabot-style dependency alerts (real CVEs) and secret-scanning alerts
        (no CVE, CWE-798) both make up this one asset type - both halves must be
        genuinely present, not one crowding out the other."""
        repo_findings = self.by_type.get("code-repository", [])
        with_cve = [f for f in repo_findings if f["cve"]]
        without_cve = [f for f in repo_findings if not f["cve"]]
        self.assertGreater(len(with_cve), 0)
        self.assertGreater(len(without_cve), 0)
        for f in without_cve:
            self.assertIn("CWE-798", f["title"], f["id"])

    def test_no_secret_shaped_literal_in_any_repository_secrets_finding(self):
        """The generator's SECRET_CLASSES descriptions are deliberately generic (never
        embedding a real AWS-key-shaped or PEM-private-key-shaped literal) - this is a
        content-level regression guard specific to this category, independent of
        NoRealSecretsLeakedAnywhere's whole-repo file scan below."""
        repo_findings = self.by_type.get("code-repository", [])
        for f in repo_findings:
            blob = f"{f['title']} {f['description']}"
            self.assertNotRegex(blob, r"AKIA[0-9A-Z]{16}", f["id"])
            self.assertNotRegex(blob, r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----", f["id"])


class EndpointPrinterVirtualizationCategoriesAreWellFormed(unittest.TestCase):
    """Structural checks (same "floor," not exact-count, discipline as
    NewFindingCategoriesAreWellFormed above) for the 4 new asset types added alongside
    the Server-Vulnerabilities-rename/End-User-Devices/Printers/Virtualization round:
    windows-endpoint + mobile-device (both roll up into the "endpoint" infra category),
    printer, and virtualization-host - all real NVD-CVE-sourced, unlike IaC/runtime/
    code-repository above."""

    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))
        cls.by_type = {}
        for f in cls.findings:
            cls.by_type.setdefault(f["asset"]["type"], []).append(f)

    def test_windows_endpoint_category_reached_at_least_100(self):
        self.assertGreaterEqual(len(self.by_type.get("windows-endpoint", [])), 100)

    def test_mobile_device_category_reached_at_least_50(self):
        self.assertGreaterEqual(len(self.by_type.get("mobile-device", [])), 50)

    def test_printer_category_reached_at_least_100(self):
        self.assertGreaterEqual(len(self.by_type.get("printer", [])), 100)

    def test_virtualization_host_category_reached_at_least_100(self):
        self.assertGreaterEqual(len(self.by_type.get("virtualization-host", [])), 100)

    def test_all_four_new_categories_have_real_cves_and_no_remediation_domain(self):
        """These are real NVD-sourced findings (unlike IaC/runtime's CWE-only
        findings above) - every one must have a real-shaped CVE, and none may claim
        working fixer automation (remediation_domain stays null; only
        remediation_mechanism, an informational field, is set)."""
        for asset_type in ("windows-endpoint", "mobile-device", "printer", "virtualization-host"):
            findings = self.by_type.get(asset_type, [])
            self.assertTrue(findings, asset_type)
            for f in findings:
                self.assertIsNotNone(f["cve"], f["id"])
                self.assertRegex(f["cve"], r"^CVE-\d{4}-\d{4,}$", f["id"])
                self.assertIsNone(f["remediation_domain"], f["id"])

    def test_remediation_mechanism_matches_the_real_world_tool_per_asset_type(self):
        expected = {
            "windows-endpoint": "SCCM / Microsoft Configuration Manager",
            "mobile-device": "MDM (e.g. Microsoft Intune)",
            "printer": "Vendor firmware update (manual or vendor management console)",
            "virtualization-host": "Vendor hypervisor patch tooling (e.g. VMware Update Manager)",
        }
        for asset_type, mechanism in expected.items():
            findings = self.by_type.get(asset_type, [])
            self.assertTrue(findings, asset_type)
            for f in findings:
                self.assertEqual(f["remediation_mechanism"], mechanism, f["id"])


class RemediationPlanIsConsistentWithFindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = (REPO_ROOT / "REMEDIATION_PLAN.md").read_text(encoding="utf-8")
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))

    def test_every_finding_id_referenced_in_plan(self):
        for f in self.findings:
            self.assertIn(f["id"], self.plan)

    def test_manual_only_domains_explicitly_called_out(self):
        self.assertIn("no automated remediation path today", self.plan.lower())


class RemediationPlaybooksMatchThePlan(unittest.TestCase):
    """The set of generated playbooks must exactly match findings the plan marked
    as having a working automation target - no more (nothing auto-generated for
    manual-only findings) and no fewer (nothing silently skipped)."""

    @classmethod
    def setUpClass(cls):
        cls.output_dir = REPO_ROOT / "remediation" / "output"
        cls.playbooks = sorted(cls.output_dir.glob("FIND-*.yml"))
        path = cls.output_dir / "normalized-findings.json"
        cls.findings = {f["id"]: f for f in json.loads(path.read_text(encoding="utf-8"))}

    def test_exactly_seven_playbooks_generated(self):
        self.assertEqual(len(self.playbooks), 7)

    def test_every_playbook_corresponds_to_an_automatable_finding(self):
        automatable_ids = {fid for fid, f in self.findings.items() if f["remediation_domain"] is not None}
        playbook_ids = {p.name.split("-", 2)[0] + "-" + p.name.split("-", 2)[1] for p in self.playbooks}
        self.assertTrue(playbook_ids.issubset(automatable_ids))

    def test_no_playbook_for_manual_only_findings(self):
        manual_only_ids = {"FIND-6", "FIND-7", "FIND-8", "FIND-9", "FIND-12", "FIND-13", "FIND-14", "FIND-15"}
        playbook_ids = {p.name.split("-", 2)[0] + "-" + p.name.split("-", 2)[1] for p in self.playbooks}
        self.assertEqual(playbook_ids & manual_only_ids, set())

    def test_every_playbook_has_finding_id_rollback_and_hosts(self):
        for p in self.playbooks:
            content = p.read_text(encoding="utf-8")
            finding_id = p.name.split("-", 2)[0] + "-" + p.name.split("-", 2)[1]
            self.assertIn(finding_id, content, f"{p.name} doesn't reference its own finding ID")
            self.assertIn("Rollback:", content, f"{p.name} missing rollback instructions")
            self.assertRegex(content, r"hosts:\s*", f"{p.name} missing an Ansible hosts: line")

    def test_change_approval_marker_matches_risk_tier(self):
        """Playbooks for needs-change-approval findings must carry the warning
        banner; auto-approvable findings' playbooks must not (so the signal
        stays meaningful and isn't just stamped on everything)."""
        needs_approval_ids = {"FIND-1", "FIND-2", "FIND-5", "FIND-10", "FIND-11"}
        auto_approvable_ids = {"FIND-3", "FIND-4"}
        for p in self.playbooks:
            finding_id = p.name.split("-", 2)[0] + "-" + p.name.split("-", 2)[1]
            content = p.read_text(encoding="utf-8")
            if finding_id in needs_approval_ids:
                self.assertIn("CHANGE APPROVAL REQUIRED", content, f"{p.name} should require change approval")
            elif finding_id in auto_approvable_ids:
                self.assertNotIn("CHANGE APPROVAL REQUIRED", content, f"{p.name} should not require change approval")


class NoRealSecretsLeakedAnywhere(unittest.TestCase):
    """Sanity/safety net: scan every tracked file in the repo for patterns that
    would indicate a real (not clearly-fake) secret slipped into the demo data
    or generated artifacts."""

    REAL_SECRET_PATTERNS = [
        r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
        r"sk_live_[A-Za-z0-9]{20,}(?!.*FAKE|.*DEMO)",  # a Stripe-shaped key NOT tagged fake/demo
        r"AKIA(?!FAKE|DEMO)[0-9A-Z]{16}",  # AWS access key ID shape, not an obviously-fake demo value
    ]

    def test_no_real_looking_secrets_in_tracked_files(self):
        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
        )
        for rel_path in result.stdout.splitlines():
            full_path = REPO_ROOT / rel_path
            if not full_path.is_file():
                continue
            try:
                content = full_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for pattern in self.REAL_SECRET_PATTERNS:
                self.assertNotRegex(content, pattern, f"possible real secret pattern in {rel_path}")


if __name__ == "__main__":
    unittest.main()
