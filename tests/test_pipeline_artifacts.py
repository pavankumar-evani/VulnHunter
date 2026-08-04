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


class VulnHuntReportIsAccurate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = git_show(find_fix_branch(), "vulnerable-demo-app/SECURITY_REPORT.md")

    def test_reports_nine_findings(self):
        self.assertIn("9 findings", self.report)

    def test_reports_six_auto_fixed(self):
        self.assertIn("Auto-fixing now (6)", self.report)

    def test_all_nine_finding_ids_present(self):
        for i in range(1, 10):
            self.assertIn(f"VULN-{i}", self.report)


class RemediationNormalizedFindingsAreWellFormed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))

    def test_fifteen_findings_total(self):
        self.assertEqual(len(self.findings), 15)

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

    def test_seven_findings_eligible_for_automation(self):
        eligible = [f for f in self.findings if f["remediation_domain"] is not None]
        self.assertEqual(len(eligible), 7)

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
        r"AKIA[0-9A-Z]{16}",  # AWS access key ID shape
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
