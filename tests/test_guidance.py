"""
Tests for the remediation guidance engine: the curated knowledge base is well-formed, findings are matched to
the right entry for the right reason, guidance is tailored with what Quanta knows about the finding, it says
plainly when nothing matches, and the API serves it.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from remediation.guidance import engine  # noqa: E402


def finding(**kw):
    f = {"id": "FIND-1", "title": "Something", "description": "", "severity": "High", "asset": {"name": "h1", "type": "unix-server"}}
    f.update(kw)
    return f


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.kb = engine.load_kb()

    def test_every_entry_is_complete(self):
        ids = [e["id"] for e in self.kb["entries"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate entry id")
        for e in self.kb["entries"]:
            for key in ("title", "summary", "why", "steps", "verify", "compensating", "effort", "references", "match"):
                self.assertTrue(e.get(key), f"{e['id']} is missing {key}")
            self.assertGreaterEqual(len(e["steps"]), 3, e["id"])
            for r in e["references"]:
                self.assertTrue(r["url"].startswith("https://"), (e["id"], r))
            for c in (e["match"].get("cwe") or []):
                self.assertRegex(c, r"^CWE-\d+$")

    def test_a_fallback_exists_and_is_labelled_generic(self):
        self.assertEqual(self.kb["fallback"]["id"], "generic")
        self.assertTrue(self.kb["fallback"]["steps"])

    def test_covers_every_category_the_product_is_asked_about(self):
        ids = {e["id"] for e in self.kb["entries"]}
        for needed in ("sql-injection", "xss", "command-injection", "hardcoded-secret", "vulnerable-dependency", "container-image",
                       "iac-misconfiguration", "cicd-pipeline", "test-coverage-gap", "os-patch", "network-device", "ot-device",
                       "cloud-misconfiguration", "tls-certificate", "security-headers", "broken-access-control"):
            self.assertIn(needed, ids)


class MatchingTests(unittest.TestCase):
    def matched(self, **kw):
        g = engine.build(finding(**kw), client_controls=False)
        return g["id"], g

    def test_cwe_wins(self):
        self.assertEqual(self.matched(cwe="CWE-89", title="Login query", asset={})[0], "sql-injection")
        self.assertEqual(self.matched(cwe="CWE-78", title="ping endpoint", asset={})[0], "command-injection")
        self.assertEqual(self.matched(title="Issue in code (CWE-79)", asset={})[0], "xss")

    def test_cwe_given_as_a_bare_number_or_a_list(self):
        self.assertEqual(engine.finding_cwes({"cwe": "89"}), ["CWE-89"])
        self.assertEqual(engine.finding_cwes({"cwe": ["CWE-22", "cwe-79"]}), ["CWE-22", "CWE-79"])

    def test_scan_type_and_keywords(self):
        self.assertEqual(self.matched(title="Hardcoded API key", scan_type="secrets", asset={"type": "code-repository"})[0], "hardcoded-secret")
        self.assertEqual(self.matched(title="Dockerfile runs as root", asset={"type": "container-runtime"})[0], "container-image")
        self.assertEqual(self.matched(title="Unpinned action used in GitHub Actions workflow", asset={"type": "code-repository"})[0], "cicd-pipeline")
        self.assertEqual(self.matched(title="Terraform: S3 bucket allows public access", asset={"type": "iac-resource"})[0], "iac-misconfiguration")
        self.assertEqual(self.matched(title="Code coverage below threshold on auth module", asset={})[0], "test-coverage-gap")

    def test_asset_type_routes_infrastructure(self):
        self.assertEqual(self.matched(title="Update available", asset={"type": "windows-server"}, description="Apply the security update KB5004945")[0], "os-patch")
        self.assertEqual(self.matched(title="Cisco IOS firmware flaw", asset={"type": "network-routing-switching"})[0], "network-device")
        self.assertEqual(self.matched(title="Controller firmware flaw", asset={"type": "iot-ot-device"})[0], "ot-device")

    def test_says_why_it_matched(self):
        _, g = self.matched(cwe="CWE-89", asset={})
        self.assertIn("CWE-89", g["matched_by"])

    def test_unknown_findings_get_the_generic_approach_not_a_guess(self):
        gid, g = self.matched(title="Zzyzx quark anomaly", description="nothing recognisable", asset={"type": "printer"})
        self.assertEqual(gid, "generic")
        self.assertFalse(g["curated"])
        self.assertIsNone(g["matched_by"])


class TailoringTests(unittest.TestCase):
    def test_dependency_details_become_a_concrete_upgrade(self):
        g = engine.build(finding(title="Vulnerable PyYAML", cve="CVE-2020-14343", asset={"name": "repo", "type": "code-repository"},
                                 dependency={"package": "pyyaml", "ecosystem": "pypi", "version": "5.3", "fixed_version": "5.4", "direct": True}),
                         client_controls=False)
        self.assertEqual(g["id"], "vulnerable-dependency")
        text = " ".join(g["tailored"])
        self.assertIn("the fixed version is 5.4", text)
        self.assertIn("pip install 'pyyaml>=5.4'", text)

    def test_a_transitive_dependency_is_called_out(self):
        g = engine.build(finding(title="x", cve="CVE-2021-1", asset={"type": "application"}, remediation_domain="application",
                                 dependency={"package": "lib", "ecosystem": "npm", "version": "1", "fixed_version": "2", "direct": False}),
                         client_controls=False)
        self.assertIn("transitive", " ".join(g["tailored"]))

    def test_windows_patch_gets_the_hotfix_check(self):
        g = engine.build(finding(title="PrintNightmare", cve="CVE-2021-34527", description="Apply KB5004945.",
                                 asset={"name": "WIN-DC01", "type": "windows-server", "os": "Windows Server 2019"}), client_controls=False)
        self.assertIn("Get-HotFix -Id KB5004945", " ".join(g["tailored"]))

    def test_linux_gets_a_package_check(self):
        g = engine.build(finding(title="openssl flaw", asset={"type": "unix-server", "os": "Ubuntu 22.04"}), client_controls=False)
        self.assertIn("dpkg -l", " ".join(g["tailored"]))

    def test_kev_epss_and_sla_raise_urgency(self):
        g = engine.build(finding(title="x", cve="CVE-2021-44228", kev={"listed": True, "due_date": "2021-12-24"}, epss={"score": 0.97},
                                 sla={"breached": True}), client_controls=False)
        text = " ".join(g["tailored"])
        self.assertIn("Known Exploited", text)
        self.assertIn("2021-12-24", text)
        self.assertIn("97%", text)
        self.assertIn("SLA deadline has already passed", text)

    def test_a_useless_vendor_line_is_not_presented_as_advice(self):
        g = engine.build(finding(title="x", recommended_fix="See vendor advisory for CVE-2021-1."), client_controls=False)
        self.assertFalse(g["vendor_solution"]["informative"])
        g = engine.build(finding(title="x", recommended_fix="Upgrade to version 2.4.58 or later."), client_controls=False)
        self.assertTrue(g["vendor_solution"]["informative"])

    def test_references_include_the_cwe_and_cve_pages(self):
        g = engine.build(finding(cwe="CWE-89", cve="CVE-2024-0001", asset={}), client_controls=False)
        urls = [r["url"] for r in g["references"]]
        self.assertIn("https://cwe.mitre.org/data/definitions/89.html", urls)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-0001", urls)

    def test_client_controls_are_used_only_when_recorded(self):
        f = finding(title="Exposed service", asset={"name": "app01", "type": "unix-server"})
        with patch("remediation.enrichment.control_coverage.assess_coverage", return_value={"has_data": False}):
            g = engine.build(f)
        self.assertIsNone(g["client_controls"])
        self.assertIn("security_controls.yaml", g["client_controls_note"])
        cov = {"has_data": True, "existing_coverage_pct": 60, "residual_risk_pct": 40, "recommended_controls": ["Enable EDR block mode"]}
        with patch("remediation.enrichment.control_coverage.assess_coverage", return_value=cov):
            g = engine.build(f)
        self.assertEqual((g["client_controls"]["existing_coverage_pct"], g["client_controls"]["recommended_controls"]), (60, ["Enable EDR block mode"]))

    def test_automation_is_described_honestly(self):
        a = engine.build(finding(remediation_domain="windows-server"), client_controls=False)["automation"]
        self.assertTrue(a["available"])
        self.assertIn("never runs", a["note"])
        self.assertEqual(engine.build(finding(remediation_domain="iot-ot-device"), client_controls=False)["automation"]["kind"], "isolation-plan")
        self.assertEqual(engine.build(finding(auto_fixable="Yes", asset={}), client_controls=False)["automation"]["kind"], "code-fix")
        none = engine.build(finding(asset={"type": "printer"}), client_controls=False)["automation"]
        self.assertFalse(none["available"])


class GuidanceApiTests(unittest.TestCase):
    def setUp(self):
        self.p = patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))
        self.p.start()
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        self.p.stop()

    def test_lookup_by_cwe_for_a_code_scan_row(self):
        r = self.client.get("/api/guidance", params={"cwe": "CWE-89", "title": "SQL injection in /user", "file": "app.py", "scan_type": "sast"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["id"], "sql-injection")
        self.assertGreaterEqual(len(body["steps"]), 3)
        self.assertIsNone(body["client_controls"])

    def test_a_queue_finding_has_guidance(self):
        r = self.client.get("/api/findings/FIND-1/guidance")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["steps"])

    def test_unknown_finding_is_404(self):
        self.assertEqual(self.client.get("/api/findings/FIND-NOPE/guidance").status_code, 404)


if __name__ == "__main__":
    unittest.main()
