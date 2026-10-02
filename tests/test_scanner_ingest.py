"""
Tests for the scanner ingest layer: the SARIF adapter (SAST, DAST, SCA, secrets, IaC, container, pipeline tools),
the CI/CD pipeline checks, test-coverage ingest, and the API routes that carry them.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.enrichment.scan_type_mapping import classify_finding  # noqa: E402
from remediation.ingest import coverage, merge, sarif  # noqa: E402
from remediation.scanners import cicd  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"


def sarif_doc(tool, results, rules=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool, "rules": rules or []}}, "results": results}]}


def result(rule, msg="Problem", uri="src/app.py", line=10, level="warning", snippet="query = 'SELECT ' + name", **kw):
    r = {"ruleId": rule, "level": level, "message": {"text": msg},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line, "snippet": {"text": snippet}}}}]}
    r.update(kw)
    return r


class SarifTests(unittest.TestCase):
    def parse(self, doc, **kw):
        return sarif.parse(doc, kw.pop("source", "scan"), today="2026-10-01", **kw)

    def test_a_sast_result_becomes_a_finding_with_location_cwe_and_severity(self):
        rules = [{"id": "python.sqli", "shortDescription": {"text": "SQL injection"}, "help": {"text": "Use parameterized queries."},
                  "properties": {"tags": ["security", "external/cwe/cwe-89"], "security-severity": "8.1"}}]
        (f,), skipped = self.parse(sarif_doc("Semgrep OSS", [result("python.sqli")], rules), asset="shop-api")
        self.assertEqual((f["scan_type"], f["severity"], f["cvss"], f["cwe"]), ("sast", "High", 8.1, ["CWE-89"]))
        self.assertEqual((f["location"]["file"], f["location"]["line"]), ("src/app.py", 10))
        self.assertEqual((f["asset"]["name"], f["asset"]["type"]), ("shop-api", "code-repository"))
        self.assertEqual(f["recommended_fix"], "Use parameterized queries.")
        self.assertEqual(f["title"], "SQL injection")

    def test_severity_from_level_when_there_is_no_score(self):
        for level, want in (("error", "High"), ("warning", "Medium"), ("note", "Low")):
            (f,), _ = self.parse(sarif_doc("Semgrep", [result("r", level=level)]))
            self.assertEqual(f["severity"], want)

    def test_scan_type_is_inferred_from_the_tool_and_can_be_overridden(self):
        cases = (("OWASP ZAP", "dast"), ("gitleaks", "secrets"), ("Checkov", "iac"), ("Hadolint", "container"), ("actionlint", "cicd"),
                 ("Grype", "sca"), ("CodeQL", "sast"), ("Trivy", "container"), ("some unknown tool", "sast"))
        for tool, want in cases:
            (f,), _ = self.parse(sarif_doc(tool, [result("r")]))
            self.assertEqual(f["scan_type"], want, tool)
        (f,), _ = self.parse(sarif_doc("some unknown tool", [result("r")]), scan_type="iac")
        self.assertEqual(f["scan_type"], "iac")
        with self.assertRaises(sarif.SarifError):
            self.parse(sarif_doc("x", [result("r")]), scan_type="nonsense")

    def test_dast_uses_the_host_as_the_asset_and_keeps_the_url(self):
        (f,), _ = self.parse(sarif_doc("OWASP ZAP", [result("10202", uri="https://shop.example.com/login", snippet="")]))
        self.assertEqual((f["asset"]["name"], f["asset"]["type"], f["location"]["url"]), ("shop.example.com", "application", "https://shop.example.com/login"))
        self.assertIsNone(f["location"]["file"])

    def test_a_cve_from_a_dependency_tool_becomes_sca_with_the_dependency(self):
        r = result("CVE-2024-1234", msg="pyyaml 5.3 has a flaw", uri="requirements.txt",
                   properties={"package": "pyyaml", "ecosystem": "pypi", "installedVersion": "5.3", "fixedVersion": "5.4"})
        (f,), _ = self.parse(sarif_doc("Grype", [r]), asset="shop-api")
        self.assertEqual((f["scan_type"], f["cve"], f["asset"]["type"], f["remediation_domain"]), ("sca", "CVE-2024-1234", "application", "application"))
        self.assertEqual((f["dependency"]["package"], f["dependency"]["fixed_version"]), ("pyyaml", "5.4"))

    def test_image_scanner_cves_stay_container_findings(self):
        (f,), _ = self.parse(sarif_doc("Trivy", [result("CVE-2024-9999", uri="Dockerfile")]), asset="registry/app:1.0")
        self.assertEqual((f["scan_type"], f["asset"]["type"], f["remediation_domain"]), ("container", "container-runtime", None))

    def test_suppressed_and_non_failing_results_are_skipped(self):
        doc = sarif_doc("Semgrep", [result("a", suppressions=[{"kind": "inSource"}]), result("b", kind="pass"), result("c")])
        findings, skipped = self.parse(doc)
        self.assertEqual(len(findings), 1)
        self.assertEqual((skipped["suppressed"], skipped["not_a_failure"]), (1, 1))

    def test_identity_survives_a_moved_line_but_not_different_code(self):
        (a,), _ = self.parse(sarif_doc("Semgrep", [result("r", line=10)]))
        (b,), _ = self.parse(sarif_doc("Semgrep", [result("r", line=42)]))
        (c,), _ = self.parse(sarif_doc("Semgrep", [result("r", snippet="something else entirely")]))
        self.assertEqual(a["source_ref"], b["source_ref"])
        self.assertNotEqual(a["source_ref"], c["source_ref"])

    def test_a_tool_fingerprint_wins(self):
        (f,), _ = self.parse(sarif_doc("CodeQL", [result("r", partialFingerprints={"primaryLocationLineHash": "abc123"})]))
        self.assertEqual(f["source_ref"], "r:abc123")

    def test_a_fix_suggested_by_the_tool_is_kept(self):
        (f,), _ = self.parse(sarif_doc("Semgrep", [result("r", fixes=[{"description": {"text": "Use a bound parameter."}}])]))
        self.assertEqual(f["recommended_fix"], "Use a bound parameter.")

    def test_rejects_things_that_are_not_sarif(self):
        for bad in ("not json", "{}", '{"runs": "x"}', "[]"):
            with self.assertRaises(sarif.SarifError):
                self.parse(bad)

    def test_ingest_is_idempotent_through_the_merge(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "f.json"
            path.write_text("[]", encoding="utf-8")
            doc = sarif_doc("Semgrep", [result("r1"), result("r2", uri="src/b.py")])
            first = merge.merge(self.parse(doc, asset="api")[0], "semgrep", path=path)
            again = merge.merge(self.parse(doc, asset="api")[0], "semgrep", path=path)
            self.assertEqual((first["added"], again["added"], again["total"]), (2, 0, 2))
            fixed = merge.merge(self.parse(sarif_doc("Semgrep", [result("r1")]), asset="api")[0], "semgrep", path=path, reconcile=True)
            self.assertEqual((fixed["removed"], fixed["total"]), (1, 1))  # r2 was fixed and left the queue
            stored = merge.load(path)[0]
            self.assertEqual((stored["scan_type"], stored["location"]["file"]), ("sast", "src/app.py"))

    def test_the_explicit_scan_type_drives_classification(self):
        self.assertEqual(classify_finding({"scan_type": "cicd", "asset": {"type": "code-repository"}}), "cicd")
        self.assertEqual(classify_finding({"scan_type": "bogus", "asset": {"type": "application"}}), "dast")
        self.assertEqual(classify_finding({"asset": {"type": "application"}, "cve": "CVE-2024-1"}), "sca")


WORKFLOW_BAD = """\
name: build
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someorg/some-action@v1
      - uses: another/action@0123456789abcdef0123456789abcdef01234567
      - run: echo "${{ github.event.pull_request.title }}"
      - run: |
          curl -s https://example.com/install.sh | bash
          echo ${{ secrets.DEPLOY_TOKEN }}
      - env:
          AWS_KEY: AKIAABCDEFGHIJKLMNOP
        run: ./deploy.sh
"""
WORKFLOW_GOOD = """\
name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: pytest
        env:
          TITLE: ${{ github.event.head_commit.message }}
"""


class PipelineChecksTests(unittest.TestCase):
    def rules(self, text, path=".github/workflows/x.yml"):
        return {f["rule_id"]: f for f in cicd.scan_file(path, text, rel=path)}

    def test_finds_the_poisoned_pipeline_and_credential_problems(self):
        found = self.rules(WORKFLOW_BAD)
        for rule in ("GHA001", "GHA002", "GHA003", "GHA004", "GHA005", "GHA006", "GHA008"):
            self.assertIn(rule, found, rule)
        self.assertEqual(found["GHA002"]["severity"], "Critical")
        self.assertEqual(found["GHA006"]["severity"], "Critical")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", json.dumps(found["GHA006"]))  # the credential is never copied into the finding

    def test_first_party_actions_are_low_third_party_medium_and_pinned_ones_ignored(self):
        findings = [f for f in cicd.scan_file(".github/workflows/x.yml", WORKFLOW_BAD) if f["rule_id"] == "GHA001"]
        sev = {f["location"]["snippet"].split("uses:")[1].strip(): f["severity"] for f in findings}
        self.assertEqual(sev["actions/checkout@v4"], "Low")
        self.assertEqual(sev["someorg/some-action@v1"], "Medium")
        self.assertNotIn("another/action@0123456789abcdef0123456789abcdef01234567", sev)

    def test_a_clean_workflow_has_no_findings_and_event_data_via_env_is_fine(self):
        self.assertEqual(cicd.scan_file(".github/workflows/ci.yml", WORKFLOW_GOOD), [])

    def test_missing_permissions_gets_a_ready_patch(self):
        f = self.rules(WORKFLOW_GOOD.replace("permissions:\n  contents: read\n", ""))["GHA004"]
        self.assertIn("+permissions:", f["suggested_patch"])
        self.assertIn("+  contents: read", f["suggested_patch"])

    def test_write_all_is_flagged(self):
        self.assertIn("GHA004", self.rules(WORKFLOW_GOOD.replace("contents: read", "write-all").replace("permissions:\n  write-all", "permissions: write-all")))

    def test_self_hosted_runner_on_pull_requests(self):
        text = "on: pull_request\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n"
        self.assertIn("GHA007", self.rules(text))

    def test_gitlab_and_jenkins_rules(self):
        gl = {f["rule_id"] for f in cicd.scan_file(".gitlab-ci.yml", "build:\n  image: node:latest\n  script:\n    - curl -sL https://x.io/i.sh | sh\n"
                                                  "    - export TOKEN=\"ghp_" + "a" * 36 + "\"\n")}
        self.assertEqual(gl, {"GL001", "GL002", "GL003"})
        jk = {f["rule_id"] for f in cicd.scan_file("Jenkinsfile", 'pipeline {\n  stages {\n    stage("b") {\n      steps {\n        sh "deploy ${params.TARGET}"\n'
                                                   "        sh 'curl http://x/y | bash'\n      }\n    }\n  }\n}\n")}
        self.assertEqual(jk, {"JK001", "JK003"})

    def test_scan_path_discovers_files_and_the_output_is_valid_sarif_that_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            wf = Path(d) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "bad.yml").write_text(WORKFLOW_BAD, encoding="utf-8")
            (wf / "good.yml").write_text(WORKFLOW_GOOD, encoding="utf-8")
            findings, files = cicd.scan_path(d)
            self.assertEqual(files, 2)
            self.assertTrue(all(f["location"]["file"] == ".github/workflows/bad.yml" for f in findings))
            parsed, _ = sarif.parse(cicd.to_sarif(findings), "pipelines", scan_type="cicd", asset="shop-repo")
            self.assertEqual(len(parsed), len(findings))
            self.assertTrue(all(p["scan_type"] == "cicd" for p in parsed))
            self.assertIn("Critical", {p["severity"] for p in parsed})

    def test_this_repositorys_own_workflows_are_scanned_without_error(self):
        findings, files = cicd.scan_path(REPO_ROOT)
        self.assertGreaterEqual(files, 1)
        self.assertFalse([f for f in findings if f["severity"] == "Critical"])


COBERTURA = """<?xml version="1.0"?><coverage><packages><package><classes>
<class filename="app/auth/login.py"><lines><line number="1" hits="1"/><line number="2" hits="0"/><line number="3" hits="0"/><line number="4" hits="0"/></lines></class>
<class filename="app/utils/strings.py"><lines><line number="1" hits="0"/><line number="2" hits="0"/></lines></class>
<class filename="app/payments/charge.py"><lines><line number="1" hits="1"/><line number="2" hits="1"/><line number="3" hits="1"/></lines></class>
</classes></package></packages></coverage>"""
LCOV = "SF:src/session/token.js\nDA:1,1\nDA:2,0\nDA:3,0\nend_of_record\nSF:src/ui/button.js\nDA:1,0\nend_of_record\n"
JACOCO = ('<report name="x"><package name="com/acme/auth"><sourcefile name="PasswordService.java">'
          '<counter type="LINE" missed="9" covered="1"/></sourcefile></package></report>')


class CoverageTests(unittest.TestCase):
    def test_only_security_relevant_files_below_the_threshold_become_findings(self):
        findings, summary = coverage.analyse(COBERTURA, threshold=60, asset="shop")
        self.assertEqual([f["source_ref"] for f in findings], ["app/auth/login.py"])  # strings.py is untested but not security-relevant
        self.assertEqual(findings[0]["scan_type"], "coverage")
        self.assertEqual((summary["files"], summary["security_relevant_files"], summary["below_threshold"]), (3, 2, 1))
        self.assertEqual(summary["overall_pct"], 44.4)

    def test_severity_rises_for_very_low_coverage_on_core_security_code(self):
        (f,), _ = coverage.analyse(COBERTURA, threshold=60)
        self.assertEqual(f["severity"], "Medium")  # login.py: 25%, and "login" is core security code
        (g,), _ = coverage.analyse(JACOCO, threshold=60)
        self.assertEqual(g["severity"], "Medium")  # PasswordService: 10%
        (h,), _ = coverage.analyse(LCOV, threshold=60)
        self.assertEqual(h["severity"], "Low")  # token.js: 33%, not low enough to rise

    def test_lcov_and_jacoco_are_read(self):
        f, _ = coverage.analyse(LCOV, threshold=60)
        self.assertEqual([x["source_ref"] for x in f], ["src/session/token.js"])
        self.assertEqual(coverage.detect(LCOV), "lcov")
        self.assertEqual(coverage.detect(JACOCO), "jacoco")

    def test_bad_input_is_refused(self):
        with self.assertRaises(coverage.CoverageError):
            coverage.analyse("<!DOCTYPE x [<!ENTITY a 'b'>]><coverage/>")
        # a genuine JaCoCo report names a DTD in its DOCTYPE; that is fine, only entity declarations are refused
        real = '<?xml version="1.0"?><!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd"><report name="x"></report>'
        self.assertEqual(coverage.analyse(real)[1]["format"], "jacoco")
        with self.assertRaises(coverage.CoverageError):
            coverage.analyse("hello")
        with self.assertRaises(coverage.CoverageError):
            coverage.analyse(COBERTURA, threshold=500)


class ScannerIngestApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fpath = Path(self.tmp.name) / "f.json"
        self.fpath.write_text("[]", encoding="utf-8")
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine), patch.object(merge, "DEFAULT_PATH", self.fpath),
                        patch.object(dashboard_app_module, "_enrich_in_background", lambda bg: None),
                        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        self.key = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()
        self.h = {"Authorization": f"Bearer {self.key}"}

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def test_sarif_upload_needs_a_key_and_stores_the_finding_with_its_location(self):
        body = json.dumps(sarif_doc("Semgrep", [result("python.sqli", level="error")]))
        self.assertEqual(self.client.post("/api/ingest/sarif?source=semgrep", content=body).status_code, 401)
        r = self.client.post("/api/ingest/sarif?source=semgrep&asset=shop-api", headers=self.h, content=body)
        self.assertEqual((r.status_code, r.json()["added"]), (200, 1), r.text)
        stored = merge.load(self.fpath)[0]
        self.assertEqual((stored["scan_type"], stored["asset"]["name"], stored["location"]["line"]), ("sast", "shop-api", 10))
        again = self.client.post("/api/ingest/sarif?source=semgrep&asset=shop-api", headers=self.h, content=body).json()
        self.assertEqual((again["added"], again["updated"]), (0, 0))

    def test_bad_sarif_and_bad_scan_type_are_400(self):
        for q, content in (("source=s", "not json"), ("source=s", "{}"), ("source=s&scan_type=nope", json.dumps(sarif_doc("x", [result("r")]))),
                           ("source=Bad Name", json.dumps(sarif_doc("x", [result("r")])))):
            self.assertEqual(self.client.post(f"/api/ingest/sarif?{q}", headers=self.h, content=content).status_code, 400, q)

    def test_pipeline_findings_round_trip_through_the_api(self):
        findings = cicd.scan_file(".github/workflows/x.yml", WORKFLOW_BAD)
        body = json.dumps(cicd.to_sarif(findings))
        r = self.client.post("/api/ingest/sarif?source=pipelines&scan_type=cicd&asset=shop-repo", headers=self.h, content=body)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertGreaterEqual(r.json()["added"], 5)

    def test_coverage_upload(self):
        r = self.client.post("/api/ingest/coverage?source=cov&asset=shop&threshold=60", headers=self.h, content=COBERTURA)
        self.assertEqual((r.status_code, r.json()["added"], r.json()["coverage"]["overall_pct"]), (200, 1, 44.4), r.text)
        self.assertEqual(self.client.post("/api/ingest/coverage?threshold=0", headers=self.h, content=COBERTURA).status_code, 400)
        self.assertEqual(self.client.post("/api/ingest/coverage", content=COBERTURA).status_code, 401)

    def test_the_admin_file_import_recognises_sarif(self):
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        r = self.client.post("/api/connections/import-file?source=semgrep-export", content=json.dumps(sarif_doc("Semgrep", [result("r")])))
        self.assertEqual((r.status_code, r.json()["added"]), (200, 1), r.text)

    def test_api_findings_push_accepts_the_new_optional_fields(self):
        r = self.client.post("/api/ingest/findings", headers=self.h, json={"source": "custom", "enrich": False, "findings": [
            {"title": "Weak hash", "severity": "Medium", "asset": {"name": "svc"}, "scan_type": "sast", "cwe": ["CWE-328", "junk"],
             "location": {"file": "a.py", "line": 7}, "rule_id": "R1", "tool": "mytool"}]})
        self.assertEqual(r.status_code, 200, r.text)
        stored = merge.load(self.fpath)[0]
        self.assertEqual((stored["scan_type"], stored["cwe"], stored["location"]["file"]), ("sast", ["CWE-328"], "a.py"))
        bad = self.client.post("/api/ingest/findings", headers=self.h, json={"source": "custom", "enrich": False, "findings": [
            {"title": "x", "severity": "Low", "asset": {"name": "s"}, "scan_type": "nope"}]}).json()
        self.assertEqual(bad["rejected"], 1)


if __name__ == "__main__":
    unittest.main()
