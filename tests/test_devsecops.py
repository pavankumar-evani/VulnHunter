"""
Tests for the DevSecOps control library, scan-run evidence, policy mapping, the code remediation queue and the zero-day watch.
"""
import datetime
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
from remediation.devsecops import controls, factory  # noqa: E402
from remediation.enrichment import zero_day_watch as zd  # noqa: E402
from remediation.scanners import cicd  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
LIB = {c["id"]: c for c in controls.library()}


def run(asset, scan_type, tool="Semgrep", n=0, at="2026-10-01T00:00:00Z"):
    return {"asset": asset, "scan_type": scan_type, "tool": tool, "source": "s", "findings": n, "received_at": at}


def code_finding(i, repo="shop-api", scan_type="sast", sev="High", **kw):
    return {"id": f"FIND-{i}", "title": f"Issue {i}", "severity": sev, "scan_type": scan_type, "asset": {"name": repo, "type": "code-repository"}, "location": f"app/x{i}.py:{i}",
            "rule_id": kw.pop("rule_id", "r1"), "cwe": ["CWE-89"], **kw}


class LibraryTests(unittest.TestCase):
    def test_the_library_is_well_formed(self):
        lib = controls.library()
        self.assertGreaterEqual(len(lib), 25)
        self.assertEqual(len({c["id"] for c in lib}), len(lib))
        for c in lib:
            self.assertIn(c["stage"], controls.STAGES, c["id"])
            for k in ("title", "why", "how"):
                self.assertTrue(isinstance(c[k], str) and c[k], (c["id"], k))
            self.assertTrue(all(isinstance(v, str) for v in (c.get("snippets") or {}).values()), c["id"])
            ev = c.get("evidence") or {}
            self.assertTrue(set(ev) <= {"scan_type", "clean_of", "quanta"}, c["id"])
            for r in ev.get("clean_of", []):
                self.assertIn(r, cicd.RULES, f"{c['id']} names an unknown pipeline rule {r}")
            for o in c.get("owasp_cicd", []):
                self.assertRegex(o, r"^CICD-SEC-\d+$")

    def test_every_pipeline_rule_belongs_to_a_control(self):
        covered = {r for c in controls.library() for r in (c.get("evidence") or {}).get("clean_of", [])}
        self.assertEqual(sorted(set(cicd.RULES) - covered), [])

    def test_every_stage_has_controls(self):
        self.assertEqual({c["stage"] for c in controls.library()}, set(controls.STAGES))


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def st(self, cid, asset="shop-api", runs=(), rec=(), findings=(), tms=0):
        return controls.control_status(LIB[cid], asset, list(runs), list(rec), list(findings), tms)

    def test_a_scan_that_ran_is_evidence_even_when_clean(self):
        s = self.st("sast", runs=[run("Shop-API", "sast", "Semgrep", 0)])
        self.assertEqual(s["status"], "evidenced")
        self.assertIn("Semgrep ran 2026-10-01 (0 finding(s))", s["detail"])
        self.assertEqual(self.st("sast", runs=[run("shop-api", "sca")])["status"], "no-evidence")
        self.assertEqual(self.st("sast", runs=[run("other", "sast")])["status"], "no-evidence")

    def test_pipeline_controls_fail_on_a_finding_and_pass_only_after_a_check_ran(self):
        bad = code_finding(1, scan_type="cicd", rule_id="GHA001")
        self.assertEqual(self.st("pin-pipeline-dependencies", findings=[bad], runs=[run("shop-api", "cicd")])["status"], "failing")
        self.assertIn("GHA001", self.st("pin-pipeline-dependencies", findings=[bad])["detail"])
        self.assertEqual(self.st("pin-pipeline-dependencies", runs=[run("shop-api", "cicd")])["status"], "evidenced")
        self.assertEqual(self.st("pin-pipeline-dependencies")["status"], "no-evidence")  # never checked is not the same as clean
        self.assertEqual(self.st("pin-pipeline-dependencies", findings=[{**bad, "status": "resolved"}], runs=[run("shop-api", "cicd")])["status"], "evidenced")
        other_rule = code_finding(2, scan_type="cicd", rule_id="GHA004")
        self.assertEqual(self.st("pin-pipeline-dependencies", findings=[other_rule], runs=[run("shop-api", "cicd")])["status"], "evidenced")

    def test_threat_models_and_unobservable_controls(self):
        self.assertEqual(self.st("design-review", tms=2)["status"], "evidenced")
        self.assertEqual(self.st("design-review")["status"], "no-evidence")
        self.assertEqual(self.st("branch-protection")["status"], "not-observable")

    def test_a_recorded_state_is_shown_beside_the_observed_one_and_never_overrides_it(self):
        controls.set_state("shop-api", "branch-protection", "implemented", "Verified in settings 2026-09-30", "a@t", self.e)
        controls.set_state("shop-api", "branch-protection", "planned", "Q4", "b@t", self.e)  # replaces
        rec = controls.states(self.e)
        self.assertEqual([(r["state"], r["set_by"]) for r in rec], [("planned", "b@t")])
        s = self.st("branch-protection", rec=rec)
        self.assertEqual((s["status"], s["recorded"]["state"], s["recorded"]["note"]), ("not-observable", "planned", "Q4"))
        controls.set_state("shop-api", "pin-pipeline-dependencies", "implemented", "we think so", "a@t", self.e)
        bad = code_finding(1, scan_type="cicd", rule_id="GHA001")
        s2 = self.st("pin-pipeline-dependencies", rec=controls.states(self.e), findings=[bad])
        self.assertEqual((s2["status"], s2["recorded"]["state"]), ("failing", "implemented"))  # the claim does not hide the finding
        self.assertTrue(controls.clear_state("shop-api", "branch-protection", self.e))
        self.assertFalse(controls.clear_state("shop-api", "branch-protection", self.e))

    def test_state_validation(self):
        for args in (("shop", "branch-protection", "great"), (" ", "branch-protection", "implemented")):
            with self.assertRaises(ValueError):
                controls.set_state(*args, "", "a", self.e)
        with self.assertRaises(KeyError):
            controls.set_state("shop", "no-such-control", "implemented", "", "a", self.e)

    def test_overview_counts_per_repo_and_per_control(self):
        runs = [run("shop-api", "sast"), run("shop-api", "cicd"), run("web", "sca")]
        controls.record_scan_run("late", "dast", "ZAP", "s", 3, "a", self.e)
        o = controls.overview(runs + controls.scan_runs(self.e), [], [code_finding(1, repo="shop-api", scan_type="cicd", rule_id="GHA004")], 0)
        repos = {r["asset"]: r["counts"] for r in o["repos"]}
        self.assertEqual(set(repos), {"shop-api", "web", "late"})
        self.assertEqual((repos["shop-api"]["failing"], repos["late"]["evidenced"]), (1, 1))
        sast = next(p for p in o["per_control"] if p["id"] == "sast")
        self.assertEqual((sast["evidenced"], sast["no_evidence"]), (1, 2))
        self.assertEqual(len(o["per_control"]), len(controls.library()))


class PolicyTests(unittest.TestCase):
    POLICY = """1. All code must be peer reviewed before it is merged.
- Secrets must never be committed; secret scanning is required.
- Dependencies are checked for known vulnerabilities (software composition analysis).
- Staff will enjoy the annual picnic in the summer.
Container images shall be scanned and signed before release."""

    def test_sentences_are_matched_to_controls_by_keyword(self):
        r = controls.map_policy(self.POLICY)
        by = {m["requirement"]: {c["id"] for c in m["controls"]} for m in r["matched"]}
        self.assertIn("branch-protection", by["All code must be peer reviewed before it is merged."])
        self.assertTrue({"secret-scan-commit", "secret-scan-ci"} <= by["Secrets must never be committed; secret scanning is required."])
        self.assertIn("sca", next(v for k, v in by.items() if "Dependencies are checked" in k))
        self.assertTrue({"container-scan", "artifact-provenance"} & next(v for k, v in by.items() if k.startswith("Container images")))
        self.assertEqual(r["unmatched"], ["Staff will enjoy the annual picnic in the summer."])
        self.assertIn("dast", r["controls_not_mentioned"])

    def test_blank_text_and_short_fragments_produce_nothing(self):
        r = controls.map_policy("  \n- ok\n")
        self.assertEqual((r["matched"], r["unmatched"]), ([], []))


class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.fs = [code_finding(1, sev="Critical", kev={"listed": True}), code_finding(2, sev="Low"), code_finding(3, scan_type="sca", sev="High"),
                   {"id": "FIND-9", "title": "Host patch", "severity": "Critical", "scan_type": "infra-vm", "asset": {"name": "WIN-1"}}]

    def test_only_code_findings_are_queued_once(self):
        r = factory.queue(["FIND-1", "FIND-9", "FIND-404", "FIND-3"], self.fs, "a", self.e)
        self.assertEqual(r["queued"], ["FIND-1", "FIND-3"])
        self.assertEqual({s["id"] for s in r["skipped"]}, {"FIND-9", "FIND-404"})
        again = factory.queue(["FIND-1"], self.fs, "a", self.e)
        self.assertEqual((again["queued"], again["skipped"][0]["reason"]), ([], "already queued"))

    def test_candidates_are_the_worst_first_and_exclude_queued(self):
        factory.queue(["FIND-3"], self.fs, "a", self.e)
        c = factory.candidates(self.fs, self.e)
        self.assertEqual([x["id"] for x in c], ["FIND-1", "FIND-2"])
        self.assertTrue(c[0]["kev"])

    def test_state_changes_are_validated_and_verification_is_not_self_reported(self):
        factory.queue(["FIND-1", "FIND-2"], self.fs, "a", self.e)
        row = factory.update_item("FIND-1", {"state": "pr-opened", "pr_url": "https://git.example/pr/7", "assignee": "dev@t"}, self.e)
        self.assertEqual((row["state"], row["pr_url"]), ("pr-opened", "https://git.example/pr/7"))
        for bad in ({"state": "verified"}, {"pr_url": "javascript:alert(1)"}):
            with self.assertRaises(ValueError):
                factory.update_item("FIND-1", bad, self.e)
        with self.assertRaises(KeyError):
            factory.update_item("FIND-404", {"state": "queued"}, self.e)
        factory.update_item("FIND-1", {"state": "merged"}, self.e)
        shown = {i["finding_id"]: i["shown_state"] for i in factory.items(self.fs, self.e)}
        self.assertEqual(shown, {"FIND-1": "merged-still-reported", "FIND-2": "queued"})  # merged but still reported
        later = {i["finding_id"]: i["shown_state"] for i in factory.items([f for f in self.fs if f["id"] != "FIND-1"], self.e)}
        self.assertEqual(later["FIND-1"], "resolved-in-latest-scan")  # a later scan no longer reports it
        self.assertEqual(factory.summary(self.fs, self.e)["by_state"], {"merged-still-reported": 1, "queued": 1})

    def test_the_fix_brief_has_the_where_the_steps_and_how_to_verify(self):
        md = factory.brief(self.fs[0])
        for want in ("# Fix: Issue 1", "shop-api", "app/x1.py:1", "## What to do", "1. ", "## Prove it is fixed", "Rescan"):
            self.assertIn(want, md)
        self.assertIn("not a patch", md)


CATALOG = [
    {"cveID": "CVE-2026-1001", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "FortiOS auth bypass", "dateAdded": "2026-10-10", "dueDate": "2026-10-31",
     "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Apply updates."},
    {"cveID": "CVE-2026-1002", "vendorProject": "Apache", "product": "Struts", "vulnerabilityName": "Struts RCE", "dateAdded": "2026-10-12", "dueDate": "2026-11-02",
     "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."},
    {"cveID": "CVE-2026-1003", "vendorProject": "Microsoft", "product": "Windows", "vulnerabilityName": "Windows bug", "dateAdded": "2026-10-11", "dueDate": "x", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2025-0001", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "Old", "dateAdded": "2025-01-01", "dueDate": "x", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-1005", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Not ours", "dateAdded": "2026-10-12", "dueDate": "x", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-1006", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "Already found", "dateAdded": "2026-10-12", "dueDate": "x", "knownRansomwareCampaignUse": "Unknown"},
]
ESTATE = [{"id": "F1", "title": "Fortinet FortiOS SSL-VPN heap overflow", "cve": "CVE-2026-1006", "asset": {"name": "FW-1", "os": "FortiOS 7.2"}},
          {"id": "F2", "title": "Outdated component", "asset": {"name": "APP-1", "os": "Ubuntu 22.04"}, "dependency": {"package": "struts2-core"}}]


class ZeroDayTests(unittest.TestCase):
    def test_new_exploited_products_you_run_that_have_no_finding(self):
        r = zd.watch(CATALOG, ESTATE, [{"name": "struts", "supplier": "Apache Software Foundation"}], 30, today=datetime.date(2026, 10, 15))
        self.assertEqual([i["cve"] for i in r["items"]], ["CVE-2026-1002", "CVE-2026-1001"])  # ransomware-linked first, then newest
        self.assertEqual((r["already_tracked"], r["total_matches"]), (1, 2))
        top = r["items"][0]
        self.assertTrue(top["ransomware"])
        self.assertTrue({"apache", "struts"} <= set(top["matched_on"]))
        self.assertIn("name match", r["note"])

    def test_old_entries_and_unrelated_vendors_are_ignored(self):
        r = zd.watch(CATALOG, ESTATE, [], 30, today=datetime.date(2026, 10, 15))
        cves = {i["cve"] for i in r["items"]}
        self.assertTrue({"CVE-2025-0001", "CVE-2026-1005"}.isdisjoint(cves))
        self.assertNotIn("CVE-2026-1003", cves)  # "windows" alone is too generic to count as a product match
        self.assertEqual(zd.watch(CATALOG, ESTATE, [], 1, today=datetime.date(2026, 10, 15))["catalog_entries_in_window"], 0)

    def test_fetch_catalog(self):
        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return {"vulnerabilities": CATALOG}

        class S:
            def get(self, url, timeout=None):
                self.url = url
                return R()

        s = S()
        self.assertEqual(len(zd.fetch_catalog(s)), len(CATALOG))
        self.assertIn("cisa.gov", s.url)


SARIF_CLEAN = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": []}]}
SARIF_ONE = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [{"id": "r1"}]}}, "results": [
    {"ruleId": "r1", "level": "error", "message": {"text": "SQL injection"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 4}}}]}]}]}


class DevSecOpsApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fs = [code_finding(1, sev="Critical"), code_finding(2, scan_type="cicd", rule_id="GHA001")]
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=self.fs),
                  patch.object(dashboard_app_module.findings_merge, "merge", return_value={"added": 1, "updated": 0, "removed": 0})]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def upload(self, doc, asset="shop-api"):
        return self.client.post(f"/api/ingest/sarif?asset={asset}", content=json.dumps(doc), headers={"Authorization": f"Bearer {self.key}"})

    def test_a_clean_sarif_scan_is_accepted_and_recorded_as_evidence(self):
        r = self.upload(SARIF_CLEAN)
        self.assertEqual((r.status_code, r.json()["clean_scan"], r.json()["parsed"]), (200, True, 0), r.text)
        self.login("user@t.local")
        sast = next(c for c in self.client.get("/api/devsecops/repos?asset=shop-api").json()["controls"] if c["id"] == "sast")
        self.assertEqual(sast["status"], "evidenced")
        self.assertEqual(self.upload({"version": "2.1.0", "runs": []}).status_code, 400)
        self.assertEqual(self.upload({"nope": 1}).status_code, 400)

    def test_a_sarif_scan_with_findings_still_merges_and_records_the_run(self):
        r = self.upload(SARIF_ONE)
        self.assertEqual((r.status_code, r.json()["added"]), (200, 1), r.text)
        runs = controls.scan_runs(self.engine)
        self.assertEqual((runs[0]["asset"], runs[0]["scan_type"], runs[0]["findings"]), ("shop-api", "sast", 1))

    def test_reads_need_login_and_writes_need_an_admin(self):
        self.assertEqual(self.client.get("/api/devsecops/overview").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/devsecops/overview").status_code, 200)
        self.assertEqual(self.client.post("/api/devsecops/state", json={"asset": "a", "control_id": "sast", "state": "implemented"}).status_code, 403)
        self.assertEqual(self.client.post("/api/devsecops/factory/queue", json={"finding_ids": ["FIND-1"]}).status_code, 403)
        self.assertEqual(self.client.post("/api/devsecops/policy-check", json={"text": "Code must be peer reviewed before merge."}).status_code, 200)

    def test_record_a_state_and_read_it_back(self):
        self.login("admin@t.local")
        self.assertEqual(self.client.post("/api/devsecops/state", json={"asset": "shop-api", "control_id": "branch-protection", "state": "implemented", "note": "checked"}).status_code, 200)
        self.assertEqual(self.client.post("/api/devsecops/state", json={"asset": "shop-api", "control_id": "nope", "state": "implemented"}).status_code, 404)
        self.assertEqual(self.client.post("/api/devsecops/state", json={"asset": "shop-api", "control_id": "sast", "state": "great"}).status_code, 400)
        bp = next(c for c in self.client.get("/api/devsecops/repos?asset=shop-api").json()["controls"] if c["id"] == "branch-protection")
        self.assertEqual((bp["status"], bp["recorded"]["state"]), ("not-observable", "implemented"))
        self.assertEqual(self.client.delete("/api/devsecops/state?asset=shop-api&control_id=branch-protection").status_code, 200)
        self.assertEqual(self.client.delete("/api/devsecops/state?asset=shop-api&control_id=branch-protection").status_code, 404)
        ov = self.client.get("/api/devsecops/overview").json()
        self.assertIn("shop-api", {r["asset"] for r in ov["repos"]})
        self.assertEqual(len(ov["library"]), len(controls.library()))

    def test_remediation_queue_flow(self):
        self.login("admin@t.local")
        cand = self.client.get("/api/devsecops/factory").json()
        self.assertEqual([c["id"] for c in cand["candidates"]], ["FIND-1"])  # the cicd finding is not a code fix
        q = self.client.post("/api/devsecops/factory/queue", json={"finding_ids": ["FIND-1", "FIND-404"]}).json()
        self.assertEqual((q["queued"], len(q["skipped"])), (["FIND-1"], 1))
        u = self.client.put("/api/devsecops/factory/FIND-1", json={"state": "pr-opened", "pr_url": "https://git.example/pr/1"})
        self.assertEqual((u.status_code, u.json()["state"]), (200, "pr-opened"))
        self.assertEqual(self.client.put("/api/devsecops/factory/FIND-1", json={"state": "verified"}).status_code, 400)
        self.assertEqual(self.client.put("/api/devsecops/factory/FIND-404", json={"state": "queued"}).status_code, 404)
        brief = self.client.get("/api/devsecops/factory/FIND-1/brief")
        self.assertIn("text/markdown", brief.headers["content-type"])
        self.assertIn("# Fix: Issue 1", brief.text)
        self.assertEqual(self.client.get("/api/devsecops/factory/FIND-2/brief").status_code, 404)

    def test_zero_day_route(self):
        self.login("user@t.local")
        with patch.object(zd, "fetch_catalog", return_value=CATALOG), patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=ESTATE):
            r = self.client.get("/api/zero-day-watch?days=3650")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertGreaterEqual(r.json()["total_matches"], 1)
        with patch.object(zd, "fetch_catalog", side_effect=OSError("offline")):
            r = self.client.get("/api/zero-day-watch")
            self.assertEqual(r.status_code, 502)
            self.assertIn("could not be fetched", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
