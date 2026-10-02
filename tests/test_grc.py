"""
Tests for governance, risk and compliance: framework catalogs and OSCAL import, the risk register, the automated control tests and the
status they give each control, attestations, the OSCAL export, policies with acknowledgements, and the API.
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
from remediation.grc import catalog, evidence, policies, report, risks  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)
OSCAL = {"catalog": {"metadata": {"title": "Test catalog", "version": "9"}, "groups": [
    {"id": "ac", "title": "Access Control", "controls": [
        {"id": "ac-1", "title": "Policy", "parts": [{"name": "statement", "prose": "Develop a policy.", "parts": [{"name": "item", "prose": "and procedures."}]}],
         "controls": [{"id": "ac-1.1", "title": "Enhancement", "parts": [{"name": "statement", "prose": "More {{ insert: param, ac-1_prm_1 }}."}]}]}]},
    {"id": "si", "title": "System Integrity", "controls": [{"id": "si-2", "title": "Flaw Remediation"}]}]}}


def fnd(i, sev="High", breached=False, kev=False, last="2026-10-14"):
    f = {"id": f"FIND-{i}", "severity": sev, "sla": {"breached": breached}, "asset": {"name": f"HOST-{i % 3}"}, "last_seen": last}
    if kev:
        f["kev"] = {"listed": True}
    return f


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_builtin_catalogs_load_once_and_never_overwrite_an_import(self):
        catalog.ensure_builtin(self.e)
        ids = {f["id"] for f in catalog.list_frameworks(self.e)}
        self.assertEqual(ids, {"nist-800-53-r5", "nist-csf-2", "quanta-ai-governance"})
        catalog.import_oscal("nist-800-53-r5", OSCAL, engine=self.e)
        catalog.ensure_builtin(self.e)
        self.assertEqual(catalog.list_frameworks(self.e)[1]["source"] if False else next(f for f in catalog.list_frameworks(self.e) if f["id"] == "nist-800-53-r5")["source"], "oscal")

    def test_oscal_import_reads_nested_controls_statements_and_ids(self):
        n = catalog.import_oscal("test-cat", OSCAL, engine=self.e)
        self.assertEqual(n, 3)
        by = {c["control_id"]: c for c in catalog.controls_of("test-cat", self.e)}
        self.assertEqual(set(by), {"AC-1", "AC-1(1)", "SI-2"})
        self.assertIn("Develop a policy. and procedures.", by["AC-1"]["statement"])
        self.assertNotIn("{{", by["AC-1(1)"]["statement"])
        self.assertEqual(by["AC-1"]["family"], "Access Control")

    def test_bad_input_is_refused(self):
        for doc in ("not json", {}, {"catalog": {}}, []):
            with self.assertRaises(catalog.CatalogError):
                catalog.import_oscal("x-cat", doc, engine=self.e)
        with self.assertRaises(catalog.CatalogError):
            catalog.import_oscal("Bad ID!", OSCAL, engine=self.e)

    def test_every_built_in_control_a_test_maps_to_exists(self):
        catalog.ensure_builtin(self.e)
        have = {f["id"]: {c["control_id"] for c in catalog.controls_of(f["id"], self.e)} for f in catalog.list_frameworks(self.e)}
        for fid, ctls in report.mapping().items():
            for c in ctls:
                self.assertIn(c, have[fid], (fid, c))

    def test_every_test_is_mapped_to_a_control(self):
        mapped = set(evidence.config()["mappings"])
        self.assertEqual(sorted(set(evidence.TESTS) - mapped), [])
        self.assertEqual(sorted(mapped - set(evidence.TESTS)), [])


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_scoring_levels_and_overdue_flags(self):
        r = risks.create({"title": "Unpatched edge", "inherent_likelihood": 4, "inherent_impact": 4, "residual_likelihood": 2, "residual_impact": 3,
                          "review_date": "2020-01-01", "due_date": "2020-01-01"}, "a", engine=self.e)
        self.assertEqual((r["inherent_score"], r["inherent_level"], r["residual_score"], r["residual_level"]), (16, "Critical", 6, "Medium"))
        self.assertTrue(r["review_overdue"] and r["treatment_overdue"])

    def test_accepting_a_risk_needs_a_reason_and_a_review_date(self):
        base = {"title": "x", "inherent_likelihood": 2, "inherent_impact": 2, "status": "accepted"}
        with self.assertRaises(ValueError):
            risks.create(base, "a", engine=self.e)
        r = risks.create({**base, "treatment_plan": "Behind the VPN", "review_date": "2027-01-01"}, "a", engine=self.e)
        self.assertEqual(r["status"], "accepted")

    def test_validation(self):
        for bad in ({"title": "", "inherent_likelihood": 1, "inherent_impact": 1}, {"title": "x", "inherent_likelihood": 9, "inherent_impact": 1},
                    {"title": "x", "inherent_likelihood": 1, "inherent_impact": 1, "status": "weird"}, {"title": "x", "inherent_likelihood": 1, "inherent_impact": 1, "review_date": "soon"}):
            with self.assertRaises(ValueError):
                risks.create(bad, "a", engine=self.e)

    def test_update_delete_and_ordering(self):
        a = risks.create({"title": "low", "inherent_likelihood": 1, "inherent_impact": 1}, "a", engine=self.e)
        b = risks.create({"title": "high", "inherent_likelihood": 5, "inherent_impact": 5}, "a", engine=self.e)
        self.assertEqual([r["title"] for r in risks.list_risks(self.e)], ["high", "low"])
        risks.update_risk(b["id"], {"status": "closed"}, self.e)
        self.assertEqual(risks.list_risks(self.e)[-1]["title"], "high")
        self.assertEqual(risks.summary(risks.list_risks(self.e))["total"], 1)
        self.assertTrue(risks.delete_risk(a["id"], self.e))
        with self.assertRaises(KeyError):
            risks.update_risk(999, {"status": "closed"}, self.e)

    def test_suggestions_come_from_live_data_and_threats_and_are_not_repeated(self):
        findings = [fnd(1, breached=True, kev=True), fnd(2)]
        analyses = [{"id": 7, "name": "Portal", "threats": [{"key": "TM-S01:web", "title": "Impersonation", "element": {"name": "Web"}, "description": "d",
                                                             "likelihood": 4, "impact": 4, "residual_score": 16, "review": {"status": "open"}},
                                                            {"key": "TM-R01:web", "title": "Untraceable", "element": {"name": "Web"}, "description": "d",
                                                             "likelihood": 2, "impact": 2, "residual_score": 4, "review": {"status": "open"}}]}]
        sug = risks.suggestions(findings, analyses, existing=[])
        self.assertEqual({(s["source"], s["source_ref"]) for s in sug}, {("finding", "kev-overdue"), ("threat", "7:TM-S01:web")})
        risks.create({k: sug[0][k] for k in ("title", "inherent_likelihood", "inherent_impact")}, "a", source=sug[0]["source"], source_ref=sug[0]["source_ref"], engine=self.e)
        with self.assertRaises(ValueError):
            risks.create({k: sug[0][k] for k in ("title", "inherent_likelihood", "inherent_impact")}, "a", source=sug[0]["source"], source_ref=sug[0]["source_ref"], engine=self.e)
        again = risks.suggestions(findings, analyses, existing=risks.list_risks(self.e))
        self.assertNotIn(("finding", "kev-overdue"), {(s["source"], s["source_ref"]) for s in again})


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        db_module.ensure_schema(self.e)

    def ctx(self, findings):
        return evidence.Context(findings, self.e, today=TODAY)

    def run_one(self, tid, findings):
        (r,) = evidence.run_all(self.ctx(findings), only=[tid])
        return r

    def test_patch_sla_pass_fail_and_na(self):
        self.assertEqual(self.run_one("patch-sla", [fnd(i) for i in range(10)])["result"], "pass")
        r = self.run_one("patch-sla", [fnd(i, breached=i < 5) for i in range(10)])
        self.assertEqual((r["result"], r["metric"]), ("fail", 50.0))
        self.assertEqual(self.run_one("patch-sla", [fnd(1, sev="Low")])["result"], "na")  # too little data is never a pass

    def test_kev_remediation(self):
        self.assertEqual(self.run_one("kev-remediation", [fnd(1, kev=True)])["result"], "pass")
        r = self.run_one("kev-remediation", [fnd(1, kev=True, breached=True)])
        self.assertEqual((r["result"], r["metric"]), ("fail", 1))

    def test_scan_freshness(self):
        self.assertEqual(self.run_one("scan-freshness", [fnd(1, last="2026-10-14")])["result"], "pass")
        self.assertEqual(self.run_one("scan-freshness", [fnd(1, last="2026-08-01")])["result"], "fail")
        self.assertEqual(self.run_one("scan-freshness", [])["result"], "na")

    def test_audit_trail_needs_recent_events(self):
        self.assertEqual(self.run_one("audit-trail", [])["result"], "fail")
        from remediation.audit.activity_log import record_activity
        record_activity("a@t", "x", None, {}, engine=self.e, as_of=datetime.datetime(2026, 10, 10))
        self.assertEqual(self.run_one("audit-trail", [])["result"], "pass")

    def test_risk_register_test(self):
        self.assertEqual(self.run_one("risk-register", [])["result"], "fail")
        risks.create({"title": "x", "inherent_likelihood": 3, "inherent_impact": 3, "owner": "o@t"}, "a", engine=self.e)
        self.assertEqual(self.run_one("risk-register", [])["result"], "pass")

    def test_ai_tests_are_na_without_data_and_budgets_fail_when_missing(self):
        self.assertEqual(self.run_one("ai-apps-reviewed", [])["result"], "na")
        self.assertEqual(self.run_one("ai-usage-recorded", [])["result"], "na")
        self.assertEqual(self.run_one("ai-budgets", [])["result"], "fail")
        self.assertEqual(self.run_one("ai-approved-models", [])["result"], "na")

    def test_a_broken_test_is_reported_as_error_and_does_not_stop_the_rest(self):
        with patch.dict(evidence.TESTS, {"patch-sla": ("x", lambda c: 1 / 0)}):
            out = evidence.run_all(self.ctx([fnd(1)]))
        by = {r["test_id"]: r["result"] for r in out}
        self.assertEqual(by["patch-sla"], "error")
        self.assertIn("scan-freshness", by)

    def test_results_are_stored_with_history(self):
        evidence.run_all(self.ctx([fnd(i) for i in range(4)]), only=["patch-sla"])
        evidence.run_all(self.ctx([fnd(i, breached=True) for i in range(4)]), only=["patch-sla"])
        self.assertEqual(evidence.latest(self.e)["patch-sla"]["result"], "fail")
        self.assertEqual([h["result"] for h in evidence.history("patch-sla", engine=self.e)], ["fail", "pass"])


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        catalog.ensure_builtin(self.e)

    def test_control_status_rules(self):
        cs = report.control_status
        self.assertEqual(cs([{"result": "pass"}, {"result": "pass"}]), "satisfied")
        self.assertEqual(cs([{"result": "pass"}, {"result": "fail"}]), "not-satisfied")
        self.assertEqual(cs([{"result": "pass"}, {"result": "warn"}]), "partially")
        self.assertEqual(cs([{"result": "pass"}, {"result": "na"}]), "partially")
        self.assertEqual(cs([{"result": "na"}]), "no-evidence")
        self.assertEqual(cs([]), "not-evidenced")

    def test_report_reflects_the_latest_evidence_and_never_calls_unobserved_controls_satisfied(self):
        evidence.run_all(evidence.Context([fnd(i) for i in range(10)], self.e, today=TODAY), only=["patch-sla"])
        rep = report.framework_report("nist-800-53-r5", self.e)
        by = {c["control_id"]: c for c in rep["controls"]}
        self.assertEqual(by["SI-2"]["status"], "satisfied")
        self.assertEqual(by["AC-6"]["status"], "no-evidence")  # mapped, but its test has not run
        self.assertEqual(report.framework_report("quanta-ai-governance", self.e)["controls"][0]["status"], "no-evidence")
        self.assertEqual(rep["counts"]["not-evidenced"], sum(1 for c in rep["controls"] if not c["mapped_tests"]))

    def test_attestation_counts_as_evidence_until_it_expires(self):
        report.attest("nist-800-53-r5", "PM-9", "effective", "Reviewed by the CISO", "ciso@t", valid_until="2099-01-01", engine=self.e)
        rep = report.framework_report("nist-800-53-r5", self.e)
        pm9 = next(c for c in rep["controls"] if c["control_id"] == "PM-9")
        self.assertTrue(pm9["attestation"]["current"])
        report.attest("nist-800-53-r5", "AU-2", "effective", "old", "ciso@t", valid_until="2020-01-01", engine=self.e)
        au2 = next(c for c in report.framework_report("nist-800-53-r5", self.e)["controls"] if c["control_id"] == "AU-2")
        self.assertFalse(au2["attestation"]["current"])
        self.assertEqual(rep["evidenced"], sum(1 for c in rep["controls"] if c["status"] in ("satisfied", "partially", "not-satisfied") or (c["attestation"] and c["attestation"]["current"])))

    def test_attestation_validation(self):
        for args in (("nist-800-53-r5", "PM-9", "great", "x"), ("nist-800-53-r5", "PM-9", "effective", "  ")):
            with self.assertRaises(ValueError):
                report.attest(*args, "a", engine=self.e)
        with self.assertRaises(KeyError):
            report.attest("nist-800-53-r5", "ZZ-9", "effective", "x", "a", engine=self.e)

    def test_oscal_export_has_the_expected_shape_and_says_it_is_not_an_opinion(self):
        evidence.run_all(evidence.Context([fnd(i, breached=i < 5) for i in range(10)], self.e, today=TODAY), only=["patch-sla"])
        doc = report.to_oscal("nist-800-53-r5", self.e)["assessment-results"]
        self.assertEqual(doc["metadata"]["oscal-version"], "1.1.2")
        res = doc["results"][0]
        states = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in res["findings"]}
        self.assertEqual(states["si-2"], "not-satisfied")
        self.assertTrue(res["observations"] and all(o["methods"] == ["TEST"] for o in res["observations"]))
        self.assertIn("Not an audit opinion", doc["metadata"]["remarks"])
        json.dumps(doc)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_new_text_makes_a_new_version_that_needs_acknowledging_again(self):
        p = policies.create("Acceptable use", "v1 text", "ciso", "a", status="active", engine=self.e)
        policies.acknowledge(p["id"], "u1@t", self.e)
        self.assertEqual(policies.get(p["id"], self.e)["acknowledged_by"], ["u1@t"])
        policies.update_policy(p["id"], "a", owner="new owner", engine=self.e)
        self.assertEqual(policies.get(p["id"], self.e)["version"], 1)  # owner change is not a new version
        p2 = policies.update_policy(p["id"], "a", body="v2 text", engine=self.e)
        self.assertEqual((p2["version"], p2["acknowledged_by"]), (2, []))

    def test_coverage_and_who_is_missing(self):
        p = policies.create("P", "text", "o", "a", status="active", engine=self.e)
        policies.acknowledge(p["id"], "u1@t", self.e)
        got = policies.get(p["id"], self.e, users=[{"email": "u1@t"}, {"email": "u2@t"}])
        self.assertEqual((got["ack_pct"], got["not_yet_acknowledged"]), (50, ["u2@t"]))

    def test_only_active_policies_can_be_acknowledged_and_validation(self):
        p = policies.create("P", "text", "o", "a", engine=self.e)  # draft
        with self.assertRaises(ValueError):
            policies.acknowledge(p["id"], "u@t", self.e)
        for args in (("", "x"), ("t", " ")):
            with self.assertRaises(ValueError):
                policies.create(*args, "o", "a", engine=self.e)


class GrcApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def test_admin_only_except_reading_and_acknowledging_active_policies(self):
        for path in ("/api/grc/overview", "/api/grc/frameworks", "/api/grc/risks", "/api/grc/evidence"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.login("user@t.local")
        for path in ("/api/grc/overview", "/api/grc/frameworks", "/api/grc/risks", "/api/grc/evidence"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        self.assertEqual(self.client.get("/api/grc/policies").status_code, 200)

    def test_overview_evidence_report_attest_and_oscal(self):
        self.login("admin@t.local")
        run = self.client.post("/api/grc/evidence/run")
        self.assertEqual(run.status_code, 200, run.text)
        self.assertEqual(len(run.json()["results"]), len(evidence.TESTS))
        ov = self.client.get("/api/grc/overview").json()
        self.assertEqual({f["id"] for f in ov["frameworks"]}, {"nist-800-53-r5", "nist-csf-2", "quanta-ai-governance"})
        rep = self.client.get("/api/grc/frameworks/nist-800-53-r5/report").json()
        self.assertEqual(rep["total"], 16)
        self.assertEqual(self.client.get("/api/grc/frameworks/nope/report").status_code, 404)
        a = self.client.post("/api/grc/frameworks/nist-800-53-r5/controls/PM-9/attest", json={"result": "effective", "statement": "CISO reviewed"})
        self.assertEqual(a.status_code, 200, a.text)
        self.assertEqual(self.client.post("/api/grc/frameworks/nist-800-53-r5/controls/PM-9/attest", json={"result": "bad", "statement": "x"}).status_code, 400)
        o = self.client.get("/api/grc/frameworks/nist-800-53-r5/oscal")
        self.assertEqual(o.status_code, 200)
        self.assertIn("attachment", o.headers["content-disposition"])
        self.assertIn("assessment-results", o.json())

    def test_import_a_catalog(self):
        self.login("admin@t.local")
        r = self.client.post("/api/grc/frameworks/import?id=test-cat&name=Test", content=json.dumps(OSCAL))
        self.assertEqual((r.status_code, r.json()["controls"]), (200, 3), r.text)
        self.assertEqual(self.client.post("/api/grc/frameworks/import?id=BAD ID", content=json.dumps(OSCAL)).status_code, 400)
        self.assertEqual(self.client.post("/api/grc/frameworks/import?id=ok-id", content="nope").status_code, 400)
        self.assertEqual(self.client.delete("/api/grc/frameworks/test-cat").status_code, 200)
        self.assertEqual(self.client.delete("/api/grc/frameworks/test-cat").status_code, 404)

    def test_risk_register_flow_including_a_suggestion(self):
        self.login("admin@t.local")
        r = self.client.post("/api/grc/risks", json={"title": "Edge gateway unpatched", "inherent_likelihood": 4, "inherent_impact": 5, "owner": "ops@t"})
        self.assertEqual(r.status_code, 200, r.text)
        rid = r.json()["id"]
        self.assertEqual(self.client.post("/api/grc/risks", json={"title": "", "inherent_likelihood": 4, "inherent_impact": 5}).status_code, 400)
        self.assertEqual(self.client.put(f"/api/grc/risks/{rid}", json={"status": "accepted"}).status_code, 400)
        ok = self.client.put(f"/api/grc/risks/{rid}", json={"status": "treating", "treatment": "mitigate", "treatment_plan": "Patch in the next window"})
        self.assertEqual((ok.status_code, ok.json()["status"]), (200, "treating"), ok.text)
        listing = self.client.get("/api/grc/risks").json()
        self.assertEqual(listing["summary"]["total"], 1)
        if listing["suggestions"]:  # the sample queue has known-exploited findings past their SLA
            s = listing["suggestions"][0]
            added = self.client.post("/api/grc/risks/from-suggestion", json={"source": s["source"], "source_ref": s["source_ref"]})
            self.assertEqual(added.status_code, 200, added.text)
            self.assertEqual(self.client.post("/api/grc/risks/from-suggestion", json={"source": s["source"], "source_ref": s["source_ref"]}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/grc/risks/{rid}").status_code, 200)

    def test_policies_for_admins_and_ordinary_users(self):
        self.login("admin@t.local")
        p = self.client.post("/api/grc/policies", json={"title": "Acceptable use", "body": "Be careful.", "owner": "CISO", "status": "active"})
        self.assertEqual(p.status_code, 200, p.text)
        pid = p.json()["id"]
        draft = self.client.post("/api/grc/policies", json={"title": "Draft", "body": "x"}).json()
        admin_view = self.client.get("/api/grc/policies").json()["policies"]
        self.assertEqual({x["title"] for x in admin_view}, {"Acceptable use", "Draft"})
        self.login("user@t.local")
        view = self.client.get("/api/grc/policies").json()["policies"]
        self.assertEqual([(x["title"], x["acknowledged_by_me"]) for x in view], [("Acceptable use", False)])
        self.assertEqual(self.client.post(f"/api/grc/policies/{draft['id']}/acknowledge").status_code, 400)
        self.assertEqual(self.client.post(f"/api/grc/policies/{pid}/acknowledge").status_code, 200)
        self.assertTrue(self.client.get("/api/grc/policies").json()["policies"][0]["acknowledged_by_me"])
        self.assertEqual(self.client.put(f"/api/grc/policies/{pid}", json={"body": "new"}).status_code, 403)
        self.login("admin@t.local")
        upd = self.client.put(f"/api/grc/policies/{pid}", json={"body": "Be very careful."}).json()
        self.assertEqual((upd["version"], upd["acknowledged_by"]), (2, []))


if __name__ == "__main__":
    unittest.main()
