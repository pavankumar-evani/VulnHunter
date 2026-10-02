"""
Tests for the release gate, the secure design assistant, custom DevSecOps controls, the OSV connector, and the application / pull-request API routes.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import appsec_api  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from appsec_fixtures import SBOM, code_finding, dep_finding  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.appsec import store as app_store  # noqa: E402
from remediation.connectors import git_host_connector as gh  # noqa: E402
from remediation.connectors import osv_connector  # noqa: E402
from remediation.devsecops import controls, design, gates  # noqa: E402
from remediation.gitops import proposals  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from test_gitops import FILE, PATCH, FakeSession, TestPom  # noqa: E402

PW = "test-password-123"
NOW = datetime.datetime(2026, 10, 2, 12, 0, tzinfo=datetime.timezone.utc)


def fnd(i, sev="High", days_old=3, kev=False, scan_type="sca", fixed="2.0", **kw):
    first = (NOW - datetime.timedelta(days=days_old)).strftime("%Y-%m-%d")
    f = {"id": f"FIND-{i}", "title": f"Issue {i}", "severity": sev, "scan_type": scan_type, "asset": {"name": "orders"}, "first_seen": first, "kev": {"listed": kev}}
    if fixed:
        f["dependency"] = {"package": "x", "fixed_version": fixed}
    f.update(kw)
    return f


def run(scan_type, days_old=1):
    return {"asset": "orders", "scan_type": scan_type, "tool": "t", "source": "s", "findings": 0, "received_at": (NOW - datetime.timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")}


GOOD_RUNS = [run("sast"), run("sca"), run("secrets")]
SBOM_OK = {"uploaded_at": (NOW - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), "components": 5, "format": "cyclonedx-1.5"}


class GateTests(unittest.TestCase):
    def ev(self, findings=(), runs=GOOD_RUNS, sbom=SBOM_OK, env="production"):
        return gates.evaluate("orders", env, list(findings), list(runs), sbom, now=NOW)

    def status(self, res):
        return {r["id"]: r["status"] for r in res["rules"]}

    def test_a_clean_application_passes_everything(self):
        r = self.ev()
        self.assertEqual(r["decision"], "pass")
        self.assertEqual(self.status(r), {k: "pass" for k in ("open_severity", "known_exploited", "fixable_overdue", "required_scans", "sbom", "secrets")})

    def test_critical_and_known_exploited_block_production_but_only_warn_in_staging(self):
        fs = [fnd(1, "Critical", kev=True)]
        prod = self.ev(fs)
        self.assertEqual(prod["decision"], "fail")
        self.assertEqual(self.status(prod)["known_exploited"], "fail")
        self.assertEqual(prod["rules"][0]["finding_ids"], ["FIND-1"])
        self.assertIn("1 open Critical", prod["rules"][0]["detail"])
        stg = self.ev(fs, env="staging")
        self.assertEqual((self.status(stg)["open_severity"], self.status(stg)["known_exploited"]), ("warn", "fail"))
        dev = self.ev([fnd(2, "Critical")], env="development")
        self.assertEqual((dev["decision"], self.status(dev)["open_severity"]), ("pass", "skipped"))

    def test_an_active_exception_does_not_count(self):
        r = self.ev([fnd(1, "Critical", kev=True, exception={"id": 1})])
        self.assertEqual(r["decision"], "pass")

    def test_overdue_fixable_findings(self):
        self.assertEqual(self.status(self.ev([fnd(1, "High", days_old=30)])).get("fixable_overdue"), "fail")
        self.assertEqual(self.status(self.ev([fnd(1, "High", days_old=5)])).get("fixable_overdue"), "pass")
        self.assertEqual(self.status(self.ev([fnd(1, "High", days_old=30, fixed=None)])).get("fixable_overdue"), "pass")  # nothing to apply yet
        self.assertEqual(self.status(self.ev([fnd(1, "Medium", days_old=300)])).get("fixable_overdue"), "pass")  # below the severity floor

    def test_missing_or_stale_scans_are_reported_not_assumed_clean(self):
        r = self.ev(runs=[run("sast"), run("sca", days_old=40)])
        rule = next(x for x in r["rules"] if x["id"] == "required_scans")
        self.assertEqual(rule["status"], "fail")
        self.assertIn("secrets (never uploaded)", rule["detail"])
        self.assertIn("sca (last 40 days ago)", rule["detail"])
        self.assertEqual(r["decision"], "fail")

    def test_sbom_age_and_absence_and_secret_findings(self):
        self.assertEqual(self.status(self.ev(sbom=None))["sbom"], "fail")
        old = {**SBOM_OK, "uploaded_at": (NOW - datetime.timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.assertEqual(self.status(self.ev(sbom=old))["sbom"], "fail")
        r = self.ev([fnd(1, "Low", scan_type="secrets", fixed=None)])
        self.assertEqual(self.status(r)["secrets"], "fail")

    def test_unknown_environment_uses_the_default_and_says_so(self):
        r = self.ev(env="qa")
        self.assertEqual((r["environment"], r["requested_environment"]), ("production", "qa"))

    def test_policy_validation(self):
        with tempfile.TemporaryDirectory() as d:
            pol = yaml.safe_load(gates.PATH.read_text(encoding="utf-8"))
            pol["environments"]["production"]["secrets"] = "maybe"
            (Path(d) / "g.yaml").write_text(yaml.safe_dump(pol), encoding="utf-8")
            with self.assertRaises(ValueError):
                gates.load(Path(d) / "g.yaml")
            pol["environments"]["production"]["secrets"] = False  # an unquoted off
            (Path(d) / "g.yaml").write_text(yaml.safe_dump(pol), encoding="utf-8")
            self.assertEqual(gates.load(Path(d) / "g.yaml")["environments"]["production"]["secrets"], "off")

    def test_snippets_are_valid_yaml_and_carry_no_secret(self):
        s = gates.snippets("https://quanta.example/", "orders", "production")
        for k in ("github-actions", "gitlab-ci"):
            self.assertIn("orders", yaml.safe_load(s[k])["release-gate"] and s[k])
        self.assertIn("secrets.QUANTA_API_KEY", s["github-actions"])
        self.assertIn("https://quanta.example/api/gate/evaluate?application=orders&environment=production", s["shell"])


class DesignTests(unittest.TestCase):
    def setUp(self):
        self.lib = controls.library()
        self.spec = design.load()

    def test_every_rule_points_at_real_controls_and_questions(self):
        ids = {c["id"] for c in self.lib}
        qs = {q["id"]: q for q in self.spec["questions"]}
        for r in self.spec["rules"]:
            self.assertTrue(set(r["controls"]) <= ids, (r["id"], set(r["controls"]) - ids))
            self.assertIn(r["priority"], ("must", "should"))
            self.assertTrue(set(r["stride"]) <= set("STRIDE"))
            for term in (r["when"].get("all") or []) + (r["when"].get("any") or []):
                q, v = term.split("=")
                self.assertIn(q, qs, r["id"])
                self.assertIn(v, ["yes", "no"] if qs[q]["type"] == "yesno" else qs[q]["options"], term)
        self.assertEqual(len({r["id"] for r in self.spec["rules"]}), len(self.spec["rules"]))

    def test_answers_drive_the_requirements(self):
        res = design.assess({"internet_facing": "yes", "payment_data": "yes", "file_upload": "yes", "authentication": "api-keys", "open_source": "yes"}, self.lib)
        got = {r["id"] for r in res["requirements"]}
        self.assertTrue({"threat-model", "payment-scope", "safe-uploads", "key-management", "dependency-hygiene", "authenticate-everything"} <= got)
        self.assertNotIn("llm-boundaries", got)
        self.assertEqual(res["requirements"][0]["priority"], "must")
        self.assertIn("sca", {c["id"] for c in res["controls"]})
        self.assertTrue(any(t["letter"] == "T" for t in res["threat_prompts"]))
        none = design.assess({"internet_facing": "no", "personal_data": "no"}, self.lib)
        self.assertEqual(none["requirements"], [])  # no answer is treated as yes
        self.assertIn("containers", none["unanswered"])

    def test_bad_answers_are_refused(self):
        for bad in ({"nope": "yes"}, {"internet_facing": "maybe"}, {"authentication": "telepathy"}):
            with self.assertRaises(ValueError):
                design.assess(bad, self.lib)

    def test_markdown(self):
        md = design.to_markdown("orders", design.assess({"uses_llm": "yes", "internet_facing": "yes"}, self.lib))
        self.assertIn("# Security requirements: orders", md)
        self.assertIn("## Required", md)
        self.assertIn("OWASP ASVS 4.0", md)
        self.assertIn("not a threat model", md)


class CustomControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def test_custom_controls_join_the_library_and_use_the_same_evidence(self):
        c = controls.save_custom_control("org-change-ticket", {"stage": "release", "title": "Every release has a change ticket", "why": "Auditors ask.", "how": "Link the ticket in the release job.",
                                                               "keywords": ["Change Ticket", " "], "evidence": {"scan_type": "dast"}}, "admin", self.engine)
        self.assertEqual(c["keywords"], ["change ticket"])
        lib = controls.full_library(self.engine)
        self.assertEqual(len(lib), len(controls.library()) + 1)
        mine = next(x for x in lib if x["id"] == "org-change-ticket")
        self.assertTrue(mine["custom"])
        none = controls.control_status(mine, "orders", [], [], [])
        self.assertEqual(none["status"], "no-evidence")
        seen = controls.control_status(mine, "orders", [run("dast")], [], [])
        self.assertEqual(seen["status"], "evidenced")
        ov = controls.overview([run("dast")], [], [], lib=lib)
        self.assertIn("org-change-ticket", {c["id"] for c in ov["per_control"]})
        m = controls.map_policy("Every release must have an approved Change Ticket attached.", lib)
        self.assertEqual(m["matched"][0]["controls"][0]["id"], "org-change-ticket")

    def test_validation(self):
        ok = {"stage": "code", "title": "T", "why": "W", "how": "H"}
        for cid, fields in (("bad id", ok), ("org-x", {**ok, "stage": "moon"}), ("org-x", {**ok, "title": ""}), ("org-x", {**ok, "evidence": {"quanta": "sbom"}}),
                            ("org-x", {**ok, "evidence": {"clean_of": "GHA001"}}), ("sast", ok), ("org-sast", {**ok, "evidence": {"a": 1, "b": 2}})):
            with self.assertRaises(ValueError, msg=(cid, fields)):
                controls.save_custom_control(cid, fields, "admin", self.engine)
        controls.save_custom_control("org-x", ok, "admin", self.engine)
        controls.set_state("orders", "org-x", "implemented", "n", "admin", self.engine)
        self.assertTrue(controls.delete_custom_control("org-x", self.engine))
        self.assertFalse(controls.delete_custom_control("org-x", self.engine))
        self.assertEqual(controls.states(self.engine), [])  # the recorded states of a deleted control go with it

    def test_sbom_and_gate_controls_have_evidence_from_quanta_itself(self):
        lib = {c["id"]: c for c in controls.library()}
        iso = lambda days: (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        ex = {"sboms": {"orders": {"format": "cyclonedx-1.5", "components": 7, "uploaded_at": iso(1)}}, "gate_runs": {"orders": iso(2), "old": iso(90)}}
        self.assertEqual(controls.control_status(lib["sbom"], "Orders", [], [], [], extras=ex)["status"], "evidenced")
        self.assertEqual(controls.control_status(lib["sbom"], "other", [], [], [], extras=ex)["status"], "no-evidence")
        self.assertEqual(controls.control_status(lib["vulnerability-gate"], "orders", [], [], [], extras=ex)["status"], "evidenced")
        self.assertEqual(controls.control_status(lib["vulnerability-gate"], "old", [], [], [], extras=ex)["status"], "no-evidence")
        self.assertEqual(controls.control_status(lib["sbom"], "orders", [], [], [])["status"], "no-evidence")  # no extras supplied


class FakeOsv:
    def __init__(self):
        self.queried = None

    def query(self, comps):
        self.queried = comps
        return [["GHSA-xxxx-1111"] if c["name"] == "log4j-core" else [] for c in comps]

    def advisory(self, i):
        return {"id": i, "summary": "Remote code execution in log4j", "aliases": ["CVE-2021-44228"], "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}, {"fixed": "2.17.1"}]}]}]}


class OsvConnectorTests(unittest.TestCase):
    def test_request_shapes_and_batches(self):
        calls = []

        class S:
            def post(self, url, json=None, timeout=None):
                calls.append(("POST", url, json))
                return type("R", (), {"status_code": 200, "json": lambda self: {"results": [{"vulns": [{"id": "OSV-1"}]}, {}]}})()

            def get(self, url, timeout=None):
                calls.append(("GET", url, None))
                return type("R", (), {"status_code": 200, "json": lambda self: {"id": "OSV-1"}})()
        c = osv_connector.OsvConnector(session=S())
        out = c.query([{"purl": "pkg:pypi/a@1.0", "name": "a", "ecosystem": "pypi", "version": "1.0"}, {"purl": "pkg:npm/b", "name": "b", "ecosystem": "npm", "version": "2.0"}])
        self.assertEqual(out, [["OSV-1"], []])
        q = calls[0][2]["queries"]
        self.assertEqual(q[0], {"package": {"purl": "pkg:pypi/a@1.0"}})
        self.assertEqual(q[1], {"package": {"name": "b", "ecosystem": "npm"}, "version": "2.0"})  # a purl without a version falls back to name and version
        self.assertEqual(c.advisory("OSV-1"), {"id": "OSV-1"})
        self.assertTrue(calls[1][1].endswith("/v1/vulns/OSV-1"))
        with self.assertRaises(osv_connector.OsvError):
            c.advisory("../etc/passwd")

    def test_fixed_version_picks_the_lowest_fix_above_the_installed_version(self):
        adv = FakeOsv().advisory("X")
        self.assertEqual(osv_connector.fixed_version(adv, "maven", "org.apache.logging.log4j:log4j-core", "2.14.1"), "2.15.0")
        self.assertEqual(osv_connector.fixed_version(adv, "maven", "org.apache.logging.log4j:log4j-core", "2.16.0"), "2.17.1")
        self.assertIsNone(osv_connector.fixed_version(adv, "maven", "org.apache.logging.log4j:log4j-core", "2.17.1"))
        self.assertIsNone(osv_connector.fixed_version(adv, "maven", "other", "1.0"))

    def test_findings_are_in_quantas_schema(self):
        comp = {"name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1", "ecosystem": "maven", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "direct": False}
        f = osv_connector.to_findings("orders", [comp], [(comp, FakeOsv().advisory("GHSA-xxxx-1111"))], "2026-10-02")[0]
        self.assertEqual((f["severity"], f["cve"], f["scan_type"], f["remediation_domain"]), ("Critical", "CVE-2021-44228", "sca", "application"))
        self.assertEqual(f["dependency"], {"package": "org.apache.logging.log4j:log4j-core", "ecosystem": "maven", "version": "2.14.1", "fixed_version": "2.15.0", "direct": False})
        self.assertEqual(f["asset"]["name"], "orders")
        self.assertIsNone(f["cvss"])


class ApiBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fs = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", cvss=10.0, kev=True, epss=0.97),
                   dep_finding(2, "log4j-core", "2.14.1", "2.15.0", "CVE-2021-45046", cvss=9.0), code_finding(5, "app/db.py")]
        self.merge_calls = []

        def fake_merge(findings, source, **kw):
            self.merge_calls.append((findings, source, kw))
            return {"added": len(findings), "updated": 0, "removed": 0, "total": len(findings)}
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", side_effect=lambda: [dict(f) for f in self.fs]),
                  patch.object(appsec_api.findings_merge, "merge", side_effect=fake_merge)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("admin2@t.local", PW, "Admin2", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.keys = {}
        for name, scopes in (("ci", ["ingest:write", "read:findings"]), ("hook", ["tickets:update"]), ("weak", ["read:findings"])):
            self.keys[name] = self.client.post("/api/api-keys", json={"name": name, "scopes": scopes}).json()["key"]
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

    def bearer(self, name):
        return {"Authorization": f"Bearer {self.keys[name]}"}

    def make_app(self, **extra):
        body = {"environment": "production", "internet_facing": True, "business_criticality": "high", "repo_provider": "github", "repo": "acme/orders", "default_branch": "main",
                "manifest_paths": ["pom.xml"], **extra}
        r = self.client.put("/api/applications/orders/context", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()


class ApplicationApiTests(ApiBase):
    def test_permissions(self):
        self.assertEqual(self.client.get("/api/applications").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/applications").status_code, 200)
        self.assertEqual(self.client.put("/api/applications/orders/context", json={"owner": "x"}).status_code, 403)
        self.assertEqual(self.client.post("/api/applications/orders/sbom", content=json.dumps(SBOM)).status_code, 403)
        self.assertEqual(self.client.post("/api/applications/orders/osv-check", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/gitops/proposals/dependency", json={"application": "orders", "item_id": "dep:x"}).status_code, 403)
        self.assertEqual(self.client.post("/api/gitops/proposals/1/open", json={"confirm": True}).status_code, 403)
        self.assertEqual(self.client.post("/api/gitops/sync").status_code, 403)
        self.assertEqual(self.client.put("/api/devsecops/custom-controls/org-x", json={"stage": "code", "title": "t", "why": "w", "how": "h"}).status_code, 403)

    def test_context_sbom_and_analysis_round_trip(self):
        self.login("admin@t.local")
        self.make_app()
        self.assertEqual(self.client.put("/api/applications/orders/context", json={"environment": "moon"}).status_code, 400)
        up = self.client.post("/api/applications/orders/sbom?source=manual", content=json.dumps(SBOM))
        self.assertEqual((up.status_code, up.json()["components"]), (200, 6), up.text)
        self.assertEqual(self.client.post("/api/applications/orders/sbom", content="nope").status_code, 400)
        a = self.client.get("/api/applications/orders/analysis").json()
        self.assertEqual(a["stats"]["vulnerable_components"], 1)
        self.assertEqual(a["work_items"][0]["package"], "log4j-core")
        self.assertEqual(a["work_items"][0]["target_version"], "2.17.1")
        self.assertEqual(a["sbom"]["format"], "cyclonedx-1.5")
        self.assertEqual(self.client.get("/api/applications/orders/analysis?view=weird").status_code, 400)
        self.assertEqual(self.client.get("/api/applications/ghost/analysis").status_code, 404)
        lst = self.client.get("/api/applications").json()
        row = lst["applications"][0]
        self.assertEqual((row["name"], row["findings"], row["sbom"]["components"]), ("orders", 3, 6))
        self.assertEqual(self.client.delete("/api/applications/orders/context").status_code, 200)
        self.assertEqual(self.client.delete("/api/applications/orders/context").status_code, 404)

    def test_ci_uploads_an_sbom_with_an_api_key_and_creates_the_application(self):
        r = self.client.post("/api/ingest/sbom?application=payments", content=json.dumps(SBOM), headers=self.bearer("ci"))
        self.assertEqual((r.status_code, r.json()["components"]), (200, 6), r.text)
        self.assertEqual(self.client.post("/api/ingest/sbom?application=payments", content=json.dumps(SBOM)).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/sbom?application=payments", content=json.dumps(SBOM), headers=self.bearer("hook")).status_code, 401)  # wrong scope
        self.assertEqual(self.client.post("/api/ingest/sbom?application=payments", content="x", headers=self.bearer("ci")).status_code, 400)
        self.assertIsNotNone(app_store.get_application("payments", self.engine))

    def test_generate_an_sbom_from_dependency_files(self):
        self.login("admin@t.local")
        r = self.client.post("/api/applications/web/sbom/generate", json={"files": {"requirements.txt": "flask==2.0.1\n"}})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["components"], 1)
        self.assertTrue(r.json()["notes"])
        self.assertEqual(self.client.post("/api/applications/web/sbom/generate", json={"files": {"Gemfile": "x"}}).status_code, 400)

    def test_osv_check_asks_first_then_creates_findings(self):
        self.login("admin@t.local")
        self.make_app()
        self.client.post("/api/applications/orders/sbom", content=json.dumps(SBOM))
        fake = FakeOsv()
        with patch.object(appsec_api, "osv_connector_factory", return_value=fake):
            pre = self.client.post("/api/applications/orders/osv-check", json={}).json()
            self.assertTrue(pre["preview_only"])
            self.assertIsNone(fake.queried)  # nothing was sent
            self.assertNotIn("orders", json.dumps(pre["example"]))
            done = self.client.post("/api/applications/orders/osv-check", json={"confirm": True}).json()
        self.assertEqual((done["preview_only"], done["advisories"], done["findings"], done["source"]), (False, 1, 1, "osv-orders"))
        findings, source, kw = self.merge_calls[-1]
        self.assertEqual((source, kw), ("osv-orders", {"reconcile": True}))
        self.assertEqual(findings[0]["dependency"]["package"], "org.apache.logging.log4j:log4j-core")
        self.assertTrue(all("orders" not in c["purl"] for c in fake.queried))
        no_sbom = self.client.post("/api/applications/ghost/osv-check", json={"confirm": True})
        self.assertEqual(no_sbom.status_code, 404)


class PullRequestApiTests(ApiBase):
    def setUp(self):
        super().setUp()
        self.login("admin@t.local")
        self.make_app()
        self.client.post("/api/applications/orders/sbom", content=json.dumps(SBOM))
        self.session = FakeSession("github", {"pom.xml": TestPom, "app/db.py": FILE})
        self.conn = gh.GitHubConnector("tok", session=self.session)
        self.cp = patch.object(appsec_api.gitops_service, "connector", return_value=(self.conn, {"name": "GitHub (acme)"}))
        self.fp = patch.object(appsec_api.gitops_service, "find_connection", return_value=({"name": "GitHub (acme)"}, {}))
        self.cp.start()
        self.fp.start()

    def tearDown(self):
        self.cp.stop()
        self.fp.stop()
        super().tearDown()

    def propose(self, **kw):
        r = self.client.post("/api/gitops/proposals/dependency", json={"application": "orders", "item_id": "dep:log4j-core", "manifests": {"pom.xml": TestPom}, **kw})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_the_whole_workflow(self):
        p = self.propose()
        self.assertEqual((p["status"], p["summary"]["to"], p["summary"]["from"]), ("draft", "2.17.1", "2.14.1"))
        self.assertNotIn("new_content", json.dumps(p))
        pid = p["id"]
        # opening before approval is refused
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{pid}/open", json={"confirm": True}).status_code, 409)
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{pid}/approve").status_code, 200)
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{pid}/approve").status_code, 409)
        dry = self.client.post(f"/api/gitops/proposals/{pid}/open", json={}).json()
        self.assertTrue(dry["preview_only"])
        self.assertEqual(dry["connection"], "GitHub (acme)")
        self.assertEqual(self.session.calls, [])  # a dry run sends nothing
        live = self.client.post(f"/api/gitops/proposals/{pid}/open", json={"confirm": True})
        self.assertEqual(live.status_code, 200, live.text)
        self.assertTrue(live.json()["pr_url"].endswith("/pull/7"))
        detail = self.client.get(f"/api/gitops/proposals/{pid}").json()
        self.assertEqual((detail["status"], detail["pr_number"]), ("pr-opened", 7))
        self.assertIn("diff", detail["files"][0])
        self.assertEqual(detail["plan"]["branch"], detail["branch"])
        self.assertEqual(detail["verification"]["state"], "not-merged")
        # the host reports a merge; Quanta only observes it
        self.session.pr = {"state": "closed", "merged": True, "merged_at": "2026-10-02T10:00:00Z"}
        for f in self.fs:
            f["last_seen"] = "2026-10-03"
        with patch.object(appsec_api.gitops_service, "connector_for_proposal", return_value=self.conn):
            s = self.client.post("/api/gitops/sync").json()
        self.assertTrue(s["synced"][0]["ok"])
        self.assertEqual(s["verification"][0]["state"], "still-present")  # the same findings are still in the queue
        self.fs.clear()
        v = self.client.post("/api/gitops/verify").json()["verification"][0]
        self.assertEqual(v["state"], "verified")
        vel = self.client.get("/api/gitops/velocity").json()
        self.assertEqual((vel["outcomes"]["merged"], vel["outcomes"]["verified"]), (1, 1))
        listed = self.client.get("/api/gitops/proposals?application=orders").json()["proposals"]
        self.assertEqual([x["id"] for x in listed], [pid])
        self.assertEqual(self.client.get("/api/gitops/proposals/999").status_code, 404)

    def test_inbound_status_needs_the_right_key(self):
        p = self.propose()
        self.client.post(f"/api/gitops/proposals/{p['id']}/approve")
        self.client.post(f"/api/gitops/proposals/{p['id']}/open", json={"confirm": True})
        body = {"proposal": str(p["id"]), "state": "merged", "merged_at": "2026-10-03T08:00:00Z"}
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/inbound/pr-status", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/inbound/pr-status", json=body, headers=self.bearer("ci")).status_code, 401)
        r = self.client.post("/api/inbound/pr-status", json=body, headers=self.bearer("hook"))
        self.assertEqual((r.status_code, r.json()["status"]), (200, "merged"), r.text)
        self.assertEqual(self.client.post("/api/inbound/pr-status", json={**body, "state": "weird"}, headers=self.bearer("hook")).status_code, 400)
        self.assertEqual(self.client.post("/api/inbound/pr-status", json={**body, "proposal": "999"}, headers=self.bearer("hook")).status_code, 404)

    def test_fetching_files_from_the_repository_and_reporting_lock_files(self):
        self.session.files["package-lock.json"] = "{}"
        r = self.client.post("/api/gitops/proposals/dependency", json={"application": "orders", "item_id": "dep:log4j-core", "fetch": True})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["summary"]["manifests"], ["pom.xml"])
        self.assertEqual([c for c in self.session.calls if c[0] != "GET"], [])  # reading only

    def test_dependency_proposal_errors(self):
        post = lambda b: self.client.post("/api/gitops/proposals/dependency", json=b)  # noqa: E731
        self.assertEqual(post({"application": "ghost", "item_id": "dep:x"}).status_code, 404)
        self.assertEqual(post({"application": "orders", "item_id": "dep:nothing"}).status_code, 404)
        self.assertEqual(post({"application": "orders", "item_id": "dep:log4j-core"}).status_code, 400)  # neither files nor fetch
        self.propose()
        self.assertEqual(post({"application": "orders", "item_id": "dep:log4j-core", "manifests": {"pom.xml": TestPom}}).status_code, 400)  # already proposed
        r = post({"application": "orders", "item_id": "dep:log4j-core", "manifests": {".github/pom.xml": TestPom}})
        self.assertEqual(r.status_code, 400)

    def test_code_fix_proposal_over_the_api(self):
        body = {"application": "orders", "finding_id": "FIND-5", "patches": {"app/db.py": PATCH}, "originals": {"app/db.py": FILE}, "explanation": "Parameterise.", "validation": {"confirmed_vulnerable": True}}
        r = self.client.post("/api/gitops/proposals/code", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["kind"], "code-fix")
        self.assertEqual(self.client.post("/api/gitops/proposals/code", json={**body, "finding_id": "FIND-1"}).status_code, 404)  # a dependency finding is not a code fix
        self.assertEqual(self.client.post("/api/gitops/proposals/code", json={**body, "finding_id": "../x"}).status_code, 400)
        self.assertEqual(self.client.post("/api/gitops/proposals/code", json=body).status_code, 400)  # the same change is already proposed
        self.assertEqual(self.client.post("/api/gitops/proposals/code", json={"application": "orders", "finding_id": "FIND-5", "from_output": True}).status_code, 404)

    def test_discard_and_policy_endpoint(self):
        p = self.propose()
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{p['id']}/discard", json={"reason": "no"}).json()["status"], "discarded")
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{p['id']}/discard", json={}).status_code, 409)  # already discarded
        pol = self.client.get("/api/gitops/policy").json()
        self.assertIn("merge a pull request", pol["never"])
        self.assertIn("steps", pol["policy"]["process"])


class GateAndDesignApiTests(ApiBase):
    def test_ci_gate_needs_a_key_and_records_each_evaluation(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/gate/evaluate?application=orders").status_code, 401)
        r = self.client.get("/api/gate/evaluate?application=orders&environment=production", headers=self.bearer("weak"))
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["decision"], "fail")  # a critical known-exploited finding, no scans, no SBOM
        self.assertFalse(d["application_known"])
        self.assertIn("known_exploited", {x["id"] for x in d["rules"] if x["status"] == "fail"})
        self.assertEqual(gates.history("orders", engine=self.engine)[0]["decision"], "fail")
        self.assertEqual(self.client.get("/api/gate/evaluate?application=", headers=self.bearer("weak")).status_code, 400)
        # the library's release-gate control is now evidenced for this application
        self.login("admin@t.local")
        ov = self.client.get("/api/devsecops/repos?asset=orders").json()
        self.assertEqual(next(c for c in ov["controls"] if c["id"] == "vulnerability-gate")["status"], "evidenced")

    def test_gate_page_route_and_info(self):
        self.login("user@t.local")
        r = self.client.post("/api/pipeline-gates/evaluate", json={"application": "orders", "environment": "staging"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["environment"], "staging")
        info = self.client.get("/api/pipeline-gates?application=orders").json()
        self.assertEqual(info["history"][0]["application"], "orders")
        self.assertIn("api/gate/evaluate?application=orders", info["snippets"]["shell"])
        self.assertIn("production", info["policy"]["environments"])
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/pipeline-gates/evaluate", json={"application": "orders"}).status_code, 401)

    def test_sbom_evidence_appears_for_the_sbom_control(self):
        self.login("admin@t.local")
        self.client.post("/api/applications/orders/sbom", content=json.dumps(SBOM))
        sb = next(c for c in self.client.get("/api/devsecops/repos?asset=orders").json()["controls"] if c["id"] == "sbom")
        self.assertEqual(sb["status"], "evidenced")

    def test_secure_design_assistant(self):
        self.login("user@t.local")
        q = self.client.get("/api/secure-design/questions").json()["questions"]
        self.assertGreaterEqual(len(q), 10)
        r = self.client.post("/api/secure-design/assess", json={"answers": {"internet_facing": "yes", "uses_llm": "yes"}})
        self.assertEqual(r.status_code, 200)
        self.assertIn("llm-boundaries", {x["id"] for x in r.json()["requirements"]})
        md = self.client.post("/api/secure-design/assess?format=markdown", json={"answers": {"internet_facing": "yes"}, "name": "orders"})
        self.assertIn("text/markdown", md.headers["content-type"])
        self.assertIn("# Security requirements: orders", md.text)
        self.assertEqual(self.client.post("/api/secure-design/assess", json={"answers": {"internet_facing": "perhaps"}}).status_code, 400)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/secure-design/questions").status_code, 401)

    def test_custom_control_lifecycle_through_the_library_views(self):
        self.login("admin@t.local")
        body = {"stage": "release", "title": "Change ticket", "why": "Audit.", "how": "Link it.", "keywords": ["change ticket"], "evidence": {"scan_type": "dast"}}
        self.assertEqual(self.client.put("/api/devsecops/custom-controls/org-change-ticket", json=body).status_code, 200)
        self.assertEqual(self.client.put("/api/devsecops/custom-controls/BAD", json=body).status_code, 400)
        ov = self.client.get("/api/devsecops/overview").json()
        mine = next(c for c in ov["library"] if c["id"] == "org-change-ticket")
        self.assertTrue(mine["custom"])
        m = self.client.post("/api/devsecops/policy-check", json={"text": "Each release needs an approved change ticket before deployment."}).json()
        self.assertIn("org-change-ticket", m["controls_referenced"])
        self.assertEqual(self.client.delete("/api/devsecops/custom-controls/org-change-ticket").status_code, 200)
        self.assertEqual(self.client.delete("/api/devsecops/custom-controls/org-change-ticket").status_code, 404)


if __name__ == "__main__":
    unittest.main()
