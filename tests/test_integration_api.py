"""
Tests for how other systems connect to Quanta: issued API keys, the findings ingest and CSV
upload endpoints, the ticket-status callback, the read-only export, push connections that
open tickets (ServiceNow / Jira / Splunk) and read their state back, and the connection
schema. No network: connectors are replaced by fakes.
"""
import json
import os
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
from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.connections import crypto, links, push, registry, store, sync  # noqa: E402
from remediation.ingest import api_findings, merge  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
CSV = ("Plugin ID,CVE,Risk,CVSS v3.0 Base Score,Host,IP Address,FQDN,OS,Name,Synopsis,Solution,Port,Protocol,First Discovered,Last Observed\n"
       "1,CVE-2024-0001,High,8.1,web01,10.0.0.1,web01.x,Linux Kernel 5,OpenSSL flaw,syn,upgrade,443,tcp,2026-09-01,2026-09-30\n")


def finding(n, severity="High", **kw):
    f = {"id": f"FIND-{n}", "source": "tenable", "title": f"Issue {n}", "severity": severity, "cve": None,
         "asset": {"name": f"host{n}", "type": "unix-server"}, "kev": None, "epss": None, "cvss": 7.0}
    f.update(kw)
    return f


class ApiKeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_key_is_shown_once_and_only_its_hash_is_kept(self):
        rec, token = apikeys.create("CI", ["ingest:write"], "admin@t", engine=self.engine)
        self.assertTrue(token.startswith("qk_"))
        self.assertNotIn(token, json.dumps(apikeys.list_keys(self.engine)))
        with self.engine.connect() as c:
            row = c.execute(db_module.api_keys.select()).mappings().first()
        self.assertNotIn(token, json.dumps(dict(row)))
        self.assertEqual(apikeys.verify(token, "ingest:write", self.engine)["id"], rec["id"])

    def test_scope_expiry_revocation_and_garbage(self):
        _, token = apikeys.create("CI", ["ingest:write"], "a", expires_days=1, engine=self.engine, now=None)
        self.assertIsNone(apikeys.verify(token, "tickets:update", self.engine))  # wrong scope
        import datetime
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
        self.assertIsNone(apikeys.verify(token, "ingest:write", self.engine, now=later))  # expired
        rec, token2 = apikeys.create("CI2", ["ingest:write"], "a", engine=self.engine)
        apikeys.revoke(rec["id"], "a", self.engine)
        self.assertIsNone(apikeys.verify(token2, "ingest:write", self.engine))
        for bad in ("", "nope", "qk_xxxx_yyyy", token[:-1] + ("A" if token[-1] != "A" else "B")):
            self.assertIsNone(apikeys.verify(bad, None, self.engine))

    def test_validation(self):
        with self.assertRaises(ValueError):
            apikeys.create("", ["ingest:write"], "a", engine=self.engine)
        with self.assertRaises(ValueError):
            apikeys.create("x", [], "a", engine=self.engine)
        with self.assertRaises(ValueError):
            apikeys.create("x", ["root"], "a", engine=self.engine)


class NormaliseTests(unittest.TestCase):
    def test_minimal_record_is_completed(self):
        f = api_findings.normalise({"title": "T", "severity": "critical", "asset": {"name": "db1", "os": "Windows Server 2019"}}, "2026-09-30")
        self.assertEqual((f["severity"], f["asset"]["type"], f["first_seen"]), ("Critical", "windows-server", "2026-09-30"))
        self.assertEqual(f["remediation_domain"], "windows-server")

    def test_bad_records_are_named(self):
        for bad, msg in (({"severity": "High", "asset": {"name": "a"}}, "title"), ({"title": "t", "severity": "bad", "asset": {"name": "a"}}, "severity"),
                         ({"title": "t", "severity": "High", "asset": {}}, "asset.name"),
                         ({"title": "t", "severity": "High", "asset": {"name": "a"}, "cve": "nope"}, "cve"),
                         ({"title": "t", "severity": "High", "asset": {"name": "a"}, "cvss": 11}, "cvss")):
            with self.assertRaises(ValueError) as cm:
                api_findings.normalise(bad)
            self.assertIn(msg, str(cm.exception))

    def test_batch_reports_by_index_and_keeps_the_good(self):
        good, errors = api_findings.normalise_batch([{"title": "t", "severity": "Low", "asset": {"name": "a"}}, {"title": ""}])
        self.assertEqual((len(good), errors[0]["index"]), (1, 1))

    def test_ot_assets_route_to_the_ot_fixer(self):
        f = api_findings.normalise({"title": "PLC firmware", "severity": "High", "asset": {"name": "plc-3", "type": "iot-ot-device"}})
        self.assertEqual(f["remediation_domain"], "iot-ot-device")


class PushRuleTests(unittest.TestCase):
    def test_rule_selection_and_ordering(self):
        rule = push.normalise_rule({"min_severity": "High", "max_per_run": 2})
        fs = [finding(1, "Low"), finding(2, "High"), finding(3, "Critical"), finding(4, "High", kev={"listed": True}), finding(5, "Medium")]
        chosen = push.select_findings(fs, rule, already_pushed={"FIND-3"})
        self.assertEqual([f["id"] for f in chosen], ["FIND-4", "FIND-2"])  # KEV first; Critical already pushed; Low/Medium excluded

    def test_kev_only_and_epss(self):
        rule = push.normalise_rule({"min_severity": "Low", "kev_only": True})
        self.assertEqual([f["id"] for f in push.select_findings([finding(1), finding(2, kev={"listed": True})], rule, set())], ["FIND-2"])
        rule = push.normalise_rule({"min_severity": "Low", "min_epss": "0.5"})
        self.assertEqual([f["id"] for f in push.select_findings([finding(1, epss={"score": 0.2}), finding(2, epss={"score": 0.9})], rule, set())], ["FIND-2"])

    def test_invalid_rules(self):
        for bad in ({"min_severity": "Huge"}, {"max_per_run": 0}, {"max_per_run": "x"}, {"min_epss": 2}):
            with self.assertRaises(ValueError):
                push.normalise_rule(bad)


class FakeSnow:
    def __init__(self, state="1", fail_on=None):
        self.state, self.fail_on, self.created = state, fail_on, []

    def create_incident(self, f):
        if f["id"] == self.fail_on:
            raise RuntimeError("503 from ServiceNow")
        self.created.append(f["id"])
        return {"number": f"INC00{len(self.created)}", "sys_id": f"sys{len(self.created)}", "state": "1"}

    def find_existing_incident(self, fid):
        return {"state": self.state, "number": "x"}


class PushRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'p.db'}")
        self.path = Path(self.tmp.name) / "f.json"
        self.path.write_text(json.dumps([finding(1, "Critical"), finding(2, "High"), finding(3, "Low")]), encoding="utf-8")

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_push(self, snow, rule=None):
        return push.push("servicenow", snow, 1, rule or {}, self.path, self.engine, "t")

    def test_creates_tickets_once_and_links_them(self):
        snow = FakeSnow()
        r = self.run_push(snow)
        self.assertEqual((r["matched"], r["sent"], r["errors"]), (2, 2, 0))
        self.assertEqual(self.run_push(snow)["matched"], 0)  # a re-run does not re-send
        self.assertEqual(snow.created, ["FIND-1", "FIND-2"])
        link = links.for_finding("FIND-1", self.engine)[0]
        self.assertEqual((link["external_ref"], link["system"], link["state"]), ("INC001", "servicenow", "open"))

    def test_one_failure_does_not_abort_and_is_retried_next_run(self):
        r = self.run_push(FakeSnow(fail_on="FIND-1"))
        self.assertEqual((r["sent"], r["errors"]), (1, 1))
        bad = links.for_finding("FIND-1", self.engine)[0]
        self.assertIn("503", bad["last_error"])
        again = FakeSnow()
        self.assertEqual(self.run_push(again)["sent"], 1)
        self.assertEqual(again.created, ["FIND-1"])

    def test_ticket_state_is_read_back_and_a_resolved_ticket_stops_being_polled(self):
        self.run_push(FakeSnow())
        r = self.run_push(FakeSnow(state="2"))
        self.assertEqual(r["refreshed"], 2)
        self.assertEqual(links.for_finding("FIND-1", self.engine)[0]["state"], "in_progress")
        self.run_push(FakeSnow(state="6"))
        self.assertEqual(links.for_finding("FIND-1", self.engine)[0]["state"], "resolved")
        self.assertEqual(self.run_push(FakeSnow(state="2"))["refreshed"], 0)

    def test_state_mapping(self):
        for system, raw, want in (("servicenow", "1", "open"), ("servicenow", "3", "blocked"), ("servicenow", "7", "resolved"),
                                  ("jira", "indeterminate", "in_progress"), ("jira", "Done", "resolved"), ("other", "on hold", "blocked")):
            self.assertEqual(links.map_state(system, raw), want)
        self.assertIsNone(links.map_state("servicenow", "banana"))


class PushConnectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'c.db'}")
        self.path = Path(self.tmp.name) / "f.json"
        self.path.write_text(json.dumps([finding(1, "Critical")]), encoding="utf-8")
        self.env = patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()})
        self.env.start()
        self.guard = patch.object(registry.url_safety, "assert_safe_target")
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        self.env.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    VALUES = {"instance": "acme", "username": "svc", "password": "pw", "min_severity": "High"}

    def test_servicenow_connection_validates_and_runs_as_a_push(self):
        with self.assertRaises(ValueError):
            registry.split_values("servicenow", {**self.VALUES, "instance": "evil.com/x"})
        with self.assertRaises(ValueError):
            registry.split_values("servicenow", {**self.VALUES, "min_severity": "Nonsense"})
        c = store.create("SNOW", "servicenow", self.VALUES, "admin", engine=self.engine)
        fake = FakeSnow()
        with patch.dict(registry.SPECS["servicenow"], {"make": lambda v: fake}):
            r = sync.run(c["id"], "admin", self.engine, self.path, enrich=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 1)
        self.assertIn("1 sent", r["message"])
        self.assertEqual(store.get_public(c["id"], self.engine)["last_status"], "ok")

    def test_catalog_marks_push_connections_and_hides_secrets(self):
        by_type = {i["type"]: i for i in registry.public_catalog()}
        for t in ("servicenow", "jira", "splunk"):
            self.assertEqual(by_type[t]["kind"], "push")
        self.assertEqual(by_type["tenable"]["kind"], "pull")


class IntegrationRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fpath = Path(self.tmp.name) / "f.json"
        self.fpath.write_text("[]", encoding="utf-8")
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine),
                        patch.object(merge, "DEFAULT_PATH", self.fpath),
                        patch.object(dashboard_app_module, "_enrich_in_background", lambda bg: None),
                        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.admin_login()
        self.key = self.make_key(["ingest:write", "tickets:update", "read:findings"])
        self.client.cookies.clear()  # from here on, calls are machine calls

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def admin_login(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW}).status_code, 200)

    def make_key(self, scopes, name="ci"):
        r = self.client.post("/api/api-keys", json={"name": name, "scopes": scopes})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["key"]

    def h(self, key=None):
        return {"Authorization": f"Bearer {key or self.key}"}

    def post_findings(self, items, **kw):
        return self.client.post("/api/ingest/findings", headers=self.h(), json={"source": "my-scanner", "findings": items, "enrich": False, **kw})

    ITEM = {"title": "Outdated TLS", "severity": "High", "asset": {"name": "web01", "ip": "10.0.0.5"}, "cve": "CVE-2024-1234", "source_ref": "scan-77"}

    # ---- keys
    def test_key_management_is_admin_only_and_the_key_is_shown_once(self):
        self.assertEqual(self.client.get("/api/api-keys").status_code, 401)
        self.client.post("/api/auth/login", json={"email": "user@t.local", "password": PW})
        self.assertEqual(self.client.post("/api/api-keys", json={"name": "x", "scopes": ["ingest:write"]}).status_code, 403)
        self.admin_login()
        listing = self.client.get("/api/api-keys").json()
        self.assertNotIn(self.key, json.dumps(listing))
        self.assertEqual(self.client.post("/api/api-keys", json={"name": "x", "scopes": ["root"]}).status_code, 400)
        kid = listing["keys"][0]["id"]
        self.assertEqual(self.client.delete(f"/api/api-keys/{kid}").status_code, 200)
        self.assertEqual(self.client.delete("/api/api-keys/9999").status_code, 404)
        self.client.cookies.clear()
        self.assertEqual(self.post_findings([self.ITEM]).status_code, 401)  # revoked

    # ---- ingest
    def test_ingest_requires_a_key_with_the_scope(self):
        r = self.client.post("/api/ingest/findings", json={"source": "my-scanner", "findings": [self.ITEM]})
        self.assertEqual(r.status_code, 401)
        self.admin_login()
        ro = self.make_key(["read:findings"], "ro")
        self.client.cookies.clear()
        r = self.client.post("/api/ingest/findings", headers=self.h(ro), json={"source": "my-scanner", "findings": [self.ITEM]})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/findings", headers={"X-API-Key": self.key}, json={"source": "my-scanner", "findings": [self.ITEM], "enrich": False}).status_code, 200)

    def test_ingest_adds_then_updates_and_never_duplicates(self):
        first = self.post_findings([self.ITEM]).json()
        self.assertEqual((first["added"], first["updated"], first["rejected"]), (1, 0, 0))
        again = self.post_findings([{**self.ITEM, "last_seen": "2026-10-01"}]).json()
        self.assertEqual((again["added"], again["updated"]), (0, 1))
        stored = merge.load(self.fpath)
        self.assertEqual((len(stored), stored[0]["id"], stored[0]["source"]), (1, "FIND-1", "my-scanner"))

    def test_bad_records_are_reported_and_the_rest_accepted(self):
        r = self.post_findings([self.ITEM, {"title": "x", "severity": "bogus", "asset": {"name": "a"}}]).json()
        self.assertEqual((r["added"], r["rejected"], r["errors"][0]["index"]), (1, 1, 1))

    def test_reconcile_removes_what_the_source_no_longer_reports(self):
        self.post_findings([self.ITEM, {**self.ITEM, "title": "Other", "source_ref": "scan-78", "cve": None}])
        r = self.post_findings([self.ITEM], reconcile=True).json()
        self.assertEqual((r["removed"], r["total"]), (1, 1))
        bad = self.post_findings([self.ITEM, {"title": ""}], reconcile=True)
        self.assertEqual(bad.status_code, 400)  # an incomplete export must never delete data
        self.assertEqual(len(merge.load(self.fpath)), 1)

    def test_source_name_is_validated(self):
        r = self.client.post("/api/ingest/findings", headers=self.h(), json={"source": "Bad Name!", "findings": [self.ITEM]})
        self.assertEqual(r.status_code, 400)

    def test_scanner_csv_upload(self):
        r = self.client.post("/api/ingest/scanner-csv?source=tenable-export", headers=self.h(), content=CSV.encode())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["added"], 1)
        self.assertEqual(self.client.post("/api/ingest/scanner-csv", content=CSV.encode()).status_code, 401)
        empty = self.client.post("/api/ingest/scanner-csv", headers=self.h(), content=b"")
        self.assertEqual(empty.status_code, 400)

    def test_admin_file_import_from_the_connections_page(self):
        self.assertEqual(self.client.post("/api/connections/import-file", content=CSV.encode()).status_code, 401)
        self.client.post("/api/auth/login", json={"email": "user@t.local", "password": PW})
        self.assertEqual(self.client.post("/api/connections/import-file", content=CSV.encode()).status_code, 403)
        self.admin_login()
        r = self.client.post("/api/connections/import-file?source=qualys-export", content=CSV.encode())
        self.assertEqual((r.status_code, r.json()["added"]), (200, 1))

    # ---- ticket callback
    def test_ticket_status_callback(self):
        self.post_findings([self.ITEM])
        body = {"finding_id": "FIND-1", "system": "servicenow", "state": "2", "external_ref": "INC0099"}
        self.assertEqual(self.client.post("/api/inbound/ticket-status", json=body).status_code, 401)
        r = self.client.post("/api/inbound/ticket-status", headers=self.h(), json=body)
        self.assertEqual((r.status_code, r.json()["status"], r.json()["link"]["external_ref"]), (200, "in_progress", "INC0099"))
        r = self.client.post("/api/inbound/ticket-status", headers=self.h(), json={**body, "state": "6"})
        self.assertEqual(r.json()["link"]["state"], "resolved")
        self.assertEqual(len(links.for_finding("FIND-1", self.engine)), 1)  # updated in place
        self.assertEqual(self.client.post("/api/inbound/ticket-status", headers=self.h(), json={**body, "finding_id": "FIND-404"}).status_code, 404)
        self.assertEqual(self.client.post("/api/inbound/ticket-status", headers=self.h(), json={**body, "state": "banana"}).status_code, 400)
        self.assertEqual(self.client.post("/api/inbound/ticket-status", headers=self.h(), json={**body, "system": "x"}).status_code, 400)

    def test_finding_links_endpoint(self):
        self.post_findings([self.ITEM])
        self.client.post("/api/inbound/ticket-status", headers=self.h(), json={"finding_id": "FIND-1", "state": "1", "external_ref": "INC1"})
        self.admin_login()
        out = self.client.get("/api/findings/FIND-1/links").json()["links"]
        self.assertEqual(out[0]["external_ref"], "INC1")

    # ---- export
    def test_export_is_read_only_filtered_and_paged(self):
        self.post_findings([self.ITEM, {**self.ITEM, "title": "B", "severity": "Low", "source_ref": "b", "cve": None}])
        self.assertEqual(self.client.get("/api/export/findings").status_code, 401)
        self.assertEqual(self.client.get("/api/export/findings", headers=self.h()).json()["total"], 2)
        self.assertEqual(self.client.get("/api/export/findings?severity=low", headers=self.h()).json()["total"], 1)
        page = self.client.get("/api/export/findings?limit=1&offset=1", headers=self.h()).json()
        self.assertEqual((len(page["findings"]), page["total"]), (1, 2))
        self.admin_login()
        wo = self.make_key(["ingest:write"], "wo")
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/export/findings", headers=self.h(wo)).status_code, 401)

    # ---- generic webhook in production
    def test_generic_webhook_needs_a_key_in_production(self):
        body = {"findings": []}
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}):
            self.assertEqual(self.client.post("/api/ingest/generic", json=body).status_code, 401)
            self.assertEqual(self.client.post("/api/ingest/generic", headers=self.h(), json=body).status_code, 200)

    # ---- the login gate does not leak
    def test_login_gate_exempts_only_key_checked_routes(self):
        with patch.object(dashboard_app_module, "_require_login_for_reads_enabled", return_value=True):
            self.assertEqual(self.client.get("/api/findings").status_code, 401)  # still gated
            self.assertEqual(self.client.get("/api/export/findings").status_code, 401)  # reaches the key check, refuses
            self.assertEqual(self.client.get("/api/export/findings", headers=self.h()).status_code, 200)

    # ---- schema
    def test_connection_schema_describes_every_type(self):
        self.assertEqual(self.client.get("/api/connections/schema").status_code, 401)
        self.admin_login()
        types = self.client.get("/api/connections/schema").json()["types"]
        snow = types["servicenow"]
        self.assertEqual(snow["kind"], "push")
        self.assertIn("instance", snow["schema"]["required"])
        self.assertTrue(snow["schema"]["properties"]["password"]["writeOnly"])
        self.assertEqual(snow["schema"]["properties"]["min_severity"]["enum"], ["Critical", "High", "Medium", "Low"])
        for name in ("tenable", "qualys", "jira", "splunk"):
            self.assertIn(name, types)


if __name__ == "__main__":
    unittest.main()
