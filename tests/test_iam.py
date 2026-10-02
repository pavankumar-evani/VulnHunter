"""
Tests for identity and access governance: intake, the findings, separation of duties, certification campaigns and the API.
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
from remediation.iam import model, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)

CSV = """User,Account,Application,Role,Last Login,Status,Manager,Department,Granted
alice@co.com,alice,SAP,Create Vendor,2026-10-10,active,mgr@co.com,Finance,2024-01-01
alice@co.com,alice,SAP,Approve Payment,2026-10-12,active,mgr@co.com,Finance,2024-01-01
bob@co.com,bob,AD,Domain Admins,2026-03-01,active,mgr@co.com,IT,2023-01-01
carol@co.com,carol,Okta,Standard User,,active,mgr@co.com,Sales,2026-01-01
dave@co.com,dave,GitHub,Owner,2026-10-14,active,,Eng,2022-01-01
svc-batch,svc-batch,SAP,Batch Runner,2026-10-14,active,,,2022-01-01
mallory@co.com,mallory,AD,Standard User,2026-10-01,active,mgr@co.com,IT,2022-01-01
"""
ROSTER = """User,Status,Manager,Department,End Date
alice@co.com,active,mgr@co.com,Finance,
bob@co.com,active,mgr@co.com,IT,
carol@co.com,active,mgr@co.com,Sales,
dave@co.com,active,,Eng,
mallory@co.com,terminated,mgr@co.com,IT,2026-08-31
"""


def ids(findings, user=None):
    return sorted({f["id"] for f in findings if user is None or f["user"] == user})


class ParseTests(unittest.TestCase):
    def test_csv_with_common_headers(self):
        es = model.from_csv(CSV)
        self.assertEqual(len(es), 7)
        a = es[0]
        self.assertEqual((a["user"], a["system"], a["entitlement"], a["last_login"], a["status"], a["manager"]), ("alice@co.com", "SAP", "Create Vendor", "2026-10-10", "active", "mgr@co.com"))
        self.assertTrue(es[2]["privileged"])  # "Domain Admins"
        self.assertFalse(es[0]["privileged"])
        self.assertIsNone(es[3]["last_login"])

    def test_privilege_status_and_dates_are_normalised(self):
        e = model.make_entitlement({"user": "X", "system": "S", "entitlement": "Reader", "privileged": "yes", "status": "Disabled", "last_login": "10/05/2026"})
        self.assertEqual((e["privileged"], e["status"], e["last_login"], e["user"]), (True, "disabled", "2026-10-05", "x"))
        self.assertEqual(model.make_entitlement({"user": "x", "system": "s", "entitlement": "r", "status": "TRUE"})["status"], "active")

    def test_errors(self):
        for bad in ("", "a,b\n1,2\n", "User,Application,Role\n"):
            with self.assertRaises(model.IamFormatError):
                model.from_csv(bad)
        with self.assertRaises(model.IamFormatError):
            model.make_entitlement({"user": "x", "system": "", "entitlement": "r"})
        with self.assertRaises(model.IamFormatError):
            model.from_json("[]")

    def test_json_and_detection(self):
        es = model.parse(json.dumps({"entitlements": [{"user": "a", "system": "s", "entitlement": "Admin"}]}))
        self.assertTrue(es[0]["privileged"])
        self.assertEqual(len(model.parse(CSV)), 7)

    def test_roster(self):
        r = model.parse_roster(ROSTER)
        self.assertEqual((len(r), r[4]["status"], r[4]["end_date"]), (5, "terminated", "2026-08-31"))
        with self.assertRaises(model.IamFormatError):
            model.parse_roster("name,status\nx,y\n")


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.ents = model.from_csv(CSV)
        self.roster = model.parse_roster(ROSTER)
        self.f = model.analyse(self.ents, self.roster, today=TODAY)

    def test_a_leaver_with_access_is_critical(self):
        f = [x for x in self.f if x["id"] == "IAM001"]
        self.assertEqual([(x["user"], x["severity"]) for x in f], [("mallory@co.com", "Critical")])
        self.assertIn("ended 2026-08-31", f[0]["detail"])
        self.assertEqual(model.analyse(self.ents, None, today=TODAY) and "IAM001" in ids(model.analyse(self.ents, None, today=TODAY)), False)  # no roster, no such finding

    def test_dormant_accounts_and_privilege(self):
        d = [x for x in self.f if x["id"] == "IAM002"]
        self.assertEqual([(x["user"], x["severity"]) for x in d], [("bob@co.com", "High")])  # Domain Admins unused since March
        self.assertEqual(ids(self.f, "alice@co.com"), ["IAM005"])

    def test_separation_of_duties(self):
        sod = [x for x in self.f if x["id"] == "IAM005"]
        self.assertEqual((len(sod), sod[0]["severity"], sod[0]["user"]), (1, "Critical", "alice@co.com"))
        self.assertIn("Create vendors and approve payments", sod[0]["title"])

    def test_generic_accounts_need_an_owner_and_unknown_people_are_flagged_only_with_a_roster(self):
        self.assertEqual(ids(self.f, "svc-batch"), ["IAM006"])
        self.assertEqual(ids(self.f, "dave@co.com"), [])  # owner access, but used recently and in the roster
        extra = model.from_csv(CSV + "ghost@co.com,ghost,AD,Standard User,2026-10-01,active,mgr@co.com,IT,2024-01-01\n")
        self.assertIn("IAM003", ids(model.analyse(extra, self.roster, today=TODAY), "ghost@co.com"))
        self.assertNotIn("IAM003", ids(model.analyse(extra, None, today=TODAY)))

    def test_never_used_accounts_and_disabled_ones(self):
        self.assertEqual(ids(self.f, "carol@co.com"), ["IAM007"])
        disabled = [{**e, "status": "disabled"} for e in self.ents]
        self.assertEqual(model.analyse(disabled, self.roster, today=TODAY), [])  # a disabled account is not access

    def test_too_many_privileged_systems(self):
        many = [model.make_entitlement({"user": "p@co.com", "system": f"S{i}", "entitlement": "Administrator", "last_login": "2026-10-10"}) for i in range(5)]
        f = model.analyse(many, None, today=TODAY)
        self.assertEqual(ids(f), ["IAM004"])

    def test_ordering_and_summary(self):
        self.assertEqual(self.f[0]["severity"], "Critical")
        s = model.summary(self.ents, self.f, self.roster)
        self.assertEqual((s["entitlements"], s["people"], s["systems"], s["roster_loaded"]), (7, 6, 4, True))
        self.assertEqual(s["by_severity"]["Critical"], 2)

    def test_precheck_before_access_is_requested(self):
        pc = model.precheck("alice@co.com", "SAP", "Release Payment Run", self.ents)
        self.assertEqual((pc["verdict"], pc["conflicts"][0]["rule"]), ("blocked-pending-exception", "SOD01"))
        self.assertEqual(model.precheck("carol@co.com", "Okta", "Standard User", self.ents)["verdict"], "no-issue-found")
        self.assertEqual(model.precheck("carol@co.com", "AD", "Domain Admins", self.ents)["verdict"], "needs-review")
        self.assertTrue(model.precheck("carol@co.com", "Okta", "standard user", self.ents)["already_held"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        store.import_entitlements("okta", CSV, None, "a", self.e)
        store.import_roster(ROSTER, self.e)

    def test_import_replaces_by_source(self):
        r = store.import_entitlements("okta", CSV, None, "a", self.e)
        self.assertEqual((r["rows"], r["replaced"]), (7, 7))
        store.import_entitlements("sap", "user,system,entitlement\nz,SAP,Reader\n", None, "a", self.e)
        self.assertEqual(len(store.entitlements(self.e)), 8)
        store.import_entitlements("okta", "user,system,entitlement\nq,AD,Reader\n", None, "a", self.e)
        self.assertEqual(len(store.entitlements(self.e)), 2)
        with self.assertRaises(model.IamFormatError):
            store.import_entitlements(" ", CSV, None, "a", self.e)

    def test_campaign_scope_snapshot_and_reviewers(self):
        c = store.create_campaign("Q4 privileged", {"privileged_only": True}, "2026-12-31", "admin@t", self.e)
        self.assertEqual((c["total"], c["status"], c["pct"]), (2, "open", 0))  # Domain Admins and GitHub Owner
        items = store.items_for(c["id"], engine=self.e)
        reviewers = {i["entitlement"]["user"]: i["reviewer"] for i in items}
        self.assertEqual(reviewers, {"bob@co.com": "mgr@co.com", "dave@co.com": "unassigned"})
        self.assertEqual(store.get_campaign(c["id"], self.e)["unassigned"], 1)
        every = store.create_campaign("All SAP", {"systems": ["sap"]}, "2026-12-31", "admin@t", self.e)
        self.assertEqual(every["total"], 3)
        for bad in (("", {}, "2026-12-31"), ("x", {}, "soon"), ("x", {"systems": ["nothing"]}, "2026-12-31")):
            with self.assertRaises(ValueError):
                store.create_campaign(bad[0], bad[1], bad[2], "a", self.e)

    def test_only_the_reviewer_decides_and_a_revocation_needs_a_reason(self):
        c = store.create_campaign("Q4 privileged", {"privileged_only": True}, "2026-12-31", "admin@t", self.e)
        bob_item = next(i for i in store.items_for(c["id"], engine=self.e) if i["entitlement"]["user"] == "bob@co.com")
        with self.assertRaises(PermissionError):
            store.decide(bob_item["id"], "certify", "someone@co.com", engine=self.e)
        with self.assertRaises(ValueError):
            store.decide(bob_item["id"], "revoke", "mgr@co.com", " ", engine=self.e)
        with self.assertRaises(ValueError):
            store.decide(bob_item["id"], "maybe", "mgr@co.com", engine=self.e)
        store.decide(bob_item["id"], "revoke", "MGR@co.com", "Moved teams", engine=self.e)
        dave = next(i for i in store.items_for(c["id"], engine=self.e) if i["entitlement"]["user"] == "dave@co.com")
        with self.assertRaises(PermissionError):
            store.decide(dave["id"], "certify", "mgr@co.com", engine=self.e)  # unassigned: only an administrator may decide
        store.decide(dave["id"], "certify", "admin@t", "ok", is_admin=True, engine=self.e)
        got = store.get_campaign(c["id"], self.e)
        self.assertEqual((got["decided"], got["certified"], got["revoke"], got["pct"]), (2, 1, 1, 100))
        self.assertEqual([r["user"] for r in store.revocations(c["id"], self.e)], ["bob@co.com"])
        store.close_campaign(c["id"], self.e)
        with self.assertRaises(ValueError):
            store.decide(bob_item["id"], "certify", "mgr@co.com", engine=self.e)  # closed
        with self.assertRaises(KeyError):
            store.close_campaign(c["id"], self.e)

    def test_reassignment_and_self_review(self):
        c = store.create_campaign("Q4 privileged", {"privileged_only": True}, "2026-12-31", "admin@t", self.e)
        dave = next(i for i in store.items_for(c["id"], engine=self.e) if i["entitlement"]["user"] == "dave@co.com")
        store.reassign(dave["id"], "Lead@co.com", self.e)
        self.assertEqual(store.items_for(c["id"], reviewer="lead@co.com", engine=self.e)[0]["id"], dave["id"])
        store.reassign(dave["id"], "dave@co.com", self.e)
        with self.assertRaises(PermissionError):
            store.decide(dave["id"], "certify", "dave@co.com", engine=self.e)  # nobody reviews their own access
        with self.assertRaises(ValueError):
            store.reassign(dave["id"], " ", self.e)


class IamApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("mgr@co.com", PW, "Manager", role="user", engine=self.engine)
        auth_users.create_user("other@co.com", PW, "Other", role="user", engine=self.engine)
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

    def test_who_can_do_what(self):
        self.assertEqual(self.client.get("/api/iam/overview").status_code, 401)
        self.login("mgr@co.com")
        for method, path in (("get", "/api/iam/overview"), ("get", "/api/iam/campaigns"), ("delete", "/api/iam/data")):
            self.assertEqual(getattr(self.client, method)(path).status_code, 403, path)
        self.assertEqual(self.client.post("/api/iam/import?source=x", content=CSV).status_code, 403)
        self.assertEqual(self.client.get("/api/iam/my-reviews").status_code, 200)

    def test_import_overview_and_precheck(self):
        self.login("admin@t.local")
        r = self.client.post("/api/iam/import?source=okta", content=CSV)
        self.assertEqual((r.status_code, r.json()["rows"]), (200, 7), r.text)
        self.assertEqual(self.client.post("/api/iam/import?source=okta", content="x").status_code, 400)
        self.assertEqual(self.client.post("/api/iam/roster", content=ROSTER).json()["people"], 5)
        ov = self.client.get("/api/iam/overview").json()
        self.assertEqual(ov["summary"]["by_severity"]["Critical"], 2)
        pc = self.client.post("/api/iam/precheck", json={"user": "alice@co.com", "system": "SAP", "entitlement": "Payment Approval"})
        self.assertEqual(pc.json()["verdict"], "blocked-pending-exception")

    def test_a_manager_certifies_and_revokes_their_own_reports_access(self):
        self.login("admin@t.local")
        self.client.post("/api/iam/import?source=okta", content=CSV)
        c = self.client.post("/api/iam/campaigns", json={"name": "Q4", "due_date": "2026-12-31", "privileged_only": True}).json()
        self.assertEqual(c["total"], 2)
        self.assertEqual(self.client.post("/api/iam/campaigns", json={"name": "bad", "due_date": "later"}).status_code, 400)
        self.login("mgr@co.com")
        mine = self.client.get("/api/iam/my-reviews").json()["reviews"]
        self.assertEqual((len(mine), len(mine[0]["items"])), (1, 1))
        iid = mine[0]["items"][0]["id"]
        self.assertEqual(self.client.post(f"/api/iam/items/{iid}/decide", json={"decision": "revoke"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/iam/items/{iid}/decide", json={"decision": "revoke", "note": "Left IT"}).status_code, 200)
        self.login("other@co.com")
        self.assertEqual(self.client.get("/api/iam/my-reviews").json()["reviews"], [])
        self.assertEqual(self.client.post(f"/api/iam/items/{iid}/decide", json={"decision": "certify"}).status_code, 403)
        self.assertEqual(self.client.post("/api/iam/items/999/decide", json={"decision": "certify"}).status_code, 404)
        self.login("admin@t.local")
        detail = self.client.get(f"/api/iam/campaigns/{c['id']}").json()
        self.assertEqual((detail["decided"], detail["revoke"], len(detail["items"])), (1, 1, 2))
        rev = self.client.get(f"/api/iam/campaigns/{c['id']}/revocations").json()
        self.assertEqual(rev["revocations"][0]["user"], "bob@co.com")
        self.assertIn("changes no account", rev["note"])
        self.assertEqual(self.client.post(f"/api/iam/campaigns/{c['id']}/close").json()["status"], "closed")
        self.assertEqual(self.client.post(f"/api/iam/campaigns/{c['id']}/close").status_code, 404)
        unassigned = next(i for i in detail["items"] if i["reviewer"] == "unassigned")
        self.assertEqual(self.client.post(f"/api/iam/items/{unassigned['id']}/reassign", json={"reviewer": "x@co.com"}).status_code, 400)  # a closed campaign cannot be changed
        self.assertEqual(self.client.delete("/api/iam/data").status_code, 200)
        self.assertEqual(self.client.get("/api/iam/overview").json()["summary"]["entitlements"], 0)


if __name__ == "__main__":
    unittest.main()
