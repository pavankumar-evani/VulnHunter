"""
Tests for client-specific compensating controls: the ATT&CK mitigation dataset, the controls inventory, the assessment of a
finding against what an asset actually has, and the API that serves and fills it.
"""
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
from remediation.controls import store  # noqa: E402
from remediation.enrichment import attack_mapping, client_controls  # noqa: E402
from remediation.guidance import engine as guidance_engine  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"


def inv(cls, state="verified", name="x", source="t"):
    return {"control_class": cls, "state": state, "name": name, "source": source}


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.d = client_controls.load()

    def test_every_listed_mitigation_is_defined_and_has_a_known_class(self):
        for tid, mids in self.d["techniques"].items():
            for mid in mids:
                self.assertIn(mid, self.d["mitigations"], (tid, mid))
        for mid, m in self.d["mitigations"].items():
            self.assertIn(m["class"], self.d["control_classes"], mid)
            self.assertTrue(m["action"] and m["nist"], mid)

    def test_every_technique_quanta_can_tag_has_an_entry(self):
        tagged = {tid for _p, tid, _n, _t in attack_mapping._PATTERNS if tid}
        self.assertEqual(sorted(tagged - set(self.d["techniques"])), [])

    def test_a_technique_mitre_gives_no_mitigations_for_has_none(self):
        self.assertEqual(self.d["techniques"]["T1600"], [])

    def test_cwe_mappings_point_at_known_techniques(self):
        for cwe, tid in self.d["cwe_to_technique"].items():
            self.assertIn(tid, self.d["techniques"], cwe)


class AssessmentTests(unittest.TestCase):
    SQLI = {"title": "SQL injection in login", "cwe": "CWE-89", "asset": {"name": "WEB-01"}}

    def test_techniques_come_from_attack_text_and_from_cwe(self):
        self.assertEqual([t["technique_id"] for t in client_controls.techniques_for(self.SQLI)], ["T1190"])
        self.assertEqual([t["technique_id"] for t in client_controls.techniques_for({"title": "Hardcoded password", "asset": {}})], ["T1552"])
        self.assertEqual(client_controls.techniques_for({"title": "Something unrelated", "asset": {}}), [])

    def test_no_inventory_means_unknown_not_a_guess(self):
        a = client_controls.assess(self.SQLI, inventory=[])
        self.assertFalse(a["has_inventory"])
        self.assertTrue(a["compensating"])
        self.assertTrue(all(m["status"] == "unknown" for m in a["compensating"]))
        self.assertIsNone(a["coverage_pct"])
        self.assertIn("Record its controls", a["note"])

    def test_status_is_verified_claimed_or_absent_per_mitigation(self):
        a = client_controls.assess(self.SQLI, inventory=[inv("exploit-protection"), inv("network-filtering", "claimed"), inv("edr")])
        status = {m["id"]: m["status"] for m in a["compensating"]}
        self.assertEqual((status["M1050"], status["M1037"], status["M1030"]), ("verified", "claimed", "absent"))
        self.assertIn("M1030", [m["id"] for m in a["gaps"]])

    def test_coverage_counts_verified_as_one_and_claimed_as_half(self):
        a = client_controls.assess(self.SQLI, inventory=[inv("exploit-protection"), inv("network-filtering", "claimed")])
        n = len(a["compensating"])
        self.assertEqual(a["coverage_pct"], round(100 * 1.5 / n))
        self.assertEqual(a["coverage_pct"] + a["residual_pct"], 100)

    def test_patching_and_scanning_are_the_fix_not_a_compensating_control(self):
        a = client_controls.assess(self.SQLI, inventory=[inv("edr")])
        self.assertEqual(sorted(m["id"] for m in a["the_fix_itself"]), ["M1016", "M1051"])
        self.assertTrue(all(m["control_class"] not in ("patching", "vuln-scanning") for m in a["compensating"]))

    def test_mitigations_covering_more_techniques_come_first(self):
        _t, ms = client_controls.candidates({"title": "Remote code execution via command injection", "asset": {}})
        covered = [len(m["techniques"]) for m in ms]
        self.assertEqual(covered, sorted(covered, reverse=True))
        self.assertGreater(covered[0], 1)

    def test_a_technique_with_no_mitigations_says_so_plainly(self):
        a = client_controls.assess({"title": "Weak cipher enabled", "asset": {"name": "h"}}, inventory=[inv("edr")])
        self.assertEqual(a["compensating"], [])
        self.assertIn("no compensating mitigations", a["note"])

    def test_an_unmapped_finding_gets_no_invented_controls(self):
        a = client_controls.assess({"title": "Printer toner low", "asset": {"name": "p"}}, inventory=[])
        self.assertEqual((a["techniques"], a["compensating"]), ([], []))
        self.assertIn("does not map", a["note"])

    def test_guidance_carries_the_assessment(self):
        g = guidance_engine.build(self.SQLI | {"id": "F1"})
        self.assertIn("compensating", g["client_assessment"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_upsert_deduplicates_and_never_downgrades_verified(self):
        a = store.upsert("WEB-01", "edr", "CrowdStrike", "verified", "falcon", "bot", engine=self.engine)
        b = store.upsert("WEB-01", "edr", "CrowdStrike", "claimed", "manual", "alice", engine=self.engine)
        self.assertEqual((a["id"], b["id"], b["state"]), (a["id"], a["id"], "verified"))
        self.assertEqual(len(store.list_controls(engine=self.engine)), 1)

    def test_glob_entries_apply_to_matching_assets_only(self):
        store.upsert("WEB-*", "exploit-protection", "WAF in front of the web tier", "claimed", "manual", "a", engine=self.engine)
        self.assertEqual(len(store.for_asset("web-07", engine=self.engine)), 1)
        self.assertEqual(store.for_asset("DB-01", engine=self.engine), [])

    def test_validation(self):
        for args in (("bad name!!", "edr", "x", "claimed"), ("A", "nonsense", "x", "claimed"), ("A", "edr", "", "claimed"), ("A", "edr", "x", "maybe")):
            with self.assertRaises(ValueError):
                store.upsert(*args[:3], args[3], "m", "a", engine=self.engine)

    def test_csv_import_reports_bad_rows_without_blocking_good_ones(self):
        csv_text = "asset_name,control_class,name,state\nWEB-*,exploit-protection,WAF,claimed\nDB-01,nonsense,x,claimed\nDB-01,edr,EDR,verified\n"
        done, errors = store.import_csv(csv_text, "admin", engine=self.engine)
        self.assertEqual((done, [e["line"] for e in errors]), (2, [3]))

    def test_the_legacy_security_controls_file_is_read_as_claimed(self):
        entry = {"firewall_rules": [{"action": "deny", "source": "internet"}], "edr": {"mode": "block"}}
        with patch("remediation.enrichment.control_coverage.find_asset_controls", return_value=entry):
            got = store.legacy_controls("WIN-DC01")
        self.assertEqual({(c["control_class"], c["state"]) for c in got}, {("network-filtering", "claimed"), ("edr", "claimed")})

    def test_delete(self):
        c = store.upsert("A", "edr", "x", "claimed", "m", "a", engine=self.engine)
        self.assertTrue(store.delete_control(c["id"], engine=self.engine))
        self.assertFalse(store.delete_control(c["id"], engine=self.engine))


class ControlsApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch("remediation.enrichment.control_coverage.find_asset_controls", return_value=None)]
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

    BODY = {"asset_name": "WIN-DC01", "control_class": "network-filtering", "name": "Perimeter firewall", "state": "claimed"}

    def test_admin_manages_controls_and_users_only_read(self):
        self.assertEqual(self.client.get("/api/controls").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.post("/api/controls", json=self.BODY).status_code, 403)
        self.assertEqual(self.client.get("/api/controls").status_code, 200)
        self.login("admin@t.local")
        r = self.client.post("/api/controls", json=self.BODY)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(self.client.get("/api/controls?asset=WIN-DC01").json()["controls"]), 1)
        self.assertEqual(self.client.post("/api/controls", json={**self.BODY, "control_class": "bogus"}).status_code, 400)
        self.assertEqual(self.client.delete(f"/api/controls/{r.json()['id']}").status_code, 200)
        self.assertEqual(self.client.delete("/api/controls/999").status_code, 404)

    def test_csv_import_route(self):
        self.login("admin@t.local")
        r = self.client.post("/api/controls/import", content="asset_name,control_class,name\nA,edr,EDR\nB,wrong,x\n")
        self.assertEqual((r.status_code, r.json()["imported"], len(r.json()["errors"])), (200, 1, 1))

    def test_a_connector_pushes_verified_controls_with_a_scoped_key(self):
        self.login("admin@t.local")
        key = self.client.post("/api/api-keys", json={"name": "edr", "scopes": ["controls:write"]}).json()["key"]
        other = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()
        body = {"source": "falcon", "controls": [{"asset_name": "WEB-01", "control_class": "edr", "name": "Falcon, prevention on"}, {"asset_name": "x y", "control_class": "edr", "name": "bad"}]}
        self.assertEqual(self.client.post("/api/ingest/controls", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/controls", json=body, headers={"Authorization": f"Bearer {other}"}).status_code, 401)
        r = self.client.post("/api/ingest/controls", json=body, headers={"Authorization": f"Bearer {key}"})
        self.assertEqual((r.status_code, r.json()["recorded"], r.json()["rejected"]), (200, 1, 1))
        self.login("admin@t.local")
        got = self.client.get("/api/controls?asset=WEB-01").json()["controls"]
        self.assertEqual((got[0]["state"], got[0]["source"]), ("verified", "falcon"))

    def test_compensating_controls_endpoint_for_a_queue_finding(self):
        r = self.client.get("/api/findings/FIND-1/compensating-controls")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("compensating", body)
        self.assertIn("disclaimer", body)
        self.assertEqual(self.client.get("/api/findings/FIND-NOPE/compensating-controls").status_code, 404)


if __name__ == "__main__":
    unittest.main()
