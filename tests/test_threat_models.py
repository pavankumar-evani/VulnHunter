"""
Tests for threat modelling: model validation, the STRIDE rules (confirmed vs unconfirmed), scoring, the join to live findings and to the
controls inventory, drafting a model from assets, review decisions, and the API.
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
from remediation.controls import store as controls_store  # noqa: E402
from remediation.threatmodel import engine, rules, seed, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"


def model(**web):
    w = {"id": "web", "name": "Web portal", "type": "process", "internet_facing": True, "trust_zone": "dmz", "assets": ["WEB-*"], "handles": ["pii"]}
    w.update(web)
    return {"components": [{"id": "users", "name": "Customers", "type": "external", "trust_zone": "internet"}, w,
                           {"id": "db", "name": "Customer DB", "type": "datastore", "trust_zone": "internal", "handles": ["pii", "payment"], "assets": ["DB-*"]}],
            "data_flows": [{"from": "users", "to": "web", "encrypted": True, "authenticated": True, "data": ["pii"]},
                           {"from": "web", "to": "db", "encrypted": True, "authenticated": True, "data": ["pii"]}],
            "trust_zones": [{"id": "internet", "trust": 0}, {"id": "dmz", "trust": 1}, {"id": "internal", "trust": 2}]}


def keys(result):
    return {t["key"]: t for t in result["threats"]}


class ModelValidationTests(unittest.TestCase):
    def test_a_good_model_is_completed(self):
        m = engine.normalise_model(model())
        self.assertEqual(m["data_flows"][0]["name"], "Customers to Web portal")
        self.assertTrue(m["data_flows"][0]["crosses_zones"])

    def test_every_problem_is_listed(self):
        bad = {"components": [{"id": "a", "type": "nonsense"}, {"id": "a", "type": "process"}, {"id": "bad id!", "type": "process"}],
               "data_flows": [{"from": "a", "to": "ghost"}], "trust_zones": []}
        with self.assertRaises(engine.ModelError) as cm:
            engine.normalise_model(bad)
        text = " | ".join(cm.exception.problems)
        for needle in ("type must be", "used twice", "id must be", "must name existing components"):
            self.assertIn(needle, text)

    def test_limits_and_shape(self):
        with self.assertRaises(engine.ModelError):
            engine.normalise_model([])
        with self.assertRaises(engine.ModelError):
            engine.normalise_model({"components": [{"id": f"c{i}", "type": "process"} for i in range(engine.MAX_COMPONENTS + 1)]})


class RuleTests(unittest.TestCase):
    def test_a_well_protected_system_raises_only_questions_not_confirmed_gaps(self):
        r = engine.analyse(model(authn=True, input_validated=True, logging=True, rate_limited=True))
        self.assertFalse([t for t in r["threats"] if t["confidence"] == "confirmed" and t["rule_id"] in ("TM-S01", "TM-T01", "TM-D01")])

    def test_a_stated_weakness_is_confirmed_and_a_missing_one_is_only_unconfirmed(self):
        stated = keys(engine.analyse(model(authn=False)))
        missing = keys(engine.analyse(model()))
        self.assertEqual(stated["TM-S01:web"]["confidence"], "confirmed")
        self.assertEqual(missing["TM-S01:web"]["confidence"], "unconfirmed")
        self.assertLess(missing["TM-S01:web"]["inherent_score"], stated["TM-S01:web"]["inherent_score"])

    def test_unencrypted_sensitive_data_in_a_store_and_on_the_wire(self):
        m = model()
        m["components"][2]["encrypted_at_rest"] = False
        m["data_flows"][1]["encrypted"] = False
        k = keys(engine.analyse(m))
        self.assertEqual(k["TM-I01:db"]["confidence"], "confirmed")
        self.assertIn("TM-I02:web->db#2", k)
        self.assertNotIn("TM-I02:users->web#1", k)  # that one is encrypted

    def test_privileged_internet_facing_process_and_plaintext_secrets(self):
        k = keys(engine.analyse(model(privileged=True, secrets_management="env")))
        self.assertIn("TM-E01:web", k)
        self.assertEqual(k["TM-I03:web"]["confidence"], "confirmed")

    def test_third_party_without_a_bill_of_materials(self):
        k = keys(engine.analyse(model(third_party=True, sbom=False)))
        self.assertEqual(k["TM-T03:web"]["confidence"], "confirmed")

    def test_an_external_party_reaching_a_data_store_directly(self):
        m = model()
        m["data_flows"].append({"from": "users", "to": "db", "data": []})
        self.assertIn("TM-E02:users->db#3", keys(engine.analyse(m)))

    def test_ai_components_get_ai_threats(self):
        m = model()
        m["components"].append({"id": "llm", "name": "Support assistant", "type": "ai-model", "third_party": True, "tools": ["refund", "email"],
                                "human_approval": False, "trust_zone": "dmz"})
        m["data_flows"].append({"from": "web", "to": "llm", "data": ["pii"], "untrusted_content": True})
        k = keys(engine.analyse(m))
        for rid in ("TM-AI01", "TM-AI02", "TM-AI03"):
            self.assertIn(f"{rid}:llm", k)

    def test_every_rule_references_known_control_classes_and_techniques(self):
        from remediation.enrichment import client_controls
        data = client_controls.load()
        for r in rules.RULES:
            self.assertEqual(sorted(set(r["controls"]) - set(data["control_classes"])), [], r["id"])
            self.assertEqual(sorted(set(r["techniques"]) - set(data["techniques"])), [], r["id"])
            self.assertIn(r["stride"], rules.STRIDE)


class RealityJoinTests(unittest.TestCase):
    FINDING = {"id": "FIND-9", "title": "SQL injection in portal", "cwe": "CWE-89", "severity": "High", "asset": {"name": "WEB-01", "type": "application"}}

    def test_a_live_finding_that_could_realise_a_threat_raises_it_and_a_kev_one_raises_it_more(self):
        m = model(internet_facing=False)  # not internet-facing and unconfirmed, so there is headroom below the cap of 5
        base = keys(engine.analyse(m))["TM-T01:web"]
        with_f = keys(engine.analyse(m, [self.FINDING]))["TM-T01:web"]
        kev = keys(engine.analyse(m, [{**self.FINDING, "kev": {"listed": True}}]))["TM-T01:web"]
        self.assertEqual([f["id"] for f in with_f["findings"]], ["FIND-9"])
        self.assertGreater(with_f["likelihood"], base["likelihood"])
        self.assertGreater(kev["likelihood"], with_f["likelihood"])
        self.assertTrue(kev["findings"][0]["kev"])

    def test_findings_on_other_assets_or_of_other_kinds_are_not_linked(self):
        other_asset = {**self.FINDING, "asset": {"name": "HR-01", "type": "application"}}
        other_kind = {**self.FINDING, "cwe": "CWE-16", "title": "Verbose banner"}
        t = keys(engine.analyse(model(input_validated=False), [other_asset, other_kind]))["TM-T01:web"]
        self.assertEqual(t["findings"], [])

    def test_recorded_controls_lower_the_residual_risk_but_never_to_zero(self):
        inv = [{"control_class": "exploit-protection", "state": "verified", "name": "WAF", "source": "t"},
               {"control_class": "secure-development", "state": "claimed", "name": "SDLC", "source": "t"}]
        none = keys(engine.analyse(model(input_validated=False), controls_for=lambda names: []))["TM-T01:web"]
        some = keys(engine.analyse(model(input_validated=False), controls_for=lambda names: inv))["TM-T01:web"]
        self.assertFalse(none["controls_known"])
        self.assertEqual(none["residual_score"], none["inherent_score"])
        self.assertEqual(some["coverage_pct"], 75)
        self.assertLess(some["residual_score"], some["inherent_score"])
        self.assertGreater(some["residual_score"], 0)
        self.assertEqual({c["control_class"]: c["status"] for c in some["controls"]}, {"exploit-protection": "verified", "secure-development": "claimed"})

    def test_a_missing_control_is_absent_when_other_controls_are_known(self):
        inv = [{"control_class": "audit-logging", "state": "verified", "name": "SIEM", "source": "t"}]
        t = keys(engine.analyse(model(input_validated=False), controls_for=lambda names: inv))["TM-T01:web"]
        self.assertEqual({c["status"] for c in t["controls"]}, {"absent"})

    def test_summary_counts(self):
        r = engine.analyse(model(authn=False, input_validated=False), [self.FINDING])
        s = r["summary"]
        self.assertEqual(s["total"], len(r["threats"]))
        self.assertGreaterEqual(s["with_live_findings"], 1)
        self.assertEqual(sum(s["by_rating"].values()), s["total"])


class SeedTests(unittest.TestCase):
    FINDINGS = [{"asset": {"name": "WEB-01", "type": "application"}}, {"asset": {"name": "WEB-01", "type": "application"}},
                {"asset": {"name": "DB-01", "type": "unix-server"}}, {"asset": {"name": "PRINTER-1", "type": "printer"}}, {"asset": {"name": "CERT-1", "type": "certificate"}}]

    def test_drafts_components_from_assets_and_marks_them_inferred(self):
        topo = {"assets": [{"match": {"name": "WEB-01"}, "path_to_internet": [{"hop_type": "firewall", "name": "fw", "default_action": "allow"}]}]}
        m = seed.from_findings(self.FINDINGS, topology=topo)
        names = {c["name"]: c for c in m["components"]}
        self.assertEqual(set(names) - {"Users and the internet"}, {"WEB-01", "DB-01"})  # printers and certificates are not systems to model
        self.assertTrue(names["WEB-01"]["internet_facing"])
        self.assertFalse(names["DB-01"]["internet_facing"])
        self.assertTrue(all(c["inferred"] for c in m["components"]))
        self.assertEqual([f["to"] for f in m["data_flows"]], ["WEB-01"])
        engine.normalise_model(m)  # the draft is itself a valid model

    def test_patterns_limit_the_assets(self):
        m = seed.from_findings(self.FINDINGS, ["db-*"], topology={"assets": []})
        self.assertEqual([c["name"] for c in m["components"]], ["DB-01"])

    def test_security_properties_are_left_unset_so_rules_ask_instead_of_assuming(self):
        m = seed.from_findings(self.FINDINGS, topology={"assets": []})
        self.assertTrue(all("authn" not in c and "encrypted_at_rest" not in c for c in m["components"]))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_create_update_review_and_delete(self):
        rec = store.create("Portal", "customer portal", model(), "admin", engine=self.engine)
        mid = rec["id"]
        self.assertEqual([m["name"] for m in store.list_models(self.engine)], ["Portal"])
        store.update_model(mid, "bob", name="Portal v2", engine=self.engine)
        a = store.analyse(mid, engine=self.engine)
        self.assertEqual((a["name"], a["updated_by"]), ("Portal v2", "bob"))
        key = a["threats"][0]["key"]
        store.set_review(mid, key, "mitigated", None, "bob", self.engine)
        self.assertEqual(keys(store.analyse(mid, engine=self.engine))[key]["review"]["status"], "mitigated")
        self.assertTrue(store.delete_model(mid, self.engine))
        self.assertIsNone(store.get(mid, self.engine))

    def test_accepting_a_risk_needs_a_reason(self):
        mid = store.create("P", "", model(), "a", engine=self.engine)["id"]
        for status in ("accepted", "not-applicable"):
            with self.assertRaises(ValueError):
                store.set_review(mid, "TM-S01:web", status, "  ", "a", self.engine)
        store.set_review(mid, "TM-S01:web", "accepted", "behind the VPN", "a", self.engine)
        with self.assertRaises(ValueError):
            store.set_review(mid, "TM-S01:web", "maybe", "x", "a", self.engine)
        with self.assertRaises(KeyError):
            store.set_review(999, "k", "open", None, "a", self.engine)

    def test_a_changed_model_keeps_decisions_on_threats_that_remain(self):
        mid = store.create("P", "", model(authn=False), "a", engine=self.engine)["id"]
        store.set_review(mid, "TM-S01:web", "accepted", "VPN only", "a", self.engine)
        store.update_model(mid, "a", model=model(authn=False, logging=False), engine=self.engine)
        self.assertEqual(keys(store.analyse(mid, engine=self.engine))["TM-S01:web"]["review"]["status"], "accepted")


class ThreatModelApiTests(unittest.TestCase):
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

    def test_admin_only(self):
        self.assertEqual(self.client.get("/api/threat-models").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/threat-models").status_code, 403)
        self.assertEqual(self.client.post("/api/threat-models", json={"name": "x"}).status_code, 403)

    def test_full_flow(self):
        self.login("admin@t.local")
        r = self.client.post("/api/threat-models", json={"name": "Portal", "description": "d", "model": model(authn=False)})
        self.assertEqual(r.status_code, 200, r.text)
        mid = r.json()["id"]
        got = self.client.get(f"/api/threat-models/{mid}").json()
        self.assertTrue(got["threats"])
        self.assertIn("TM-S01:web", {t["key"] for t in got["threats"]})
        self.assertEqual(self.client.post(f"/api/threat-models/{mid}/review", json={"key": "TM-S01:web", "status": "accepted"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/threat-models/{mid}/review", json={"key": "TM-S01:web", "status": "accepted", "note": "VPN only"}).status_code, 200)
        self.assertEqual(self.client.put(f"/api/threat-models/{mid}", json={"model": {"components": [{"id": "a", "type": "bogus"}]}}).status_code, 400)
        self.assertEqual(self.client.put(f"/api/threat-models/{mid}", json={"name": "Portal 2"}).status_code, 200)
        self.assertEqual(self.client.get("/api/threat-models").json()["models"][0]["name"], "Portal 2")
        self.assertEqual(self.client.get("/api/threat-models/999").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/threat-models/{mid}").status_code, 200)

    def test_seed_adds_inferred_components_from_the_real_queue_without_duplicates(self):
        self.login("admin@t.local")
        mid = self.client.post("/api/threat-models", json={"name": "Estate"}).json()["id"]
        first = self.client.post(f"/api/threat-models/{mid}/seed", json={"patterns": ["WIN-DC01"]})
        self.assertEqual((first.status_code, first.json()["added"]), (200, 1), first.text)
        again = self.client.post(f"/api/threat-models/{mid}/seed", json={"patterns": ["WIN-DC01"]})
        self.assertEqual(again.json()["added"], 0)
        got = self.client.get(f"/api/threat-models/{mid}").json()
        self.assertTrue(got["model"]["components"][0]["inferred"])

    def test_the_rule_catalogue_is_served(self):
        self.login("admin@t.local")
        cat = self.client.get("/api/threat-models/rules").json()
        self.assertEqual({r["id"] for r in cat["rules"]}, {r["id"] for r in rules.RULES})
        self.assertIn("S", cat["stride"])

    def test_threats_see_controls_the_inventory_holds(self):
        self.login("admin@t.local")
        controls_store.upsert("WEB-*", "exploit-protection", "WAF", "verified", "t", "a", engine=self.engine)
        mid = self.client.post("/api/threat-models", json={"name": "P", "model": model(input_validated=False)}).json()["id"]
        t = {x["key"]: x for x in self.client.get(f"/api/threat-models/{mid}").json()["threats"]}["TM-T01:web"]
        self.assertTrue(t["controls_known"])
        self.assertIn("verified", {c["status"] for c in t["controls"]})


if __name__ == "__main__":
    unittest.main()
