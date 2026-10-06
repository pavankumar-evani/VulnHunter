"""Tests for the threat modelling posture framework: empty data, good and bad seeded cases, shape, determinism, no secrets."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.apisec import store as apisec  # noqa: E402
from remediation.appsec import store as appsec  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.posture import threat_modelling as tm  # noqa: E402
from remediation.posture.model import Context  # noqa: E402
from remediation.threatmodel import store as tm_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

ACTOR = "pat.owner@corp.test"
NOW = datetime.datetime.now(datetime.timezone.utc)
SECRET = "SUPER-SECRET-VALUE-123"

FULL = {"trust_zones": [{"id": "dmz", "name": "DMZ", "trust": 0}, {"id": "core", "name": "Core", "trust": 2}],
        "components": [{"id": "web", "name": "Web front", "type": "service", "internet_facing": True, "authn": False, "trust_zone": "dmz",
                        "logging": True, "input_validated": True, "rate_limited": True, "assets": ["web01.corp.test"]},
                       {"id": "db", "name": "Orders DB", "type": "datastore", "trust_zone": "core", "handles": ["pii"], "encrypted_at_rest": False,
                        "logging": True, "assets": ["db01.corp.test"]}],
        "data_flows": [{"from": "web", "to": "db", "data": ["pii"], "encrypted": True, "authenticated": True}]}
THIN = {"components": [{"id": "x", "name": "Thin app", "type": "service"}]}
FINDING = {"id": "F-1", "title": "Missing authentication on web", "severity": "Critical", "asset": {"name": "web01.corp.test"}, "cwe": "CWE-306",
           "first_seen": "2026-01-01", "kev": {"listed": False}}
OPENAPI = json.dumps({"openapi": "3.0.0", "info": {"title": "Shop API", "version": "1"}, "paths": {"/orders": {"get": {"responses": {"200": {"description": "ok"}}}}}})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'p.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def ctx(self, findings=(), now=NOW):
        c = Context(engine=self.engine, findings=list(findings), env={"QUANTA_X": SECRET}, now=now)
        c.thr = posture_engine.policy()["thresholds"]
        return c

    def checks(self, findings=(), now=NOW):
        return {c["id"]: c for c in tm.run(self.ctx(findings, now))}

    def model(self, name, body=FULL):
        return tm_store.create(name, "test", body, ACTOR, engine=self.engine)

    def decide_all(self, rec, status="mitigated"):
        for t in tm_store.analyse(rec["id"], engine=self.engine, controls_for=lambda n: [])["threats"]:
            tm_store.set_review(rec["id"], t["key"], status, "done in test", ACTOR, engine=self.engine)


class EmptyTests(Base):
    def test_everything_unknown(self):
        c = self.checks()
        self.assertEqual(len(c), 12)
        for cid, ch in c.items():
            self.assertEqual(ch["status"], "unknown", cid)
            self.assertIsNone(ch["score"])

    def test_models_without_apps_still_unknown_for_coverage(self):
        self.model("Shop")
        c = self.checks()
        self.assertEqual(c["tm-cov-internet-facing"]["status"], "unknown")
        self.assertEqual(c["tm-cov-api-services"]["status"], "unknown")


class CoverageTests(Base):
    def test_internet_facing(self):
        appsec.upsert_application("Shop", {"internet_facing": True, "business_criticality": "critical"}, ACTOR, engine=self.engine)
        self.assertEqual(self.checks()["tm-cov-internet-facing"]["status"], "fail")
        self.model("shop")
        c = self.checks()
        self.assertEqual(c["tm-cov-internet-facing"]["status"], "pass")
        self.assertEqual(c["tm-cov-critical-apps"]["status"], "pass")
        appsec.upsert_application("Blog", {"internet_facing": True}, ACTOR, engine=self.engine)
        c = self.checks()["tm-cov-internet-facing"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)
        self.assertIn("1 of 2", c["evidence"][0])
        self.assertIn("Blog", c["evidence"][0])

    def test_api_services(self):
        apisec.import_spec(OPENAPI, "shop-api", "upload", ACTOR, engine=self.engine)
        self.assertEqual(self.checks()["tm-cov-api-services"]["status"], "fail")
        self.model("shop-api")
        self.assertEqual(self.checks()["tm-cov-api-services"]["status"], "pass")


class QualityTests(Base):
    def test_structure_and_assets(self):
        self.model("Thin", THIN)
        c = self.checks()
        self.assertEqual(c["tm-qual-zones-flows"]["status"], "fail")
        self.assertEqual(c["tm-qual-assets-linked"]["status"], "fail")
        self.model("Full")
        c = self.checks()
        self.assertEqual(c["tm-qual-zones-flows"]["status"], "partial")
        self.assertEqual(c["tm-qual-zones-flows"]["score"], 0.5)
        tm_store.delete_model(tm_store.list_models(self.engine)[1]["id"] if tm_store.list_models(self.engine)[0]["name"] == "Full" else tm_store.list_models(self.engine)[0]["id"], self.engine)
        self.assertEqual(self.checks()["tm-qual-zones-flows"]["status"], "pass")
        self.assertEqual(self.checks()["tm-qual-assets-linked"]["status"], "pass")


class TreatmentTests(Base):
    def test_decisions(self):
        rec = self.model("Shop")
        c = self.checks()
        self.assertEqual(c["tm-treat-undecided-high"]["status"], "fail")
        self.assertEqual(c["tm-treat-high-residual"]["status"], "fail")
        self.assertEqual(c["tm-treat-decision-rate"]["status"], "fail")
        self.assertRegex(c["tm-treat-undecided-high"]["evidence"][0], r"\d+ of \d+")
        self.decide_all(rec)
        c = self.checks()
        self.assertEqual(c["tm-treat-undecided-high"]["status"], "pass")
        self.assertEqual(c["tm-treat-high-residual"]["status"], "pass")
        self.assertEqual(c["tm-treat-decision-rate"]["status"], "pass")

    def test_live_findings(self):
        rec = self.model("Shop")
        self.assertEqual(self.checks()["tm-treat-live-findings"]["status"], "unknown")   # no findings loaded
        c = self.checks([FINDING])["tm-treat-live-findings"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 open findings", c["evidence"][0])
        self.decide_all(rec)
        self.assertEqual(self.checks([FINDING])["tm-treat-live-findings"]["status"], "pass")


class CurrencyTests(Base):
    def test_stale(self):
        self.model("Shop")
        self.assertEqual(self.checks()["tm-cur-reviewed"]["status"], "pass")
        c = self.checks(now=NOW + datetime.timedelta(days=200))["tm-cur-reviewed"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 of 1", c["evidence"][0])

    def test_reassessed_after_critical(self):
        self.model("Shop")
        newer = dict(FINDING, first_seen=(NOW + datetime.timedelta(days=2)).date().isoformat())
        c = self.checks([newer], now=NOW + datetime.timedelta(days=3))["tm-cur-reassessed-after-critical"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1", c["evidence"][0])
        self.assertEqual(self.checks([FINDING])["tm-cur-reassessed-after-critical"]["status"], "pass")


class ShapeTests(Base):
    def seed(self):
        appsec.upsert_application("Shop", {"internet_facing": True}, ACTOR, engine=self.engine)
        self.model("Shop")
        self.model("Thin", THIN)

    def test_shape_deterministic_no_secrets(self):
        self.seed()
        a, b = tm.run(self.ctx([FINDING])), tm.run(self.ctx([FINDING]))
        self.assertEqual(a, b)
        ids = [c["id"] for c in a]
        self.assertEqual(len(ids), len(set(ids)))
        areas = {x[0] for x in tm.FRAMEWORK["areas"]}
        for c in a:
            self.assertTrue({"id", "framework", "area", "title", "status", "score", "weight", "evidence", "recommendation", "change", "refs", "data_used"} <= set(c))
            self.assertEqual(c["framework"], "threat-modelling")
            self.assertIn(c["area"], areas)
            self.assertNotEqual(c["status"], "unknown", c["id"]) if c["id"] not in ("tm-cov-api-services", "tm-cov-critical-apps") else None
            self.assertRegex(" ".join(c["evidence"]), r"\d", c["id"])
        self.assertNotIn(SECRET, json.dumps(a))

    def test_changes_name_real_pages(self):
        nav = (ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        for c in tm.run(self.ctx()):
            if c["change"]:
                self.assertEqual(c["change"]["kind"], "page")
                self.assertIn(f'"{c["change"]["where"]}"', nav)


if __name__ == "__main__":
    unittest.main()
