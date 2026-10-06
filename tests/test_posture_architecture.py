"""Tests for the architecture review posture framework (remediation/posture/architecture.py)."""
import datetime
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from sqlalchemy import create_engine  # noqa: E402

from appsec_fixtures import SBOM, dep_finding  # noqa: E402
from remediation.appsec import store as app_store  # noqa: E402
from remediation.assignments import store as assignments  # noqa: E402
from remediation.firewall import store as fw_store  # noqa: E402
from remediation.inventory import asset_inventory  # noqa: E402
from remediation.posture import architecture, engine as posture_engine, model  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
HEAD = "Name,Source Zone,Destination Zone,Source Address,Destination Address,Service,Action,Log,Hit Count,Last Hit,Created,Owner,Comment\n"
FW_ZONED = HEAD + ("allow-web,untrust,dmz,any,10.1.1.10,tcp/443,allow,yes,500,2026-10-01,2026-09-01,pat.owner@corp.test,site\n"
                   "dmz-app,dmz,app,10.1.1.10,10.2.2.10,tcp/8443,allow,yes,500,2026-10-01,2026-09-01,pat.owner@corp.test,\n"
                   "app-data,app,data,10.2.2.10,10.3.3.10,tcp/5432,allow,yes,500,2026-10-01,2026-09-01,pat.owner@corp.test,\n")
FW_FLAT = HEAD + ("allow-rdp-in,untrust,untrust,any,10.1.1.20,rdp,allow,no,0,,2024-01-01,,\n"
                  "allow-all,any,any,any,any,any,allow,yes,9,2026-10-01,2024-01-01,,\n")
SOLO_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "solo", "version": "1.0.0"}},
             "components": [{"bom-ref": "req", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}], "dependencies": [{"ref": "app", "dependsOn": ["req"]}]}
TOPOLOGY = {"assets": [{"match": {"name_prefix": "web-"}, "path_to_internet": [{"hop_type": "firewall", "name": "Edge-FW", "default_action": "allow"}]}]}


def finding(i, host, sev="High", typ="unix-server", kev=None, first_seen="2026-09-01"):
    return {"id": f"FIND-{i}", "title": f"Issue {i}", "severity": sev, "status": "open", "asset": {"name": host, "type": typ}, "first_seen": first_seen, "last_seen": "2026-10-01", "kev": kev}


def mkctx(engine, findings=(), env=None, now=NOW):
    ctx = model.Context(engine=engine, findings=list(findings), env=env if env is not None else {}, now=now)
    pol = posture_engine.policy()
    ctx.policy, ctx.thr = pol, pol["thresholds"]
    return ctx


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.lock = str(Path(self.tmp.name) / "x.lock")
        p = patch("remediation.enrichment.network_reachability.load_topology", return_value={"assets": []})
        self.topo = p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_ar(self, findings=(), env=None, now=NOW):
        return {c["id"]: c for c in architecture.run(mkctx(self.engine, findings, env, now))}

    def owner(self, host, team="platform"):
        asset_inventory.set_owner(host, ACTOR, team, engine=self.engine, lock_path=self.lock)

    # ---- (a)
    def test_empty_estate_never_passes(self):
        checks = self.run_ar()
        self.assertFalse([c["id"] for c in checks.values() if c["status"] in ("pass", "partial")])
        # only settings can answer on an empty estate; an unset setting is an honest fail and coordination does not apply to one SQLite file
        self.assertEqual({c["id"] for c in checks.values() if c["status"] == "fail"}, {"arch-res-database", "arch-res-session-secret"})
        self.assertEqual(checks["arch-res-coordination"]["status"], "na")
        self.assertEqual(checks["arch-res-backups"]["status"], "unknown")
        self.assertEqual({c["status"] for k, c in checks.items() if not k.startswith("arch-res-")}, {"unknown"})

    # ---- (b) exposure
    def test_internet_facing_critical(self):
        asset_inventory.set_facing("web-01.corp.test", "external", engine=self.engine, lock_path=self.lock)
        good = [finding(1, "web-01.corp.test", "High"), finding(2, "db-01.corp.test", "Critical")]
        self.assertEqual(self.run_ar(good)["arch-exp-internet-critical"]["status"], "pass")
        bad = good + [finding(3, "web-01.corp.test", "Critical")]
        c = self.run_ar(bad)["arch-exp-internet-critical"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 open Critical or known-exploited findings on 1 of 1 internet-facing assets", c["evidence"][0])
        # a path recorded in the topology also makes an asset exposed
        self.topo.return_value = TOPOLOGY
        c = self.run_ar([finding(4, "web-09.corp.test", "Critical")])["arch-exp-internet-critical"]
        self.assertEqual(c["status"], "fail")

    def test_exposed_ports(self):
        fw_store.import_rules("edge-fw", FW_ZONED, "csv", ACTOR, self.engine, now=NOW)
        self.assertEqual(self.run_ar()["arch-exp-ports"]["status"], "pass")
        fw_store.import_rules("edge-fw", FW_FLAT, "csv", ACTOR, self.engine, now=NOW)
        c = self.run_ar()["arch-exp-ports"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("risky ports", c["evidence"][0])

    def test_kev_age(self):
        self.assertEqual(self.run_ar([finding(1, "a.corp.test")])["arch-exp-kev-age"]["status"], "unknown")  # not enriched
        none_listed = [finding(1, "a.corp.test", kev={"listed": False})]
        self.assertEqual(self.run_ar(none_listed)["arch-exp-kev-age"]["status"], "pass")
        fresh = [finding(1, "a.corp.test", kev={"listed": True}, first_seen="2026-10-01")]
        self.assertEqual(self.run_ar(fresh)["arch-exp-kev-age"]["status"], "pass")
        old = [finding(1, "a.corp.test", kev={"listed": True}, first_seen="2026-06-01"), finding(2, "b.corp.test", kev={"listed": True}, first_seen="2026-06-01")]
        c = self.run_ar(old)["arch-exp-kev-age"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("2 of 2 open known-exploited", c["evidence"][0])

    # ---- concentration
    def add_app(self, name, sbom=SBOM):
        app_store.upsert_application(name, {"environment": "production", "team": "web"}, ACTOR, self.engine)
        app_store.set_sbom(name, sbom, "ci", ACTOR, self.engine)

    def test_shared_vulnerable_package(self):
        self.assertEqual(self.run_ar()["arch-con-package"]["status"], "unknown")
        self.add_app("orders")
        one = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="orders")]
        self.assertEqual(self.run_ar(one)["arch-con-package"]["status"], "pass")
        self.add_app("billing")
        two = one + [dep_finding(2, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="billing")]
        c = self.run_ar(two)["arch-con-package"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("used by 2 of 2 applications", c["evidence"][0])
        for name in ("search", "portal", "ledger"):
            self.add_app(name, SOLO_SBOM)
        c = self.run_ar(two)["arch-con-package"]
        self.assertEqual(c["status"], "partial")  # 2 of 5 applications
        self.assertAlmostEqual(c["score"], 0.6, places=2)

    def test_team_and_asset_concentration(self):
        few = [finding(i, f"h{i}.corp.test", "Critical") for i in range(2)]
        self.assertEqual(self.run_ar(few)["arch-con-team"]["status"], "unknown")
        self.assertEqual(self.run_ar(few)["arch-con-asset"]["status"], "unknown")
        spread = [finding(i, f"h{i}.corp.test", "Critical") for i in range(4)]
        for i in range(4):
            self.owner(f"h{i}.corp.test", f"team-{i % 2}")
        checks = self.run_ar(spread)
        self.assertEqual(checks["arch-con-team"]["status"], "pass")
        self.assertEqual(checks["arch-con-asset"]["status"], "pass")
        heavy = [finding(i, "big.corp.test", "Critical") for i in range(5)] + [finding(9, "small.corp.test", "Critical")]
        self.owner("big.corp.test", "team-x")
        self.owner("small.corp.test", "team-y")
        checks = self.run_ar(heavy)
        self.assertEqual(checks["arch-con-team"]["status"], "fail")
        self.assertIn("team-x holds 5 of 6", checks["arch-con-team"]["evidence"][0])
        self.assertEqual(checks["arch-con-asset"]["status"], "fail")

    # ---- ownership
    def test_asset_ownership(self):
        fs = [finding(1, "a.corp.test"), finding(2, "b.corp.test")]
        self.assertEqual(self.run_ar(fs)["arch-own-assets"]["status"], "fail")
        self.owner("a.corp.test")
        self.assertEqual(self.run_ar(fs)["arch-own-assets"]["status"], "partial")
        self.owner("b.corp.test")
        self.assertEqual(self.run_ar(fs)["arch-own-assets"]["status"], "pass")

    def test_urgent_findings_assigned(self):
        fs = [finding(1, "a.corp.test", "Critical"), finding(2, "b.corp.test", "Critical")]
        self.assertEqual(self.run_ar([finding(1, "a.corp.test", "Low")])["arch-own-urgent"]["status"], "na")
        self.assertEqual(self.run_ar(fs)["arch-own-urgent"]["status"], "fail")
        assignments.assign("FIND-1", ACTOR, assignee_email="dev1@corp.test", engine=self.engine, lock_path=self.lock)
        c = self.run_ar(fs)["arch-own-urgent"]
        self.assertEqual(c["status"], "partial")
        self.assertIn("1 of 2 urgent", c["evidence"][0])
        assignments.assign("FIND-2", ACTOR, team="platform", engine=self.engine, lock_path=self.lock)
        self.assertEqual(self.run_ar(fs)["arch-own-urgent"]["status"], "pass")

    def test_rule_owners(self):
        fw_store.import_rules("edge-fw", FW_ZONED, "csv", ACTOR, self.engine, now=NOW)
        self.assertEqual(self.run_ar()["arch-own-rules"]["status"], "pass")
        fw_store.import_rules("edge-fw", FW_FLAT, "csv", ACTOR, self.engine, now=NOW)
        self.assertEqual(self.run_ar()["arch-own-rules"]["status"], "fail")

    # ---- segmentation
    def test_zones_and_any_any(self):
        fw_store.import_rules("edge-fw", FW_ZONED, "csv", ACTOR, self.engine, now=NOW)
        checks = self.run_ar()
        self.assertEqual(checks["arch-seg-zones"]["status"], "pass")
        self.assertEqual(checks["arch-seg-any-any"]["status"], "pass")
        fw_store.import_rules("edge-fw", FW_FLAT, "csv", ACTOR, self.engine, now=NOW)
        checks = self.run_ar()
        self.assertEqual(checks["arch-seg-zones"]["status"], "fail")
        self.assertEqual(checks["arch-seg-any-any"]["status"], "fail")
        self.assertIn("allow-all", " ".join(checks["arch-seg-any-any"]["evidence"]))

    def test_topology_paths(self):
        fs = [finding(1, "web-01.corp.test"), finding(2, "db-01.corp.test")]
        self.assertEqual(self.run_ar(fs)["arch-seg-topology"]["status"], "fail")
        self.topo.return_value = TOPOLOGY
        c = self.run_ar(fs)["arch-seg-topology"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)

    # ---- resilience
    def test_database_and_coordination_settings(self):
        self.assertEqual(self.run_ar(env={"QUANTA_DATABASE_URL": "sqlite:///x.db"})["arch-res-database"]["status"], "fail")
        pg = {"QUANTA_DATABASE_URL": "postgresql+psycopg2://quanta:Hunter2Password@db.corp.test/quanta"}
        checks = self.run_ar(env=pg)
        self.assertEqual(checks["arch-res-database"]["status"], "pass")
        self.assertNotIn("Hunter2Password", json.dumps(checks["arch-res-database"]))  # the URL carries a password: only the scheme is reported
        self.assertEqual(checks["arch-res-coordination"]["status"], "fail")
        self.assertEqual(self.run_ar(env={**pg, "QUANTA_LOCK_BACKEND": "db"})["arch-res-coordination"]["status"], "partial")
        self.assertEqual(self.run_ar(env={**pg, "QUANTA_LOCK_BACKEND": "db", "QUANTA_FILES_BACKEND": "db"})["arch-res-coordination"]["status"], "pass")

    def test_session_secret_presence_only(self):
        self.assertEqual(self.run_ar()["arch-res-session-secret"]["status"], "fail")
        c = self.run_ar(env={"QUANTA_SESSION_SECRET": "very-secret-value-0123456789"})["arch-res-session-secret"]
        self.assertEqual(c["status"], "pass")
        self.assertNotIn("very-secret-value", json.dumps(c))
        self.assertIn("28 characters", c["evidence"][0])
        self.assertEqual(self.run_ar(env={"QUANTA_SESSION_SECRET_FILE": "/var/run/secrets/quanta/QUANTA_SESSION_SECRET"})["arch-res-session-secret"]["status"], "pass")

    def test_backups_are_never_observable(self):
        c = self.run_ar(env={"QUANTA_DATABASE_URL": "postgresql://db.corp.test/quanta"})["arch-res-backups"]
        self.assertEqual(c["status"], "unknown")
        self.assertIsNone(c["score"])
        self.assertEqual(c["change"]["kind"], "process")

    # ---- (c)(d)(e)
    def seed_bad(self):
        fw_store.import_rules("edge-fw", FW_FLAT, "csv", ACTOR, self.engine, now=NOW)
        self.add_app("orders")
        self.add_app("billing")
        asset_inventory.set_facing("web-01.corp.test", "external", engine=self.engine, lock_path=self.lock)
        return [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="orders", kev=True, first_seen="2026-06-01"),
                dep_finding(2, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="billing", kev=True, first_seen="2026-06-01"),
                finding(3, "web-01.corp.test", "Critical"), finding(4, "web-01.corp.test", "Critical"), finding(5, "web-01.corp.test", "Critical")]

    def test_shape_ids_and_numbers(self):
        for fs in ((), self.seed_bad()):
            checks = architecture.run(mkctx(self.engine, fs))
            ids = [c["id"] for c in checks]
            self.assertEqual(len(ids), len(set(ids)))
            areas = {a for a, _ in architecture.FRAMEWORK["areas"]}
            self.assertEqual({c["area"] for c in checks}, areas)
            for c in checks:
                self.assertEqual(set(c), {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"})
                self.assertEqual(c["framework"], "architecture")
                self.assertTrue(c["recommendation"], c["id"])
                self.assertTrue(any(re.search(r"\d", e) for e in c["evidence"]), c["id"])

    def test_deterministic(self):
        fs = self.seed_bad()
        self.assertEqual(architecture.run(mkctx(self.engine, fs)), architecture.run(mkctx(self.engine, fs)))

    def test_changes_name_real_settings(self):
        fs = self.seed_bad()
        nav = (REPO_ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")
        sources = "".join(p.read_text(encoding="utf-8") for pat in ("dashboard/*.py", "dashboard/auth/*.py", "remediation/utils/*.py") for p in REPO_ROOT.glob(pat))
        seen = 0
        for c in architecture.run(mkctx(self.engine, fs)):
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] == "page":
                self.assertIn(f'"{ch["where"]}"', nav, c["id"])
            elif ch["kind"] == "yaml":
                self.assertIn(ch["key"], (REPO_ROOT / ch["where"]).read_text(encoding="utf-8"), c["id"])
            elif ch["kind"] == "env":
                self.assertIn(ch["key"], sources, c["id"])
        self.assertGreaterEqual(seen, 8)
        # the settings the coordination check names exist in both the code and the Helm chart
        values = (REPO_ROOT / "deploy" / "helm" / "quanta" / "values.yaml").read_text(encoding="utf-8")
        self.assertIn("lockBackend", values)
        self.assertIn("QUANTA_LOCK_BACKEND", sources)
        self.assertIn("QUANTA_FILES_BACKEND", sources)


if __name__ == "__main__":
    unittest.main()
