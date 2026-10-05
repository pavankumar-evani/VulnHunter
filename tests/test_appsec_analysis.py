"""
Tests for the application store, the dependency graph analysis, package criticality and finding ranking.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.appsec import analysis, criticality, graph, scoring, store  # noqa: E402
from appsec_fixtures import SBOM, code_finding, dep_finding  # noqa: E402
from remediation.appsec.sbom_parse import SbomError  # noqa: E402

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()


class StoreTests(Base):
    def test_application_round_trip_and_validation(self):
        a = store.upsert_application("orders", {"environment": "Production", "internet_facing": True, "repo_provider": "github", "repo": "acme/orders", "default_branch": "main",
                                                "manifest_paths": "pom.xml, services/api/pom.xml", "business_criticality": "HIGH"}, "admin", self.engine)
        self.assertEqual((a["environment"], a["business_criticality"], a["internet_facing"]), ("production", "high", True))
        self.assertEqual(a["manifest_paths"], ["pom.xml", "services/api/pom.xml"])
        self.assertEqual(store.get_application("ORDERS", self.engine)["name"], "orders")
        store.upsert_application("ORDERS", {"owner": "team-b"}, "admin", self.engine)  # the same application, whatever the case
        self.assertEqual([a["name"] for a in store.list_applications(self.engine)], ["orders"])
        store.upsert_application("orders", {"owner": "team-a"}, "admin", self.engine)
        self.assertEqual(store.get_application("orders", self.engine)["owner"], "team-a")
        self.assertEqual(store.get_application("orders", self.engine)["repo"], "acme/orders")  # an update leaves other fields alone
        for bad in ({"environment": "moon"}, {"repo": "no-slash"}, {"repo_provider": "svn"}, {"manifest_paths": "../etc/passwd"}, {"manifest_paths": "/abs/pom.xml"},
                    {"business_criticality": "huge"}, {"default_branch": "a..b"}):
            with self.assertRaises(ValueError, msg=bad):
                store.upsert_application("x", bad, "admin", self.engine)
        with self.assertRaises(ValueError):
            store.upsert_application("  ", {}, "admin", self.engine)

    def test_sbom_replaces_and_creates_the_application(self):
        out = store.set_sbom("payments", SBOM, "ci", "key:ci", self.engine)
        self.assertEqual((out["components"], out["has_graph"]), (6, True))
        self.assertIsNotNone(store.get_application("payments", self.engine))
        store.set_sbom("payments", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "x", "version": "1"}]}), "ci", "key:ci", self.engine)
        self.assertEqual(store.get_sbom("payments", self.engine)["graph"]["components"][0]["name"], "x")
        self.assertEqual(store.sbom_summaries(self.engine)["payments"]["components"], 1)
        with self.assertRaises(SbomError):
            store.set_sbom("payments", "garbage", "ci", "k", self.engine)
        self.assertTrue(store.delete_application("payments", self.engine))
        self.assertIsNone(store.get_sbom("payments", self.engine))


class CriticalityTests(unittest.TestCase):
    def test_categories_override_and_scope_cap(self):
        self.assertEqual(criticality.classify("jackson-databind", "com.fasterxml.jackson.core")["category"], "deserialization")
        self.assertEqual(criticality.classify("spring-security-core")["level"], "critical")
        self.assertEqual(criticality.classify("spring-core")["category"], "other")  # 'ring' must not match inside 'spring'
        self.assertEqual(criticality.classify("junit-jupiter")["level"], "low")
        capped = criticality.classify("jackson-databind", scope="optional")
        self.assertEqual(capped["level"], "low")
        self.assertIn("capped", capped["reason"])
        rules = {"default_level": "medium", "overrides": [{"match": "acme-auth-core", "level": "critical", "reason": "ours"}], "categories": [], "development_scope_level": "low"}
        self.assertEqual(criticality.classify("acme-auth-core", rules=rules)["reason"], "ours")

    def test_a_bad_level_in_the_rules_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            p.write_text("default_level: huge\ncategories: []\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                criticality.load_rules(p)


class GraphTests(unittest.TestCase):
    def setUp(self):
        from remediation.appsec import sbom_parse
        self.g = sbom_parse.parse(SBOM)
        self.st = graph.structure(self.g)

    def test_depths_direct_and_paths(self):
        d = self.st["depth"]
        self.assertEqual((d["web"], d["log"], d["l4j"]), (1, 2, 3))
        self.assertNotIn("lone", d)  # nothing depends on it, so no path is recorded
        self.assertTrue(graph.is_direct(self.st, "web"))
        self.assertFalse(graph.is_direct(self.st, "l4j"))
        self.assertIsNone(graph.is_direct(self.st, "lone"))
        self.assertEqual(graph.path_to_root(self.st, "l4j"), ["orders", "spring-boot-starter-web", "spring-boot-starter-logging", "log4j-core"])
        self.assertEqual(graph.direct_parents(self.st, "l4j"), ["spring-boot-starter-web"])
        self.assertEqual({self.st["comps"][a]["name"] for a in graph.ancestors(self.st, "l4j")}, {"spring-boot-starter-web", "spring-boot-starter-logging"})

    def test_flat_sbom_reports_unknown_not_guessed(self):
        flat = graph.structure({"format": "x", "root": None, "components": self.g["components"], "edges": [], "has_graph": False})
        self.assertEqual(flat["depth"], {})
        self.assertIsNone(graph.is_direct(flat, "web"))

    def test_matching_prefers_the_installed_version_and_reports_misses(self):
        fs = [dep_finding(1, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228"), dep_finding(2, "log4j-core", "2.14.1", "2.15.0", "CVE-2021-45046"),
              dep_finding(3, "left-pad", "1.0.0", "1.3.0", "CVE-2099-0001")]
        hits, unmatched = graph.match_findings(self.st, fs)
        self.assertEqual(hits, {"l4j": ["FIND-1", "FIND-2"]})
        self.assertEqual(unmatched, ["FIND-3"])


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.rules = scoring.load_rules()

    def test_shipped_weights_add_up(self):
        self.assertAlmostEqual(sum(self.rules["weights"].values()), 1.0)

    def test_a_bad_weight_total_is_refused(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.yaml"
            r = yaml.safe_load(scoring.PATH.read_text(encoding="utf-8"))
            r["weights"]["cvss"] = 0.9
            p.write_text(yaml.safe_dump(r), encoding="utf-8")
            with self.assertRaises(ValueError):
                scoring.load_rules(p)

    def ctx(self, **kw):
        return {"app": {"business_criticality": "high", "environment": "production", "internet_facing": True}, "reach": {"verdict": "allowed"}, "package_level": "high",
                "depth": "direct", **kw}

    def test_known_exploited_exposed_finding_outranks_a_quiet_internal_one(self):
        hot = scoring.score_finding(dep_finding(1, "x", "1", "2", "CVE-1", cvss=9.8, kev=True, epss=0.9), self.ctx(), self.rules)
        cold = scoring.score_finding(dep_finding(2, "x", "1", "2", "CVE-2", cvss=9.8), self.ctx(app={"business_criticality": "low", "environment": "development", "internet_facing": False},
                                                                                                    reach={"verdict": "unknown"}, package_level="low", depth="transitive"), self.rules)
        self.assertGreater(hot["score"], 75)
        self.assertEqual(hot["tier"], "P1")
        self.assertLess(cold["score"], hot["score"] - 30)

    def test_a_denied_path_lowers_the_score_without_removing_it(self):
        f = dep_finding(1, "x", "1", "2", "CVE-1", cvss=9.0, kev=True, epss=0.5)
        open_ = scoring.score_finding(f, self.ctx(), self.rules)["score"]
        denied = scoring.score_finding(f, self.ctx(reach={"verdict": "denied"}), self.rules)["score"]
        self.assertAlmostEqual(denied, round(open_ * 0.6, 1), delta=0.2)
        self.assertGreater(denied, 0)

    def test_breakdown_is_explained_and_assumptions_are_listed(self):
        f = {"id": "F", "title": "t", "severity": "High", "scan_type": "sast", "asset": {"name": "x"}}
        r = scoring.score_finding(f, {"app": {}, "reach": {"verdict": "unknown"}, "package_level": "unknown", "depth": None}, self.rules)
        self.assertTrue(any("assumed" in a for a in r["assumptions"]))
        self.assertTrue(any("environment" in a for a in r["assumptions"]))
        self.assertEqual(len(r["breakdown"]), 7)
        self.assertEqual([m["name"] for m in r["modifiers"]], ["Network path"])  # no dependency modifier for a code finding
        self.assertEqual(r["breakdown"], sorted(r["breakdown"], key=lambda x: -x["points"]))

    def test_file_sensitivity(self):
        self.assertEqual(scoring.file_sensitivity({"file": "src/auth/login.py"}), "critical")
        self.assertEqual(scoring.file_sensitivity("app/api/handler.py"), "high")
        self.assertEqual(scoring.file_sensitivity({"file": "lib/strings.py"}), "unknown")


class AnalysisTests(Base):
    def setUp(self):
        super().setUp()
        store.upsert_application("orders", {"environment": "production", "internet_facing": True, "business_criticality": "high", "manifest_paths": ["pom.xml"]}, "admin", self.engine)
        store.set_sbom("orders", SBOM, "ci", "admin", self.engine)
        self.topology = {"assets": [{"match": {"name": "orders"}, "path_to_internet": [
            {"hop_type": "waf", "name": "Edge-WAF", "default_action": "allow"}, {"hop_type": "load_balancer", "name": "LB-1", "default_action": "allow"},
            {"hop_type": "dmz", "name": "DMZ-A", "default_action": "allow"}]}]}
        self.fs = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", cvss=10.0, kev=True, epss=0.97),
                   dep_finding(2, "log4j-core", "2.14.1", "2.15.0", "CVE-2021-45046", cvss=9.0),
                   dep_finding(3, "jackson-databind", "2.12.4", "2.12.7.1", "CVE-2022-42003", cvss=7.5),
                   dep_finding(4, "left-pad", "1.0.0", None, "CVE-2099-1", sev="Low", cvss=3.0),
                   code_finding(5, "src/auth/login.py"), dep_finding(6, "x", "1", "2", "CVE-9", app="other-app")]

    def run_it(self, **kw):
        return analysis.analyse("orders", self.fs, engine=self.engine, topology=self.topology, **kw)

    def test_graph_findings_and_reachability_are_joined(self):
        r = self.run_it()
        nodes = {n["name"]: n for n in r["nodes"]}
        self.assertTrue(nodes["log4j-core"]["vulnerable"])
        self.assertEqual(nodes["log4j-core"]["path"], ["orders", "spring-boot-starter-web", "spring-boot-starter-logging", "log4j-core"])
        self.assertEqual(nodes["log4j-core"]["pulled_in_by"], ["spring-boot-starter-web"])
        self.assertEqual(nodes["log4j-core"]["fixed_version"], "2.17.1")
        self.assertEqual(nodes["log4j-core"]["dependents"], ["spring-boot-starter-logging", "spring-boot-starter-web"])
        self.assertEqual(nodes["junit-jupiter"]["criticality"]["level"], "low")
        self.assertEqual(r["unmatched_findings"], ["FIND-4"])
        self.assertEqual([s["kind"] for s in r["reachability"]["stops"]], ["internet", "waf", "load_balancer", "dmz", "application"])
        self.assertEqual((r["reachability"]["verdict"], r["reachability"]["exposure"]), ("allowed", "internet"))
        self.assertNotIn("FIND-6", {f["id"] for f in r["findings"]})  # another application's finding

    def test_one_upgrade_closes_both_log4j_cves_at_the_highest_fixed_version(self):
        r = self.run_it()
        top = r["work_items"][0]
        self.assertEqual((top["kind"], top["package"], top["target_version"], top["resolves"]), ("dependency-upgrade", "log4j-core", "2.17.1", 2))
        self.assertEqual((top["direct"], top["pulled_in_by"], top["crosses_major"], top["tier"]), (False, ["spring-boot-starter-web"], False, "P1"))
        self.assertTrue(top["kev"])
        self.assertEqual(sorted(top["cves"]), ["CVE-2021-44228", "CVE-2021-45046"])
        self.assertGreater(top["score"], max(f["score"] for f in r["findings"] if f["id"] == "FIND-1"))
        scores = [i["score"] for i in r["work_items"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        unknown = next(i for i in r["work_items"] if i.get("package") == "left-pad")
        self.assertIsNone(unknown["target_version"])
        self.assertIn("No fixed version", unknown["note"])
        self.assertFalse(unknown["in_sbom"])
        code = next(i for i in r["work_items"] if i["kind"] == "code-fix")
        self.assertEqual(code["id"], "FIND-5")

    def test_a_denied_hop_lowers_every_score(self):
        base = {f["id"]: f["score"] for f in self.run_it()["findings"]}
        self.topology["assets"][0]["path_to_internet"][0]["default_action"] = "deny"
        after = self.run_it()
        self.assertEqual(after["reachability"]["verdict"], "denied")
        self.assertIn("lowers", after["reachability"]["note"])
        self.assertTrue(all(f["score"] < base[f["id"]] for f in after["findings"]))

    def test_no_recorded_path_is_said_plainly(self):
        r = analysis.analyse("orders", self.fs, engine=self.engine, topology={"assets": []})
        self.assertEqual(r["reachability"]["verdict"], "unknown")
        self.assertIn("No network path is recorded", r["reachability"]["note"])
        self.assertEqual(r["reachability"]["exposure"], "internet")  # from the flag

    def test_large_graphs_are_cut_down_to_what_matters(self):
        comps = [{"bom-ref": f"c{i}", "name": f"lib{i}", "version": "1.0"} for i in range(60)]
        deps = [{"ref": "app", "dependsOn": ["c0"]}] + [{"ref": f"c{i}", "dependsOn": [f"c{i + 1}"]} for i in range(59)]
        store.set_sbom("big", {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "big"}}, "components": comps, "dependencies": deps}, "ci", "a", self.engine)
        f = dep_finding(1, "lib40", "1.0", "1.1", "CVE-1", app="big")
        small = analysis.analyse("big", [f], engine=self.engine, limit=10)
        self.assertEqual(len(small["nodes"]), 42)  # the application, lib0..lib40 on the path
        self.assertEqual(small["hidden"], 19)
        full = analysis.analyse("big", [f], engine=self.engine, view="all")
        self.assertEqual((len(full["nodes"]), full["hidden"]), (61, 0))

    def test_application_without_an_sbom_still_ranks_its_findings(self):
        store.upsert_application("plain", {}, "admin", self.engine)
        r = analysis.analyse("plain", [dep_finding(1, "lodash", "4.17.0", "4.17.21", "CVE-1", app="plain")], engine=self.engine)
        self.assertIsNone(r["sbom"])
        self.assertEqual(r["nodes"], [])
        self.assertEqual(r["work_items"][0]["target_version"], "4.17.21")
        self.assertFalse(r["work_items"][0]["in_sbom"])

    def test_unknown_application_and_overview(self):
        with self.assertRaises(KeyError):
            analysis.analyse("ghost", [], engine=self.engine)
        ov = analysis.overview(self.fs + [dep_finding(9, "x", "1", "2", "CVE-9", app="unregistered-svc")], engine=self.engine)
        row = next(a for a in ov["applications"] if a["name"] == "orders")
        self.assertEqual((row["findings"], row["dependency_findings"], row["code_findings"], row["kev"], row["critical"]), (5, 4, 1, 1, 1))
        self.assertEqual(row["sbom"]["components"], 6)
        self.assertIn("unregistered-svc", ov["unregistered"])
        self.assertIn("other-app", ov["unregistered"])


if __name__ == "__main__":
    unittest.main()
