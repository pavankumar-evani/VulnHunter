"""Validation of graphs against the ontology: a valid graph passes, each violation type is reported with its node or edge and rule, and nothing is mutated."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from sqlalchemy import create_engine  # noqa: E402

import ontology_fixtures as fx  # noqa: E402
from appsec_fixtures import SBOM, dep_finding  # noqa: E402
from remediation import graphs as module_graphs  # noqa: E402
from remediation.appsec import store  # noqa: E402
from remediation.ontology import validate  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


def node(i, kind, **kw):
    return {"id": i, "label": i, "kind": kind, "weight": 1, "sev": kw.pop("sev", None), "meta": kw.pop("meta", {}), "href": None, **kw}


def edge(s, t, kind, **kw):
    return {"source": s, "target": t, "kind": kind, "label": None, "weight": 1, **kw}


def estate_like(nodes, edges, **kw):
    return {"module": "estate", "nodes": nodes, "edges": edges, "truncated": False, **kw}


def rules(report):
    return sorted({v["rule"] for v in report["violations"]})


class ValidGraphTests(unittest.TestCase):
    def test_the_hand_built_module_graphs_conform(self):
        for m, g in fx.graphs().items():
            r = validate.validate(g)
            self.assertTrue(r["conforms"], (m, r["violations"]))

    def test_the_estate_graph_conforms(self):
        r = validate.validate(fx.estate_graph())
        self.assertTrue(r["conforms"], r["violations"])
        self.assertEqual(r["checked"]["nodes"], 16)
        self.assertEqual(r["notes"], [])

    def test_an_empty_graph_conforms(self):
        self.assertTrue(validate.validate({"module": "soc", "nodes": [], "edges": []})["conforms"])

    def test_real_builders_on_real_stored_data_conform(self):
        with tempfile.TemporaryDirectory() as d:
            eng = create_engine(f"sqlite:///{Path(d) / 'q.db'}")
            db_module.ensure_schema(eng)
            for n in ("orders", "billing"):
                store.upsert_application(n, {"environment": "production", "team": "web"}, "o@x", eng)
                store.set_sbom(n, SBOM, "ci", "o@x", eng)
            findings = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", app="orders", kev=True, epss=0.9),
                        dep_finding(2, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="High", app="billing")]
            topology = {"assets": [{"match": {"name": "orders"}, "path_to_internet": [{"name": "edge-fw", "hop_type": "firewall", "default_action": "allow"}]}]}
            for m in module_graphs.MODULES:
                ctx = {"topology": topology} if m == "infra" else {}
                g = module_graphs.build(m, engine=eng, findings=findings, **ctx)
                r = validate.validate(g)
                self.assertTrue(r["conforms"], (m, r["violations"][:3]))
            eng.dispose()

    def test_validate_all_gives_one_verdict(self):
        out = validate.validate_all(fx.graphs())
        self.assertTrue(out["conforms"])
        self.assertEqual(set(out["modules"]), set(fx.graphs()))
        bad = fx.graphs()
        bad["ai"]["nodes"][0]["kind"] = "nonsense"
        out = validate.validate_all(bad)
        self.assertFalse(out["conforms"])
        self.assertGreaterEqual(out["totals"]["violations"], 1)


class ViolationTests(unittest.TestCase):
    def one(self, report, rule):
        found = [v for v in report["violations"] if v["rule"] == rule]
        self.assertTrue(found, (rule, report["violations"]))
        return found[0]

    def test_unknown_class_names_the_node(self):
        r = validate.validate(estate_like([node("x", "gadget")], []))
        v = self.one(r, "unknown-class")
        self.assertEqual(v["node"], "x")
        self.assertFalse(r["conforms"])

    def test_unknown_relation_names_the_edge(self):
        r = validate.validate(estate_like([node("a", "asset"), node("b", "asset")], [edge("a", "b", "befriends")]))
        v = self.one(r, "unknown-relation")
        self.assertEqual((v["edge"]["source"], v["edge"]["target"], v["edge"]["kind"]), ("a", "b", "befriends"))

    def test_an_illegal_relation_for_its_domain_and_range(self):
        nodes = [node("asset:a", "asset"), node("finding:f", "finding", meta={"severity": "high"})]
        r = validate.validate(estate_like(nodes, [edge("asset:a", "finding:f", "affects")]))
        v = self.one(r, "domain-range")
        self.assertEqual(v["detail"], {"relation": "affects", "source_class": "Asset", "target_class": "Finding"})
        self.assertIn("Finding -> Asset", v["message"])

    def test_a_subclass_satisfies_a_domain(self):
        nodes = [node("m:1", "mcp-server"), node("s:1", "ai-asset", meta={"reviewed": True})]
        self.assertTrue(validate.validate(estate_like(nodes, [edge("s:1", "m:1", "invokes")]))["conforms"])

    def test_an_inverse_relation_is_checked_with_swapped_signatures(self):
        nodes = [node("asset:a", "asset"), node("team:t", "team")]
        self.assertTrue(validate.validate(estate_like(nodes, [edge("asset:a", "team:t", "owned-by")]))["conforms"])
        self.assertFalse(validate.validate(estate_like(nodes, [edge("team:t", "asset:a", "owned-by")]))["conforms"])

    def test_a_missing_required_attribute(self):
        r = validate.validate(estate_like([node("cve:x", "vulnerability")], []))
        v = self.one(r, "required-attribute")
        self.assertEqual((v["node"], v["detail"]["attribute"]), ("cve:x", "cve"))
        self.assertTrue(validate.validate(estate_like([node("cve:x", "vulnerability", meta={"cve": "CVE-1"})], []))["conforms"])

    def test_severity_counts_from_the_node_field_as_well_as_meta(self):
        self.assertTrue(validate.validate(estate_like([node("f", "finding", sev="high")], [], truncated=True))["conforms"])

    def test_an_attribute_of_the_wrong_type_or_outside_its_enum(self):
        r = validate.validate(estate_like([node("asset:a", "asset", meta={"internet_facing": "yes", "verified_controls": True})], []))
        self.assertEqual(sum(1 for v in r["violations"] if v["rule"] == "attribute-type"), 2)
        r = validate.validate(estate_like([node("c", "control", meta={"state": "maybe"})], []))
        self.assertIn("verified, claimed", self.one(r, "attribute-type")["message"])

    def test_an_unknown_attribute_value_is_not_a_violation(self):
        self.assertTrue(validate.validate(estate_like([node("asset:a", "asset", meta={"internet_facing": None})], []))["conforms"])

    def test_a_cardinality_maximum(self):
        nodes = [node("f", "finding", sev="high"), node("asset:a", "asset"), node("asset:b", "asset")]
        r = validate.validate(estate_like(nodes, [edge("f", "asset:a", "affects"), edge("f", "asset:b", "affects")]))
        v = self.one(r, "cardinality")
        self.assertEqual((v["node"], v["detail"]["max"], v["detail"]["found"]), ("f", 1, 2))

    def test_a_cardinality_minimum_on_a_complete_graph_but_not_a_truncated_one(self):
        nodes = [node("f", "finding", sev="high")]
        r = validate.validate(estate_like(nodes, []))
        self.assertEqual(self.one(r, "cardinality")["detail"]["min"], 1)
        r = validate.validate(estate_like(nodes, [], truncated=True))
        self.assertTrue(r["conforms"])
        self.assertIn("truncated", r["notes"][0])

    def test_a_dangling_edge(self):
        r = validate.validate(estate_like([node("asset:a", "asset")], [edge("asset:a", "asset:ghost", "reaches")]))
        self.assertEqual(self.one(r, "dangling-edge")["edge"]["target"], "asset:ghost")

    def test_invalid_provenance(self):
        n = [node("asset:a", "asset"), node("asset:b", "asset")]
        r = validate.validate(estate_like(n, [edge("asset:a", "asset:b", "reaches", prov={"source_kind": "rumour", "confidence": "certain"})]))
        self.assertEqual(sum(1 for v in r["violations"] if v["rule"] == "invalid-provenance"), 2)

    def test_module_graph_kinds_are_read_through_the_modules_mapping(self):
        g = {"module": "soc", "nodes": [node("host:a", "host"), node("alert:1", "alert")], "edges": [edge("alert:1", "host:a", "involves")]}
        self.assertTrue(validate.validate(g)["conforms"])
        g["edges"][0]["kind"] = "owns"      # a real relation, but Alert -owns-> Asset is not allowed
        self.assertEqual(rules(validate.validate(g)), ["domain-range"])

    def test_several_violations_are_all_reported_with_counts(self):
        nodes = [node("x", "gadget"), node("y", "widget"), node("cve:x", "vulnerability")]
        r = validate.validate(estate_like(nodes, []))
        self.assertEqual(r["counts"], {"required-attribute": 1, "unknown-class": 2})

    def test_the_report_is_capped_but_the_counts_are_not(self):
        nodes = [node(f"x{i}", "gadget") for i in range(validate.MAX_VIOLATIONS + 20)]
        r = validate.validate(estate_like(nodes, []))
        self.assertEqual(len(r["violations"]), validate.MAX_VIOLATIONS)
        self.assertTrue(r["truncated_violations"])
        self.assertEqual(r["counts"]["unknown-class"], validate.MAX_VIOLATIONS + 20)


class NeverMutatesTests(unittest.TestCase):
    def test_validation_changes_nothing_and_drops_nothing(self):
        nodes = [node("x", "gadget"), node("asset:a", "asset", meta={"internet_facing": "yes"}), node("f", "finding", sev="high")]
        g = estate_like(nodes, [edge("x", "asset:a", "befriends"), edge("f", "asset:a", "affects"), edge("f", "ghost", "affects")])
        before = copy.deepcopy(g)
        r = validate.validate(g)
        self.assertEqual(g, before)
        self.assertEqual(r["checked"], {"nodes": 3, "edges": 3})
        self.assertFalse(r["conforms"])


if __name__ == "__main__":
    unittest.main()
