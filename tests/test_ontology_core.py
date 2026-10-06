"""The ontology file itself: it loads, is internally consistent, and a broken edit is refused with a clear error."""
import copy
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation import graphs as module_graphs  # noqa: E402
from remediation.ontology import ontology as om  # noqa: E402

RAW = copy.deepcopy(om.load().raw)


class LoadTests(unittest.TestCase):
    def test_it_loads_and_every_class_and_relation_is_described_in_a_sentence(self):
        o = om.load()
        self.assertGreater(len(o.classes), 30)
        for name, c in o.classes.items():
            self.assertTrue(c["description"].strip().endswith("."), name)
        for name, r in o.relations.items():
            self.assertTrue(r["description"].strip().endswith("."), name)

    def test_the_hierarchy_and_the_named_axioms(self):
        o = om.load()
        self.assertTrue(o.is_a("Package", "Component"))
        self.assertTrue(o.is_a("McpServer", "Tool"))
        self.assertTrue(o.is_a("AIAsset", "Asset"))
        self.assertTrue(o.is_a("Package", "Thing"))
        self.assertFalse(o.is_a("Asset", "Package"))
        self.assertTrue(o.relations["depends-on"]["transitive"])
        self.assertTrue(o.relations["reaches"]["transitive"])
        self.assertEqual(o.relations["owned-by"]["inverse_of"], "owns")
        self.assertEqual(o.with_subrelations("reaches"), ["reaches", "routes-to"])

    def test_the_relations_named_in_the_brief_have_the_right_signatures(self):
        o = om.load()
        sigs = {r: set(o.signatures(r)) for r in ("affects", "runs", "depends-on", "exploits", "mitigates", "owns", "reaches", "invokes")}
        self.assertIn(("Finding", "Asset"), sigs["affects"])
        self.assertIn(("Asset", "Application"), sigs["runs"])
        self.assertIn(("Application", "Component"), sigs["depends-on"])
        self.assertIn(("Vulnerability", "Component"), sigs["exploits"])
        self.assertIn(("Control", "Technique"), sigs["mitigates"])
        self.assertIn(("Team", "Asset"), sigs["owns"])
        self.assertIn(("Asset", "Asset"), sigs["reaches"])
        self.assertIn(("AIAsset", "Tool"), sigs["invokes"])

    def test_an_inverse_reads_the_original_backwards(self):
        o = om.load()
        self.assertEqual(set(o.signatures("owned-by")), {(r, d) for d, r in o.signatures("owns")})
        self.assertEqual(o.base("owned-by"), ("owns", True))
        self.assertEqual(o.base("owns"), ("owns", False))

    def test_attributes_are_inherited(self):
        o = om.load()
        self.assertIn("internet_facing", o.attributes("AIAsset"))   # from Asset
        self.assertEqual(o.required("Vulnerability"), ["cve"])

    def test_slugs(self):
        self.assertEqual([om.slug(x) for x in ("Asset", "FirewallRule", "AIAsset", "McpServer")], ["asset", "firewall-rule", "ai-asset", "mcp-server"])

    def test_the_wire_form_lists_everything(self):
        d = om.load().describe()
        self.assertEqual(len(d["classes"]), len(om.load().classes))
        self.assertTrue(all(r["signatures"] for r in d["relations"]))


class CheckTests(unittest.TestCase):
    def broken(self, edit):
        data = copy.deepcopy(RAW)
        edit(data)
        with self.assertRaises(om.OntologyError) as cm:
            om.Ontology(data)
        return str(cm.exception)

    def test_an_unknown_parent(self):
        self.assertIn("unknown class", self.broken(lambda d: d["classes"]["Asset"].update(is_a="Nope")))

    def test_a_cycle_leaves_no_root(self):
        self.assertIn("root", self.broken(lambda d: d["classes"]["Thing"].update(is_a="Asset")))

    def test_an_is_a_cycle_below_the_root(self):
        def edit(d):
            d["classes"]["Asset"]["is_a"] = "Application"
            d["classes"]["Application"]["is_a"] = "Asset"
        self.assertIn("cycle", self.broken(edit))

    def test_a_signature_naming_an_unknown_class(self):
        self.assertIn("not a class", self.broken(lambda d: d["relations"]["affects"]["signatures"].append({"domain": "Finding", "range": "Nope"})))

    def test_an_inverse_of_something_unknown(self):
        self.assertIn("inverse_of", self.broken(lambda d: d["relations"]["owned-by"].update(inverse_of="nope")))

    def test_a_mapping_onto_something_undeclared(self):
        self.assertIn("unknown class", self.broken(lambda d: d["mappings"]["soc"]["nodes"].update(alert="Nope")))
        self.assertIn("unknown relation", self.broken(lambda d: d["mappings"]["soc"]["edges"].update(involves="nope")))

    def test_a_missing_description_and_a_bad_attribute_type(self):
        self.assertIn("no description", self.broken(lambda d: d["classes"]["Asset"].update(description="")))
        self.assertIn("type must be", self.broken(lambda d: d["classes"]["Asset"]["attributes"]["owned"].update(type="blob")))

    def test_a_required_attribute_must_be_declared(self):
        self.assertIn("not declared", self.broken(lambda d: d["classes"]["Asset"].update(required=["nope"])))


class MappingCoverageTests(unittest.TestCase):
    def test_every_module_has_a_mapping(self):
        self.assertEqual(sorted(om.load().mappings), sorted(module_graphs.MODULES))

    def test_the_kinds_each_builder_declares_are_mapped(self):
        """Builders name their node and edge kinds in g.kind(...) calls and node(...) literals; the mapping must cover the ones tests know about."""
        o = om.load()
        expected = {"soc": (["alert", "case", "hunt", "technique", "host", "user", "ip", "domain"], ["involves", "tagged", "contains", "hunts", "covers"]),
                    "devsecops": (["application", "package", "proposal"], ["uses", "depends_on", "fixes", "for"]),
                    "infra": (["internet", "hop", "asset", "rule", "port"], ["reaches", "routes_to", "opens", "pivot"]),
                    "ai": (["system", "model", "provider", "tool", "mcp-server", "data-source", "shadow"], ["runs", "hosted_by", "can_call", "reads", "talks_to"]),
                    "remediation": (["team", "person", "asset", "exception", "approval", "ticket"], ["member_of", "assigned", "owns", "waives", "approves", "tracks"]),
                    "grc": (["framework", "control", "evidence", "risk", "threat", "findings"], ["part-of", "evidences", "mitigated-by", "cites"]),
                    "admin": (["core", "module", "connection", "access"], ["serves", "sends-to", "feeds", "calls-into", "ingests-into", "works-in"]),
                    "appsec": (["service", "endpoint", "data-class", "component"], ["serves", "returns", "calls", "flows to"])}
        for module, (nodes, edges) in expected.items():
            for k in nodes:
                self.assertIsNotNone(o.node_class(module, k), (module, k))
            for k in edges:
                self.assertIsNotNone(o.edge_relation(module, k), (module, k))


if __name__ == "__main__":
    unittest.main()
