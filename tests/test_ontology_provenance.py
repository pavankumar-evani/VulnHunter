"""Provenance: the GraphBuilder extension is optional and backward compatible, builders attach it only where stored data says it, and unknown stays unknown."""
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
from remediation.appsec import store  # noqa: E402
from remediation.graphs import devsecops  # noqa: E402
from remediation.graphs.schema import GraphBuilder, prov  # noqa: E402
from remediation.ontology import provenance  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


class BuilderTests(unittest.TestCase):
    def test_without_prov_the_output_is_exactly_what_it_was(self):
        g = GraphBuilder("m", "t", "d")
        g.node("a", "A", "k")
        g.node("b", "B", "k")
        g.edge("a", "b", "r")
        out = g.build()
        self.assertEqual(set(out["nodes"][0]), {"id", "label", "kind", "weight", "sev", "meta", "href"})
        self.assertEqual(set(out["edges"][0]), {"source", "target", "kind", "label", "weight"})

    def test_prov_helper_is_none_when_nothing_is_known(self):
        self.assertIsNone(prov())
        self.assertEqual(prov(source="x")["source_kind"], None)

    def test_prov_is_carried_and_a_repeated_edge_fills_gaps_but_keeps_what_is_known(self):
        g = GraphBuilder("m", "t", "d")
        g.node("a", "A", "k", prov=prov(source="scanner"))
        g.node("a", "A", "k", prov=prov(source="other", observed_at="2026-10-01"))
        g.node("b", "B", "k")
        g.edge("a", "b", "r", prov=prov(source="first"))
        g.edge("a", "b", "r", prov=prov(source="second", confidence="observed"), weight=2)
        out = g.build()
        self.assertEqual(out["nodes"][0]["prov"], {"source": "scanner", "source_kind": None, "observed_at": "2026-10-01", "confidence": None})
        self.assertEqual(out["edges"][0]["prov"]["source"], "first")
        self.assertEqual(out["edges"][0]["prov"]["confidence"], "observed")
        self.assertEqual(out["edges"][0]["weight"], 3)

    def test_it_stays_deterministic(self):
        self.assertEqual(fx.infra(), fx.infra())
        self.assertEqual(fx.estate_graph(), fx.estate_graph())


class RealBuilderTests(unittest.TestCase):
    def test_the_supply_chain_graph_carries_the_sbom_upload_time_and_source(self):
        with tempfile.TemporaryDirectory() as d:
            eng = create_engine(f"sqlite:///{Path(d) / 'q.db'}")
            db_module.ensure_schema(eng)
            store.upsert_application("orders", {"environment": "production"}, "o@x", eng)
            store.set_sbom("orders", SBOM, "ci-pipeline", "o@x", eng)
            g = devsecops.build(engine=eng, findings=[dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", app="orders")])
            uses = [e for e in g["edges"] if e["kind"] == "uses"]
            self.assertTrue(uses)
            p = uses[0]["prov"]
            self.assertEqual(p["source"], "SBOM (ci-pipeline)")
            self.assertTrue(p["observed_at"])
            self.assertEqual(p["confidence"], "declared")
            self.assertIsNone(p["source_kind"])            # an SBOM upload does not say whether a person or a pipeline made it
            eng.dispose()


class FactTests(unittest.TestCase):
    def setUp(self):
        self.g = fx.estate_graph()
        self.facts = {(f["subject"], f["relation"], f["object"]): f for f in provenance.facts(self.g, "estate")}

    def test_every_edge_becomes_a_fact(self):
        self.assertEqual(len(self.facts), len(self.g["edges"]))

    def test_known_provenance_is_carried_through(self):
        f = self.facts[("team:platform", "owns", "asset:web-01")]
        self.assertEqual((f["source"], f["confidence"], f["known"]), ("asset ownership record", "declared", True))
        f = self.facts[("inventory/control:1", "protects", "asset:db-01")]
        self.assertEqual((f["source"], f["source_kind"], f["observed_at"], f["confidence"]), ("crowdstrike", "connector", "2026-10-01T00:00:00Z", "observed"))

    def test_a_heuristic_link_says_so(self):
        f = self.facts[("asset:web-01", "reaches", "asset:db-01")]
        self.assertEqual((f["source_kind"], f["confidence"]), ("derived", "heuristic"))
        f = self.facts[("cve:CVE-A", "exploits", "pkg:maven:org.apache.logging.log4j:log4j-core")]
        self.assertEqual(f["confidence"], "heuristic")

    def test_unknown_stays_unknown_and_is_never_invented(self):
        f = self.facts[("ai/system:bot", "invokes", "ai/tool:shell")]       # the AI builder here passes no provenance
        self.assertEqual((f["source"], f["source_kind"], f["observed_at"], f["confidence"]), (None, None, None, None))
        self.assertFalse(f["known"])
        self.assertEqual(f["unknown"], ["source", "source_kind", "observed_at", "confidence"])

    def test_a_partly_known_fact_lists_only_the_gaps(self):
        f = self.facts[("finding:F1", "affects", "asset:web-01")]
        self.assertEqual(f["source"], "tenable")
        self.assertIsNone(f["source_kind"])       # the finding's source is a scanner name, not a statement of how it arrived
        self.assertEqual(f["unknown"], ["source_kind"])

    def test_an_empty_string_counts_as_unknown(self):
        f = provenance.fact_for({"source": "a", "target": "b", "kind": "r", "prov": {"source": "", "confidence": "observed"}})
        self.assertIsNone(f["source"])
        self.assertIn("source", f["unknown"])

    def test_coverage_counts_what_is_known_and_what_is_not(self):
        c = provenance.coverage(list(self.facts.values()))
        self.assertEqual(c["facts"], len(self.g["edges"]))
        self.assertLess(c["with_any"], c["facts"])           # some edges really have nothing recorded
        self.assertGreater(c["with_any"], 0)
        self.assertEqual(c["by_confidence"]["heuristic"], 2)

    def test_problems_names_what_is_wrong(self):
        self.assertEqual(provenance.problems({"source": "x", "confidence": "observed", "source_kind": "scan"}), [])
        self.assertEqual(len(provenance.problems({"source_kind": "rumour", "confidence": "sure", "extra": 1, "source": 3})), 4)
        self.assertEqual(provenance.problems("nope"), ["provenance must be an object"])


if __name__ == "__main__":
    unittest.main()
