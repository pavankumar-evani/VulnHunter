import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation import graphs
from remediation.graphs.schema import GraphBuilder, empty


class BuilderTests(unittest.TestCase):
    def make(self):
        g = GraphBuilder("soc", "T", "D")
        g.kind("host", "Host")
        g.node("h1", "web-01", "host", sev="low")
        g.node("h1", "web-01", "host", sev="critical", weight=2, meta={"a": 1})
        g.node("t1", "T1190", "technique")
        return g

    def test_nodes_merge_weights_and_keep_the_worst_severity(self):
        out = self.make().build()
        h = next(n for n in out["nodes"] if n["id"] == "h1")
        self.assertEqual((h["weight"], h["sev"], h["meta"]), (3, "critical", {"a": 1}))

    def test_repeated_edges_add_up_and_self_loops_and_dangling_edges_are_dropped(self):
        g = self.make()
        g.edge("h1", "t1", "exposes")
        g.edge("h1", "t1", "exposes")
        g.edge("h1", "h1", "loop")
        g.edge("h1", "missing", "dangling")
        out = g.build()
        self.assertEqual([(e["source"], e["target"], e["weight"]) for e in out["edges"]], [("h1", "t1", 2)])

    def test_output_is_deterministic_and_lists_only_kinds_in_use(self):
        a = self.make()
        a.edge("h1", "t1", "exposes")
        b = self.make()
        b.edge("h1", "t1", "exposes")
        self.assertEqual(a.build(), b.build())
        self.assertEqual(sorted(a.build()["kinds"]), ["exposes", "host", "technique"])
        self.assertEqual(a.build()["kinds"]["technique"]["label"], "Technique")

    def test_a_large_graph_is_capped_to_the_best_connected_nodes_and_says_so(self):
        g = GraphBuilder("soc", "T", "D")
        g.node("hub", "hub", "host")
        for i in range(30):
            g.node(f"n{i}", f"n{i}", "host")
            g.edge("hub", f"n{i}", "link")
        out = g.build(limit=10)
        self.assertTrue(out["truncated"])
        self.assertEqual(len(out["nodes"]), 10)
        self.assertIn("hub", {n["id"] for n in out["nodes"]})
        self.assertEqual(out["totals"], {"nodes": 31, "edges": 30})
        self.assertIn("best-connected", out["note"])

    def test_an_empty_graph_carries_the_note(self):
        out = empty("soc", "T", "D", "Nothing recorded yet.")
        self.assertEqual((out["nodes"], out["edges"], out["note"]), ([], [], "Nothing recorded yet."))

    def test_unknown_module_is_refused(self):
        with self.assertRaises(KeyError):
            graphs.build("nope")


if __name__ == "__main__":
    unittest.main()
