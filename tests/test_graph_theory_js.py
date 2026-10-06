"""graphTheory.js is pure JavaScript that runs in the browser; these tests run it under Node on graphs whose right answers are known.
Skipped when Node is not installed (the app itself needs no Node: this only tests a browser module)."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

NODE = shutil.which("node")
MODULE = (Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js" / "graphTheory.js").as_uri()


def run_js(body):
    script = f"import * as T from {json.dumps(MODULE)};\nconst G = (ids, edges, directed = true) => ({{directed, nodes: ids.map((id) => ({{id}})), edges: edges.map(([source, target]) => ({{source, target}}))}});\n{body}"
    proc = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class GraphTheoryTests(unittest.TestCase):
    def test_components_largest_first_and_isolated_nodes_counted(self):
        out = run_js("""
          const g = G(["a","b","c","d","e","f"], [["a","b"],["b","c"],["d","e"]]);
          const c = T.components(g);
          console.log(JSON.stringify({list: c.list, of: Object.fromEntries(c.of)}));""")
        self.assertEqual(out["list"], [["a", "b", "c"], ["d", "e"], ["f"]])
        self.assertEqual(out["of"]["a"], 0)
        self.assertEqual(out["of"]["f"], 2)

    def test_shortest_path_undirected_and_directed(self):
        out = run_js("""
          const g = G(["a","b","c","d"], [["a","b"],["b","c"],["d","c"]]);
          console.log(JSON.stringify({u: T.shortestPath(g,"a","d"), d: T.shortestPath(g,"a","d",{directed:true}),
            fwd: T.shortestPath(g,"a","c",{directed:true}), same: T.shortestPath(g,"a","a"), missing: T.shortestPath(g,"a","zz")}));""")
        self.assertEqual(out["u"], ["a", "b", "c", "d"])
        self.assertIsNone(out["d"])          # d points at c, so there is no directed route a -> d
        self.assertEqual(out["fwd"], ["a", "b", "c"])
        self.assertEqual(out["same"], ["a"])
        self.assertIsNone(out["missing"])

    def test_betweenness_is_highest_in_the_middle_of_a_path_and_zero_at_the_ends(self):
        out = run_js("""
          const g = G(["a","b","c","d","e"], [["a","b"],["b","c"],["c","d"],["d","e"]]);
          console.log(JSON.stringify(Object.fromEntries(T.betweenness(g))));""")
        self.assertAlmostEqual(out["a"], 0)
        self.assertAlmostEqual(out["e"], 0)
        self.assertGreater(out["c"], out["b"])
        self.assertAlmostEqual(out["b"], out["d"])

    def test_the_hub_of_a_star_carries_every_path(self):
        out = run_js("""
          const g = G(["hub","a","b","c","d"], [["hub","a"],["hub","b"],["hub","c"],["hub","d"]]);
          console.log(JSON.stringify(Object.fromEntries(T.betweenness(g))));""")
        self.assertAlmostEqual(out["hub"], 1.0)   # every pair of leaves is joined only through the hub
        self.assertAlmostEqual(out["a"], 0)

    def test_betweenness_is_skipped_above_the_node_limit(self):
        out = run_js("""
          const ids = Array.from({length: 30}, (_, i) => "n" + i);
          console.log(JSON.stringify({r: T.betweenness(G(ids, []), {maxNodes: 10})}));""")
        self.assertIsNone(out["r"])

    def test_articulation_points_and_bridges(self):
        out = run_js("""
          // two triangles joined by the path c - x - d: x and c and d are cut points, c-x and x-d are bridges
          const g = G(["a","b","c","x","d","e","f"], [["a","b"],["b","c"],["c","a"],["c","x"],["x","d"],["d","e"],["e","f"],["f","d"]]);
          const r = T.articulation(g);
          console.log(JSON.stringify({points: [...r.points].sort(), bridges: r.bridges}));""")
        self.assertEqual(out["points"], ["c", "d", "x"])
        self.assertEqual(out["bridges"], [["c", "x"], ["d", "x"]])

    def test_a_cycle_has_no_cut_point_and_a_chain_has_every_inner_node(self):
        out = run_js("""
          const ring = T.articulation(G(["a","b","c","d"], [["a","b"],["b","c"],["c","d"],["d","a"]]));
          const chain = T.articulation(G(["a","b","c","d"], [["a","b"],["b","c"],["c","d"]]));
          console.log(JSON.stringify({ring: [...ring.points], chain: [...chain.points].sort()}));""")
        self.assertEqual(out["ring"], [])
        self.assertEqual(out["chain"], ["b", "c"])

    def test_pagerank_sums_to_one_and_favours_the_node_everyone_points_at(self):
        out = run_js("""
          const g = G(["a","b","c","t"], [["a","t"],["b","t"],["c","t"]]);
          const pr = T.pagerank(g);
          console.log(JSON.stringify({sum: [...pr.values()].reduce((x, y) => x + y, 0), t: pr.get("t"), a: pr.get("a")}));""")
        self.assertAlmostEqual(out["sum"], 1.0, places=6)
        self.assertGreater(out["t"], out["a"])

    def test_find_cycle_returns_a_loop_or_null(self):
        out = run_js("""
          const loop = T.findCycle(G(["a","b","c","d"], [["a","b"],["b","c"],["c","a"],["c","d"]]));
          const none = T.findCycle(G(["a","b","c"], [["a","b"],["b","c"]]));
          console.log(JSON.stringify({loop, none}));""")
        self.assertEqual(sorted(out["loop"]), ["a", "b", "c"])
        self.assertIsNone(out["none"])

    def test_analyse_summarises_and_is_deterministic(self):
        out = run_js("""
          const g = G(["a","b","c","d","z"], [["a","b"],["b","c"],["c","d"]]);
          const r1 = T.analyse(g), r2 = T.analyse(g);
          const s = r1.summary;
          console.log(JSON.stringify({s: {nodes: s.nodes, edges: s.edges, components: s.components, largest: s.largest, isolated: s.isolated,
            spofs: s.spofs, hubs: s.hubs.map((x) => x.id), cycle: s.cycle}, same: JSON.stringify(r1.summary) === JSON.stringify(r2.summary)}));""")
        s = out["s"]
        self.assertEqual((s["nodes"], s["edges"], s["components"], s["largest"], s["isolated"]), (5, 3, 2, 4, 1))
        self.assertEqual(s["spofs"], ["b", "c"])
        self.assertIsNone(s["cycle"])
        self.assertTrue(out["same"])

    def test_edges_to_missing_nodes_and_self_loops_are_ignored(self):
        out = run_js("""
          const g = G(["a","b"], [["a","a"],["a","ghost"],["a","b"]]);
          console.log(JSON.stringify({deg: Object.fromEntries(T.degrees(g)), c: T.components(g).list}));""")
        self.assertEqual(out["deg"]["a"], {"in": 0, "out": 1, "total": 1})
        self.assertEqual(out["c"], [["a", "b"]])

    def test_a_graph_of_two_thousand_nodes_does_not_overflow_the_stack(self):
        out = run_js("""
          const ids = Array.from({length: 2000}, (_, i) => "n" + String(i).padStart(4, "0"));
          const edges = ids.slice(1).map((id, i) => [ids[i], id]);   // one long chain
          const g = G(ids, edges);
          console.log(JSON.stringify({c: T.components(g).list.length, a: T.articulation(g).points.size, cyc: T.findCycle(g), p: T.shortestPath(g, ids[0], ids[1999]).length}));""")
        self.assertEqual((out["c"], out["a"], out["cyc"], out["p"]), (1, 1998, None, 2000))


if __name__ == "__main__":
    unittest.main()
