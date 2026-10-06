"""graphLayout.js under Node: the layout must be deterministic, finite, and keep clusters apart and linked nodes close."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

NODE = shutil.which("node")
JS = Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js"


def run_js(body):
    script = (f"import * as L from {json.dumps((JS / 'graphLayout.js').as_uri())};\n"
              "const G = (ids, edges) => ({directed: true, nodes: ids.map((id) => ({id})), edges: edges.map(([source, target]) => ({source, target}))});\n"
              "const dist = (p, q) => Math.hypot(p.x - q.x, p.y - q.y);\n" + body)
    proc = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class LayoutTests(unittest.TestCase):
    def test_the_same_graph_always_lands_in_the_same_place(self):
        out = run_js("""
          const g = G(["a","b","c","d","e"], [["a","b"],["b","c"],["c","d"],["d","e"],["e","a"]]);
          const a = JSON.stringify([...L.forceLayout(g)]), b = JSON.stringify([...L.forceLayout(g)]);
          console.log(JSON.stringify({same: a === b}));""")
        self.assertTrue(out["same"])

    def test_every_position_is_a_finite_number_even_for_awkward_graphs(self):
        out = run_js("""
          const g = G(["a","b","c","d"], [["a","b"],["a","b"],["a","a"]]);
          const bad = [...L.forceLayout(g).values()].filter((p) => !Number.isFinite(p.x) || !Number.isFinite(p.y)).length;
          const empty = L.forceLayout(G([], [])).size;
          const single = [...L.forceLayout(G(["only"], [])).values()];
          console.log(JSON.stringify({bad, empty, single}));""")
        self.assertEqual((out["bad"], out["empty"]), (0, 0))
        self.assertEqual(len(out["single"]), 1)

    def test_linked_nodes_end_up_closer_than_unlinked_ones(self):
        out = run_js("""
          const ids = ["a","b","c","d","e","f","g","h"];
          const g = G(ids, [["a","b"],["b","c"],["c","d"],["d","a"],["e","f"],["f","g"],["g","h"],["h","e"]]);
          const p = L.forceLayout(g);
          const near = (dist(p.get("a"), p.get("b")) + dist(p.get("e"), p.get("f"))) / 2;
          const far = (dist(p.get("a"), p.get("e")) + dist(p.get("b"), p.get("g"))) / 2;
          console.log(JSON.stringify({near, far}));""")
        self.assertLess(out["near"], out["far"])

    def test_separate_clusters_do_not_overlap(self):
        out = run_js("""
          const g = G(["a","b","c","d","e","f"], [["a","b"],["b","c"],["d","e"],["e","f"]]);
          const p = L.forceLayout(g);
          const box = (ids) => { const xs = ids.map((i) => p.get(i).x), ys = ids.map((i) => p.get(i).y);
            return {x0: Math.min(...xs), x1: Math.max(...xs), y0: Math.min(...ys), y1: Math.max(...ys)}; };
          const A = box(["a","b","c"]), B = box(["d","e","f"]);
          const overlap = A.x0 < B.x1 && B.x0 < A.x1 && A.y0 < B.y1 && B.y0 < A.y1;
          console.log(JSON.stringify({overlap, clusters: [p.get("a").cluster, p.get("d").cluster]}));""")
        self.assertFalse(out["overlap"])
        self.assertNotEqual(out["clusters"][0], out["clusters"][1])

    def test_unlinked_nodes_are_packed_into_one_compact_block(self):
        out = run_js("""
          const ids = Array.from({length: 16}, (_, i) => "iso" + String(i).padStart(2, "0"));
          const linked = G(["a","b","c"], [["a","b"],["b","c"]]);
          const g = G([...ids, "a", "b", "c"], [["a","b"],["b","c"]]);
          const p = L.forceLayout(g);
          const xs = ids.map((i) => p.get(i).x), ys = ids.map((i) => p.get(i).y);
          const w = Math.max(...xs) - Math.min(...xs), h = Math.max(...ys) - Math.min(...ys);
          console.log(JSON.stringify({w, h, clusters: new Set(ids.map((i) => p.get(i).cluster)).size}));""")
        self.assertLess(out["w"], 46 * 4)       # a 4 x 4 grid, not sixteen slots strung across the canvas
        self.assertLess(out["h"], 46 * 4)
        self.assertEqual(out["clusters"], 16)   # each is still its own cluster for colouring

    def test_fit_puts_every_node_inside_the_viewport(self):
        out = run_js("""
          const g = G(["a","b","c","d","e","f"], [["a","b"],["b","c"],["d","e"]]);
          const p = L.forceLayout(g), t = L.fit(p, 800, 500);
          const inside = [...p.values()].every((q) => { const x = q.x * t.k + t.x, y = q.y * t.k + t.y; return x >= 0 && x <= 800 && y >= 0 && y <= 500; });
          console.log(JSON.stringify({inside, k: t.k}));""")
        self.assertTrue(out["inside"])
        self.assertGreater(out["k"], 0)

    def test_four_hundred_nodes_lay_out_in_a_few_seconds(self):
        out = run_js("""
          const ids = Array.from({length: 400}, (_, i) => "n" + String(i).padStart(3, "0"));
          const edges = ids.slice(1).map((id, i) => [ids[Math.floor(i / 3)], id]);   // a wide tree
          const t0 = Date.now(); const p = L.forceLayout(G(ids, edges));
          console.log(JSON.stringify({ms: Date.now() - t0, n: p.size}));""")
        self.assertEqual(out["n"], 400)
        self.assertLess(out["ms"], 8000)


if __name__ == "__main__":
    unittest.main()
