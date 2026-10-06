// Deterministic force-directed layout (Fruchterman-Reingold) for the relationship graphs. Pure maths: no DOM, so it runs in Node tests.
//
// Deterministic means the same graph always lands in the same place, so a screenshot, a bug report and a colleague's screen all agree: the start
// positions come from the node order (sorted ids on a golden-angle spiral), never from Math.random. Each disconnected cluster is laid out on its own
// and the clusters are then packed side by side, largest first, so separate clusters never pile on top of one another.

import { build, components } from "./graphTheory.js";

function layoutCluster(ids, edges, iterations) {
  const n = ids.length;
  const pos = new Map();
  if (n === 1) { pos.set(ids[0], { x: 0, y: 0 }); return pos; }
  const side = Math.sqrt(n) * 90 + 60;                   // the area grows with the number of nodes
  const k = Math.sqrt((side * side) / n) * 0.9;          // ideal edge length
  const x = new Float64Array(n), y = new Float64Array(n), dx = new Float64Array(n), dy = new Float64Array(n);
  const at = new Map(ids.map((id, i) => [id, i]));
  const GOLDEN = 2.399963229728653;
  for (let i = 0; i < n; i++) {                           // golden-angle spiral start
    const r = k * Math.sqrt(i + 0.5);
    x[i] = Math.cos(i * GOLDEN) * r; y[i] = Math.sin(i * GOLDEN) * r;
  }
  const links = [];
  for (const e of edges) {
    const a = at.get(e.source), b = at.get(e.target);
    if (a !== undefined && b !== undefined && a !== b) links.push([a, b, Math.min(3, 1 + Math.log2(e.weight || 1))]);
  }
  let temp = side / 8;
  const cool = temp / (iterations + 1);
  for (let it = 0; it < iterations; it++) {
    dx.fill(0); dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {                  // every pair repels
        let ex = x[i] - x[j], ey = y[i] - y[j];
        let d2 = ex * ex + ey * ey;
        if (d2 < 0.01) { ex = (i - j) * 0.1; ey = 0.1; d2 = ex * ex + ey * ey; }
        const f = (k * k) / d2;
        dx[i] += ex * f; dy[i] += ey * f; dx[j] -= ex * f; dy[j] -= ey * f;
      }
    }
    for (const [a, b, w] of links) {                     // linked nodes attract
      const ex = x[a] - x[b], ey = y[a] - y[b];
      const d = Math.sqrt(ex * ex + ey * ey) || 0.01;
      const f = (d / k) * w;
      dx[a] -= ex * f; dy[a] -= ey * f; dx[b] += ex * f; dy[b] += ey * f;
    }
    for (let i = 0; i < n; i++) {                        // gentle pull to the centre, then move by at most the temperature
      dx[i] -= x[i] * 0.02; dy[i] -= y[i] * 0.02;
      const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 0.01;
      const m = Math.min(d, temp);
      x[i] += (dx[i] / d) * m; y[i] += (dy[i] / d) * m;
    }
    temp -= cool;
  }
  ids.forEach((id, i) => pos.set(id, { x: x[i], y: y[i] }));
  return pos;
}

function bounds(pos) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const p of pos.values()) { x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y); }
  return { x0, y0, x1, y1, w: x1 - x0, h: y1 - y0 };
}

// Returns Map id -> {x, y, cluster}. Positions are in an arbitrary plane; the view fits it to the screen.
export function forceLayout(graph, { iterations = 220, gap = 90 } = {}) {
  const g = build(graph);
  const comp = components(graph, g);
  // Nodes with no link at all would each claim a whole cluster slot and string out across the canvas, so they are packed together
  // into one compact grid and treated as a single block (still tagged with their own cluster number).
  const loose = comp.list.filter((ids) => ids.length === 1).map((ids) => ids[0]);
  const linked = comp.list.filter((ids) => ids.length > 1);
  const placed = linked.map((ids) => {
    const members = new Set(ids);
    const pos = layoutCluster(ids, graph.edges.filter((e) => members.has(e.source) && members.has(e.target)), iterations);
    return { pos, box: bounds(pos), loose: false };
  });
  if (loose.length) {
    const cols = Math.ceil(Math.sqrt(loose.length)), step = 46;
    const pos = new Map(loose.map((id, i) => [id, { x: (i % cols) * step, y: Math.floor(i / cols) * step }]));
    placed.push({ pos, box: bounds(pos), loose: true });
  }
  // pack clusters left to right into rows no wider than the widest of (the largest cluster, a square of the total area)
  const totalArea = placed.reduce((s, c) => s + (c.box.w + gap) * (c.box.h + gap), 0);
  const rowWidth = Math.max(placed.length ? placed[0].box.w + gap : 0, Math.sqrt(totalArea) * 1.3);
  const out = new Map();
  let cx = 0, cy = 0, rowH = 0;
  placed.forEach((c, index) => {
    if (cx > 0 && cx + c.box.w > rowWidth) { cx = 0; cy += rowH + gap; rowH = 0; }
    for (const [id, p] of c.pos) out.set(id, { x: p.x - c.box.x0 + cx, y: p.y - c.box.y0 + cy, cluster: c.loose ? comp.of.get(id) : index });
    cx += c.box.w + gap; rowH = Math.max(rowH, c.box.h);
  });
  return out;
}

// The transform that fits a set of positions into a width x height viewport with a margin.
export function fit(positions, width, height, margin = 48) {
  const pts = [...positions.values()];
  if (!pts.length) return { x: 0, y: 0, k: 1 };
  const b = bounds(new Map(pts.map((p, i) => [i, p])));
  const k = Math.min(2.2, Math.max(0.05, Math.min((width - 2 * margin) / (b.w || 1), (height - 2 * margin) / (b.h || 1))));
  return { k, x: (width - b.w * k) / 2 - b.x0 * k, y: (height - b.h * k) / 2 - b.y0 * k };
}
