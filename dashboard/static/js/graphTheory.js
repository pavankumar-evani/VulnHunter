// Graph theory for the relationship graphs: pure functions over the node-link shape in remediation/graphs/schema.py
// ({nodes: [{id, ...}], edges: [{source, target, weight?}]}). No DOM, no network, no dependencies, so it runs in the browser and in Node tests.
//
// Everything is iterative (no recursion), so a few thousand nodes cannot overflow the stack, and everything is deterministic: ties
// are broken by node id, so the same graph always gives the same answer.
//
// What each measure is for, in the language of the product:
//   components        separate clusters that share nothing (for the SOC: candidate campaigns; for ownership: islands nobody connects)
//   degree            how many things a node touches (hubs)
//   betweenness       how many shortest paths run through a node (choke points; Brandes' algorithm, undirected)
//   articulation      nodes whose removal splits their cluster (single points of failure) and the bridges between clusters
//   pagerank          importance by who points at you (directed)
//   shortestPath      the fewest-hops route between two nodes (BFS)
//   cycles            whether a directed graph loops back on itself, and one such loop

export function build(graph) {
  const ids = graph.nodes.map((n) => n.id).sort();
  const index = new Map(ids.map((id, i) => [id, i]));
  const n = ids.length;
  const und = Array.from({ length: n }, () => new Set());
  const out = Array.from({ length: n }, () => new Set());
  const inn = Array.from({ length: n }, () => new Set());
  for (const e of graph.edges) {
    const a = index.get(e.source), b = index.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    und[a].add(b); und[b].add(a);
    out[a].add(b); inn[b].add(a);
  }
  const toArr = (sets) => sets.map((s) => [...s].sort((x, y) => x - y));
  return { ids, index, n, und: toArr(und), out: toArr(out), inn: toArr(inn) };
}

export function degrees(graph, g = build(graph)) {
  const res = new Map();
  g.ids.forEach((id, i) => res.set(id, { in: g.inn[i].length, out: g.out[i].length, total: g.und[i].length }));
  return res;
}

// Weakly connected components. Returns {of: Map id -> component number (0 = largest), list: [[id, ...], ...] largest first}.
export function components(graph, g = build(graph)) {
  const seen = new Array(g.n).fill(false);
  const raw = [];
  for (let s = 0; s < g.n; s++) {
    if (seen[s]) continue;
    const members = [];
    const stack = [s];
    seen[s] = true;
    while (stack.length) {
      const v = stack.pop();
      members.push(v);
      for (const w of g.und[v]) if (!seen[w]) { seen[w] = true; stack.push(w); }
    }
    raw.push(members.map((i) => g.ids[i]).sort());
  }
  raw.sort((a, b) => b.length - a.length || (a[0] < b[0] ? -1 : 1));
  const of = new Map();
  raw.forEach((members, c) => members.forEach((id) => of.set(id, c)));
  return { of, list: raw };
}

// Fewest-hops path from one node to another, or null. directed=false ignores edge direction.
export function shortestPath(graph, from, to, { directed = false } = {}, g = build(graph)) {
  const s = g.index.get(from), t = g.index.get(to);
  if (s === undefined || t === undefined) return null;
  if (s === t) return [from];
  const adj = directed ? g.out : g.und;
  const prev = new Array(g.n).fill(-1);
  const seen = new Array(g.n).fill(false);
  seen[s] = true;
  let frontier = [s];
  while (frontier.length) {
    const next = [];
    for (const v of frontier) {
      for (const w of adj[v]) {
        if (seen[w]) continue;
        seen[w] = true; prev[w] = v;
        if (w === t) {
          const path = [];
          for (let x = t; x !== -1; x = prev[x]) path.push(g.ids[x]);
          return path.reverse();
        }
        next.push(w);
      }
    }
    frontier = next;
  }
  return null;
}

// Betweenness centrality (Brandes), undirected, normalised to 0..1. Skipped (returns null) above maxNodes because it is O(V*E).
export function betweenness(graph, { maxNodes = 600 } = {}, g = build(graph)) {
  if (g.n > maxNodes) return null;
  const cb = new Array(g.n).fill(0);
  for (let s = 0; s < g.n; s++) {
    const stack = [];
    const pred = Array.from({ length: g.n }, () => []);
    const sigma = new Array(g.n).fill(0);
    const dist = new Array(g.n).fill(-1);
    sigma[s] = 1; dist[s] = 0;
    const queue = [s];
    for (let qi = 0; qi < queue.length; qi++) {
      const v = queue[qi];
      stack.push(v);
      for (const w of g.und[v]) {
        if (dist[w] < 0) { dist[w] = dist[v] + 1; queue.push(w); }
        if (dist[w] === dist[v] + 1) { sigma[w] += sigma[v]; pred[w].push(v); }
      }
    }
    const delta = new Array(g.n).fill(0);
    while (stack.length) {
      const w = stack.pop();
      for (const v of pred[w]) delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w]);
      if (w !== s) cb[w] += delta[w];
    }
  }
  const norm = g.n > 2 ? 1 / ((g.n - 1) * (g.n - 2)) : 1;   // undirected pairs are counted twice, which this absorbs
  const res = new Map();
  g.ids.forEach((id, i) => res.set(id, cb[i] * norm));
  return res;
}

// Articulation points (single points of failure) and bridges, undirected (iterative Tarjan).
export function articulation(graph, g = build(graph)) {
  const disc = new Array(g.n).fill(-1), low = new Array(g.n).fill(0), parent = new Array(g.n).fill(-1);
  const cut = new Set();
  const bridges = [];
  let time = 0;
  for (let root = 0; root < g.n; root++) {
    if (disc[root] !== -1) continue;
    let rootChildren = 0;
    const stack = [[root, 0]];
    disc[root] = low[root] = time++;
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const v = frame[0];
      if (frame[1] < g.und[v].length) {
        const w = g.und[v][frame[1]++];
        if (disc[w] === -1) {
          parent[w] = v;
          disc[w] = low[w] = time++;
          if (v === root) rootChildren++;
          stack.push([w, 0]);
        } else if (w !== parent[v]) {
          low[v] = Math.min(low[v], disc[w]);
        }
      } else {
        stack.pop();
        const p = parent[v];
        if (p !== -1) {
          low[p] = Math.min(low[p], low[v]);
          if (p !== root && low[v] >= disc[p]) cut.add(p);
          if (low[v] > disc[p]) bridges.push([g.ids[p], g.ids[v]].sort());
        }
      }
    }
    if (rootChildren > 1) cut.add(root);
  }
  bridges.sort((a, b) => (a[0] + a[1] < b[0] + b[1] ? -1 : 1));
  return { points: new Set([...cut].map((i) => g.ids[i])), bridges };
}

// PageRank on the directed graph; dangling nodes spread their rank evenly.
export function pagerank(graph, { damping = 0.85, iterations = 60 } = {}, g = build(graph)) {
  const n = g.n;
  if (!n) return new Map();
  let rank = new Array(n).fill(1 / n);
  for (let it = 0; it < iterations; it++) {
    const next = new Array(n).fill((1 - damping) / n);
    let dangling = 0;
    for (let v = 0; v < n; v++) {
      if (!g.out[v].length) { dangling += rank[v]; continue; }
      const share = (damping * rank[v]) / g.out[v].length;
      for (const w of g.out[v]) next[w] += share;
    }
    const spread = (damping * dangling) / n;
    for (let v = 0; v < n; v++) next[v] += spread;
    rank = next;
  }
  const res = new Map();
  g.ids.forEach((id, i) => res.set(id, rank[i]));
  return res;
}

// A directed cycle if there is one: the node ids in order, or null.
export function findCycle(graph, g = build(graph)) {
  const color = new Array(g.n).fill(0);   // 0 new, 1 on the current path, 2 done
  const parent = new Array(g.n).fill(-1);
  for (let s = 0; s < g.n; s++) {
    if (color[s]) continue;
    const stack = [[s, 0]];
    color[s] = 1;
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const v = frame[0];
      if (frame[1] < g.out[v].length) {
        const w = g.out[v][frame[1]++];
        if (color[w] === 0) { color[w] = 1; parent[w] = v; stack.push([w, 0]); }
        else if (color[w] === 1) {
          const cycle = [g.ids[w]];
          for (let x = v; x !== w && x !== -1; x = parent[x]) cycle.push(g.ids[x]);
          return cycle.reverse();
        }
      } else { color[v] = 2; stack.pop(); }
    }
  }
  return null;
}

// Everything the side panel and the summary strip need, computed once.
export function analyse(graph) {
  const g = build(graph);
  const deg = degrees(graph, g);
  const comp = components(graph, g);
  const art = articulation(graph, g);
  const btw = betweenness(graph, {}, g);
  const pr = pagerank(graph, {}, g);
  const nodes = g.ids.map((id) => ({ id, ...deg.get(id), component: comp.of.get(id), betweenness: btw ? btw.get(id) : null, pagerank: pr.get(id), spof: art.points.has(id) }));
  const byId = new Map(nodes.map((x) => [x.id, x]));
  const top = (key, k = 5) => [...nodes].filter((x) => x[key] !== null && x[key] > 0).sort((a, b) => b[key] - a[key] || (a.id < b.id ? -1 : 1)).slice(0, k);
  const edgeCount = graph.edges.length;
  return {
    byId, g, components: comp, articulation: art,
    summary: {
      nodes: g.n, edges: edgeCount, components: comp.list.length, largest: comp.list.length ? comp.list[0].length : 0,
      isolated: comp.list.filter((c) => c.length === 1).length,
      density: g.n > 1 ? edgeCount / (g.n * (g.n - 1) / (graph.directed === false ? 2 : 1)) : 0,
      avgDegree: g.n ? (2 * edgeCount) / g.n : 0,
      hubs: top("total"), chokepoints: top("betweenness"), important: top("pagerank"),
      spofs: [...art.points].sort(), bridges: art.bridges, cycle: findCycle(graph, g), betweennessSkipped: btw === null,
    },
  };
}
