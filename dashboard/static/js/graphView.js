// Interactive relationship graph, drawn as plain SVG (no library, no build step). One component for every module: the data comes from
// GET /api/graphs/<module> in the shape of remediation/graphs/schema.py, the layout from graphLayout.js and the graph theory from graphTheory.js.
//
// What a person can do: drag the background to pan, scroll or pinch to zoom, drag a node to move it, click a node for its facts and its place in the
// graph (connections, choke-point score, cluster, whether it is a single point of failure), pick two nodes to see the shortest route between them,
// focus on one node's neighbourhood, hide kinds, colour by kind, cluster or severity, size by weight, connections or choke-point score, search, switch
// to a table (the accessible alternative), and download the graph as JSON or SVG. Arrow keys pan and + / - zoom when the graph has focus.
import { escapeHtml } from "./dom.js";
import { analyse, shortestPath } from "./graphTheory.js";
import { forceLayout, fit } from "./graphLayout.js";

const PALETTE = ["#6d97f7", "#3fd0b6", "#f0a35c", "#b48cf2", "#e8cf6a", "#f06a9a", "#5ec7e8", "#9bd45c", "#d98f6a", "#8e9bc0"];
const SEV = { critical: "#f06a6a", high: "#f0a35c", medium: "#e8cf6a", low: "#6d97f7", info: "#8e9bc0" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const trunc = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const pct = (x) => (x === null || x === undefined ? "n/a" : (x * 100).toFixed(x < 0.01 && x > 0 ? 2 : 0) + "%");

export function renderGraphView(host, graph, opts = {}) {
  const navigate = opts.navigate || ((href) => { window.location.assign(href); });
  if (!graph.nodes.length) {
    host.innerHTML = `<div class="gv"><p class="gv-empty">${escapeHtml(graph.note || "Nothing is recorded for this graph yet.")}</p></div>`;
    return { destroy() {} };
  }

  const A = analyse(graph);
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const kindKeys = Object.keys(graph.kinds || {}).filter((k) => graph.nodes.some((n) => n.kind === k));
  const kindColor = new Map(kindKeys.map((k, i) => [k, PALETTE[i % PALETTE.length]]));
  const clusterColor = (c) => PALETTE[c % PALETTE.length];
  const maxWeight = Math.max(1, ...graph.nodes.map((n) => n.weight || 1));
  const maxBtw = Math.max(1e-9, ...A.g.ids.map((id) => A.byId.get(id).betweenness || 0));
  const maxDeg = Math.max(1, ...A.g.ids.map((id) => A.byId.get(id).total));
  const neighbours = new Map(A.g.ids.map((id, i) => [id, A.g.und[i].map((j) => A.g.ids[j])]));
  const important = new Set([...A.summary.hubs, ...A.summary.chokepoints].map((x) => x.id));

  const pos = forceLayout(graph);
  const S = { sizeBy: "weight", colorBy: "kind", labels: "auto", hidden: new Set(), selected: null, pathFrom: null, path: null, focus: 0, query: "", spof: false, table: false, hl: { nodes: new Set(), edges: new Set() }, view: { x: 0, y: 0, k: 1 }, touched: false };

  host.innerHTML = `<div class="dg gv">
    <div class="gv-summary" data-gv="summary"></div>
    <div class="gv-bar">
      <input type="search" data-gv="search" placeholder="Find a node" aria-label="Find a node">
      <label>Colour <select data-gv="colorBy"><option value="kind">by kind</option><option value="cluster">by cluster</option><option value="severity">by severity</option></select></label>
      <label>Size <select data-gv="sizeBy"><option value="weight">by weight</option><option value="connections">by connections</option><option value="chokepoint">by choke point</option></select></label>
      <label>Labels <select data-gv="labels"><option value="auto">auto</option><option value="all">all</option><option value="none">none</option></select></label>
      <label class="gv-check"><input type="checkbox" data-gv="spof"> Single points of failure</label>
      <span class="gv-spacer"></span>
      <button type="button" class="secondary-button" data-gv="zoom-in" aria-label="Zoom in">+</button>
      <button type="button" class="secondary-button" data-gv="zoom-out" aria-label="Zoom out">&minus;</button>
      <button type="button" class="secondary-button" data-gv="fit">Fit</button>
      <button type="button" class="secondary-button" data-gv="table">Table</button>
      <button type="button" class="secondary-button" data-gv="json">JSON</button>
      <button type="button" class="secondary-button" data-gv="svg">SVG</button>
    </div>
    <div class="gv-kinds" data-gv="kinds" role="group" aria-label="Show or hide kinds"></div>
    <div class="gv-main">
      <div class="gv-stage" data-gv="stage"><svg class="gv-svg" role="application" aria-label="${escapeHtml(graph.title || "Relationship graph")}. Arrow keys pan, plus and minus zoom." tabindex="0"><defs><marker id="gv-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#5d6e9f"/></marker></defs><g data-gv="world"></g></svg><div class="gv-tablewrap" data-gv="tablewrap" hidden></div></div>
      <aside class="gv-panel" data-gv="panel" aria-live="polite"></aside>
    </div>
    <p class="gv-foot">${escapeHtml(graph.description || "")}${graph.note ? " " + escapeHtml(graph.note) : ""}</p></div>`;

  const q = (name) => host.querySelector(`[data-gv="${name}"]`);
  const svg = host.querySelector(".gv-svg"), world = q("world"), stage = q("stage"), panel = q("panel"), tablewrap = q("tablewrap");

  // ---------------------------------------------------------------- measures
  const radius = (n) => {
    const a = A.byId.get(n.id);
    if (S.sizeBy === "connections") return 7 + 14 * Math.sqrt(a.total / maxDeg);
    if (S.sizeBy === "chokepoint") return 7 + 16 * Math.pow((a.betweenness || 0) / maxBtw, 0.6);
    return 8 + 13 * Math.sqrt((n.weight || 1) / maxWeight);
  };
  const fill = (n) => {
    if (S.colorBy === "cluster") return clusterColor(A.byId.get(n.id).component);
    if (S.colorBy === "severity") return n.sev ? SEV[n.sev] : "#3b4b7a";
    return kindColor.get(n.kind) || "#8e9bc0";
  };
  const visibleSet = () => {
    let vis = new Set(graph.nodes.filter((n) => !S.hidden.has(n.kind)).map((n) => n.id));
    if (S.selected && S.focus) {
      const keep = new Set([S.selected]);
      let frontier = [S.selected];
      for (let h = 0; h < S.focus; h++) {
        const next = [];
        for (const id of frontier) for (const w of neighbours.get(id) || []) if (!keep.has(w)) { keep.add(w); next.push(w); }
        frontier = next;
      }
      vis = new Set([...vis].filter((id) => keep.has(id)));
    }
    return vis;
  };

  // ---------------------------------------------------------------- drawing
  function stageSize() { const r = stage.getBoundingClientRect(); return { w: Math.max(240, r.width), h: Math.max(240, r.height) }; }
  function applyView() { world.setAttribute("transform", `translate(${S.view.x},${S.view.y}) scale(${S.view.k})`); }
  function fitView() { const s = stageSize(); S.view = fit(pos, s.w, s.h); applyView(); }

  function draw() {
    const vis = visibleSet();
    const hit = (n) => S.query && (n.label.toLowerCase().includes(S.query) || n.id.toLowerCase().includes(S.query));
    const onPath = new Set([...(S.path || []), ...S.hl.nodes]);
    const pathEdges = new Set();
    if (S.path) for (let i = 0; i + 1 < S.path.length; i++) { pathEdges.add(S.path[i] + "\u0000" + S.path[i + 1]); pathEdges.add(S.path[i + 1] + "\u0000" + S.path[i]); }
    const near = S.selected ? new Set([S.selected, ...(neighbours.get(S.selected) || [])]) : null;
    let out = "";
    for (const e of graph.edges) {
      if (!vis.has(e.source) || !vis.has(e.target)) continue;
      const a = pos.get(e.source), b = pos.get(e.target);
      if (!a || !b) continue;
      const on = pathEdges.has(e.source + "\u0000" + e.target) || S.hl.edges.has(e.source + "\u0000" + e.target);
      const dim = near && !(near.has(e.source) && near.has(e.target)) && !on;
      const bridge = A.summary.bridges.some((p) => (p[0] === e.source && p[1] === e.target) || (p[1] === e.source && p[0] === e.target));
      const stroke = on ? "#ffffff" : S.spof && bridge ? "#f06a6a" : "#3a4a78";
      const sw = on ? 3 : Math.min(3.2, 1.1 + Math.log2(e.weight || 1) * 0.5);
      out += `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="${stroke}" stroke-width="${sw}" stroke-opacity="${dim ? 0.12 : on ? 1 : 0.7}"${graph.directed !== false ? ' marker-end="url(#gv-arrow)"' : ""}><title>${escapeHtml((nodeById.get(e.source)?.label || "") + " → " + (nodeById.get(e.target)?.label || "") + " (" + (graph.kinds?.[e.kind]?.label || e.kind) + ")")}</title></line>`;
    }
    const many = vis.size > 120;
    for (const n of graph.nodes) {
      if (!vis.has(n.id)) continue;
      const p = pos.get(n.id);
      const r = radius(n), a = A.byId.get(n.id);
      const sel = S.selected === n.id, isHit = hit(n);
      const dim = (near && !near.has(n.id) && !onPath.has(n.id)) || (S.query && !isHit && !sel);
      const ring = sel || onPath.has(n.id) ? "#ffffff" : isHit ? "#ffffff" : S.spof && a.spof ? "#f06a6a" : n.sev && S.colorBy !== "severity" ? SEV[n.sev] : "#0a0e1a";
      const rw = sel || onPath.has(n.id) || isHit ? 3 : S.spof && a.spof ? 3 : n.sev && S.colorBy !== "severity" ? 2.5 : 1.5;
      const showLabel = S.labels === "all" || sel || isHit || onPath.has(n.id) || (S.labels === "auto" && (S.view.k >= 1 || important.has(n.id)) && !(many && S.view.k < 0.7 && !important.has(n.id)));
      const fs = Math.min(26, Math.max(11, 12 / S.view.k));   // labels keep a readable size on screen whatever the zoom
      out += `<g class="gv-node${sel ? " gv-selected" : ""}" data-id="${escapeHtml(n.id)}" opacity="${dim ? 0.18 : 1}" ${many ? "" : 'tabindex="0" role="button"'} aria-label="${escapeHtml(n.label + ", " + (graph.kinds?.[n.kind]?.label || n.kind) + ", " + a.total + " connections")}">`
        + `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r.toFixed(1)}" fill="${fill(n)}" stroke="${ring}" stroke-width="${rw}"/>`
        + (showLabel ? `<text x="${p.x.toFixed(1)}" y="${(p.y + r + fs).toFixed(1)}" text-anchor="middle" font-size="${fs.toFixed(1)}" font-family="Chakra Petch, sans-serif" fill="#dbe2f7" paint-order="stroke" stroke="#0a0e1a" stroke-width="${(fs / 3.5).toFixed(1)}">${escapeHtml(trunc(n.label, 26))}</text>` : "")
        + `<title>${escapeHtml(n.label + " (" + (graph.kinds?.[n.kind]?.label || n.kind) + ")")}</title></g>`;
    }
    world.innerHTML = out;
    drawKinds();
  }

  function drawKinds() {
    q("kinds").innerHTML = kindKeys.map((k) => {
      const count = graph.nodes.filter((n) => n.kind === k).length;
      return `<button type="button" class="gv-kind${S.hidden.has(k) ? " gv-off" : ""}" data-kind="${escapeHtml(k)}" aria-pressed="${!S.hidden.has(k)}"><i style="background:${kindColor.get(k)}"></i>${escapeHtml(graph.kinds[k]?.label || k)} <b>${count}</b></button>`;
    }).join("") + (S.colorBy === "severity" ? SEV_ORDER.map((s) => `<span class="gv-sev"><i style="background:${SEV[s]}"></i>${s}</span>`).join("") : "");
  }

  function drawSummary() {
    const s = A.summary;
    const chip = (label, value, hint) => `<div class="gv-stat" title="${escapeHtml(hint || "")}"><span>${escapeHtml(label)}</span><b>${value}</b></div>`;
    q("summary").innerHTML = chip("Nodes", s.nodes) + chip("Links", s.edges) + chip("Clusters", s.components, "Parts of the graph that share nothing with each other") + chip("Largest cluster", s.largest) + chip("Isolated", s.isolated, "Nodes with no link at all")
      + chip("Single points of failure", s.spofs.length, "Nodes whose removal splits their cluster") + chip("Loop", s.cycle ? "yes" : "no", "Whether the directed links loop back on themselves");
  }

  function link(id) { const n = nodeById.get(id); return `<button type="button" class="link-button" data-pick="${escapeHtml(id)}">${escapeHtml(trunc(n ? n.label : id, 34))}</button>`; }

  function drawPanel() {
    const s = A.summary;
    if (!S.selected) {
      const list = (items, key, fmt) => items.length ? `<ol class="gv-list">${items.map((x) => `<li>${link(x.id)} <span class="muted">${fmt(x)}</span></li>`).join("")}</ol>` : `<p class="muted">None.</p>`;
      panel.innerHTML = `<h3>What the structure says</h3><p class="muted">Select a node for its facts, or pick one of these.</p>
        <h4>Most connected</h4>${list(s.hubs, "total", (x) => x.total + " links")}
        <h4>Choke points</h4>${s.betweennessSkipped ? '<p class="muted">Not computed: the graph is too large for it.</p>' : list(s.chokepoints, "betweenness", (x) => "carries " + pct(x.betweenness) + " of paths")}
        <h4>Single points of failure</h4>${s.spofs.length ? `<ol class="gv-list">${s.spofs.slice(0, 8).map((id) => `<li>${link(id)}</li>`).join("")}</ol>${s.spofs.length > 8 ? `<p class="muted">and ${s.spofs.length - 8} more</p>` : ""}` : '<p class="muted">None: no single node splits a cluster.</p>'}
        <h4>Clusters</h4><p class="muted">${s.components} cluster${s.components === 1 ? "" : "s"}; the largest holds ${s.largest} of ${s.nodes} nodes.${s.isolated ? ` ${s.isolated} node${s.isolated === 1 ? " is" : "s are"} not linked to anything.` : ""}</p>
        ${s.cycle ? `<h4>Loop</h4><p class="muted">The directed links loop: ${s.cycle.map((id) => escapeHtml(trunc(nodeById.get(id)?.label || id, 18))).join(" → ")} → …</p>` : ""}`;
      return;
    }
    const n = nodeById.get(S.selected), a = A.byId.get(n.id);
    const meta = Object.entries(n.meta || {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
    const compSize = A.components.list[a.component].length;
    const nb = neighbours.get(n.id) || [];
    panel.innerHTML = `<h3>${escapeHtml(n.label)}</h3>
      <p class="muted">${escapeHtml(graph.kinds?.[n.kind]?.label || n.kind)}${n.sev ? ` · <span class="gv-sevtag" style="color:${SEV[n.sev]}">${escapeHtml(n.sev)}</span>` : ""}</p>
      ${n.href ? `<p><button type="button" class="link-button" data-go="${escapeHtml(n.href)}">Open the page for this</button></p>` : ""}
      <dl class="gv-dl"><dt>Links</dt><dd>${a.total} (${a.in} in, ${a.out} out)</dd><dt>Weight</dt><dd>${n.weight}</dd>
        <dt>Choke point</dt><dd>${a.betweenness === null ? "n/a" : pct(a.betweenness) + " of paths"}</dd><dt>Importance</dt><dd>${pct(a.pagerank)}</dd>
        <dt>Cluster</dt><dd>${a.component + 1} of ${s.components} (${compSize} node${compSize === 1 ? "" : "s"})</dd>
        <dt>Single point of failure</dt><dd>${a.spof ? '<b style="color:#f06a6a">yes: removing it splits its cluster</b>' : "no"}</dd>
        ${meta.map(([k, v]) => `<dt>${escapeHtml(k.replace(/_/g, " "))}</dt><dd>${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</dd>`).join("")}</dl>
      <div class="gv-actions">
        <button type="button" class="secondary-button" data-act="focus1">Neighbours</button>
        <button type="button" class="secondary-button" data-act="focus2">Two hops</button>
        <button type="button" class="secondary-button" data-act="all"${S.focus ? "" : " disabled"}>Show all</button>
        <button type="button" class="secondary-button" data-act="path-from">${S.pathFrom === n.id ? "Cancel route" : "Route from here…"}</button></div>
      ${S.pathFrom && S.pathFrom !== n.id ? `<p class="muted">Route from ${escapeHtml(nodeById.get(S.pathFrom)?.label || "")} to here:</p>` : ""}
      ${S.path ? `<p class="gv-route">${S.path.map((id) => link(id)).join(" → ")}</p><p class="muted">${S.path.length - 1} hop${S.path.length === 2 ? "" : "s"}</p>` : S.pathFrom && S.pathFrom !== n.id ? '<p class="muted">No route connects them.</p>' : ""}
      <h4>Linked to (${nb.length})</h4>${nb.length ? `<ul class="gv-list">${nb.slice(0, 14).map((id) => `<li>${link(id)} <span class="muted">${escapeHtml(graph.kinds?.[nodeById.get(id)?.kind]?.label || "")}</span></li>`).join("")}</ul>${nb.length > 14 ? `<p class="muted">and ${nb.length - 14} more</p>` : ""}` : '<p class="muted">Nothing: this node is on its own.</p>'}
      <p><button type="button" class="link-button" data-act="clear">Clear selection</button></p>`;
  }

  function drawTable() {
    const rows = [...graph.nodes].sort((x, y) => (A.byId.get(y.id).betweenness || 0) - (A.byId.get(x.id).betweenness || 0) || A.byId.get(y.id).total - A.byId.get(x.id).total || (x.id < y.id ? -1 : 1));
    tablewrap.innerHTML = `<table class="data-table gv-table"><thead><tr><th>Node</th><th>Kind</th><th>Severity</th><th>Links</th><th>Choke point</th><th>Cluster</th><th>SPOF</th></tr></thead><tbody>${rows.map((n) => {
      const a = A.byId.get(n.id);
      return `<tr data-pick="${escapeHtml(n.id)}" tabindex="0"><td>${escapeHtml(trunc(n.label, 48))}</td><td>${escapeHtml(graph.kinds?.[n.kind]?.label || n.kind)}</td><td>${escapeHtml(n.sev || "")}</td><td>${a.total}</td><td>${a.betweenness === null ? "n/a" : pct(a.betweenness)}</td><td>${a.component + 1}</td><td>${a.spof ? "yes" : ""}</td></tr>`;
    }).join("")}</tbody></table>`;
  }

  function select(id, { center = false } = {}) {
    S.selected = id;
    if (!id) { S.focus = 0; S.path = null; S.pathFrom = null; }
    else if (S.pathFrom && S.pathFrom !== id) S.path = shortestPath(graph, S.pathFrom, id, { directed: false }, A.g);
    else S.path = null;
    if (id && center && pos.get(id)) { const s = stageSize(), p = pos.get(id); S.view.x = s.w / 2 - p.x * S.view.k; S.view.y = s.h / 2 - p.y * S.view.k; applyView(); }
    draw(); drawPanel();
  }

  // ---------------------------------------------------------------- interaction
  const pointers = new Map();
  let drag = null, pinch = null;
  const toWorld = (cx, cy) => { const r = svg.getBoundingClientRect(); return { x: (cx - r.left - S.view.x) / S.view.k, y: (cy - r.top - S.view.y) / S.view.k }; };
  function zoomAt(factor, cx, cy) {
    const r = svg.getBoundingClientRect();
    const px = cx === undefined ? r.width / 2 : cx - r.left, py = cy === undefined ? r.height / 2 : cy - r.top;
    const k = Math.min(4, Math.max(0.05, S.view.k * factor));
    S.view.x = px - ((px - S.view.x) / S.view.k) * k; S.view.y = py - ((py - S.view.y) / S.view.k) * k; S.view.k = k;
    S.touched = true; applyView(); draw();
  }

  svg.addEventListener("pointerdown", (ev) => {
    pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* a pointer that is not active (some browsers, synthetic events): dragging still works without capture */ }
    if (pointers.size === 2) { const [a, b] = [...pointers.values()]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) }; drag = null; return; }
    const g = ev.target.closest?.(".gv-node");
    drag = { node: g ? g.getAttribute("data-id") : null, sx: ev.clientX, sy: ev.clientY, vx: S.view.x, vy: S.view.y, moved: false };
    if (drag.node) { const p = pos.get(drag.node), w = toWorld(ev.clientX, ev.clientY); drag.ox = p.x - w.x; drag.oy = p.y - w.y; }
  });
  svg.addEventListener("pointermove", (ev) => {
    if (pointers.has(ev.pointerId)) pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (pinch && pointers.size === 2) {
      const [a, b] = [...pointers.values()], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch.d) zoomAt(d / pinch.d, (a.x + b.x) / 2, (a.y + b.y) / 2);
      pinch.d = d; return;
    }
    if (!drag) return;
    const dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    drag.moved = true; S.touched = true;
    if (drag.node) { const w = toWorld(ev.clientX, ev.clientY); pos.set(drag.node, { ...pos.get(drag.node), x: w.x + drag.ox, y: w.y + drag.oy }); draw(); }
    else { S.view.x = drag.vx + dx; S.view.y = drag.vy + dy; applyView(); stage.classList.add("gv-grab"); }
  });
  const end = (ev) => {
    pointers.delete(ev.pointerId);
    if (pointers.size < 2) pinch = null;
    stage.classList.remove("gv-grab");
    if (drag && !drag.moved) select(drag.node && drag.node !== S.selected ? drag.node : drag.node ? S.selected : null);
    drag = null;
  };
  svg.addEventListener("pointerup", end);
  svg.addEventListener("pointercancel", end);
  svg.addEventListener("wheel", (ev) => { ev.preventDefault(); zoomAt(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX, ev.clientY); }, { passive: false });
  svg.addEventListener("keydown", (ev) => {
    const step = 60;
    if (ev.key === "ArrowLeft") S.view.x += step; else if (ev.key === "ArrowRight") S.view.x -= step; else if (ev.key === "ArrowUp") S.view.y += step; else if (ev.key === "ArrowDown") S.view.y -= step;
    else if (ev.key === "+" || ev.key === "=") { zoomAt(1.2); return; } else if (ev.key === "-") { zoomAt(1 / 1.2); return; }
    else if (ev.key === "Escape") { select(null); return; }
    else if ((ev.key === "Enter" || ev.key === " ") && ev.target.closest?.(".gv-node")) { select(ev.target.closest(".gv-node").getAttribute("data-id")); ev.preventDefault(); return; }
    else return;
    ev.preventDefault(); S.touched = true; applyView();
  });

  const bind = (name, evt, fn) => q(name).addEventListener(evt, fn);
  bind("search", "input", (ev) => { S.query = ev.target.value.trim().toLowerCase(); draw(); });
  bind("colorBy", "change", (ev) => { S.colorBy = ev.target.value; draw(); });
  bind("sizeBy", "change", (ev) => { S.sizeBy = ev.target.value; draw(); });
  bind("labels", "change", (ev) => { S.labels = ev.target.value; draw(); });
  bind("spof", "change", (ev) => { S.spof = ev.target.checked; draw(); });
  bind("zoom-in", "click", () => zoomAt(1.25));
  bind("zoom-out", "click", () => zoomAt(1 / 1.25));
  bind("fit", "click", () => { S.touched = false; fitView(); draw(); });
  bind("table", "click", (ev) => {
    S.table = !S.table; ev.target.textContent = S.table ? "Graph" : "Table";
    svg.style.display = S.table ? "none" : ""; tablewrap.hidden = !S.table;
    if (S.table) drawTable(); else { fitView(); draw(); }
  });
  const download = (name, type, text) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
  const fileBase = () => `quanta-${graph.module || "graph"}-graph`;
  bind("json", "click", () => download(fileBase() + ".json", "application/json", JSON.stringify({ ...graph, analysis: { ...A.summary, hubs: A.summary.hubs.map((x) => x.id), chokepoints: A.summary.chokepoints.map((x) => x.id), important: A.summary.important.map((x) => x.id) } }, null, 2)));
  bind("svg", "click", () => {
    const b = world.getBBox(), m = 24;
    const body = world.innerHTML.replace(/ tabindex="0" role="button"/g, "");
    download(fileBase() + ".svg", "image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${b.x - m} ${b.y - m} ${b.width + 2 * m} ${b.height + 2 * m}" width="${Math.round(b.width + 2 * m)}" height="${Math.round(b.height + 2 * m)}"><rect x="${b.x - m}" y="${b.y - m}" width="${b.width + 2 * m}" height="${b.height + 2 * m}" fill="#0a0e1a"/><defs><marker id="gv-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#5d6e9f"/></marker></defs>${body}</svg>`);
  });
  host.addEventListener("click", (ev) => {
    const kind = ev.target.closest("[data-kind]");
    if (kind) { const k = kind.getAttribute("data-kind"); S.hidden.has(k) ? S.hidden.delete(k) : S.hidden.add(k); if (S.selected && S.hidden.has(nodeById.get(S.selected).kind)) S.selected = null; draw(); drawPanel(); return; }
    const pick = ev.target.closest("[data-pick]");
    if (pick && host.contains(pick)) {
      if (S.table) { S.table = false; q("table").textContent = "Table"; svg.style.display = ""; tablewrap.hidden = true; fitView(); }
      select(pick.getAttribute("data-pick"), { center: true }); return;
    }
    const go = ev.target.closest("[data-go]");
    if (go) { navigate(go.getAttribute("data-go")); return; }
    const act = ev.target.closest("[data-act]");
    if (!act) return;
    const what = act.getAttribute("data-act");
    if (what === "focus1") S.focus = 1; else if (what === "focus2") S.focus = 2; else if (what === "all") S.focus = 0;
    else if (what === "clear") { select(null); return; }
    else if (what === "path-from") { S.pathFrom = S.pathFrom === S.selected ? null : S.selected; S.path = null; }
    draw(); drawPanel();
  });
  host.addEventListener("keydown", (ev) => { if (ev.key === "Enter" && ev.target.matches?.("tr[data-pick]")) ev.target.click(); });

  const onResize = () => { if (!S.touched && !S.table) { fitView(); draw(); } };
  let ro = null;
  if (typeof ResizeObserver !== "undefined") { ro = new ResizeObserver(onResize); ro.observe(stage); }

  drawSummary(); drawKinds(); fitView(); draw(); drawPanel();
  // Highlight result paths from another source (the ontology question picker): paths = [{ nodes: [id...], edges: [{ source, target }] }] in THIS graph's ids.
  // Ids this graph does not have are ignored. Returns how many nodes were lit.
  function setHighlight(paths) {
    const nodes = new Set(), edges = new Set();
    for (const p of paths || []) {
      for (const id of p.nodes || []) if (nodeById.has(id)) nodes.add(id);
      for (const e of p.edges || []) if (nodeById.has(e.source) && nodeById.has(e.target)) edges.add(e.source + "\u0000" + e.target);
    }
    S.hl = { nodes, edges };
    draw();
    return nodes.size;
  }

  return { destroy() { ro?.disconnect(); }, select, setHighlight };
}
