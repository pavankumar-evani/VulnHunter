// Interactive dependency and exposure graph for one application, drawn as plain SVG (no library, no build step).
//
// Left to right: the path from the internet (WAF, load balancer, DMZ, firewall - whatever network_topology.yaml records) into the application, then the
// application's direct dependencies, then the packages those pull in. Vulnerable packages are coloured by their worst finding; click a package for its
// findings, fixed version, who depends on it (blast radius) and the path that pulls it in. Drag to pan, scroll to zoom, Tab and Enter work too.
//
// Input is the object from GET /api/applications/<name>/analysis (nodes, edges, root, reachability, hidden). Nothing here fetches or decides anything.
import { escapeHtml } from "./dom.js";

const NODE_W = 172, NODE_H = 36, COL_GAP = 46, ROW_GAP = 12, LANE_W = 112, LANE_H = 44, LANE_GAP = 34, PAD = 24;
const SEV_FILL = { Critical: "#f06a6a", High: "#f0a35c", Medium: "#e8cf6a", Low: "#6d97f7" };
const CRIT_MARK = { critical: "C", high: "H", medium: "M", low: "L" };
const LANE_LABEL = { internet: "Internet", waf: "WAF", load_balancer: "Load balancer", dmz: "DMZ", firewall: "Firewall" };

function trunc(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

function buildLayout(data, onlyVulnerable) {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const rootId = data.root && byId.has(data.root.id) ? data.root.id : (data.nodes.find((n) => n.kind === "application") || {}).id;
  const kids = new Map(), parent = new Map();
  for (const [a, b] of data.edges) {
    if (!byId.has(a) || !byId.has(b) || a === b) continue;
    const da = byId.get(a).depth, db = byId.get(b).depth;
    if (da != null && db != null && db === da + 1 && !parent.has(b)) {
      parent.set(b, a);
      if (!kids.has(a)) kids.set(a, []);
      kids.get(a).push(b);
    }
  }
  let keep = null;
  if (onlyVulnerable) {
    keep = new Set([rootId]);
    for (const n of data.nodes) {
      if (!n.vulnerable) continue;
      let cur = n.id;
      while (cur != null && !keep.has(cur)) { keep.add(cur); cur = parent.get(cur); }
    }
  }
  const pos = new Map();
  let row = 0;
  const order = (ids) => ids.slice().sort((a, b) => (byId.get(b).top_score || 0) - (byId.get(a).top_score || 0) || String(byId.get(a).name).localeCompare(String(byId.get(b).name)));
  function place(id, depth) {
    const list = order((kids.get(id) || []).filter((k) => !keep || keep.has(k)));
    if (!list.length) { pos.set(id, { row: row++, depth }); return; }
    list.forEach((k) => place(k, depth + 1));
    pos.set(id, { row: (pos.get(list[0]).row + pos.get(list[list.length - 1]).row) / 2, depth });
  }
  if (rootId) place(rootId, 0);
  const orphans = data.nodes.filter((n) => n.id !== rootId && !pos.has(n.id) && (n.depth == null) && (!keep || n.vulnerable));
  const orphanStart = row + 1;
  orphans.sort((a, b) => String(a.name).localeCompare(String(b.name))).forEach((n, i) => pos.set(n.id, { row: orphanStart + i, depth: 1, orphan: true }));
  return { byId, rootId, kids, parent, pos, orphans, rows: orphans.length ? orphanStart + orphans.length : row };
}

export function renderDependencyGraph(host, data, opts = {}) {
  const reach = data.reachability || { stops: [], verdict: "unknown" };
  const lane = (reach.stops || []).slice(0, -1);  // everything before the application itself
  const rootX = PAD + lane.length * (LANE_W + LANE_GAP);
  let onlyVulnerable = data.nodes.length > 60, selected = null, query = "";
  let view = { x: 0, y: 0, k: 1 };

  host.innerHTML = `<div class="dg">
    <div class="dg-bar">
      <label class="dg-check"><input type="checkbox" data-dg="vuln"${onlyVulnerable ? " checked" : ""}> Vulnerable paths only</label>
      <input type="search" data-dg="search" placeholder="Find a package" aria-label="Find a package">
      <span class="dg-spacer"></span>
      <button type="button" class="secondary-button" data-dg="zoom-in" aria-label="Zoom in">+</button>
      <button type="button" class="secondary-button" data-dg="zoom-out" aria-label="Zoom out">&minus;</button>
      <button type="button" class="secondary-button" data-dg="fit">Fit</button>
    </div>
    <div class="dg-main"><div class="dg-stage"><svg class="dg-svg" role="group" aria-label="Dependency graph" tabindex="-1"></svg></div><aside class="dg-panel" aria-live="polite"></aside></div>
    <div class="dg-legend">
      <span><i style="background:${SEV_FILL.Critical}"></i>Critical</span><span><i style="background:${SEV_FILL.High}"></i>High</span><span><i style="background:${SEV_FILL.Medium}"></i>Medium</span>
      <span><i style="background:${SEV_FILL.Low}"></i>Low</span><span><i class="dg-plain"></i>No finding</span><span><b>&#9632;</b> bar on the left: direct dependency</span>
      <span>C H M L: how sensitive the package is</span>
    </div>
    <p class="dg-foot"></p></div>`;
  const svg = host.querySelector(".dg-svg"), panel = host.querySelector(".dg-panel"), stage = host.querySelector(".dg-stage");

  function draw() {
    const L = buildLayout(data, onlyVulnerable);
    const px = (p) => rootX + p.depth * (NODE_W + COL_GAP);
    const py = (p) => PAD + p.row * (NODE_H + ROW_GAP);
    const rootP = L.pos.get(L.rootId) || { row: 0, depth: 0 };
    const laneY = py(rootP) + (NODE_H - LANE_H) / 2;
    const q = query.trim().toLowerCase();
    const hit = (n) => q && String(n.name).toLowerCase().includes(q);
    let out = "";
    // network path
    lane.forEach((s, i) => {
      const x = PAD + i * (LANE_W + LANE_GAP);
      const next = i + 1 < lane.length ? PAD + (i + 1) * (LANE_W + LANE_GAP) : rootX;
      out += `<line x1="${x + LANE_W}" y1="${laneY + LANE_H / 2}" x2="${next}" y2="${laneY + LANE_H / 2}" class="dg-lane-line ${s.action === "deny" ? "dg-deny-line" : ""}" marker-end="url(#dg-arrow)"/>`;
      out += `<g class="dg-lane" data-lane="${i}" tabindex="0" role="button" aria-label="${escapeHtml((s.label || LANE_LABEL[s.kind] || s.kind) + (s.name ? " " + s.name : "") + (s.action ? ", " + s.action : ""))}">
        <rect x="${x}" y="${laneY}" width="${LANE_W}" height="${LANE_H}" rx="8" class="dg-lane-box ${s.action === "deny" ? "dg-deny-box" : ""}"/>
        <text x="${x + 10}" y="${laneY + 18}" class="dg-lane-kind">${escapeHtml(s.label || LANE_LABEL[s.kind] || s.kind)}</text>
        ${s.action ? `<text x="${x + LANE_W - 8}" y="${laneY + 34}" text-anchor="end" class="dg-lane-action ${s.action === "deny" ? "dg-deny" : "dg-allow"}">${escapeHtml(s.action)}</text>` : ""}
        <text x="${x + 10}" y="${laneY + 34}" class="dg-lane-name">${escapeHtml(trunc(s.name || (s.kind === "internet" ? "untrusted" : ""), s.action ? 9 : 16))}</text></g>`;
    });
    // edges
    const drawn = new Set();
    for (const [a, b] of data.edges) {
      const pa = L.pos.get(a), pb = L.pos.get(b);
      if (!pa || !pb || pb.orphan) continue;
      const tree = L.parent.get(b) === a;
      const key = a + ">" + b;
      if (drawn.has(key)) continue;
      drawn.add(key);
      const x1 = px(pa) + NODE_W, y1 = py(pa) + NODE_H / 2, x2 = px(pb), y2 = py(pb) + NODE_H / 2, mx = (x1 + x2) / 2;
      out += `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" class="dg-edge${tree ? "" : " dg-edge-extra"}" data-from="${escapeHtml(a)}" data-to="${escapeHtml(b)}"/>`;
    }
    // nodes
    for (const n of data.nodes) {
      const p = L.pos.get(n.id);
      if (!p) continue;
      const x = px(p), y = py(p);
      const isRoot = n.id === L.rootId;
      const fill = n.vulnerable ? (SEV_FILL[n.worst_severity] || SEV_FILL.Medium) : "";
      const cls = ["dg-node", isRoot ? "dg-root" : "", n.vulnerable ? "dg-vuln" : "", selected === n.id ? "dg-selected" : "", hit(n) ? "dg-hit" : "", n.direct ? "dg-direct" : ""].join(" ");
      const label = isRoot ? n.name : trunc(n.name, 20);
      const sub = isRoot ? (n.version ? "v" + n.version : "application") : (n.version || "");
      const crit = !isRoot && n.criticality ? `<g class="dg-crit dg-crit-${escapeHtml(n.criticality.level)}"><circle cx="${x + NODE_W - 12}" cy="${y + 12}" r="8"/><text x="${x + NODE_W - 12}" y="${y + 15}" text-anchor="middle">${CRIT_MARK[n.criticality.level] || ""}</text></g>` : "";
      out += `<g class="${cls}" data-node="${escapeHtml(n.id)}" tabindex="0" role="button" aria-label="${escapeHtml(n.name + (n.version ? " " + n.version : "") + (n.vulnerable ? ", vulnerable" : ""))}">
        <title>${escapeHtml(n.name + (n.version ? " " + n.version : "") + (n.vulnerable ? " - " + (n.worst_severity || "finding") : ""))}</title>
        <rect x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="7" class="dg-box"${fill ? ` style="fill:${fill}"` : ""}/>
        ${n.direct ? `<rect x="${x}" y="${y}" width="5" height="${NODE_H}" rx="2" class="dg-direct-bar"/>` : ""}
        <text x="${x + 12}" y="${y + 15}" class="dg-name"${fill ? ' style="fill:#0a0e1a"' : ""}>${escapeHtml(label)}</text>
        <text x="${x + 12}" y="${y + 29}" class="dg-ver"${fill ? ' style="fill:#0a0e1a"' : ""}>${escapeHtml(trunc(sub, 24))}${n.vulnerable ? " · " + n.findings.length + (n.findings.length === 1 ? " finding" : " findings") : ""}</text>${crit}</g>`;
    }
    if (L.orphans.length) out += `<text x="${rootX + NODE_W + COL_GAP}" y="${py({ row: L.rows - L.orphans.length - 0.35 })}" class="dg-note">Components with no recorded path from the application</text>`;
    const w = rootX + (Math.max(1, ...data.nodes.map((n) => (L.pos.get(n.id) || { depth: 0 }).depth)) + 1) * (NODE_W + COL_GAP);
    const h = PAD * 2 + Math.max(1, L.rows) * (NODE_H + ROW_GAP);
    svg.innerHTML = `<defs><marker id="dg-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="dg-arrowhead"/></marker></defs><g class="dg-view">${out}</g>`;
    svg._size = { w, h };
    apply();
    host.querySelector(".dg-foot").textContent = [
      data.hidden ? `${data.hidden} component(s) with no findings are not drawn (the graph is large).` : "",
      reach.note || "",
      data.sbom && !data.sbom.has_graph ? "This SBOM lists components without saying which depends on which, so depth and direct/transitive are unknown." : "",
    ].filter(Boolean).join(" ");
  }

  function apply() {
    const g = svg.querySelector(".dg-view");
    if (g) g.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
  }
  function fit() {
    const s = svg._size || { w: 800, h: 400 }, r = stage.getBoundingClientRect();
    // Fit the whole graph when that stays readable; otherwise start at the top left (the internet end) at a readable size and let the person pan.
    const k = Math.max(0.62, Math.min(1, (r.width || 800) / s.w, (r.height || 500) / s.h));
    view = { x: 8, y: 8, k };
    apply();
  }
  function zoom(f, cx, cy) {
    const r = svg.getBoundingClientRect();
    const ux = cx ?? r.width / 2, uy = cy ?? r.height / 2;
    const k = Math.min(3, Math.max(0.15, view.k * f));
    view.x = ux - (ux - view.x) * (k / view.k);
    view.y = uy - (uy - view.y) * (k / view.k);
    view.k = k;
    apply();
  }

  function showNode(id) {
    selected = id;
    const n = data.nodes.find((x) => x.id === id);
    if (!n) return;
    svg.querySelectorAll(".dg-node").forEach((el) => el.classList.toggle("dg-selected", el.dataset.node === id));
    if (n.kind === "application") {
      const ctx = data.context || {};
      panel.innerHTML = `<h3>${escapeHtml(n.name)}</h3><p class="muted">The application</p><dl class="dg-dl">
        <dt>Environment</dt><dd>${escapeHtml(ctx.environment || "not recorded")}</dd><dt>Owner / team</dt><dd>${escapeHtml(ctx.owner || "not recorded")} / ${escapeHtml(ctx.team || "not recorded")}</dd>
        <dt>Business criticality</dt><dd>${escapeHtml(ctx.business_criticality || "not recorded")}</dd><dt>Exposure</dt><dd>${escapeHtml(reach.exposure || "unknown")} - ${escapeHtml(reach.exposure_reason || "")}</dd>
        <dt>Network path</dt><dd>${escapeHtml(reach.verdict)}</dd></dl>`;
      return;
    }
    const fs = (data.findings || []).filter((f) => (n.findings || []).includes(f.id));
    panel.innerHTML = `<h3>${escapeHtml(n.name)} <span class="muted">${escapeHtml(n.version || "")}</span></h3>
      <p class="muted">${escapeHtml(n.ecosystem || "ecosystem unknown")}${n.direct === true ? " &middot; direct dependency" : n.direct === false ? " &middot; transitive dependency" : " &middot; direct or transitive is not known"}${n.depth ? ` &middot; ${n.depth} level${n.depth === 1 ? "" : "s"} from the application` : ""}</p>
      ${n.purl ? `<p class="dg-purl"><code>${escapeHtml(n.purl)}</code></p>` : ""}
      <p><strong>Sensitivity: ${escapeHtml(n.criticality ? n.criticality.level : "unknown")}</strong><br><span class="muted">${escapeHtml(n.criticality ? n.criticality.reason : "")}</span></p>
      ${(n.licenses || []).length ? `<p class="muted">License: ${n.licenses.map(escapeHtml).join(", ")}</p>` : ""}
      ${n.path && n.path.length ? `<p><strong>Pulled in by</strong><br><span class="dg-path">${n.path.map(escapeHtml).join(" &rarr; ")}</span></p>` : ""}
      ${fs.length ? `<h4>${fs.length} finding${fs.length === 1 ? "" : "s"}</h4><ul class="dg-findings">${fs.map((f) => `<li>
          <button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button>
          <span class="badge badge-${escapeHtml(String(f.severity || "").toLowerCase())}">${escapeHtml(f.severity)}</span> <span class="badge badge-outline">${escapeHtml(f.tier)} &middot; ${f.score}</span>
          ${f.kev ? '<span class="badge badge-critical">known exploited</span>' : ""}<br><span class="muted">${escapeHtml(f.cve || f.title || "")}${f.fixed_version ? ` &middot; fixed in ${escapeHtml(f.fixed_version)}` : " &middot; no fixed version known"}</span></li>`).join("")}</ul>` : '<p class="muted">No findings on this package.</p>'}
      ${n.fixed_version ? `<p><strong>Upgrade to ${escapeHtml(n.fixed_version)}</strong>${n.pulled_in_by && n.pulled_in_by.length ? `<br><span class="muted">It is transitive: upgrade ${n.pulled_in_by.map(escapeHtml).join(", ")} if a newer release carries it, or pin it directly.</span>` : ""}</p>` : ""}
      ${n.dependents && n.dependents.length ? `<p><strong>Blast radius</strong><br><span class="muted">${n.dependents.length} package${n.dependents.length === 1 ? "" : "s"} depend on it: ${n.dependents.slice(0, 12).map(escapeHtml).join(", ")}${n.dependents.length > 12 ? ", ..." : ""}</span></p>` : (n.vulnerable ? '<p class="muted">No other package in the SBOM depends on it.</p>' : "")}
      ${n.vulnerable && opts.onPropose ? '<p><button type="button" class="btn-primary" data-dg="propose">Propose an upgrade pull request</button></p>' : ""}`;
    panel.querySelectorAll("[data-finding-id]").forEach((b) => b.addEventListener("click", () => opts.onFinding && opts.onFinding(b.dataset.findingId)));
    const prop = panel.querySelector('[data-dg="propose"]');
    if (prop) prop.addEventListener("click", () => opts.onPropose(n));
  }
  function showLane(i) {
    const s = lane[i];
    panel.innerHTML = `<h3>${escapeHtml(s.label || LANE_LABEL[s.kind] || s.kind)}${s.name ? ` <span class="muted">${escapeHtml(s.name)}</span>` : ""}</h3>
      <p class="muted">${s.kind === "internet" ? "Where an attacker starts." : `A hop between the internet and the application.${s.action ? ` Default action: <strong>${escapeHtml(s.action)}</strong>.` : ""}`}</p>
      <p>Verdict for the whole path: <strong>${escapeHtml(reach.verdict)}</strong>. ${escapeHtml(reach.note || "")}</p>
      <p class="muted">Recorded by hand in remediation/config/network_topology.yaml. One denying hop makes the verdict denied, which lowers the score of the application's findings but never removes them.</p>`;
  }

  // events
  host.addEventListener("click", (e) => {
    const node = e.target.closest("[data-node]"), ln = e.target.closest("[data-lane]");
    if (node) showNode(node.dataset.node);
    else if (ln) showLane(Number(ln.dataset.lane));
  });
  host.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const node = e.target.closest && e.target.closest("[data-node]"), ln = e.target.closest && e.target.closest("[data-lane]");
    if (node) { e.preventDefault(); showNode(node.dataset.node); } else if (ln) { e.preventDefault(); showLane(Number(ln.dataset.lane)); }
  });
  host.addEventListener("mouseover", (e) => {
    const node = e.target.closest && e.target.closest("[data-node]");
    svg.classList.toggle("dg-focus", !!node);
    svg.querySelectorAll(".dg-on").forEach((el) => el.classList.remove("dg-on"));
    if (!node) return;
    const L = buildLayout(data, onlyVulnerable);
    let cur = node.dataset.node;
    while (cur != null) {
      const el = svg.querySelector(`[data-node="${CSS.escape(cur)}"]`);
      if (el) el.classList.add("dg-on");
      const par = L.parent.get(cur);
      if (par != null) svg.querySelectorAll(`.dg-edge[data-from="${CSS.escape(par)}"][data-to="${CSS.escape(cur)}"]`).forEach((el) => el.classList.add("dg-on"));
      cur = par;
    }
  });
  host.addEventListener("mouseleave", () => { svg.classList.remove("dg-focus"); });
  host.querySelector('[data-dg="vuln"]').addEventListener("change", (e) => { onlyVulnerable = e.target.checked; draw(); fit(); });
  host.querySelector('[data-dg="search"]').addEventListener("input", (e) => { query = e.target.value; draw(); });
  host.querySelector('[data-dg="zoom-in"]').addEventListener("click", () => zoom(1.25));
  host.querySelector('[data-dg="zoom-out"]').addEventListener("click", () => zoom(0.8));
  host.querySelector('[data-dg="fit"]').addEventListener("click", fit);
  stage.addEventListener("wheel", (e) => { e.preventDefault(); const r = svg.getBoundingClientRect(); zoom(e.deltaY < 0 ? 1.12 : 0.89, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
  let drag = null;
  stage.addEventListener("pointerdown", (e) => { if (e.target.closest("[data-node],[data-lane]")) return; drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; stage.setPointerCapture(e.pointerId); stage.classList.add("dg-grab"); });
  stage.addEventListener("pointermove", (e) => {
    if (!drag) return;
    view.x = drag.vx + (e.clientX - drag.x);
    view.y = drag.vy + (e.clientY - drag.y);
    apply();
  });
  const end = () => { drag = null; stage.classList.remove("dg-grab"); };
  stage.addEventListener("pointerup", end);
  stage.addEventListener("pointercancel", end);

  draw();
  fit();
  const first = data.nodes.filter((n) => n.vulnerable).sort((a, b) => (b.top_score || 0) - (a.top_score || 0))[0];
  if (first) showNode(first.id);
  else panel.innerHTML = '<p class="muted">Click a package to see what pulls it in and what depends on it.</p>';
}
