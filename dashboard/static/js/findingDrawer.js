// The finding detail drawer: one place to read why a finding matters, what to do, what already protects the asset, how it could be reached,
// who owns it and what happened to it. Opened from the queue, and (through findingDetail.js) from every other page that lists findings.
// Sections load lazily and each fails on its own, so one slow or empty source never blocks the rest.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { getCurrentUser } from "./auth.js";
import { guidanceHtml } from "./guidanceView.js";
import { openAssignModal, statusPillHtml, assigneeLabel } from "./assignModal.js";
import { openDrawer, chip, severityChip, toast, tipAttr } from "./ui.js";
import { copyText } from "./sxKit.js";
import { slaRingFor, priorityReasons } from "./queueLogic.js";
import { ringSvg } from "./sxKit.js";
import { tabBar, wireTabBar } from "./mxKit.js";

let chainCache = { at: 0, chains: null };
async function attackChains() {
  if (chainCache.chains && Date.now() - chainCache.at < 30000) return chainCache.chains;
  const { chains } = await api.attackPaths();
  chainCache = { at: Date.now(), chains };
  return chains;
}

const dd = (label, valueHtml) => (valueHtml === null || valueHtml === undefined || valueHtml === "" ? "" : `<div class="mx-fact"><dt>${escapeHtml(label)}</dt><dd>${valueHtml}</dd></div>`);
const code = (v) => (v ? `<code>${escapeHtml(v)}</code>` : "");
const none = (t) => `<p class="ui-muted mx-none">${t}</p>`;

function overviewHtml(f) {
  const asset = f.asset || {};
  const ring = slaRingFor(f);
  const kev = f.kev && f.kev.listed
    ? `${chip("KEV listed", { tone: "critical" })}${f.kev.due_date ? ` <span class="ui-muted">CISA due ${escapeHtml(f.kev.due_date)}</span>` : ""}${f.kev.vulnerability_name ? `<div class="ui-muted">${escapeHtml(f.kev.vulnerability_name)}</div>` : ""}`
    : (f.kev ? `<span class="ui-muted">Not on the KEV list</span>` : "");
  const epss = f.epss ? `<span class="mx-epss"><i style="width:${Math.round(f.epss.score * 100)}%"></i></span> <strong>${(f.epss.score * 100).toFixed(1)}%</strong> <span class="ui-muted">exploit probability, ${(f.epss.percentile * 100).toFixed(0)}th percentile</span>` : "";
  const why = priorityReasons(f);
  const L = f.location || {};
  const loc = L.file || L.url ? `<code>${escapeHtml(L.file || L.url)}${L.line ? `:${escapeHtml(String(L.line))}` : ""}</code>${L.snippet ? `<pre class="finding-snippet">${escapeHtml(L.snippet)}</pre>` : ""}` : "";
  const eol = f.eol_status && f.eol_status.status && f.eol_status.status !== "unknown" ? `${escapeHtml(f.eol_status.status)} (${escapeHtml(f.eol_status.eol_date || "")}, ${escapeHtml(f.eol_status.vendor || "")})` : "";
  return `${f.description ? `<p class="mx-desc">${escapeHtml(f.description)}</p>` : ""}
    ${f.recommended_fix ? `<div class="mx-callout"><strong>Recommended fix</strong><p>${escapeHtml(f.recommended_fix)}</p></div>` : ""}
    <div class="mx-sla"><span class="mx-sla-ring">${ringSvg(ring, { size: 44, radius: 11 })}</span><div><strong>${f.sla && f.sla.due_date ? `Due ${escapeHtml(f.sla.due_date)}` : "No SLA date"}</strong><div class="ui-muted">${escapeHtml(ring.label)}${f.sla && f.sla.risk_tier_multiplier && f.sla.risk_tier_multiplier !== 1 ? `, window scaled x${f.sla.risk_tier_multiplier} for asset risk` : ""}</div></div></div>
    ${f.exception ? `<div class="mx-callout mx-callout-warn"><strong>Risk accepted until ${escapeHtml(f.exception.expires_on)}</strong><p>${escapeHtml(f.exception.reason)}</p><a href="/exceptions?highlight=${encodeURIComponent(f.exception.id)}" data-link>Open the exception record</a></div>` : ""}
    <h3 class="mx-h3">Why this priority</h3>
    ${why.lines.length ? `<ol class="mx-reasons">${why.lines.map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ol><p class="ui-muted">Engine score ${why.score ?? "n/a"}. Edit the weights on <a href="/priority-rules" data-link>Priority rules</a>.</p>` : none("The engine recorded no reasons for this finding.")}
    <h3 class="mx-h3">Facts</h3>
    <dl class="mx-facts">
      ${dd("Source", f.source ? `${escapeHtml(f.source)}${f.source_ref ? ` <span class="ui-muted">(${escapeHtml(f.source_ref)})</span>` : ""}` : "")}
      ${dd("Severity", f.severity ? severityChip(f.severity) : "")}${dd("CVE", code(f.cve))}${dd("CVSS", f.cvss !== undefined && f.cvss !== null ? escapeHtml(String(f.cvss)) : "")}
      ${dd("CISA KEV", kev)}${dd("EPSS", epss)}
      ${dd("CWE", f.cwe && f.cwe.length ? f.cwe.map(code).join(" ") : "")}${dd("Rule", f.rule_id ? `${code(f.rule_id)}${f.tool ? ` <span class="ui-muted">(${escapeHtml(f.tool)})</span>` : ""}` : "")}${dd("Location", loc)}
      ${dd("ATT&CK", f.attack_techniques && f.attack_techniques.length ? f.attack_techniques.map((t) => `<span class="attack-tag" ${tipAttr(t.tactic || "")}>${escapeHtml(t.technique_id)}</span>`).join(" ") : "")}
      ${dd("Asset", asset.name ? `${escapeHtml(asset.name)}${asset.ip ? ` <span class="ui-muted">(${escapeHtml(asset.ip)})</span>` : ""}` : "")}${dd("Asset type", escapeHtml(asset.type || ""))}${dd("OS", escapeHtml(asset.os || ""))}${dd("EOL / EOS", eol)}
      ${dd("Environment", escapeHtml(f.environment || ""))}${dd("First seen", escapeHtml(f.first_seen || ""))}${dd("Last seen", escapeHtml(f.last_seen || ""))}
    </dl>`;
}

export function openFindingDrawer(f, { onChanged } = {}) {
  const idq = encodeURIComponent(f.id);
  const tabs = [{ id: "overview", label: "Overview" }, { id: "fix", label: "How to fix" }, { id: "context", label: "Context" }, { id: "owner", label: "Ownership" }];
  const drawer = openDrawer({
    title: f.title || f.id, width: 640,
    html: `<div class="mx-drawer">
      <div class="mx-drawer-meta"><span class="badge badge-priority-${escapeHtml((f.priority || "").toLowerCase())}">${escapeHtml(f.priority || "")}</span> <code>${escapeHtml(f.id)}</code>
        ${f.scan_type_label ? chip(f.scan_type_label, { tone: "neutral" }) : ""}${f.source_mode === "simulation" ? chip("Simulated", { tone: "info", title: "Recorded vendor responses replayed through the real connector code; not from a live system" }) : ""}
        ${f.pending ? chip("Saving", { tone: "warn" }) : ""}</div>
      <div class="mx-drawer-actions">
        <button type="button" class="ui-btn sx-btn-sm" data-act="assign">Assign</button>
        <a class="ui-btn ui-btn-ghost sx-btn-sm" href="/exceptions?finding_id=${idq}" data-link data-close-drawer>Request exception</a>
        <a class="ui-btn ui-btn-ghost sx-btn-sm" href="/support?finding_id=${idq}" data-link data-close-drawer>Raise ticket</a>
        <a class="ui-btn ui-btn-ghost sx-btn-sm" href="/ai-assist?finding_id=${idq}" data-link data-close-drawer>Ask AI</a>
        <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="copy">Copy link</button></div>
      ${tabBar("Finding detail", tabs, "overview")}
      <div data-panel="overview" class="mx-panel">${overviewHtml(f)}</div>
      <div data-panel="fix" class="mx-panel" hidden><div id="d-guidance">${none("Loading step-by-step guidance...")}</div></div>
      <div data-panel="context" class="mx-panel" hidden>
        <h3 class="mx-h3">Compensating controls</h3><div id="d-controls">${none("Loading...")}</div>
        <h3 class="mx-h3">Network reachability</h3><div id="d-reach">${none("Loading...")}</div>
        <h3 class="mx-h3">Attack path</h3><div id="d-chain">${none("Loading...")}</div>
        <h3 class="mx-h3">Similar findings</h3><div id="d-similar">${none("Loading...")}</div></div>
      <div data-panel="owner" class="mx-panel" hidden><div id="d-owner">${none("Loading...")}</div><div id="d-links"></div></div></div>`,
  });
  const body = drawer.body;
  const loaded = new Set();
  const lazy = { fix: () => loadGuidance(f, body), context: () => { loadControls(f, body); loadReach(f, body); loadChain(f, body); loadSimilar(f, body, onChanged); }, owner: () => { loadOwner(f, body, drawer, onChanged); loadLinks(f, body); } };
  const show = (id) => {
    body.querySelectorAll("[data-tab]").forEach((t) => { const on = t.dataset.tab === id; t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1; });
    body.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== id; });
    if (lazy[id] && !loaded.has(id)) { loaded.add(id); lazy[id](); }
  };
  wireTabBar(body.querySelector(".mx-tabs"), show);
  body.addEventListener("click", (e) => {
    if (e.target.closest("[data-close-drawer]")) { drawer.close(); return; }
    const a = e.target.closest("[data-act]");
    if (!a) return;
    if (a.dataset.act === "copy") copyText(`${window.location.origin}/queue?highlight=${encodeURIComponent(f.id)}`, "Link copied");
    if (a.dataset.act === "assign") openAssignModal({ findingId: f.id, title: f.title, onSaved: () => { toast(`Assignment saved for ${f.id}`, { tone: "good" }); loaded.delete("owner"); body.querySelector("#d-owner").innerHTML = none("Loading..."); lazy.owner(); loaded.add("owner"); if (onChanged) onChanged(f); } });
  });
  return drawer;
}

async function loadGuidance(f, body) {
  const el = body.querySelector("#d-guidance");
  try { const g = await api.findingGuidance(f.id); if (el.isConnected) el.innerHTML = guidanceHtml(g); }
  catch (err) { if (el.isConnected) el.innerHTML = none(`Guidance could not be loaded (${escapeHtml(err.message || String(err))}).`); }
}

async function loadControls(f, body) {
  const el = body.querySelector("#d-controls");
  try {
    const c = await api.controlCoverage(f.id);
    if (!el.isConnected) return;
    if (!c.has_data) { el.innerHTML = none("No firewall or EDR coverage is recorded for this asset, so nothing is claimed. Record it in <code>security_controls.yaml</code>."); return; }
    el.innerHTML = `<div class="mx-cover"><div><span class="mx-big">${c.existing_coverage_pct}%</span><span class="ui-muted"> covered today</span></div><div><span class="mx-big">${c.residual_risk_pct}%</span><span class="ui-muted"> residual risk</span></div><div><span class="mx-big">+${c.incremental_coverage_pct}%</span><span class="ui-muted"> if recommendations applied</span></div></div>
      ${c.recommended_controls.length ? `<ul class="mx-list">${c.recommended_controls.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : none("Nothing further recommended: existing coverage accounts for everything this check looks at.")}`;
  } catch (err) { if (el.isConnected) el.innerHTML = none(`Could not load control coverage (${escapeHtml(err.message || String(err))}).`); }
}

async function loadReach(f, body) {
  const el = body.querySelector("#d-reach");
  const name = f.asset && f.asset.name;
  if (!name) { el.innerHTML = none("This finding has no asset to trace."); return; }
  try {
    const p = await api.networkPath(name);
    if (!el.isConnected) return;
    if (p.verdict === "unknown") { el.innerHTML = none("No network path is recorded for this asset, so reachability is unknown. Add it to <code>network_topology.yaml</code>."); return; }
    el.innerHTML = `<p>${p.verdict === "denied" ? chip("Denied: no path from the internet", { tone: "good" }) : chip("Allowed: reachable from the internet", { tone: "critical" })}</p>
      <ol class="mx-hops">${p.hops.map((h) => `<li><span class="ui-muted">${escapeHtml(h.hop_type)}</span> <strong>${escapeHtml(h.name)}</strong> ${chip(h.default_action, { tone: String(h.default_action).toLowerCase().startsWith("allow") ? "warn" : "good" })}</li>`).join("")}</ol>`;
  } catch (err) { if (el.isConnected) el.innerHTML = none(`Could not trace the path (${escapeHtml(err.message || String(err))}).`); }
}

async function loadChain(f, body) {
  const el = body.querySelector("#d-chain");
  const name = f.asset && f.asset.name;
  try {
    const chains = await attackChains();
    if (!el.isConnected) return;
    const chain = chains.find((c) => c.asset_name === name);
    if (!chain) { el.innerHTML = none("This asset has no entry-to-impact chain of tagged findings."); return; }
    const where = ["entry", "pivots", "impact"].find((k) => chain[k].some((x) => x.id === f.id));
    const stage = (title, items, key) => `<div class="mx-stage${where === key ? " here" : ""}"><h4>${title}</h4>${items.length ? items.slice(0, 4).map((x) => `<div class="mx-stage-item${x.id === f.id ? " me" : ""}">${chip(x.technique_id || "?", { tone: "neutral" })} ${escapeHtml(x.title)}</div>`).join("") + (items.length > 4 ? `<div class="ui-muted">+${items.length - 4} more</div>` : "") : '<div class="ui-muted">None tagged</div>'}</div>`;
    el.innerHTML = `${where === "pivots" ? `<p>${chip("Pivot", { tone: "warn" })} Fixing this finding breaks every chain it sits in.</p>` : where ? `<p class="ui-muted">This finding is the ${where === "entry" ? "entry" : "impact"} stage.</p>` : ""}
      <div class="mx-chain">${stage("Entry", chain.entry, "entry")}<span class="mx-arrow" aria-hidden="true">&rsaquo;</span>${stage("Pivot", chain.pivots, "pivots")}<span class="mx-arrow" aria-hidden="true">&rsaquo;</span>${stage("Impact", chain.impact, "impact")}</div>`;
  } catch (err) { if (el.isConnected) el.innerHTML = none(`Could not load attack chains (${escapeHtml(err.message || String(err))}).`); }
}

async function loadSimilar(f, body, onChanged) {
  const el = body.querySelector("#d-similar");
  try {
    const { similar } = await api.mlSimilarFindings(f.id);
    if (!el.isConnected) return;
    el.innerHTML = similar.length ? `<ul class="mx-list">${similar.slice(0, 6).map((s) => `<li><button type="button" class="sx-link-btn" data-similar="${escapeHtml(s.id)}">${escapeHtml(s.id)}</button> ${escapeHtml(s.title)} <span class="ui-muted">${(s.similarity * 100).toFixed(0)}% similar</span></li>`).join("")}</ul>` : none("No similar findings.");
    el.onclick = (e) => { const b = e.target.closest("[data-similar]"); const m = b && similar.find((s) => s.id === b.dataset.similar); if (m) openFindingDrawer(m, { onChanged }); };
  } catch (err) { if (el.isConnected) el.innerHTML = none(`Could not load similar findings (${escapeHtml(err.message || String(err))}).`); }
}

async function loadOwner(f, body, drawer) {
  const el = body.querySelector("#d-owner");
  const me = await getCurrentUser().catch(() => null);
  if (!me) { el.innerHTML = none('<a href="/login" data-link data-close-drawer>Sign in</a> to see and change who owns this finding.'); return; }
  try {
    const d = await api.findingAssignment(f.id);
    if (!el.isConnected) return;
    const a = d.assignment;
    const state = { assigned: "Assigned to a person", team_only: "Routed to a team: nobody has picked it up", unowned: "Unowned: no person and no team" }[d.ownership_state] || d.ownership_state;
    const hist = (d.history || []).slice(0, 8).map((h) => {
      const x = h.details || {};
      const what = h.action === "finding.status" ? `status ${escapeHtml(x.from)} to ${escapeHtml(x.to)}` : h.action === "finding.unassign" ? "removed the assignment" : h.action === "finding.auto_assign" ? `auto-routed to ${escapeHtml(x.team || "a team")}` : `assigned to ${escapeHtml(x.assignee || x.team || "-")}`;
      return `<li><span class="mx-when">${escapeHtml(String(h.timestamp).slice(0, 16).replace("T", " "))}</span> <strong>${escapeHtml(h.actor)}</strong> ${what}</li>`;
    }).join("");
    el.innerHTML = `<dl class="mx-facts">${dd("State", escapeHtml(state))}${dd("Assignee", a && a.assignee_email ? `${escapeHtml(assigneeLabel(a))} <span class="ui-muted">(${escapeHtml(a.assignee_email)})</span>` : '<span class="ui-muted">Nobody</span>')}${dd("Team", d.team ? escapeHtml(d.team) : '<span class="ui-muted">None</span>')}${dd("Work status", statusPillHtml(a && a.status))}${a && a.notes ? dd("Note", escapeHtml(a.notes)) : ""}</dl>
      <h3 class="mx-h3">History</h3>${hist ? `<ol class="mx-timeline">${hist}</ol>` : none("No assignment history yet.")}`;
    api.findingTickets(f.id).then(({ tickets }) => { if (tickets.length && el.isConnected) el.insertAdjacentHTML("beforeend", `<h3 class="mx-h3">Support tickets</h3><ul class="mx-list">${tickets.map((t) => `<li>${escapeHtml(t.ref)} ${escapeHtml(t.subject)} <span class="ui-muted">${escapeHtml(t.status)}${t.sla && t.sla.breached ? ", SLA breached" : ""}</span></li>`).join("")}</ul>`); }).catch(() => {});
  } catch (err) { if (el.isConnected) el.innerHTML = none(`Could not load ownership (${escapeHtml(err.message || String(err))}).`); }
  void drawer;
}

async function loadLinks(f, body) {
  const el = body.querySelector("#d-links");
  try {
    const links = (await api.findingLinks(f.id)).links || [];
    if (!links.length || !el.isConnected) return;
    el.innerHTML = `<h3 class="mx-h3">External tickets</h3><ul class="mx-list">${links.map((l) => `<li><strong>${escapeHtml(l.external_ref || "Not created yet")}</strong> (${escapeHtml(l.system)}) ${l.state ? chip(l.state, { tone: "neutral" }) : ""}${l.last_error ? ` <span class="ui-muted">${escapeHtml(l.last_error)}</span>` : ""}</li>`).join("")}</ul>`;
  } catch { /* signed out, or none */ }
}
