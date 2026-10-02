import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Hunting & SOC";

const TABS = [["overview", "Overview"], ["proposals", "Proposed hunts"], ["hunts", "Hunts"], ["alerts", "Alert triage"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low", Informational: "badge-outline" };
const NOTE = "Quanta is not a SIEM. It knows which assets carry exploitable vulnerabilities, so it proposes where to look and adds that context to alerts. You run the queries in your own SIEM and record what you found here.";
const RESULTS = ["", "hits", "no-hits", "not-run", "error"];

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let openHunt = null;
  let openAlert = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="hunt-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; openHunt = null; openAlert = null; show(); }));
  };
  const techniques = (list) => (list || []).map((t) => `<span class="badge badge-outline">${escapeHtml(t.technique_id)} ${escapeHtml(t.technique_name)}</span>`).join(" ") || '<span class="muted">none tagged</span>';

  async function overview() {
    const o = await api.huntingOverview();
    const m = o.metrics;
    shell(`<div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">hunts proposed from live exposure</div><div class="kpi-value">${o.proposals}</div></div>
        <div class="kpi-card"><div class="kpi-label">hunts closed</div><div class="kpi-value">${m.hunts.closed}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">hunts that confirmed activity</div><div class="kpi-value">${m.hunts.confirmed}</div></div>
        <div class="kpi-card"><div class="kpi-label">alerts open</div><div class="kpi-value">${m.alerts.open}</div></div>
      </div>
      <h3>Hunt coverage</h3>
      <p>${m.coverage.pct === null ? "No ATT&CK techniques are tagged on the current findings." : `${m.coverage.hunted} of ${m.coverage.estate_techniques} techniques that appear in your open findings have an active or closed hunt (${m.coverage.pct}%).`}
        ${m.hunts.detections_created} hunt(s) led to a new detection. ${m.queries.run} of ${m.queries.total} queries have a recorded result.</p>
      ${m.coverage.not_hunted.length ? `<p class="muted">Not hunted yet: ${m.coverage.not_hunted.map((t) => escapeHtml(t.technique_id + " " + t.technique_name) + (t.library ? "" : " (no library queries)")).join("; ")}</p>` : ""}
      <h3>Alerts</h3>
      <p>${m.alerts.total} received &middot; ${m.alerts.closed} closed &middot; ${m.alerts.true_positive} true positive &middot; ${m.alerts.false_positive} benign or false positive.</p>
      <p class="muted">Send alerts with an API key that has the <code>soc:write</code> scope: <code>POST /api/ingest/alerts</code>.</p>`);
  }

  async function proposals() {
    const { proposals: ps, note } = await api.huntingProposals();
    shell(`<p class="muted">${escapeHtml(note)}</p>
      ${ps.length ? ps.map((p) => `<div class="card"><h3>${escapeHtml(p.title)}</h3><p>${escapeHtml(p.hypothesis)}</p>
        <p>${techniques(p.techniques)}</p><p><strong>Hosts:</strong> ${p.assets.slice(0, 12).map(escapeHtml).join(", ")}${p.assets.length > 12 ? ` and ${p.assets.length - 12} more` : ""}</p>
        <p class="muted">${p.queries.length} ready-made queries. ${escapeHtml(p.notes || "")}</p>
        <button type="button" data-accept="${escapeHtml(p.source_ref)}">Start this hunt</button></div>`).join("") : '<p class="empty-state">No open known-exploited or high-probability vulnerabilities need a hunt right now.</p>'}`);
    container.querySelectorAll("[data-accept]").forEach((b) => b.addEventListener("click", async () => {
      try { const h = await api.huntingAccept({ source_ref: b.dataset.accept }); openHunt = h.id; tab = "hunts"; show(); } catch (e) { flash(e.message, "error"); }
    }));
  }

  async function hunts() {
    const { hunts: hs } = await api.huntingList();
    const h = openHunt && hs.find((x) => x.id === openHunt);
    if (h) return huntDetail(h);
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Hunt</th><th>Status</th><th>Outcome</th><th>Hosts</th><th></th></tr></thead><tbody>
      ${hs.length ? hs.map((x) => `<tr><td class="wrap-cell"><strong>${escapeHtml(x.title)}</strong><br>${techniques(x.techniques)}</td><td>${escapeHtml(x.status)}</td><td>${escapeHtml(x.outcome || "-")}</td><td>${x.assets.length}</td>
        <td><button type="button" class="link-button" data-open="${x.id}">Open</button></td></tr>`).join("") : '<tr><td colspan="5" class="empty-state">No hunts yet. Start one from the proposals.</td></tr>'}</tbody></table></div>
      <h3>Start a hunt of your own</h3>
      <form id="hf" class="run-form"><label>Title <input name="title" required maxlength="200"></label><label>Hypothesis (what do you expect to find, and why?) <textarea name="hypothesis" rows="3" required></textarea></label>
        <div><button type="submit">Create</button></div></form>`);
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { openHunt = Number(b.dataset.open); show(); }));
    container.querySelector("#hf").addEventListener("submit", async (e) => {
      e.preventDefault();
      try { const r = await api.huntingCreate({ title: e.target.title.value, hypothesis: e.target.hypothesis.value }); openHunt = r.id; show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  function huntDetail(h) {
    shell(`<p><button type="button" class="link-button" id="back">&larr; All hunts</button></p>
      <h3>${escapeHtml(h.title)}</h3><p>${escapeHtml(h.hypothesis)}</p><p>${techniques(h.techniques)}</p>
      <p><strong>Hosts in scope:</strong> ${h.assets.map(escapeHtml).join(", ") || "none"}</p>
      <p><strong>Data you need:</strong> ${h.data_sources.map(escapeHtml).join("; ") || "not specified"}</p>
      <h3>Queries</h3><p class="muted">Run these in your SIEM (they are Splunk SPL; adapt the field names to your data model), then record what happened.</p>
      ${h.queries.length ? h.queries.map((q, i) => `<div class="card"><strong>${escapeHtml(q.technique)}: ${escapeHtml(q.name)}</strong>
        <pre class="code-block">${escapeHtml(q.query)}</pre>
        <label>Result <select data-q="${i}">${RESULTS.map((r) => `<option value="${r}"${(q.result || "") === r ? " selected" : ""}>${r || "(not recorded)"}</option>`).join("")}</select></label></div>`).join("") : '<p class="muted">No queries were generated; write them for your data model.</p>'}
      <form id="df" class="run-form"><label>Notes and findings <textarea name="notes" rows="4">${escapeHtml(h.notes || "")}</textarea></label>
        <label>Follow-ups <textarea name="follow_ups" rows="2">${escapeHtml(h.follow_ups || "")}</textarea></label>
        <label>Status <select name="status">${["proposed", "active", "closed"].map((s) => `<option${s === h.status ? " selected" : ""}>${s}</option>`).join("")}</select></label>
        <label>Outcome <select name="outcome">${["", "confirmed", "not-found", "needs-data"].map((s) => `<option value="${s}"${(h.outcome || "") === s ? " selected" : ""}>${s || "(none yet)"}</option>`).join("")}</select></label>
        <label><input type="checkbox" name="detection_created"${h.detection_created ? " checked" : ""}> This hunt led to a new detection</label>
        <div><button type="submit">Save</button></div></form>`);
    container.querySelector("#back").addEventListener("click", () => { openHunt = null; show(); });
    container.querySelector("#df").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      const queries = h.queries.map((q, i) => ({ ...q, result: container.querySelector(`[data-q="${i}"]`).value || null }));
      const body = { notes: f.notes.value, follow_ups: f.follow_ups.value, status: f.status.value, detection_created: f.detection_created.checked, queries };
      if (f.outcome.value) body.outcome = f.outcome.value;
      try { await api.huntingUpdate(h.id, body); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function alerts() {
    const { alerts: as } = await api.socAlerts();
    const a = openAlert && as.find((x) => x.id === openAlert);
    if (a) return alertDetail(await api.socAlert(a.id));
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Alert</th><th>Severity</th><th>Host</th><th>Priority</th><th>Why</th><th>Status</th><th></th></tr></thead><tbody>
      ${as.length ? as.map((x) => `<tr><td class="wrap-cell">${escapeHtml(x.title)}<br><span class="muted">${escapeHtml(x.source)}${x.technique ? " &middot; " + escapeHtml(x.technique) : ""}</span></td>
        <td><span class="badge ${SEV[x.severity]}">${escapeHtml(x.severity)}</span></td><td>${escapeHtml(x.asset || "-")}</td><td><strong>${x.context.priority}</strong></td>
        <td class="wrap-cell"><span class="muted">${x.context.reasons.map(escapeHtml).join("; ")}</span></td><td>${escapeHtml(x.status)}${x.disposition ? "<br>" + escapeHtml(x.disposition) : ""}</td>
        <td><button type="button" class="link-button" data-open="${x.id}">Open</button></td></tr>`).join("") : '<tr><td colspan="7" class="empty-state">No alerts yet. Send them from your SIEM or XDR with a <code>soc:write</code> API key.</td></tr>'}</tbody></table></div>`);
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { openAlert = Number(b.dataset.open); show(); }));
  }

  function alertDetail(a) {
    const c = a.context;
    shell(`<p><button type="button" class="link-button" id="back">&larr; All alerts</button></p>
      <h3>${escapeHtml(a.title)}</h3><p><span class="badge ${SEV[a.severity]}">${escapeHtml(a.severity)}</span> ${escapeHtml(a.source)} ${a.asset ? "&middot; host " + escapeHtml(a.asset) : ""} ${a.technique ? "&middot; " + escapeHtml(a.technique) : ""}</p>
      <p>${escapeHtml(a.detail || "")}</p>
      <h3>What Quanta knows about this host</h3>
      <p>Priority <strong>${c.priority}</strong>: ${c.reasons.map(escapeHtml).join("; ")}.</p>
      <p>Owner: ${escapeHtml(c.owner || "none recorded")} &middot; ${c.open_findings} open finding(s), ${c.kev_findings} known-exploited.</p>
      ${c.findings.length ? `<ul class="guidance-list">${c.findings.map((f) => `<li>${f.kev ? '<span class="badge badge-critical">KEV</span> ' : ""}${f.related_to_alert ? '<span class="badge badge-high">matches this alert</span> ' : ""}${escapeHtml(f.id)} ${escapeHtml(f.title || "")} (${escapeHtml(f.severity || "")}${f.cve ? ", " + escapeHtml(f.cve) : ""})</li>`).join("")}</ul>` : ""}
      ${c.runbook ? `<h3>Runbook: ${escapeHtml(c.runbook.title)}</h3><ol>${c.runbook.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol><p class="muted">Quanta shows the steps; responding stays with your team or SOAR.</p>` : ""}
      <form id="af" class="run-form"><label>Status <select name="status">${["new", "investigating", "closed"].map((s) => `<option${s === a.status ? " selected" : ""}>${s}</option>`).join("")}</select></label>
        <label>Disposition <select name="disposition">${["", "true-positive", "benign", "false-positive", "needs-data"].map((s) => `<option value="${s}"${(a.disposition || "") === s ? " selected" : ""}>${s || "(none yet)"}</option>`).join("")}</select></label>
        <label>Assignee <input name="assignee" value="${escapeHtml(a.assignee || "")}" placeholder="name@company.com"></label>
        <label>Notes <textarea name="notes" rows="3">${escapeHtml(a.notes || "")}</textarea></label><div><button type="submit">Save</button></div></form>`);
    container.querySelector("#back").addEventListener("click", () => { openAlert = null; show(); });
    container.querySelector("#af").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, body = { status: f.status.value, assignee: f.assignee.value, notes: f.notes.value };
      if (f.disposition.value) body.disposition = f.disposition.value;
      try { await api.socUpdateAlert(a.id, body); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show() {
    try { await { overview, proposals, hunts, alerts }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
