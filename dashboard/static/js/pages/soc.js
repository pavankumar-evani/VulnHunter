import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "SOC Operations";

const TABS = [["queues", "Incidents"], ["metrics", "Metrics"], ["analyse", "Logs and techniques"], ["analysts", "Analysts"], ["decisions", "Decisions"]];
const PRIO = { P1: "badge-critical", P2: "badge-high", P3: "badge-medium", P4: "badge-low" };
const SLA = { ok: "badge-low", at_risk: "badge-high", breached: "badge-critical" };
const NOTE = "Cases are worked in three queues: L1 triage, L2 investigation, L3 response and hunting. Priority is impact times urgency. Escalating, resolving or closing needs a written summary, so the next person never starts cold. Quanta records and measures the work; it never changes your systems.";
const pct = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
const mins = (v) => (v == null ? "n/a" : v >= 120 ? `${(v / 60).toFixed(1)} h` : `${Math.round(v)} min`);
const when = (s) => (s ? s.replace("T", " ").replace("Z", " UTC") : "");

function slaCell(c) {
  const s = c.sla || {};
  const parts = ["ack", "pickup", "resolve"].filter((k) => s[k]).map((k) => `${k} ${s[k].done ? s[k].state : mins(Math.max(0, s[k].remaining_minutes)) + " left"}`);
  return `<span class="badge ${SLA[s.worst] || "badge-outline"}">${escapeHtml(s.worst || "")}</span> <span class="muted">${escapeHtml(parts.join(", "))}</span>`;
}

function bars(rows, key, color) {
  const max = Math.max(1, ...rows.map((r) => r[key]));
  return rows.map((r) => `<div style="display:flex;align-items:center;gap:6px;font-size:12px"><span style="width:72px" class="muted">${escapeHtml(r.date.slice(5))}</span>
    <span style="display:inline-block;height:8px;width:${Math.round((r[key] / max) * 160)}px;background:${color}"></span><span>${r[key]}</span></div>`).join("");
}

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "queues";
  let openCase = null;
  let openIncident = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab && !openCase && !openIncident ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="soc-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; openCase = null; openIncident = null; show(); }));
  };
  const act = (fn, msg) => async () => { try { await fn(); if (msg) flash(msg, "success"); show(); } catch (e) { flash(e.message, "error"); } };

  // Incidents are created and routed automatically; this view is the work queue. Creating one by hand is an exception, behind the "More" menu, and needs a reason.
  async function queues() {
    const [{ incidents }, lane] = await Promise.all([api.socIncidents({ open_only: "true" }), api.socIncidents({ status: "auto_closed" })]);
    const row = (i) => `<tr>
        <td><span class="badge ${PRIO[i.priority] || "badge-outline"}">${escapeHtml(i.priority)}</span></td>
        <td><a href="#" data-inc="${i.id}"><strong>#${i.id} ${escapeHtml(i.title)}</strong></a><br><span class="muted">${escapeHtml(i.severity)} &middot; ${escapeHtml(i.status)}${i.confidence == null ? "" : " &middot; " + pct(i.confidence) + " likely real"}</span></td>
        <td>${i.assignee ? escapeHtml(i.assignee) : `<span class="badge badge-high">${escapeHtml(i.queue || "unrouted")} queue</span>`}</td>
        <td class="muted" style="max-width:360px">${escapeHtml((i.routing_reason || []).slice(-1)[0] || "")}</td>
        <td>${slaCell(i)}</td></tr>`;
    shell(`<p class="muted">Alerts are grouped into incidents and routed to the right analyst or queue automatically, with the reason shown. ${incidents.length} open.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Priority</th><th>Incident</th><th>Assigned to</th><th>Why routed here</th><th>Service level</th></tr></thead><tbody>
      ${incidents.map(row).join("") || '<tr><td colspan="5" class="empty-state">No open incidents.</td></tr>'}</tbody></table></div>
      <h3>Auto-closed <span class="muted">${lane.incidents.length}</span></h3><p class="muted">Closed automatically as likely false positives under the decision policy. Review them; undo returns one to the queue.</p>
      ${lane.incidents.slice(0, 20).map((i) => `<p>#${i.id} ${escapeHtml(i.title)} <button type="button" class="secondary-button" data-undo="${i.id}">Undo</button></p>`).join("") || '<p class="muted">None.</p>'}
      <details><summary class="muted">More</summary>
        <h4>Create an incident by hand (exception)</h4><p class="muted">Use this only when no alert exists to start from. A reason is required and is recorded.</p>
        <form id="nc" class="run-form"><label>Title <input name="title" required maxlength="300"></label>
          <label>Severity <select name="severity">${["Critical", "High", "Medium", "Low", "Informational"].map((s) => `<option ${s === "Medium" ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <label>Hosts (comma separated) <input name="assets"></label><label>Reason <input name="reason" required minlength="10"></label>
          <div><button type="submit" class="secondary-button">Create incident</button></div></form></details>`);
    container.querySelectorAll("[data-inc]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openIncident = Number(a.dataset.inc); show(); }));
    container.querySelectorAll("[data-undo]").forEach((b) => b.addEventListener("click", act(() => api.socIncidentAct(b.dataset.undo, "undo-auto-close", {}), "Returned to the queue.")));
    container.querySelector("#nc").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        const i = await api.socIncidentManual({ title: f.title.value, severity: f.severity.value, assets: f.assets.value.split(",").map((x) => x.trim()).filter(Boolean), reason: f.reason.value });
        openIncident = i.id; flash("Incident created.", "success"); show();
      } catch (err) { flash(err.message, "error"); }
    });
  }

  async function incidentView() {
    const i = await api.socIncident(openIncident);
    const live = ["new", "triaging", "investigating", "contained"].includes(i.status);
    shell(`<p><a href="#" id="back">&larr; Incidents</a></p>
      <h2><span class="badge ${PRIO[i.priority] || "badge-outline"}">${escapeHtml(i.priority)}</span> #${i.id} ${escapeHtml(i.title)}</h2>
      <p>${escapeHtml(i.status)} &middot; ${escapeHtml(i.severity)}${i.severity !== i.base_severity ? ` (raised from ${escapeHtml(i.base_severity)})` : ""} &middot; L${i.tier} &middot; owner ${escapeHtml(i.assignee || "none, in the " + (i.queue || "") + " queue")} ${i.sla ? "&middot; " + slaCell(i) : ""}</p>
      <h3>Summary</h3><p>${escapeHtml(i.summary || "")}</p>
      <h3>Why it was routed here</h3><ul>${(i.routing_reason || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
      <h3>Kill chain</h3><p>${(i.kill_chain || []).map((s) => escapeHtml(s.tactic)).join(" &rarr; ") || '<span class="muted">No mapped tactic yet.</span>'}</p>
      <h3>Alerts (${i.alerts.length})</h3><ul>${i.alerts.map((a) => `<li>#${a.id} ${escapeHtml(a.title)} <span class="muted">${escapeHtml(a.role)}; ${escapeHtml(a.asset || "no host")}; ${(a.reasons || []).map((r) => escapeHtml(r.detail)).join(" ")}</span></li>`).join("")}</ul>
      <h3>Recommended next</h3><ul>${(i.recommended.next_steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("")}${(i.recommended.playbooks || []).map((p) => `<li>Playbook: ${escapeHtml(p.name)} <span class="muted">${escapeHtml(p.why)}</span></li>`).join("")}</ul>
      ${live ? `<h3>Work it</h3><textarea id="txt" rows="3" style="width:100%" placeholder="Summary for escalate or resolve (at least 20 characters), or a note"></textarea>
        <p><button type="button" data-do="accept">Accept</button>
        <select id="adv">${["triaging", "investigating", "contained"].map((s) => `<option>${s}</option>`).join("")}</select> <button type="button" class="secondary-button" data-do="advance">Set status</button>
        <button type="button" class="secondary-button" data-do="note">Add note</button>
        ${i.tier < 3 ? `<button type="button" class="secondary-button" data-do="escalate">Escalate to L${i.tier + 1}</button>` : ""}</p>
        <p>Verdict <select id="verdict">${["true-positive", "false-positive", "benign", "duplicate", "insufficient-data", "accepted-risk"].map((v) => `<option>${v}</option>`).join("")}</select> <button type="button" data-do="resolve">Resolve</button>
        &nbsp; Reassign to <input id="who" type="email" placeholder="analyst email"> <button type="button" class="secondary-button" data-do="reassign">Reassign</button></p>` : ""}
      ${i.status === "resolved" ? '<p><textarea id="txt" rows="2" style="width:100%" placeholder="Why reopen?"></textarea></p><p><button type="button" class="secondary-button" data-do="reopen">Reopen</button></p>' : ""}
      ${i.status === "auto_closed" ? '<p><button type="button" data-do="undo-auto-close">Undo auto-close</button></p>' : ""}
      ${i.case_id ? `<p class="muted"><a href="#" id="tocase">Open its case (#${i.case_id})</a> for log analysis and service-level detail.</p>` : ""}
      <h3>Timeline</h3><ul>${i.timeline.map((e) => `<li><span class="muted">${when(e.created_at)}</span> <strong>${escapeHtml(e.kind.replace(/_/g, " "))}</strong> ${escapeHtml(e.actor || "")} ${e.body ? "&mdash; " + escapeHtml(e.body) : ""}</li>`).join("")}</ul>`);
    container.querySelector("#back").addEventListener("click", (e) => { e.preventDefault(); openIncident = null; show(); });
    const tc = container.querySelector("#tocase");
    if (tc) tc.addEventListener("click", (e) => { e.preventDefault(); openCase = i.case_id; openIncident = null; show(); });
    const txt = () => (container.querySelector("#txt") || {}).value || "";
    const doit = {
      accept: () => api.socIncidentAct(i.id, "accept", {}), advance: () => api.socIncidentAct(i.id, "advance", { status: container.querySelector("#adv").value }),
      note: () => api.socIncidentAct(i.id, "note", { note: txt() }), escalate: () => api.socIncidentAct(i.id, "escalate", { summary: txt() }),
      resolve: () => api.socIncidentAct(i.id, "resolve", { verdict: container.querySelector("#verdict").value, summary: txt() }),
      reassign: () => api.socIncidentAct(i.id, "reassign", { assignee: container.querySelector("#who").value }), reopen: () => api.socIncidentAct(i.id, "reopen", { reason: txt() }),
      "undo-auto-close": () => api.socIncidentAct(i.id, "undo-auto-close", {}),
    };
    container.querySelectorAll("[data-do]").forEach((b) => b.addEventListener("click", act(doit[b.dataset.do], "Done.")));
  }

  async function caseView() {
    const c = await api.socCase(openCase);
    const { policy } = await api.socCases({ open_only: "true" });
    const isOpen = ["new", "in_progress", "pending", "escalated"].includes(c.status);
    const codes = policy.tiers[c.tier].may_resolve_as;
    shell(`<p><a href="#" id="back">&larr; Incidents</a></p>
      <h2><span class="badge ${PRIO[c.priority]}">${c.priority}</span> #${c.id} ${escapeHtml(c.title)}</h2>
      <p>${escapeHtml(c.queue)} queue &middot; ${escapeHtml(c.status)} &middot; owner ${escapeHtml(c.assignee || "none")} &middot; impact ${escapeHtml(c.impact)} &middot; severity ${escapeHtml(c.severity)} &middot; ${slaCell(c)}</p>
      <h3>Summary</h3><p>${escapeHtml(c.summary || c.generated_summary)}</p>${c.summary ? `<details><summary class="muted">Generated from the case facts</summary><p class="muted">${escapeHtml(c.generated_summary)}</p></details>` : ""}
      <p class="muted">Techniques: ${c.techniques.map((t) => escapeHtml(t.id + (t.name ? " " + t.name : ""))).join(", ") || "none yet"} &middot; Hosts: ${escapeHtml(c.assets.join(", ") || "none")} &middot; Alerts: ${c.alerts.map((a) => "#" + a.id + " " + escapeHtml(a.title)).join("; ") || "none"}</p>
      ${isOpen ? `<h3>Work the case</h3>
        <p><button type="button" data-do="assign">Take it</button> ${c.suggested_assignee ? `<button type="button" class="secondary-button" data-do="assign-sug">Assign to ${escapeHtml(c.suggested_assignee)}</button>` : ""}
        <button type="button" class="secondary-button" data-do="pending">Mark waiting</button></p>
        <textarea id="txt" rows="4" style="width:100%" placeholder="Note or summary. A summary of at least 20 characters is required to escalate, resolve or close: what you found, what you did, what is left."></textarea>
        <p><button type="button" class="secondary-button" data-do="note">Add note</button>
        ${c.tier < 3 ? '<button type="button" data-do="escalate">Escalate to L' + (c.tier + 1) + "</button>" : ""}
        <select id="res">${codes.map((x) => `<option>${escapeHtml(x)}</option>`).join("")}</select> <button type="button" data-do="resolve">Resolve</button></p>` : ""}
      ${c.status === "resolved" ? '<p><textarea id="txt" rows="2" style="width:100%" placeholder="Closing note (optional if the resolution summary stands)"></textarea></p><p><button type="button" data-do="close">Close</button> <button type="button" class="secondary-button" data-do="reopen">Reopen</button></p>' : ""}
      ${c.status === "closed" ? '<p><textarea id="txt" rows="2" style="width:100%" placeholder="Why reopen?"></textarea></p><p><button type="button" class="secondary-button" data-do="reopen">Reopen</button></p>' : ""}
      <h3>Investigate logs</h3><textarea id="logs" rows="5" style="width:100%" placeholder="Paste log lines (JSON, key=value or plain text). Analysed here; nothing leaves Quanta."></textarea>
      <p><button type="button" class="secondary-button" id="runlogs">Analyse logs</button></p><div id="logout"></div>
      <h3>History</h3><ul>${c.events.map((e) => `<li><span class="muted">${when(e.created_at)}</span> <strong>${escapeHtml(e.kind.replace("_", " "))}</strong> ${escapeHtml(e.actor || "")} ${e.body ? "&mdash; " + escapeHtml(e.body) : ""}</li>`).join("")}</ul>`);
    container.querySelector("#back").addEventListener("click", (e) => { e.preventDefault(); openCase = null; show(); });
    const txt = () => (container.querySelector("#txt") || {}).value || "";
    const doit = {
      assign: () => api.socCaseAct(c.id, "assign", {}), "assign-sug": () => api.socCaseAct(c.id, "assign", { assignee: c.suggested_assignee }),
      pending: () => api.socCaseAct(c.id, "pending", { reason: txt() }), note: () => api.socCaseAct(c.id, "note", { note: txt() }),
      escalate: () => api.socCaseAct(c.id, "escalate", { summary: txt() }), resolve: () => api.socCaseAct(c.id, "resolve", { resolution: container.querySelector("#res").value, summary: txt() }),
      close: () => api.socCaseAct(c.id, "close", { summary: txt() }), reopen: () => api.socCaseAct(c.id, "reopen", { reason: txt() }),
    };
    container.querySelectorAll("[data-do]").forEach((b) => b.addEventListener("click", act(doit[b.dataset.do], "Done.")));
    container.querySelector("#runlogs").addEventListener("click", async () => {
      try { container.querySelector("#logout").innerHTML = logHtml(await api.socCaseLogs(c.id, { text: container.querySelector("#logs").value })); } catch (e) { flash(e.message, "error"); }
    });
  }

  function logHtml(r) {
    if (!r.lines) return '<p class="empty-state">No log lines to analyse.</p>';
    const li = (a) => (a.length ? `<ul>${a.join("")}</ul>` : '<p class="muted">None found.</p>');
    return `<p>${r.lines} lines read, ${r.with_timestamp} with a timestamp.</p>
      <h4>Techniques suggested ${r.techniques_confident ? "" : '<span class="badge badge-outline">weak</span>'}</h4>${li((r.techniques || []).map((t) => `<li><strong>${escapeHtml(t.id)}</strong> ${escapeHtml(t.name || "")} (${Math.round(t.probability * 100)}%) &mdash; ${escapeHtml((t.evidence || []).join(", "))}</li>`))}
      <h4>Regular-interval connections</h4>${li((r.beaconing || []).map((b) => `<li>${escapeHtml(b.source)} to ${escapeHtml(b.destination)}: ${b.events} events every ~${b.mean_interval_seconds}s (variation ${b.regularity_cv})</li>`))}
      <h4>Bursts</h4>${li((r.bursts || []).map((b) => `<li>${escapeHtml(b.minute)}: ${b.events} events (z ${b.z_score}, normal ${b.baseline_mean}/min)</li>`))}
      <h4>Failures then success</h4>${li((r.auth_pattern || []).map((a) => `<li>${escapeHtml(a.who)}: ${a.failures_before_success} failures, then a success at line ${a.success_line}</li>`))}
      <h4>Indicators</h4>${li(Object.entries(r.indicators || {}).map(([k, v]) => `<li>${escapeHtml(k)}: ${escapeHtml(v.join(", "))}</li>`))}
      <h4>Suspicious lines</h4>${li((r.suspicious_lines || []).map((s) => `<li>line ${s.n}: <code>${escapeHtml(s.line)}</code></li>`))}
      <p class="muted">${escapeHtml(r.caveat || "")}</p>`;
  }

  async function metrics() {
    const m = await api.socMetrics(30);
    const k = (label, v) => `<div class="kpi-card"><div class="kpi-label">${label}</div><div class="kpi-value">${v}</div></div>`;
    const acc = m.recommendation_accuracy;
    shell(`<p class="muted">The last ${m.window_days} days, computed from case timestamps. Nothing is estimated.</p>
      <div class="kpi-grid">${k("Opened", m.totals.opened)}${k("Resolved", m.totals.resolved)}${k("Open now", m.totals.open_now)}${k("Unowned", m.totals.unowned_open)}
        ${k("MTTA", mins(m.mtta_minutes))}${k("MTTR", mins(m.mttr_minutes))}${k("MTTR median", mins(m.mttr_median_minutes))}${k("MTTR p90", mins(m.mttr_p90_minutes))}
        ${k("False-positive rate", pct(m.false_positive_rate))}${k("Escalated", pct(m.escalation.rate))}${k("Reopened", pct(m.escalation.reopen_rate))}${k("Automatically opened", pct(m.automation_rate))}</div>
      <h3>From alert to action</h3><p class="muted">Measured from when each alert arrived (${m.timing.alerts_received} alert(s) in the window).</p>
        <div class="kpi-grid">${k("To first investigation", mins(m.timing.alert_to_investigation_minutes))}${k("To a case", mins(m.timing.alert_to_case_minutes))}${k("To a person acknowledging", mins(m.timing.alert_to_acknowledged_minutes))}${k("Investigated before anyone touched it", pct(m.timing.investigated_automatically_share))}</div>
      <h3>Service levels</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Clock</th><th>Finished</th><th>Met</th><th>Compliance</th><th>Open at risk</th><th>Open breached</th></tr></thead><tbody>
        ${["ack", "pickup", "resolve"].map((c) => `<tr><td>${c}</td><td>${m.sla[c].finished}</td><td>${m.sla[c].met}</td><td>${pct(m.sla[c].compliance)}</td><td>${m.sla[c].open_at_risk}</td><td>${m.sla[c].open_breached}</td></tr>`).join("")}</tbody></table></div>
      <h3>Backlog</h3><p>By queue: ${Object.entries(m.backlog.by_queue).map(([q, n]) => `${q} ${n}`).join(", ") || "none"} &middot; By priority: ${Object.entries(m.backlog.by_priority).map(([q, n]) => `${q} ${n}`).join(", ") || "none"} &middot; Oldest open: ${m.backlog.oldest_open_hours == null ? "n/a" : m.backlog.oldest_open_hours + " h"}</p>
      <h3>Resolution mix</h3><p>${Object.entries(m.resolution_mix).map(([q, n]) => `${escapeHtml(q)} ${n}`).join(", ") || "No resolved cases yet."}</p>
      <h3>Does the recommendation hold up?</h3><p class="muted">When the first-look investigation recommended something, how often the analyst's resolution agreed. ${m.recommendation_judged} case(s) judged.</p>
        <ul>${Object.entries(acc).map(([q, v]) => `<li>${escapeHtml(q)}: ${v.agreed} of ${v.judged} agreed (${pct(v.rate)})</li>`).join("")}</ul>
      <h3>Analyst workload</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Analyst</th><th>Open</th><th>Resolved</th><th>Mean time to resolve</th></tr></thead><tbody>
        ${m.analyst_workload.map((a) => `<tr><td>${escapeHtml(a.analyst)}</td><td>${a.open}</td><td>${a.resolved}</td><td>${mins(a.mean_minutes_to_resolve)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty-state">No assigned cases yet.</td></tr>'}</tbody></table></div>
      <h3>Per day</h3><div style="display:grid;grid-template-columns:1fr 1fr;gap:16px"><div><strong>Opened</strong>${bars(m.daily.slice(-14), "opened", "#6ea8fe")}</div><div><strong>Resolved</strong>${bars(m.daily.slice(-14), "resolved", "#5fd3a0")}</div></div>`);
  }

  async function analyse() {
    shell(`<h3>Identify techniques</h3><p class="muted">Paste an alert, a log excerpt or your own notes. A Naive Bayes classifier trained on the technique phrase list, the hunt library and alerts your analysts confirmed gives the likely ATT&amp;CK techniques with the words that drove each answer. It recognises wording, not behaviour: treat it as a lead.</p>
      <textarea id="tt" rows="4" style="width:100%"></textarea><p><button type="button" id="tgo">Identify</button></p><div id="tout"></div>
      <h3>Analyse logs</h3><textarea id="lt" rows="6" style="width:100%" placeholder="Log lines"></textarea><p><button type="button" id="lgo">Analyse</button></p><div id="lout"></div>`);
    container.querySelector("#tgo").addEventListener("click", async () => {
      try {
        const r = await api.socTtp({ text: container.querySelector("#tt").value });
        container.querySelector("#tout").innerHTML = r.techniques.length ? `<p>${r.confident ? "Confident" : '<span class="badge badge-outline">weak</span> Not confident'}</p><ul>${r.techniques.map((t) => `<li><strong>${escapeHtml(t.id)}</strong> ${escapeHtml(t.name || "")} &middot; ${escapeHtml(t.tactic || "")} &middot; ${Math.round(t.probability * 100)}% &mdash; ${escapeHtml(t.evidence.join(", "))}</li>`).join("")}</ul>` : '<p class="empty-state">No technique recognised.</p>';
      } catch (e) { flash(e.message, "error"); }
    });
    container.querySelector("#lgo").addEventListener("click", async () => {
      try { container.querySelector("#lout").innerHTML = logHtml(await api.socAnalyseLogs({ text: container.querySelector("#lt").value })); } catch (e) { flash(e.message, "error"); }
    });
  }

  async function analysts() {
    const { analysts: list } = await api.socAnalysts();
    shell(`<p class="muted">An analyst belongs to one tier and cannot be assigned a case in a higher queue. Suggestions go to the least-loaded analyst of the tier who is under the cap.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Analyst</th><th>Tier</th><th>Open cases</th><th>Specialties</th><th>Shift (UTC)</th><th>Available</th><th></th></tr></thead><tbody>
      ${list.map((a) => `<tr><td>${escapeHtml(a.email)}</td><td>L${a.tier}</td><td>${a.open_cases}${a.at_capacity ? ' <span class="badge badge-high">at capacity</span>' : ""}</td><td><button type="button" class="link-button danger-link" data-rm="${escapeHtml(a.email)}">Remove</button></td></tr>`).join("") || '<tr><td colspan="4" class="empty-state">No analysts yet.</td></tr>'}</tbody></table></div>
      <form id="af" class="run-form"><label>Email <input name="email" type="email" required></label><label>Tier <select name="tier"><option value="1">L1</option><option value="2">L2</option><option value="3">L3</option></select></label><div><button type="submit">Add or move</button></div></form>`);
    container.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", act(() => api.socAnalystRemove(b.dataset.rm), "Removed.")));
    container.querySelector("#af").addEventListener("submit", (e) => { e.preventDefault(); act(() => api.socAnalystAdd({ email: e.target.email.value, tier: Number(e.target.tier.value) }), "Saved.")(); });
  }

  async function decisions() {
    const r = await api.decisionCalibration();
    const rows = Object.entries(r.decisions).map(([name, d]) => {
      const bands = d.bands ? Object.entries(d.bands).map(([b, v]) => `${b}: ${v.override_rate == null ? `${v.n} outcome(s), too few` : `${pct(v.override_rate)} overridden of ${v.n}`}`).join("; ") : "";
      const measured = d.status === "measured";
      return `<tr><td>${escapeHtml(name)}</td><td>${d.logged}</td><td>${d.judged}</td>
        <td>${measured ? `Brier ${d.brier}, ECE ${d.ece} ${d.calibrated ? "(within limit)" : "(<strong>not calibrated</strong>)"}, overridden ${pct(d.override_rate)}` : escapeHtml(d.message || "")}</td>
        <td>${escapeHtml(bands)}</td><td>${Object.entries(d.routes).map(([k, n]) => `${k} ${n}`).join(", ")}</td></tr>`;
    }).join("");
    const recs = Object.entries(r.decisions).flatMap(([n, d]) => (d.recommendations || []).map((x) => `<li><strong>${escapeHtml(n)}</strong>: ${escapeHtml(x.message)}</li>`)).join("");
    shell(`<p class="muted">Every typed decision (alert verdict, finding routing, change approval) is logged with its stated probability and, later, what the person did with it. Nothing is called calibrated until enough outcomes exist. ${escapeHtml(r.note)}</p>
      <div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">Judged outcomes</div><div class="kpi-value">${r.judged_total}</div></div>
        <div class="kpi-card"><div class="kpi-label">Model calls avoided (estimate)</div><div class="kpi-value">${r.model_calls_avoided}</div></div></div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Decision</th><th>Logged</th><th>Judged</th><th>Calibration</th><th>Override rate by confidence band</th><th>Routes</th></tr></thead><tbody>${rows}</tbody></table></div>
      <h3>Suggested changes</h3>${recs ? `<ul>${recs}</ul><p class="muted">Advice only. Edit remediation/config/decision_policy.yaml yourself if you agree.</p>` : '<p class="muted">None.</p>'}`);
  }

  async function show() {
    try {
      if (openIncident) return await incidentView();
      if (openCase) return await caseView();
      return await ({ queues, metrics, analyse, analysts, decisions }[tab] || queues)();
    } catch (e) { container.innerHTML = `<p class="empty-state">${escapeHtml(e.message)}</p>`; }
  }
  await show();
}
