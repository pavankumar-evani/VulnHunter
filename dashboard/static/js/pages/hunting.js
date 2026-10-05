import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Hunting & SOC";

const TABS = [["overview", "Overview"], ["alerts", "Alert triage"], ["intel", "Threat intel"], ["proposals", "Proposed hunts"], ["hunts", "Hunts"], ["detections", "Detection engineering"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low", Informational: "badge-outline" };
const NOTE = "Quanta is not a SIEM. It knows which assets carry exploitable vulnerabilities, so it proposes where to look, adds that context to alerts and judges how well your detections work. Searches in your SIEM are read-only and only run when you confirm.";
const RESULTS = ["", "hits", "no-hits", "not-run", "error"];
const ASSESS = ["", "benign", "suspicious", "malicious"];
const VERDICT = { "likely-true-positive": "badge-critical", "likely-false-positive": "badge-low", "escalate-l2": "badge-high" };
const LEAD = { "not-run": "badge-outline", "no-hits": "badge-low", "likely-fp": "badge-low", "possible-tp": "badge-high", "confirmed-tp": "badge-critical" };
const OVERALL = { incomplete: "badge-outline", "no-findings": "badge-low", "low-confidence": "badge-medium", "multi-hit-correlated": "badge-high", "confirmed-compromise": "badge-critical" };
const TIER = { high_fidelity: "badge-auto_approvable", healthy: "badge-low", noisy: "badge-medium", critical_noise: "badge-critical", low_value: "badge-high", low_volume: "badge-outline" };
const PRIO = { high: "badge-critical", medium: "badge-medium", low: "badge-outline" };

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
  const pct = (x) => (x === null || x === undefined ? "-" : Math.round(x * 100) + "%");

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
      <p class="muted">Send alerts with an API key that has the <code>soc:write</code> scope: <code>POST /api/ingest/alerts</code>, or OCSF Detection Findings to <code>POST /api/ingest/alerts/ocsf</code>. Threat-intelligence reports go to <code>POST /api/ingest/threat-intel</code>.
      To run searches and look up indicators, add a "Splunk search" and an "Indicator reputation" connection on the Connections page.</p>`);
  }

  async function intel() {
    const { reports } = await api.huntingIntelList();
    shell(`<p class="muted">Paste a threat-intelligence report (advisory text, or a STIX 2.1 bundle). Quanta extracts the CVEs, ATT&CK techniques, actors and indicators, scores how much it matters to <em>your</em> estate, and can start a hunt from it.</p>
      <form id="inf" class="run-form"><label>Title (optional) <input name="title" maxlength="160"></label><label>Source (optional) <input name="source" placeholder="advisory name or feed"></label>
        <label>Report text or STIX JSON <textarea name="content" rows="8" required></textarea></label><div><button type="submit">Analyse report</button></div></form>
      <h3>Reports</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Report</th><th>Relevance</th><th>Why</th><th>Found</th><th></th></tr></thead><tbody>
      ${reports.length ? reports.map((r) => `<tr><td class="wrap-cell"><strong>${escapeHtml(r.title)}</strong><br><span class="muted">${escapeHtml(r.source || "")} ${escapeHtml(r.received_at)}</span></td>
        <td><span class="badge ${PRIO[r.priority]}">${escapeHtml(r.priority)}</span> ${r.relevance}</td><td class="wrap-cell"><span class="muted">${r.reasons.map(escapeHtml).join("; ")}</span></td>
        <td class="wrap-cell">${r.extracted.cves.length} CVE &middot; ${r.extracted.techniques.length} technique &middot; ${r.extracted.ips.length + r.extracted.domains.length + r.extracted.hashes.length + r.extracted.urls.length} indicator${r.extracted.actors.length ? "<br>" + r.extracted.actors.map(escapeHtml).join(", ") : ""}</td>
        <td>${r.hunt_id ? `<button type="button" class="link-button" data-gohunt="${r.hunt_id}">Open hunt</button>` : `<button type="button" data-hunt="${r.id}">Start a hunt</button>`}</td></tr>`).join("") : '<tr><td colspan="5" class="empty-state">No reports yet.</td></tr>'}</tbody></table></div>`);
    container.querySelector("#inf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const r = await api.huntingIntelAdd({ content: f.content.value, title: f.title.value || null, source: f.source.value || null }); flash(r.created ? `Analysed: ${r.priority} relevance.` : "That report was already analysed.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-hunt]").forEach((b) => b.addEventListener("click", async () => { try { const h = await api.huntingIntelHunt(Number(b.dataset.hunt)); openHunt = h.id; tab = "hunts"; show(); } catch (e) { flash(e.message, "error"); } }));
    container.querySelectorAll("[data-gohunt]").forEach((b) => b.addEventListener("click", () => { openHunt = Number(b.dataset.gohunt); tab = "hunts"; show(); }));
  }

  async function proposals() {
    const { proposals: ps, note } = await api.huntingProposals();
    shell(`<p class="muted">${escapeHtml(note)}</p>
      ${ps.length ? ps.map((p) => `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:4px 18px 14px;margin:14px 0"><h3>${escapeHtml(p.title)}</h3><p>${escapeHtml(p.hypothesis)}</p>
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
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Hunt</th><th>Verdict</th><th>Status</th><th>Outcome</th><th>Hosts</th><th></th></tr></thead><tbody>
      ${hs.length ? hs.map((x) => `<tr><td class="wrap-cell"><strong>${escapeHtml(x.title)}</strong><br>${techniques(x.techniques)}</td><td><span class="badge ${OVERALL[x.verdict.overall]}">${escapeHtml(x.verdict.overall)}</span></td>
        <td>${escapeHtml(x.status)}</td><td>${escapeHtml(x.outcome || "-")}</td><td>${x.assets.length}</td><td><button type="button" class="link-button" data-open="${x.id}">Open</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No hunts yet. Start one from the proposals or a threat-intelligence report.</td></tr>'}</tbody></table></div>
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
    const v = h.verdict;
    shell(`<p><button type="button" class="link-button" id="back">&larr; All hunts</button></p>
      <h3>${escapeHtml(h.title)} <span class="badge ${OVERALL[v.overall]}">${escapeHtml(v.overall)}</span></h3><p>${escapeHtml(h.hypothesis)}</p><p>${techniques(h.techniques)}</p>
      <p><strong>Hosts in scope:</strong> ${h.assets.map(escapeHtml).join(", ") || "none"}</p>
      <p><strong>Data you need:</strong> ${h.data_sources.map(escapeHtml).join("; ") || "not specified"}</p>
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">trial hits run</div><div class="kpi-value">${h.summary.run} of ${h.summary.total}</div></div>
        <div class="kpi-card"><div class="kpi-label">returned results</div><div class="kpi-value">${h.summary.with_hits}</div></div>
        <div class="kpi-card"><div class="kpi-label">entities in the results</div><div class="kpi-value">${h.summary.entities.length}</div></div>
        <div class="kpi-card"><div class="kpi-label">techniques without a rule</div><div class="kpi-value">${h.summary.gaps.length}</div></div></div>
      <p>${escapeHtml(h.summary.headline)}</p>${h.summary.executive_summary.map((x) => `<p class="muted">${escapeHtml(x)}</p>`).join("")}
      ${h.queries.length ? `<p><button type="button" id="run-all">Run all leads in the SIEM</button> <label>Look back <select id="ra-earliest"><option value="-24h">24 hours</option><option value="-7d">7 days</option><option value="-30d">30 days</option><option value="-90d">90 days</option><option value="-180d">180 days (needs a reason)</option></select></label> <label>Why (past 90 days) <input id="ra-why" size="36" placeholder="at least 20 characters"></label></p>` : ""}
      ${v.correlated_entities.length ? `<p class="callout callout-warn">The same entity appears in more than one lead: ${v.correlated_entities.map(escapeHtml).join(", ")}</p>` : ""}
      <h3>Leads</h3><p class="muted">Run a lead in your SIEM from here (needs a "Splunk search" connection), or run the query yourself and record the result. Then say what you made of the results. Unassessed hits are treated as possible true positives, never as benign.</p>
      ${h.queries.length ? h.queries.map((q, i) => `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:10px 16px;margin:10px 0"><strong>${escapeHtml(q.technique)}: ${escapeHtml(q.name)}</strong>
        <span class="badge ${LEAD[v.leads[i]]}">${escapeHtml(v.leads[i])}</span>
        <pre class="code-block">${escapeHtml(q.query)}</pre>
        ${q.ran_at ? `<p class="muted">Ran ${escapeHtml(q.ran_at)} over ${escapeHtml(q.window || "")}: ${q.error ? "failed (" + escapeHtml(q.error) + ")" : q.count + " event(s)"}</p>` : ""}
        ${q.sample && q.sample.length ? `<div class="table-scroll"><table class="data-table"><tbody>${q.sample.slice(0, 5).map((row) => `<tr>${Object.entries(row).slice(0, 6).map(([k, val]) => `<td class="wrap-cell"><span class="muted">${escapeHtml(k)}</span> ${escapeHtml(String(val))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : ""}
        <label>Result <select data-q="${i}">${RESULTS.map((r) => `<option value="${r}"${(q.result || "") === r ? " selected" : ""}>${r || "(not recorded)"}</option>`).join("")}</select></label>
        <label>My assessment <select data-a="${i}">${ASSESS.map((r) => `<option value="${r}"${(q.assessment || "") === r ? " selected" : ""}>${r || "(not assessed)"}</option>`).join("")}</select></label>
        <button type="button" class="secondary-button" data-run="${i}">Run in SIEM</button></div>`).join("") : '<p class="muted">No queries were generated; write them for your data model.</p>'}
      <form id="df" class="run-form"><label>Notes and findings <textarea name="notes" rows="4">${escapeHtml(h.notes || "")}</textarea></label>
        <label>Follow-ups <textarea name="follow_ups" rows="2">${escapeHtml(h.follow_ups || "")}</textarea></label>
        <label>Status <select name="status">${["proposed", "active", "closed"].map((s) => `<option${s === h.status ? " selected" : ""}>${s}</option>`).join("")}</select></label>
        <label>Outcome <select name="outcome">${["", "confirmed", "not-found", "needs-data"].map((s) => `<option value="${s}"${(h.outcome || "") === s ? " selected" : ""}>${s || "(none yet)"}</option>`).join("")}</select></label>
        <label><input type="checkbox" name="detection_created"${h.detection_created ? " checked" : ""}> This hunt led to a new detection</label>
        <div><button type="submit">Save</button> <a style="color:var(--brand-accent)" href="/api/hunting/hunts/${h.id}/report?format=html">Download report (HTML)</a> &middot; <a style="color:var(--brand-accent)" href="/api/hunting/hunts/${h.id}/report">Markdown for a ticket</a></div></form>`);
    container.querySelector("#back").addEventListener("click", () => { openHunt = null; show(); });
    const collect = () => h.queries.map((q, i) => ({ ...q, result: container.querySelector(`[data-q="${i}"]`).value || null, assessment: container.querySelector(`[data-a="${i}"]`).value || null }));
    container.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", async () => {
      const i = Number(b.dataset.run);
      try {
        const pre = await api.huntingRunQuery(h.id, i, {});
        if (!window.confirm(`Run this read-only search in "${pre.connection}" over the last 24 hours?\n\n${pre.query}`)) return;
        const done = await api.huntingRunQuery(h.id, i, { confirm: true });
        flash(`The search found ${done.query.count} event(s).`, "success");
        show();
      } catch (e) { flash(e.message, "error"); }
    }));
    const ra = container.querySelector("#run-all");
    if (ra) ra.addEventListener("click", async () => {
      const body = { earliest: container.querySelector("#ra-earliest").value, justification: container.querySelector("#ra-why").value };
      try {
        const pre = await api.huntingRunAll(h.id, body);
        if (!window.confirm(`${pre.message}\n\nLeads: ${pre.leads.map((l) => l.name).join("; ") || "none to run"}${pre.not_run_because_of_the_cap ? `\n\n${pre.not_run_because_of_the_cap} more are held back by the per-run cap of ${pre.cap}.` : ""}`)) return;
        const done = await api.huntingRunAll(h.id, { ...body, confirm: true });
        flash(`Ran ${done.ran} lead(s); ${done.failed} failed.`, done.failed ? "error" : "success");
        show();
      } catch (e) { flash(e.message, "error"); }
    });
    container.querySelector("#df").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      const body = { notes: f.notes.value, follow_ups: f.follow_ups.value, status: f.status.value, detection_created: f.detection_created.checked, queries: collect() };
      if (f.outcome.value) body.outcome = f.outcome.value;
      try { await api.huntingUpdate(h.id, body); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function alerts() {
    const { alerts: as } = await api.socAlerts();
    const a = openAlert && as.find((x) => x.id === openAlert);
    if (a) return alertDetail(await api.socAlert(a.id));
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Alert</th><th>Severity</th><th>Host</th><th>Priority</th><th>Why</th><th>Status</th><th></th></tr></thead><tbody>
      ${as.length ? as.map((x) => `<tr><td class="wrap-cell">${escapeHtml(x.title)}<br><span class="muted">${escapeHtml(x.source)}${x.rule_name ? " &middot; " + escapeHtml(x.rule_name) : ""}${x.technique ? " &middot; " + escapeHtml(x.technique) : ""}</span></td>
        <td><span class="badge ${SEV[x.severity]}">${escapeHtml(x.severity)}</span></td><td>${escapeHtml(x.asset || "-")}</td><td><strong>${x.context.priority}</strong></td>
        <td class="wrap-cell"><span class="muted">${x.context.reasons.map(escapeHtml).join("; ")}</span></td><td>${escapeHtml(x.status)}${x.disposition ? "<br>" + escapeHtml(x.disposition) : ""}</td>
        <td><button type="button" class="link-button" data-open="${x.id}">Open</button></td></tr>`).join("") : '<tr><td colspan="7" class="empty-state">No alerts yet. Send them from your SIEM or XDR with a <code>soc:write</code> API key.</td></tr>'}</tbody></table></div>`);
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { openAlert = Number(b.dataset.open); show(); }));
  }

  function table(rows, head) {
    return rows.length ? `<div class="table-scroll"><table class="data-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td class="wrap-cell">${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : "";
  }

  function invPanel(r) {
    if (!r) return '<p class="muted">Not investigated yet.</p>';
    const inv = r.investigation, rep = inv.report;
    const card = (inner) => `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:10px 16px;margin:10px 0">${inner}</div>`;
    const head = card(`<p><span class="badge ${VERDICT[r.verdict]}">${escapeHtml(r.verdict)}</span> confidence ${escapeHtml(r.confidence)} &middot; ${escapeHtml(r.created_at)}. <span class="muted">A recommendation for you to validate; nothing has been closed.</span></p>
      ${rep ? `<p>${escapeHtml(rep.gist)}</p>` : ""}<ul class="guidance-list">${r.reasons.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`);
    if (!rep) return head + `<details><summary>Report to paste into the ticket</summary><pre class="code-block">${escapeHtml(r.report_md)}</pre></details>`;
    const sec = (title, inner) => `<h4>${title}</h4>${inner}`;
    const att = rep.attack;
    return head + card(
      sec("Historical correlation", rep.history.length ? `<ul class="guidance-list">${rep.history.map((h) => `<li>${escapeHtml(h.text)}</li>`).join("")}</ul>` : '<p class="muted">The alert names no host, user or address to correlate.</p>')
      + sec("Associated entities", table(rep.entities.map((e) => [escapeHtml(e.kind), escapeHtml(e.value), escapeHtml(e.detail)]), ["Kind", "Value", "Detail"]) || '<p class="muted">None named in the alert.</p>')
      + sec("ATT&amp;CK", att ? `<p><strong>${escapeHtml(att.id)} ${escapeHtml(att.name || "")}</strong> ${att.tactics.length ? "&middot; " + att.tactics.map(escapeHtml).join(", ") : ""}</p>${att.what_to_check ? `<p>Check next: ${escapeHtml(att.what_to_check)}</p>` : ""}${att.data_sources.length ? `<p class="muted">Look in: ${att.data_sources.map(escapeHtml).join("; ")}</p>` : ""}` : '<p class="muted">The alert carries no technique.</p>')
      + sec("Attack flow", (rep.flow.stages.length ? `<p class="muted">${rep.flow.stages.map(escapeHtml).join(" &rarr; ")}</p>` : "") + table(rep.flow.steps.map((s) => [escapeHtml(s.at || ""), (s.current ? "<strong>&rarr; " : "") + escapeHtml(s.title) + (s.current ? "</strong>" : ""), escapeHtml(s.tactic || "-"), escapeHtml(s.technique || "-")]), ["When", "Alert", "Tactic", "Technique"]))
      + sec("Indicators", inv.indicators.length ? table(inv.indicators.map((x) => [escapeHtml(x.value), escapeHtml(x.type), escapeHtml(x.result || "not looked up"), x.malicious == null ? "-" : escapeHtml(String(x.malicious)) + (x.total ? " of " + x.total : "")]), ["Indicator", "Type", "Result", "Flagged"]) + (inv.lookup_note ? `<p class="muted">${escapeHtml(inv.lookup_note)}</p>` : "") : '<p class="muted">None in the alert.</p>')
      + sec("Blast radius", `<p>${escapeHtml(rep.blast_radius.text)} <span class="muted">Scope: ${escapeHtml(rep.blast_radius.scope)}.</span></p>${rep.blast_radius.exposed.length ? `<ul class="guidance-list">${rep.blast_radius.exposed.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}`)
      + sec("What your tools did", `<p>${rep.tool_action.text ? "Reported outcome: " + escapeHtml(rep.tool_action.text) + ". " : ""}${escapeHtml(rep.tool_action.advice)}</p>`)
      + sec("Recommended actions", `<ul class="guidance-list">${rep.actions.map((x) => `<li><strong>${escapeHtml(x.action)}</strong>: ${escapeHtml(x.why)}</li>`).join("")}</ul><div id="rec-out"></div>`)
      + (rep.widen_note ? `<p class="callout callout-warn">${escapeHtml(rep.widen_note)}</p>` : "")
      + sec("References", `<ul class="guidance-list">${rep.references.map((x) => `<li>${escapeHtml(x.kind)}: ${escapeHtml(x.name)}${x.detail ? " <span class='muted'>(" + escapeHtml(x.detail) + ")</span>" : ""}</li>`).join("")}</ul>`)
      + sec("Follow-ups", `<div id="fu-list">${rep.followups.map((f) => `<p><strong>${escapeHtml(f.question)}</strong><br>${escapeHtml(f.answer)}</p>`).join("") || '<p class="muted">None asked yet.</p>'}</div>
        <p><select id="fu-kind"><option value="similar-alerts">Similar alerts involving</option><option value="entity-history">History of</option><option value="indicator-sightings">Where else was seen</option></select>
        <input id="fu-value" placeholder="host, user, address, domain or hash" size="34"> <label><input type="checkbox" id="fu-siem"> also search the SIEM (read-only)</label> <button type="button" id="fu-ask">Ask</button></p>`)
    ) + `<details><summary>Report to paste into the ticket</summary><pre class="code-block">${escapeHtml(r.report_md)}</pre></details>`;
  }

  async function alertDetail(a) {
    const c = a.context;
    let inv = null;
    try { inv = await api.socInvestigation(a.id); } catch { inv = null; }
    shell(`<p><button type="button" class="link-button" id="back">&larr; All alerts</button></p>
      <h3>${escapeHtml(a.title)}</h3><p><span class="badge ${SEV[a.severity]}">${escapeHtml(a.severity)}</span> ${escapeHtml(a.source)} ${a.rule_name ? "&middot; rule " + escapeHtml(a.rule_name) : ""} ${a.asset ? "&middot; host " + escapeHtml(a.asset) : ""} ${a.technique ? "&middot; " + escapeHtml(a.technique) : ""}</p>
      <p>${escapeHtml(a.detail || "")}</p>
      <h3>What Quanta knows about this host</h3>
      <p>Priority <strong>${c.priority}</strong>: ${c.reasons.map(escapeHtml).join("; ")}.</p>
      <p>Owner: ${escapeHtml(c.owner || "none recorded")} &middot; ${c.open_findings} open finding(s), ${c.kev_findings} known-exploited.</p>
      ${c.findings.length ? `<ul class="guidance-list">${c.findings.map((f) => `<li>${f.kev ? '<span class="badge badge-critical">KEV</span> ' : ""}${f.related_to_alert ? '<span class="badge badge-high">matches this alert</span> ' : ""}${escapeHtml(f.id)} ${escapeHtml(f.title || "")} (${escapeHtml(f.severity || "")}${f.cve ? ", " + escapeHtml(f.cve) : ""})</li>`).join("")}</ul>` : ""}
      <h3>L1 investigation</h3>
      <p class="muted">Classifies the alert, reads the history of the rule and host, extracts the indicators and weighs the signals. Looking up indicators sends only the public ones to your reputation connection; searching your SIEM is read-only. Both ask first.</p>
      <p><label><input type="checkbox" id="inv-rep"> Look up indicators</label> <label><input type="checkbox" id="inv-siem"> Search the SIEM for matching events</label> <button type="button" id="inv-run">Investigate</button></p>
      <p class="muted">Searches look back at most 90 days. <label>Look back <input id="inv-days" type="number" min="1" max="365" placeholder="90" style="width:5em"> days</label> <label>Why (needed past 90 days) <input id="inv-why" size="40" placeholder="at least 20 characters"></label></p>
      <div id="inv-out">${invPanel(inv)}</div>
      ${c.runbook ? `<h3>Runbook: ${escapeHtml(c.runbook.title)}</h3><ol>${c.runbook.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol><p class="muted">Quanta shows the steps; responding stays with your team or SOAR.</p>` : ""}
      <form id="af" class="run-form"><label>Status <select name="status">${["new", "investigating", "closed"].map((s) => `<option${s === a.status ? " selected" : ""}>${s}</option>`).join("")}</select></label>
        <label>Disposition <select name="disposition">${["", "true-positive", "benign", "false-positive", "needs-data"].map((s) => `<option value="${s}"${(a.disposition || "") === s ? " selected" : ""}>${s || "(none yet)"}</option>`).join("")}</select></label>
        <label>Assignee <input name="assignee" value="${escapeHtml(a.assignee || "")}" placeholder="name@company.com"></label>
        <label>Notes <textarea name="notes" rows="3">${escapeHtml(a.notes || "")}</textarea></label><div><button type="submit">Save</button></div></form>`);
    container.querySelector("#back").addEventListener("click", () => { openAlert = null; show(); });
    const ask = container.querySelector("#fu-ask");
    if (ask) ask.addEventListener("click", async () => {
      const body = { kind: container.querySelector("#fu-kind").value, value: container.querySelector("#fu-value").value, siem: container.querySelector("#fu-siem").checked };
      try {
        if (body.siem) {
          const pre = await api.socFollowUp(a.id, body);
          if (!window.confirm(pre.message + `\n\nConnection: ${pre.siem_connection}`)) return;
          body.confirm = true;
        }
        await api.socFollowUp(a.id, body);
        flash("Added to the report.", "success");
        show();
      } catch (e) { flash(e.message, "error"); }
    });
    const rec = container.querySelector("#rec-out");
    if (rec) api.socRecommendPlaybook(a.id).then((r) => {
      rec.innerHTML = r.recommendations.length ? `<p class="muted">Playbooks that could carry this out (${escapeHtml(r.basis)}): ${r.recommendations.map((x) => `<strong>${escapeHtml(x.name)}</strong> &mdash; ${escapeHtml(x.why)}${x.needs_second_person ? " Needs a second person." : ""}`).join("; ")}. Start one on the SOAR page; a dry run comes first.</p>` : "";
    }).catch(() => {});
    container.querySelector("#inv-run").addEventListener("click", async () => {
      const body = { reputation: container.querySelector("#inv-rep").checked, siem: container.querySelector("#inv-siem").checked };
      const days = Number(container.querySelector("#inv-days").value);
      if (days) { body.lookback_days = days; body.justification = container.querySelector("#inv-why").value; }
      try {
        if (body.reputation || body.siem) {
          const pre = await api.socInvestigate(a.id, body);
          const msg = (pre.indicators_that_would_be_sent && pre.indicators_that_would_be_sent.length ? `These public indicators will be sent to "${pre.reputation_connection}":\n${pre.indicators_that_would_be_sent.join("\n")}\n\n` : "") + (pre.siem_connection ? `Read-only searches will run in "${pre.siem_connection}".\n\n` : "") + "Continue?";
          if (!window.confirm(msg)) return;
          body.confirm = true;
        }
        await api.socInvestigate(a.id, body);
        flash("Investigation recorded.", "success");
        show();
      } catch (e) { flash(e.message, "error"); }
    });
    container.querySelector("#af").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, body = { status: f.status.value, assignee: f.assignee.value, notes: f.notes.value };
      if (f.disposition.value) body.disposition = f.disposition.value;
      try { await api.socUpdateAlert(a.id, body); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function detections() {
    const o = await api.detectionsOverview();
    shell(`<div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">rules judged</div><div class="kpi-value">${o.totals.rules}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">noisy or critical noise</div><div class="kpi-value">${o.tier_counts.noisy + o.tier_counts.critical_noise}</div></div>
        <div class="kpi-card"><div class="kpi-label">overall noise rate</div><div class="kpi-value">${pct(o.totals.noise_rate)}</div></div>
        <div class="kpi-card"><div class="kpi-label">ATT&CK coverage of your estate</div><div class="kpi-value">${o.coverage.pct === null ? "-" : o.coverage.pct + "%"}</div></div>
      </div>
      <p class="muted">${escapeHtml(o.note)} Window: ${o.window_days} days. <button type="button" class="link-button" id="snap">Record a snapshot</button> (one is also taken weekly) &middot;
        <a style="color:var(--brand-accent)" href="/api/detections/report?format=html">Summary report</a></p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Rule</th><th>Health</th><th>Recommendation</th><th>Decided</th><th>TP</th><th>Noise</th><th>Trend (noise)</th><th></th></tr></thead><tbody>
      ${o.rules.length ? o.rules.map((r, i) => { const m = r.metrics; return `<tr><td class="wrap-cell"><strong>${escapeHtml(r.rule)}</strong><br><span class="muted">${escapeHtml(r.platform || "not in the inventory")}${r.techniques.length ? " &middot; " + r.techniques.map(escapeHtml).join(", ") : ""}</span></td>
        <td><span class="badge ${TIER[m.tier]}">${escapeHtml(m.tier_label)}</span></td><td>${escapeHtml(m.recommendation)}</td><td>${m.decided}</td><td>${pct(m.tp_rate)}</td><td>${pct(m.noise_rate)}</td>
        <td class="muted">${m.trend.map((w) => (w.noise_rate === null ? "·" : Math.round(w.noise_rate * 100))).join(" ")}</td>
        <td><button type="button" class="link-button" data-rule="${i}">Details</button></td></tr>`; }).join("") : '<tr><td colspan="8" class="empty-state">No rules or alerts yet. Import Sigma rules below and send alerts that name their rule.</td></tr>'}</tbody></table></div>
      <div id="rule-detail"></div>
      <h3>ATT&CK coverage</h3>
      <p>${o.coverage.estate_techniques ? `${o.coverage.estate_covered} of ${o.coverage.estate_techniques} techniques tagged on your open findings are claimed by an enabled rule.` : "No techniques are tagged on current findings."}</p>
      ${o.coverage.gaps.length ? `<ul class="guidance-list">${o.coverage.gaps.map((g) => `<li>${escapeHtml(g.technique_id)} ${escapeHtml(g.technique_name)} - no enabled rule${g.hunt_queries ? "; hunt queries exist" : "; no hunt queries either"}</li>`).join("")}</ul>` : ""}
      <h3>Rule inventory</h3>
      <form id="imp" class="run-form"><label>Import Sigma rules (YAML file) <input type="file" name="file" accept=".yml,.yaml,.txt" required></label><div><button type="submit">Import</button></div></form>
      <form id="addr" class="run-form"><label>Or add a rule by name <input name="name" required placeholder="the rule name exactly as your alerts carry it"></label>
        <label>Platform <input name="platform" placeholder="Splunk, XSIAM, Sentinel..."></label><label>ATT&CK techniques (comma separated) <input name="techniques" placeholder="T1190, T1059"></label><div><button type="submit">Add</button></div></form>
      ${o.history.length ? `<p class="muted">Snapshots: ${o.history.map((s) => escapeHtml(s.created_at.slice(0, 10)) + " (" + s.totals.rules + " rules, noise " + pct(s.totals.noise_rate) + ")").join("; ")}</p>` : ""}`);
    container.querySelector("#snap").addEventListener("click", async () => { try { await api.detectionsAssess(); flash("Snapshot recorded.", "success"); show(); } catch (e) { flash(e.message, "error"); } });
    container.querySelectorAll("[data-rule]").forEach((b) => b.addEventListener("click", () => {
      const r = o.rules[Number(b.dataset.rule)], m = r.metrics, tu = r.tuning;
      container.querySelector("#rule-detail").innerHTML = `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:10px 16px;margin:14px 0"><h3>${escapeHtml(r.rule)}: ${escapeHtml(m.recommendation)}</h3>
        <p>${m.alerts} alert(s), ${m.decided} decided: ${m.tp} true positive, ${m.benign} benign, ${m.fp} false positive. Median time to close ${m.median_resolution_hours ?? "n/a"} hours.</p>
        ${m.recurring_noise_entities.length ? `<ul class="guidance-list">${m.recurring_noise_entities.map((e) => `<li>${escapeHtml(e.kind)} ${escapeHtml(e.value)}: ${e.alerts} noise alert(s), ${pct(e.share)} of the noise</li>`).join("")}</ul>` : ""}
        ${tu ? `<p><strong>Suggested change:</strong> exclude ${tu.exclude_hosts.map(escapeHtml).join(", ")}. ${escapeHtml(tu.basis)} Estimated noise reduction ${pct(tu.estimated_noise_reduction)}. <span class="muted">${escapeHtml(tu.note || "")}</span></p>
          ${tu.before ? `<div style="display:flex;gap:12px;flex-wrap:wrap"><div style="flex:1;min-width:280px"><strong>Before</strong><pre class="code-block">${escapeHtml(tu.before)}</pre></div><div style="flex:1;min-width:280px"><strong>After</strong><pre class="code-block">${escapeHtml(tu.after)}</pre></div></div>` : ""}` : '<p class="muted">No single host accounts for enough of the noise to suggest an exclusion.</p>'}
        <p><a style="color:var(--brand-accent)" href="/api/detections/report?rule=${encodeURIComponent(r.rule)}&format=html">Tuning report (HTML)</a> &middot; <a style="color:var(--brand-accent)" href="/api/detections/report?rule=${encodeURIComponent(r.rule)}">Markdown for a ticket</a>
          ${r.rule_id ? ` &middot; <button type="button" class="link-button" data-toggle="${r.rule_id}">${r.enabled ? "Disable in inventory" : "Enable in inventory"}</button> <button type="button" class="link-button danger-link" data-del="${r.rule_id}">Remove</button>` : ""}</p></div>`;
      container.querySelectorAll("[data-toggle]").forEach((t) => t.addEventListener("click", async () => { try { await api.detectionsToggle(Number(t.dataset.toggle), !r.enabled); show(); } catch (e) { flash(e.message, "error"); } }));
      container.querySelectorAll("[data-del]").forEach((t) => t.addEventListener("click", async () => { if (window.confirm("Remove this rule from the inventory?")) { try { await api.detectionsDelete(Number(t.dataset.del)); show(); } catch (e) { flash(e.message, "error"); } } }));
    }));
    container.querySelector("#imp").addEventListener("submit", async (e) => {
      e.preventDefault();
      try { const r = await api.detectionsImport(await e.target.file.files[0].text()); flash(`${r.imported} rule(s) imported.`, "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#addr").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { await api.detectionsAddRule({ name: f.name.value, platform: f.platform.value || null, techniques: f.techniques.value.split(",").map((x) => x.trim()).filter(Boolean) }); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show() {
    try { await { overview, intel, proposals, hunts, alerts, detections }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
