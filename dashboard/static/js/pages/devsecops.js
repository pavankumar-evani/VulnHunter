import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "DevSecOps";

const TABS = [["library", "Control library"], ["custom", "Our own controls"], ["policy", "Policy check"], ["queue", "Code fix queue"]];
const STATUS = { evidenced: ["badge-low", "Evidenced"], failing: ["badge-critical", "Failing"], "no-evidence": ["badge-medium", "No evidence yet"], "not-observable": ["badge-outline", "Not observable"] };
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const QSTATE = { queued: "badge-outline", "in-progress": "badge-medium", "pr-opened": "badge-high", merged: "badge-medium", "wont-fix": "badge-outline", "merged-still-reported": "badge-critical", "resolved-in-latest-scan": "badge-low" };
const NOTE = "The controls a secure delivery pipeline is expected to have, what to do for each, and where each repository stands. Evidenced and failing come from scans and pipeline checks uploaded to Quanta (a clean scan counts); controls Quanta cannot see wait for someone to record their state.";

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "library";
  let repo = null;
  let stage = "all";
  let me = null;

  const isAdmin = async () => { if (me === null) { try { me = ((await api.authMe()).user || {}).role === "admin"; } catch { me = false; } } return me; };
  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="dso-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };

  async function library() {
    const admin = await isAdmin();
    const ov = await api.devsecopsOverview();
    const names = ov.repos.map((r) => r.asset);
    if (!repo || !names.includes(repo)) repo = names[0] || null;
    const rep = repo ? await api.devsecopsRepo(repo) : null;
    const rows = rep ? rep.controls.filter((c) => stage === "all" || c.stage === stage) : ov.library.filter((c) => stage === "all" || c.stage === stage).map((c) => ({ ...c, status: "not-observable", detail: "", recorded: null }));
    shell(`<p><label>Repository or application <select id="repo">${names.map((n) => `<option${n === repo ? " selected" : ""}>${escapeHtml(n)}</option>`).join("") || "<option value=''>(none yet)</option>"}</select></label>
        <label>Stage <select id="stage"><option value="all">All stages</option>${ov.stages.map((s) => `<option${s === stage ? " selected" : ""}>${s}</option>`).join("")}</select></label></p>
      ${rep ? `<div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">evidenced</div><div class="kpi-value">${rep.counts.evidenced}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">failing</div><div class="kpi-value">${rep.counts.failing}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">no evidence yet</div><div class="kpi-value">${rep.counts["no-evidence"]}</div></div>
        <div class="kpi-card"><div class="kpi-label">not observable (record them)</div><div class="kpi-value">${rep.counts["not-observable"]}</div></div></div>` :
        '<p class="callout">No repository has sent a scan yet. Upload a SARIF file with <code>asset=&lt;repository&gt;</code> (<code>POST /api/ingest/sarif</code>) and it appears here, even if the scan found nothing. The library below is what to aim for.</p>'}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Control</th><th>Stage</th><th>Status</th><th>Recorded</th><th></th></tr></thead><tbody>
      ${rows.map((c) => `<tr><td class="wrap-cell"><strong>${escapeHtml(c.title)}</strong>${c.custom ? ' <span class="badge badge-outline">ours</span>' : ""}<br><span class="muted">${escapeHtml(c.why)}</span></td><td>${escapeHtml(c.stage)}</td>
        <td><span class="badge ${STATUS[c.status][0]}">${STATUS[c.status][1]}</span><br><span class="muted">${escapeHtml(c.detail || "")}</span></td>
        <td class="wrap-cell">${c.recorded ? `${escapeHtml(c.recorded.state)}<br><span class="muted">${escapeHtml(c.recorded.note || "")} (${escapeHtml(c.recorded.set_by || "")})</span>` : '<span class="muted">-</span>'}</td>
        <td><button type="button" class="link-button" data-how="${escapeHtml(c.id)}">How</button>${admin && repo ? ` <button type="button" class="link-button" data-rec="${escapeHtml(c.id)}">Record</button>` : ""}</td></tr>`).join("")}</tbody></table></div>
      <div id="how-box"></div>`);
    container.querySelector("#repo").addEventListener("change", (e) => { repo = e.target.value; show(); });
    container.querySelector("#stage").addEventListener("change", (e) => { stage = e.target.value; show(); });
    container.querySelectorAll("[data-how]").forEach((b) => b.addEventListener("click", () => {
      const c = ov.library.find((x) => x.id === b.dataset.how);
      container.querySelector("#how-box").innerHTML = `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:8px 16px;margin:14px 0"><h3>${escapeHtml(c.title)}</h3><p>${escapeHtml(c.how)}</p>
        <p class="muted">${(c.owasp_cicd || []).map(escapeHtml).join(", ")}${c.ssdf ? " &middot; NIST SSDF " + c.ssdf.map(escapeHtml).join(", ") : ""}</p>
        ${Object.entries(c.snippets || {}).map(([k, v]) => `<p><strong>${escapeHtml(k)}</strong></p><pre class="code-block">${escapeHtml(v)}</pre>`).join("")}
        <p class="muted">Snippets are starting points: pin every action to a commit SHA you have reviewed and check each tool's current documentation.</p></div>`;
    }));
    container.querySelectorAll("[data-rec]").forEach((b) => b.addEventListener("click", async () => {
      const state = window.prompt("State: implemented, planned, not-applicable or not-implemented", "implemented");
      if (!state) return;
      const note = window.prompt("What is this based on? (a note for whoever reads this later)") || "";
      try { await api.devsecopsSetState({ asset: repo, control_id: b.dataset.rec, state, note }); show(); } catch (e) { flash(e.message, "error"); }
    }));
  }

  async function policy() {
    shell(`<p class="muted">Paste a secure development policy or standard. Quanta reads it sentence by sentence and shows which controls each requirement points to, and which sentences it could not place. A match is a keyword hit, not an understanding of the sentence.</p>
      <form id="pf" class="run-form"><label>Policy text <textarea name="text" rows="9" required></textarea></label><div><button type="submit">Map it to controls</button></div></form><div id="pout"></div>`);
    container.querySelector("#pf").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const r = await api.devsecopsPolicy(e.target.text.value);
        container.querySelector("#pout").innerHTML = `<h3>${r.matched.length} requirement(s) matched, ${r.unmatched.length} not placed</h3>
          <div class="table-scroll"><table class="data-table"><thead><tr><th>Requirement</th><th>Controls</th></tr></thead><tbody>
          ${r.matched.map((m) => `<tr><td class="wrap-cell">${escapeHtml(m.requirement)}</td><td class="wrap-cell">${m.controls.map((c) => `<span class="badge badge-outline">${escapeHtml(c.title)}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>
          ${r.unmatched.length ? `<h3>Not placed</h3><ul class="guidance-list">${r.unmatched.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>` : ""}
          <h3>Controls the policy never mentions</h3><p class="muted">${r.controls_not_mentioned.length ? r.controls_not_mentioned.map(escapeHtml).join(", ") : "None."}</p><p class="muted">${escapeHtml(r.note)}</p>`;
      } catch (err) { flash(err.message, "error"); }
    });
  }

  async function queue() {
    const admin = await isAdmin();
    const q = await api.devsecopsFactory();
    shell(`<p class="muted">Code-level findings (static analysis, dependencies, secrets, infrastructure as code, containers) tracked until a later scan stops reporting them. Quanta writes a fix brief for each; it does not edit repositories. "Resolved in latest scan" is set by the scan, never by hand.</p>
      <div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">in the queue</div><div class="kpi-value">${q.summary.queued_total}</div></div>
        <div class="kpi-card"><div class="kpi-label">resolved in latest scan</div><div class="kpi-value">${q.summary.by_state["resolved-in-latest-scan"] || 0}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">merged but still reported</div><div class="kpi-value">${q.summary.by_state["merged-still-reported"] || 0}</div></div>
        <div class="kpi-card"><div class="kpi-label">waiting to be queued</div><div class="kpi-value">${q.summary.candidates}</div></div></div>
      <h3>Queue</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Finding</th><th>Repository</th><th>State</th><th>Pull request</th><th></th></tr></thead><tbody>
      ${q.items.length ? q.items.map((i) => `<tr><td class="wrap-cell"><span class="badge ${SEV[i.severity] || "badge-outline"}">${escapeHtml(i.severity || "")}</span> ${escapeHtml(i.finding_id)} ${escapeHtml(i.title || "(no longer reported)")}<br><span class="muted">${escapeHtml(i.scan_type || "")} ${escapeHtml(typeof i.location === "string" ? i.location : "")}</span></td>
        <td>${escapeHtml(i.repository || "-")}</td><td><span class="badge ${QSTATE[i.shown_state] || "badge-outline"}">${escapeHtml(i.shown_state)}</span></td>
        <td class="wrap-cell">${i.pr_url ? `<a href="${escapeHtml(i.pr_url)}" target="_blank" rel="noopener">${escapeHtml(i.pr_url)}</a>` : ""}</td>
        <td><a href="/api/devsecops/factory/${encodeURIComponent(i.finding_id)}/brief" style="color:var(--brand-accent)">Fix brief</a>${admin ? ` <button type="button" class="link-button" data-upd="${escapeHtml(i.finding_id)}">Update</button>` : ""}</td></tr>`).join("")
        : '<tr><td colspan="5" class="empty-state">Nothing queued yet.</td></tr>'}</tbody></table></div>
      <h3>Worth queueing (worst first)</h3>
      ${q.candidates.length ? `<div class="table-scroll"><table class="data-table"><tbody>${q.candidates.slice(0, 40).map((c) => `<tr><td>${admin ? `<input type="checkbox" data-pick="${escapeHtml(c.id)}">` : ""}</td><td><span class="badge ${SEV[c.severity]}">${escapeHtml(c.severity)}</span> ${c.kev ? '<span class="badge badge-critical">KEV</span>' : ""}</td>
        <td class="wrap-cell">${escapeHtml(c.id)} ${escapeHtml(c.title)}<br><span class="muted">${escapeHtml(c.repository || "")} ${escapeHtml(c.scan_type || "")}</span></td></tr>`).join("")}</tbody></table></div>
        ${admin ? '<p><button type="button" id="queuebtn">Queue the selected</button></p>' : ""}` : '<p class="muted">No code-level findings are waiting.</p>'}`);
    const qb = container.querySelector("#queuebtn");
    if (qb) qb.addEventListener("click", async () => {
      const ids = [...container.querySelectorAll("[data-pick]:checked")].map((x) => x.dataset.pick);
      if (!ids.length) { flash("Tick at least one finding.", "error"); return; }
      try { const r = await api.devsecopsQueue({ finding_ids: ids }); flash(`${r.queued.length} queued.`, "success"); show(); } catch (e) { flash(e.message, "error"); }
    });
    container.querySelectorAll("[data-upd]").forEach((b) => b.addEventListener("click", async () => {
      const state = window.prompt("State: queued, in-progress, pr-opened, merged or wont-fix", "in-progress");
      if (!state) return;
      const body = { state };
      if (state === "pr-opened") body.pr_url = window.prompt("Pull request link (https://...)") || "";
      try { await api.devsecopsUpdateItem(b.dataset.upd, body); show(); } catch (e) { flash(e.message, "error"); }
    }));
  }

  async function custom() {
    const admin = await isAdmin();
    const ov = await api.devsecopsOverview();
    const mine = ov.library.filter((c) => c.custom);
    shell(`<p class="muted">Add the controls your organisation requires that the built-in library does not name: a change ticket on every release, a security champion sign-off, an internal scanning standard. They use the same model as the built-in ones: one with an evidence rule shows <em>evidenced</em> or <em>failing</em> from uploaded scans and pipeline checks, and one without is recorded by a person. They appear in the library, in each repository's status and in the policy check.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Control</th><th>Stage</th><th>Evidence</th><th></th></tr></thead><tbody>
      ${mine.length ? mine.map((c) => `<tr><td class="wrap-cell"><strong>${escapeHtml(c.title)}</strong> <code>${escapeHtml(c.id)}</code><br><span class="muted">${escapeHtml(c.why)}</span></td><td>${escapeHtml(c.stage)}</td>
        <td>${c.evidence ? escapeHtml(JSON.stringify(c.evidence)) : '<span class="muted">recorded by a person</span>'}</td>${admin ? `<td><button type="button" class="link-button" data-del="${escapeHtml(c.id)}">Remove</button></td>` : "<td></td>"}</tr>`).join("") : '<tr><td colspan="4" class="empty-state">No controls of your own yet.</td></tr>'}</tbody></table></div>
      ${admin ? `<h3>Add a control</h3><form id="cf" class="run-form"><div class="form-grid"><label>Id (starts with org-)<input name="id" placeholder="org-change-ticket" required></label>
        <label>Stage<select name="stage">${ov.stages.map((x) => `<option>${x}</option>`).join("")}</select></label><label>Title<input name="title" required></label></div>
        <label>Why it matters<textarea name="why" rows="2" required></textarea></label><label>How to put it in place<textarea name="how" rows="3" required></textarea></label>
        <label>Keywords that point a policy sentence at it (comma separated)<input name="keywords" placeholder="change ticket, change approval"></label>
        <div class="form-grid"><label>Evidence<select name="evk"><option value="">None: a person records it</option><option value="scan_type">A scan of this type was uploaded</option><option value="clean_of">A pipeline check found none of these rules</option></select></label>
        <label>Scan type, or rule ids (comma separated)<input name="evv" placeholder="dast  or  GHA001, GL001"></label></div>
        <p><button type="submit">Save the control</button></p></form>` : ""}`);
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (window.confirm("Remove this control and the states recorded against it?")) { try { await api.customControlDelete(b.dataset.del); show(); } catch (e) { flash(e.message, "error"); } } }));
    const f = container.querySelector("#cf");
    if (f) f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const x = f.elements, evk = x.evk.value, evv = x.evv.value.trim();
      const evidence = evk === "scan_type" ? { scan_type: evv } : evk === "clean_of" ? { clean_of: evv.split(",").map((t) => t.trim()).filter(Boolean) } : null;
      try { await api.customControlSave(x.id.value.trim(), { stage: x.stage.value, title: x.title.value, why: x.why.value, how: x.how.value, keywords: x.keywords.value.split(",").map((t) => t.trim()).filter(Boolean), evidence }); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show() {
    try { await { library, custom, policy, queue }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
