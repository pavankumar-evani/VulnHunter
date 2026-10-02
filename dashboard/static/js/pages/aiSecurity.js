import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "AI Security";

const TABS = [["overview", "Overview"], ["register", "Register"], ["findings", "Findings"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const NOTE = "Where AI is used, what each system can do and how it is defended, checked against the OWASP Top 10 for LLM Applications and agent / MCP hygiene. Quanta does not probe a model: it applies rules to the facts you record. A question left unanswered is a gap, not a pass.";
const TRI_ORDER = ["untrusted_input", "internet_facing", "auth_required", "can_take_actions", "human_in_loop", "high_stakes_use", "downstream_trusts_output", "input_guardrails", "output_filtering", "rate_limited", "logging",
  "secrets_in_prompt", "plugins_reviewed", "fine_tuned", "training_data_validated", "uses_rag", "rag_access_control"];

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let data = null;
  let draft = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="ais-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; draft = null; show(); }));
  };
  const load = async () => { data = await api.aiSecurityOverview(); return data; };

  async function overview() {
    const d = await load(), a = d.assessment;
    shell(`<div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">AI assets recorded</div><div class="kpi-value">${d.assets.length}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">critical or high findings</div><div class="kpi-value">${a.by_severity.Critical + a.by_severity.High}</div></div>
        <div class="kpi-card"><div class="kpi-label">all findings</div><div class="kpi-value">${a.findings.length}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">questions still unanswered</div><div class="kpi-value">${a.unanswered_total}</div></div></div>
      ${d.assets.length ? "" : '<p class="callout">No AI assets recorded yet. Add them on the Register tab, or copy in the AI applications Quanta found in your traffic.</p>'}
      <h3>Assets by risk</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Asset</th><th>Kind</th><th>Worst finding</th><th>Findings</th><th>Unanswered</th></tr></thead><tbody>
      ${a.assets.length ? a.assets.map((x) => `<tr><td>${escapeHtml(x.name)}<br><span class="muted">${escapeHtml(x.owner || "no owner")} &middot; ${escapeHtml(x.environment || "environment unknown")}</span></td><td>${escapeHtml(x.kind)}</td>
        <td>${x.worst ? `<span class="badge ${SEV[x.worst]}">${x.worst}</span>` : '<span class="muted">none</span>'}</td><td>${x.findings}</td><td>${x.unanswered.length}</td></tr>`).join("") : '<tr><td colspan="5" class="empty-state">None.</td></tr>'}</tbody></table></div>
      <h3>By OWASP category</h3>
      <p>${Object.entries(a.by_rule).map(([k, v]) => `<span class="badge badge-outline">${escapeHtml(k)}: ${v}</span>`).join(" ") || '<span class="muted">No findings.</span>'}</p>
      <p class="muted">${escapeHtml(a.note)}</p>`);
  }

  async function register() {
    const d = data || await load();
    if (draft) return form(d);
    shell(`<p><button type="button" id="new">Add an AI asset</button> <button type="button" class="secondary-button" id="imp">Copy in the AI applications found in traffic</button></p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Asset</th><th>Kind</th><th>Owner</th><th>Environment</th><th>Last reviewed</th><th></th></tr></thead><tbody>
      ${d.assets.length ? d.assets.map((x) => `<tr><td>${escapeHtml(x.name)}<br><span class="muted">${escapeHtml(x.vendor_model || "")}</span></td><td>${escapeHtml(x.kind)}</td><td>${escapeHtml(x.owner || "-")}</td><td>${escapeHtml(x.environment || "-")}</td><td>${escapeHtml(x.last_reviewed || "never")}</td>
        <td><button type="button" class="link-button" data-edit="${x.id}">Edit</button> <button type="button" class="link-button danger-link" data-del="${x.id}">Delete</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">None.</td></tr>'}</tbody></table></div>`);
    container.querySelector("#new").addEventListener("click", () => { draft = { name: "", kind: d.meta.kinds[0], data_classes: [] }; show(); });
    container.querySelector("#imp").addEventListener("click", async () => { try { const r = await api.aiSecurityImport(); flash(`${r.added.length} application(s) copied in.`, "success"); data = null; show(); } catch (e) { flash(e.message, "error"); } });
    container.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => { draft = JSON.parse(JSON.stringify(d.assets.find((x) => x.id === Number(b.dataset.edit)))); show(); }));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (window.confirm("Delete this asset?")) { try { await api.aiSecurityDelete(Number(b.dataset.del)); data = null; show(); } catch (e) { flash(e.message, "error"); } } }));
  }

  function form(d) {
    const m = d.meta, x = draft;
    const sel = (name, label, opts, blank = true) => `<label>${label} <select name="${name}">${blank ? '<option value="">(not stated)</option>' : ""}${opts.map((o) => `<option${x[name] === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select></label>`;
    const tri = (f) => `<label>${escapeHtml(m.questions[f])} <select name="${f}"><option value="">Don't know</option><option value="true"${x[f] === true ? " selected" : ""}>Yes</option><option value="false"${x[f] === false ? " selected" : ""}>No</option></select></label>`;
    shell(`<form id="af" class="run-form"><label>Name <input name="name" value="${escapeHtml(x.name)}" required maxlength="160"></label>${sel("kind", "Kind", m.kinds, false)}
      <label>Owner <input name="owner" value="${escapeHtml(x.owner || "")}" placeholder="name@company.com"></label>${sel("environment", "Environment", m.environments)}${sel("hosting", "Hosting", m.hosting)}
      <label>Model or vendor <input name="vendor_model" value="${escapeHtml(x.vendor_model || "")}" placeholder="claude-sonnet, gpt-4o, llama-3"></label>
      <label>Last reviewed <input name="last_reviewed" type="date" value="${escapeHtml(x.last_reviewed || "")}"></label>
      <p><strong>Data it handles</strong></p><p>${m.data_classes.map((c) => `<label><input type="checkbox" name="dc" value="${c}"${(x.data_classes || []).includes(c) ? " checked" : ""}> ${c}</label>`).join(" ")}</p>
      ${sel("permissions_scope", "Highest permission its tools hold", m.scopes)}${sel("provenance", "Where the model came from", m.provenance)}${sel("serialization", "Model file format", m.serialization)}
      <p><strong>Questions</strong> <span class="muted">Answer what you know; "don't know" is kept as a gap.</span></p>${TRI_ORDER.map(tri).join("")}
      <label>Notes <textarea name="notes" rows="2">${escapeHtml(x.notes || "")}</textarea></label>
      <div><button type="submit">Save</button> <button type="button" class="secondary-button" id="cancel">Cancel</button></div></form>`);
    container.querySelector("#cancel").addEventListener("click", () => { draft = null; show(); });
    container.querySelector("#af").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, body = { name: f.name.value, kind: f.kind.value, data_classes: [...f.querySelectorAll("[name=dc]:checked")].map((c) => c.value), notes: f.notes.value };
      for (const k of ["owner", "environment", "hosting", "vendor_model", "last_reviewed", "permissions_scope", "provenance", "serialization"]) body[k] = f[k].value || null;
      for (const k of TRI_ORDER) body[k] = f[k].value === "" ? null : f[k].value === "true";
      try { if (x.id) await api.aiSecurityUpdate(x.id, body); else await api.aiSecurityAdd(body); draft = null; data = null; flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function findings() {
    const d = await load(), a = d.assessment;
    shell(`<p><button type="button" id="pub">Publish to the main queue</button> <span class="muted">Sends this set as source ai-security. It is the complete set, so a finding leaves the queue when the record shows it fixed.</span></p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>Asset</th><th>Finding</th><th>What to do</th></tr></thead><tbody>
      ${a.findings.length ? a.findings.map((f) => `<tr><td><span class="badge ${SEV[f.severity]}">${f.severity}</span><br><span class="muted">${escapeHtml(f.rule)}</span></td><td>${escapeHtml(f.asset)}</td>
        <td class="wrap-cell"><strong>${escapeHtml(f.title)}</strong><br><span class="muted">${escapeHtml(f.owasp)}. ${escapeHtml(f.why)}</span></td><td class="wrap-cell">${escapeHtml(f.fix)}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No findings.</td></tr>'}</tbody></table></div>
      ${a.assets.some((x) => x.unanswered.length) ? `<h3>Unanswered questions</h3>${a.assets.filter((x) => x.unanswered.length).map((x) => `<p><strong>${escapeHtml(x.name)}</strong>: <span class="muted">${x.unanswered.map((u) => escapeHtml(u.question)).join(" &middot; ")}</span></p>`).join("")}` : ""}`);
    container.querySelector("#pub").addEventListener("click", async () => {
      try {
        const pre = await api.aiSecurityPublish({});
        if (!window.confirm(`${pre.message}\n\n${pre.findings} finding(s) will be in the queue.`)) return;
        const r = await api.aiSecurityPublish({ confirm: true });
        flash(`Published ${r.published}: ${r.added} new, ${r.updated} updated, ${r.removed} removed.`, "success");
      } catch (e) { flash(e.message, "error"); }
    });
  }

  async function show() {
    try { await { overview, register, findings }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
