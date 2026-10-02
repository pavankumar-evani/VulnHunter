import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Security Controls";

const STATE = { verified: "badge-auto_approvable", claimed: "badge-outline" };

export async function render(container) {
  async function load() {
    const data = await api.controls();
    const classes = data.classes;
    container.innerHTML = `
      <p class="subtitle">Which controls protect which assets. Quanta checks a finding's compensating-control advice against this list, so the more complete it is, the more specific the advice.
      A control a connector observed is <strong>verified</strong>; one a person recorded is <strong>claimed</strong>. An asset can be a name or a pattern such as <code>WEB-*</code>.</p>
      <h2>Add a control</h2>
      <form id="ctl-form" class="run-form">
        <label>Asset or pattern <input name="asset_name" required placeholder="WEB-* or WIN-DC01"></label>
        <label>Kind of control <select name="control_class">${Object.entries(classes).map(([k, v]) => `<option value="${escapeHtml(k)}">${escapeHtml(v)}</option>`).join("")}</select></label>
        <label>What it is <input name="name" required maxlength="160" placeholder="Palo Alto edge firewall, deny by default"></label>
        <div><button type="submit">Add control</button>
          <label class="inline-file">or import a CSV <input type="file" id="ctl-csv" accept=".csv,text/csv"></label></div>
      </form>
      <p class="muted">CSV columns: <code>asset_name, control_class, name, state, detail</code>. An EDR or firewall integration can report what it observes through the API (key access &ldquo;Report security controls&rdquo;); those are recorded as verified.</p>
      <h2>Recorded controls (${data.controls.length})</h2>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Asset</th><th>Kind</th><th>Control</th><th>State</th><th>Source</th><th>Last seen</th><th></th></tr></thead>
      <tbody>${data.controls.length ? data.controls.map((c) => `<tr><td>${escapeHtml(c.asset_name)}</td><td>${escapeHtml(classes[c.control_class] || c.control_class)}</td>
        <td>${escapeHtml(c.name)}</td><td><span class="badge ${STATE[c.state] || ""}">${escapeHtml(c.state)}</span></td><td>${escapeHtml(c.source)}</td>
        <td>${escapeHtml(c.last_seen)}</td><td><button type="button" class="link-button danger-link" data-del="${c.id}">Delete</button></td></tr>`).join("")
        : `<tr><td colspan="7" class="empty-state">No controls recorded yet.</td></tr>`}</tbody></table></div>`;
    container.querySelector("#ctl-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        await api.addControl({ asset_name: f.asset_name.value, control_class: f.control_class.value, name: f.name.value, state: "claimed" });
        flash("Control recorded.", "success");
        load();
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#ctl-csv").addEventListener("change", async (e) => {
      if (!e.target.files[0]) return;
      try {
        const r = await api.importControls(e.target.files[0]);
        flash(`${r.imported} imported${r.errors.length ? `, ${r.errors.length} rejected (first: line ${r.errors[0].line}: ${r.errors[0].error})` : ""}.`, r.errors.length ? "error" : "success");
        load();
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Delete this control record?")) return;
      try { await api.deleteControl(Number(b.dataset.del)); load(); } catch (err) { flash(err.message, "error"); }
    }));
  }
  await load();
}
