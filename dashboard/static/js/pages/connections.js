import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";

export const title = "Connections";

const SCHEDULES = [[0, "Manual only"], [15, "Every 15 minutes"], [60, "Hourly"], [360, "Every 6 hours"], [1440, "Daily"], [10080, "Weekly"]];

function statusBadge(c) {
  if (c.last_status === "running") return `<span class="badge badge-outline">Syncing...</span>`;
  if (c.last_status === "ok") return `<span class="badge badge-outline sla-met">OK</span>`;
  if (c.last_status === "error") return `<span class="badge badge-critical">Failed</span>`;
  return `<span class="muted">Never run</span>`;
}

function fieldHtml(f, current) {
  const id = `cf-${f.name}`;
  if (f.type === "checkbox") {
    return `<label><input type="checkbox" id="${id}" name="${escapeHtml(f.name)}"${current.config && current.config[f.name] ? " checked" : ""}> ${escapeHtml(f.label)}</label>`;
  }
  const isSet = f.secret && current.secrets_set && current.secrets_set.includes(f.name);
  const val = !f.secret && current.config ? current.config[f.name] || "" : "";
  return `<label>${escapeHtml(f.label)}${f.required ? "" : " (optional)"}
    <input id="${id}" name="${escapeHtml(f.name)}" type="${f.secret ? "password" : "text"}" autocomplete="off"
      value="${escapeHtml(val)}" placeholder="${isSet ? "set - leave blank to keep" : escapeHtml(f.placeholder || "")}"></label>`;
}

function formValues(form, spec) {
  const out = {};
  for (const f of spec.fields) {
    const el = form.querySelector(`[name="${f.name}"]`);
    out[f.name] = f.type === "checkbox" ? el.checked : el.value;
  }
  return out;
}

async function openEditor(data, existing, reload) {
  const catalog = data.catalog;
  const body = openModal("");
  const type = existing ? existing.type : catalog[0].type;
  const draw = (selType) => {
    const spec = catalog.find((c) => c.type === selType);
    body.innerHTML = `
      <h2>${existing ? `Edit ${escapeHtml(existing.name)}` : "Add a connection"}</h2>
      ${data.encryption_available ? "" : `<div class="callout callout-warn"><strong>Storing credentials is switched off.</strong>
        Set <code>QUANTA_ENCRYPTION_KEY</code> on the server (generate one with <code>python cli/quanta_admin.py gen-key</code>) and restart.
        You can still use each connector's own page, which never stores anything.</div>`}
      <form id="conn-form" class="run-form">
        ${existing ? "" : `<label>Source <select name="__type">${catalog.map((c) => `<option value="${escapeHtml(c.type)}"${c.type === selType ? " selected" : ""}>${escapeHtml(c.label)} - ${escapeHtml(c.category)}</option>`).join("")}</select></label>`}
        <label>Name <input name="__name" value="${escapeHtml(existing ? existing.name : spec.label)}" maxlength="80" required></label>
        ${spec.fields.map((f) => fieldHtml(f, existing || {})).join("")}
        ${spec.docs ? `<p class="muted">${escapeHtml(spec.docs)}</p>` : ""}
        ${spec.note ? `<p class="muted">${escapeHtml(spec.note)}</p>` : ""}
        <label>Sync <select name="__schedule">${SCHEDULES.map(([v, l]) => `<option value="${v}"${(existing ? existing.schedule_minutes : 60) === v ? " selected" : ""}>${l}</option>`).join("")}</select></label>
        <label><input type="checkbox" name="__enabled"${!existing || existing.enabled ? " checked" : ""}> Enabled</label>
        <div>
          <button type="submit">${existing ? "Save" : "Add connection"}</button>
          <button type="button" class="secondary-button" id="conn-test">Test connection</button>
        </div>
      </form>`;
    const form = body.querySelector("#conn-form");
    const typeSel = form.querySelector('[name="__type"]');
    if (typeSel) typeSel.addEventListener("change", () => draw(typeSel.value));
    form.querySelector("#conn-test").addEventListener("click", async () => {
      try {
        const r = await api.testConnectionValues({ type: selType, values: formValues(form, spec), connection_id: existing ? existing.id : null });
        flash(r.message, "success");
      } catch (err) { flash(err.message, "error"); }
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = { name: form.querySelector('[name="__name"]').value, values: formValues(form, spec),
        schedule_minutes: Number(form.querySelector('[name="__schedule"]').value), enabled: form.querySelector('[name="__enabled"]').checked };
      try {
        if (existing) await api.updateConnection(existing.id, payload);
        else await api.createConnection({ ...payload, type: selType });
        flash("Connection saved.", "success");
        closeModal();
        reload();
      } catch (err) { flash(err.message, "error"); }
    });
  };
  draw(type);
}

export async function render(container) {
  let polling = null;
  async function load() {
    const data = await api.connections();
    container.innerHTML = `
      <p class="subtitle">Connect your scanners and asset sources once. Quanta stores the credentials encrypted, pulls on the schedule you choose,
      merges new findings into the queue, enriches them with CISA KEV and EPSS, and records every run.</p>
      ${data.encryption_available ? "" : `<div class="callout callout-warn"><strong>Credential storage is off.</strong> Set <code>QUANTA_ENCRYPTION_KEY</code>
        (<code>python cli/quanta_admin.py gen-key</code>) and restart to add connections. Each connector's own page still works without it.</div>`}
      <p><button type="button" id="add-conn"${data.encryption_available ? "" : " disabled"}>Add a connection</button></p>
      <div class="table-scroll"><table class="data-table">
        <thead><tr><th>Name</th><th>Source</th><th>Provides</th><th>Schedule</th><th>Last sync</th><th>Result</th><th></th></tr></thead>
        <tbody>${data.connections.length ? data.connections.map((c) => `<tr>
          <td>${escapeHtml(c.name)}${c.enabled ? "" : ` <span class="muted">(disabled)</span>`}</td>
          <td>${escapeHtml(c.label)}</td>
          <td>${escapeHtml(c.output || "")}</td>
          <td>${escapeHtml((SCHEDULES.find(([v]) => v === c.schedule_minutes) || [0, `${c.schedule_minutes} min`])[1])}</td>
          <td>${statusBadge(c)}<br><span class="muted">${escapeHtml(c.last_run_at || "")}</span></td>
          <td class="wrap-cell">${escapeHtml(c.last_message || "")}</td>
          <td class="nowrap"><button type="button" class="link-button" data-sync="${c.id}">Sync now</button>
            <button type="button" class="link-button" data-edit="${c.id}">Edit</button>
            <button type="button" class="link-button danger-link" data-del="${c.id}">Delete</button></td></tr>`).join("")
          : `<tr><td colspan="7" class="empty-state">No connections yet.</td></tr>`}</tbody></table></div>
      <h2>Supported sources</h2>
      <ul>${data.catalog.map((c) => `<li><strong>${escapeHtml(c.label)}</strong> (${escapeHtml(c.category)})${c.docs || c.note ? ` - ${escapeHtml([c.docs, c.note].filter(Boolean).join(" "))}` : ""}</li>`).join("")}</ul>
      <p class="muted">OpenVAS/GVM launches a scan and polls for a long time, so it keeps its own page under Connectors / Adaptors.</p>`;
    container.querySelector("#add-conn").addEventListener("click", () => openEditor(data, null, load));
    container.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openEditor(data, data.connections.find((c) => String(c.id) === b.dataset.edit), load)));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Delete this connection and its stored credentials? Findings already pulled stay in the queue.")) return;
      try { await api.deleteConnection(Number(b.dataset.del)); flash("Connection deleted.", "success"); load(); } catch (err) { flash(err.message, "error"); }
    }));
    container.querySelectorAll("[data-sync]").forEach((b) => b.addEventListener("click", async () => {
      try { await api.syncConnection(Number(b.dataset.sync)); flash("Sync started.", "info"); setTimeout(load, 1500); } catch (err) { flash(err.message, "error"); }
    }));
    clearTimeout(polling);
    if (data.connections.some((c) => c.last_status === "running")) polling = setTimeout(load, 3000);
  }
  await load();
}
