import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";

export const title = "Connections";

const KEY_SCOPES = [
  ["ingest:write", "Send findings and scanner files in"],
  ["tickets:update", "Report ticket status changes"],
  ["read:findings", "Read findings out (reports, BI)"],
  ["controls:write", "Report security controls an EDR or firewall observes"],
  ["ai-usage:write", "Report AI usage (gateway, OpenTelemetry)"],
  ["soc:write", "Send SIEM / XDR alerts for triage"],
  ["darkweb:write", "Send dark-web monitoring output"],
  ["mcp:read", "Let an AI assistant read findings (MCP, read-only; also tick \"Read findings out\")"],
];

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
  if (f.type === "select") {
    const cur = current.config ? current.config[f.name] || "" : "";
    return `<label>${escapeHtml(f.label)}${f.required ? "" : " (optional)"}
      <select id="${id}" name="${escapeHtml(f.name)}"><option value="">${escapeHtml(f.help || "Default")}</option>${(f.options || []).map((o) => `<option value="${escapeHtml(o)}"${cur === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select></label>`;
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

function openKeyEditor(reload) {
  const body = openModal("");
  body.innerHTML = `
    <h2>Create an API key</h2>
    <form id="key-form" class="run-form">
      <label>Name <input name="name" maxlength="80" required placeholder="Nightly Tenable export"></label>
      <fieldset><legend>Access</legend>
        ${KEY_SCOPES.map(([v, l]) => `<label><input type="checkbox" name="scope" value="${v}"${v === "ingest:write" ? " checked" : ""}> ${escapeHtml(l)}</label>`).join("")}
      </fieldset>
      <label>Limit to one team (optional, narrows what an MCP key can read) <input name="team" maxlength="80" placeholder="Leave empty for the whole estate"></label>
      <label>Expires <select name="expires"><option value="">Never</option><option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In a year</option></select></label>
      <div><button type="submit">Create key</button></div>
    </form>`;
  body.querySelector("#key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const scopes = [...f.querySelectorAll('[name="scope"]:checked')].map((x) => x.value);
    if (!scopes.length) { flash("Choose at least one kind of access.", "error"); return; }
    try {
      const r = await api.createApiKey({ name: f.name.value, scopes, expires_days: f.expires.value ? Number(f.expires.value) : null, team: f.team.value.trim() || null });
      body.innerHTML = `<h2>Your new key</h2>
        <p><strong>Copy it now.</strong> Quanta stores only a fingerprint, so it cannot be shown again.</p>
        <p><input id="new-key" readonly value="${escapeHtml(r.key)}" style="width:100%"></p>
        <p class="muted">Send it as <code>Authorization: Bearer &lt;key&gt;</code> or <code>X-API-Key: &lt;key&gt;</code>.</p>
        <p><button type="button" id="copy-key">Copy</button> <button type="button" class="secondary-button" id="done-key">Done</button></p>`;
      const box = body.querySelector("#new-key");
      box.addEventListener("focus", () => box.select());
      body.querySelector("#copy-key").addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(r.key); flash("Copied.", "success"); } catch { box.select(); }
      });
      body.querySelector("#done-key").addEventListener("click", () => { closeModal(); reload(); });
    } catch (err) { flash(err.message, "error"); }
  });
}

function openImport(reload) {
  const body = openModal("");
  body.innerHTML = `
    <h2>Import a scanner file</h2>
    <p class="muted">For a source Quanta cannot reach directly. Upload the scanner's CSV export in the Tenable column layout.
    Re-importing the same file updates findings instead of duplicating them.</p>
    <form id="imp-form" class="run-form">
      <label>File <input type="file" name="file" accept=".csv,text/csv" required></label>
      <label>Source name <input name="source" value="tenable-export" pattern="[a-z0-9][a-z0-9-]{1,39}" required></label>
      <label><input type="checkbox" name="reconcile"> This is the complete export: remove findings from this source that are not in it</label>
      <div><button type="submit">Import</button></div>
    </form>`;
  body.querySelector("#imp-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      const r = await api.importScannerFile(f.source.value, f.reconcile.checked, f.file.files[0]);
      flash(`${r.added} new, ${r.updated} updated${r.removed ? `, ${r.removed} removed` : ""}.`, "success");
      closeModal();
      reload();
    } catch (err) { flash(err.message, "error"); }
  });
}

// Placeholder key only: a real key is shown once, at creation, and never here.
function mcpPanel(m) {
  const snippet = JSON.stringify({ mcpServers: { quanta: { type: "http", url: m.endpoint_url, headers: { Authorization: "Bearer qk_YOUR_KEY_HERE" } } } }, null, 2);
  const c = m.recent_audit_counts || {};
  const total = (prefix) => Object.entries(c).filter(([k]) => k.startsWith(prefix)).reduce((n, [, v]) => n + v, 0);
  return `<h2>AI assistant access (MCP)</h2>
    <p class="muted">A read-only endpoint so an AI assistant can ask Quanta about findings, assets and posture. It cannot change anything or start anything. Results are scanner and user text:
    the assistant is told to treat them as data. Create a key with <code>mcp:read</code> and <code>read:findings</code> to use it.</p>
    <p>Status: <span class="badge ${m.enabled ? "" : "badge-outline"}">${m.enabled ? "Enabled" : "Disabled (set QUANTA_MCP_ENABLED=true and restart)"}</span>
      &nbsp; Endpoint: <code>${escapeHtml(m.endpoint_url)}</code> &nbsp; Protocol ${escapeHtml(m.protocol_version)}</p>
    <p class="muted">Recent calls: ${total("tool_call:")} answered, ${total("denied:")} refused. Tools: ${m.tools.map((t) => `<code>${escapeHtml(t.name)}</code>${t.enabled ? "" : " (off)"}`).join(", ")}.</p>
    <pre class="code-block" style="white-space:pre-wrap">${escapeHtml(snippet)}</pre>`;
}

export async function render(container) {
  let polling = null;
  async function load() {
    const data = await api.connections();
    const keys = await api.apiKeys();
    let mcp = null; // null when the status route is unavailable
    try { mcp = await api.mcpStatus(); } catch { mcp = null; }
    let sim = null; // null when simulation is not allowed in this environment (the route answers 403)
    try { sim = await api.simulationStatus(); } catch { sim = null; }
    container.innerHTML = `
      <p class="subtitle">Connect your scanners and asset sources once. Quanta stores the credentials encrypted, pulls on the schedule you choose,
      merges new findings into the queue, enriches them with CISA KEV and EPSS, and records every run.</p>
      ${data.encryption_available ? "" : `<div class="callout callout-warn"><strong>Credential storage is off.</strong> Set <code>QUANTA_ENCRYPTION_KEY</code>
        (<code>python cli/quanta_admin.py gen-key</code>) and restart to add connections. Each connector's own page still works without it.</div>`}
      <p><button type="button" id="add-conn"${data.encryption_available ? "" : " disabled"}>Add a connection</button>
        ${sim ? `<button type="button" class="secondary-button" id="sim-load">Load demonstration data</button>
        ${sim.simulated_findings || sim.connections.length ? `<button type="button" class="secondary-button danger-link" id="sim-remove">Remove demonstration data</button>` : ""}` : ""}</p>
      ${sim ? `<p class="muted">Demonstration data is not stored in a file: recorded vendor-format responses are replayed through each connector's real code, then merged, enriched
        and stored exactly like live data. Every such record is marked <span class="badge badge-outline">Simulated</span> and is never allowed to overwrite a live one.
        ${sim.simulated_findings ? `Currently ${sim.simulated_findings} simulated and ${sim.live_findings} live finding(s).` : ""}</p>` : ""}
      <div class="table-scroll"><table class="data-table">
        <thead><tr><th>Name</th><th>Source</th><th>Provides</th><th>Schedule</th><th>Last sync</th><th>Result</th><th></th></tr></thead>
        <tbody>${data.connections.length ? data.connections.map((c) => `<tr>
          <td>${escapeHtml(c.name)}${c.mode === "simulation" ? ` <span class="badge badge-outline" title="Recorded vendor responses replayed through the real connector code">Simulated</span>` : ""}${c.enabled ? "" : ` <span class="muted">(disabled)</span>`}</td>
          <td>${escapeHtml(c.label)}</td>
          <td>${escapeHtml(c.output || "")}</td>
          <td>${escapeHtml((SCHEDULES.find(([v]) => v === c.schedule_minutes) || [0, `${c.schedule_minutes} min`])[1])}</td>
          <td>${statusBadge(c)}<br><span class="muted">${escapeHtml(c.last_run_at || "")}</span></td>
          <td class="wrap-cell">${escapeHtml(c.last_message || "")}</td>
          <td class="nowrap"><button type="button" class="link-button" data-sync="${c.id}">Sync now</button>
            <button type="button" class="link-button" data-edit="${c.id}">Edit</button>
            <button type="button" class="link-button danger-link" data-del="${c.id}">Delete</button></td></tr>`).join("")
          : `<tr><td colspan="7" class="empty-state">No connections yet.</td></tr>`}</tbody></table></div>
      <h2>Send data to Quanta</h2>
      <p class="muted">For tools that call Quanta instead of being polled: a scanner export, a SOAR playbook, a CI job or ServiceNow reporting a ticket change.
      Each caller gets its own key with only the access it needs. A key is shown once.</p>
      <p><button type="button" id="add-key">Create an API key</button>
        <button type="button" class="secondary-button" id="import-file">Import a scanner file</button></p>
      <div class="table-scroll"><table class="data-table">
        <thead><tr><th>Name</th><th>Key</th><th>Access</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
        <tbody>${keys.keys.length ? keys.keys.map((k) => `<tr>
          <td>${escapeHtml(k.name)}${k.revoked_at ? ` <span class="muted">(revoked)</span>` : ""}</td>
          <td><code>qk_${escapeHtml(k.prefix)}...</code></td>
          <td>${k.scopes.map((s) => escapeHtml(s)).join(", ")}${k.team ? ` <span class="muted">(team: ${escapeHtml(k.team)})</span>` : ""}</td>
          <td>${escapeHtml(k.last_used_at || "Never")}</td>
          <td>${escapeHtml(k.expires_at || "Never")}</td>
          <td class="nowrap">${k.revoked_at ? "" : `<button type="button" class="link-button danger-link" data-revoke="${k.id}">Revoke</button>`}</td></tr>`).join("")
          : `<tr><td colspan="6" class="empty-state">No API keys yet.</td></tr>`}</tbody></table></div>
      ${mcp ? mcpPanel(mcp) : ""}
      <h2>Supported sources</h2>
      <ul>${data.catalog.map((c) => `<li><strong>${escapeHtml(c.label)}</strong> (${escapeHtml(c.category)})${c.docs || c.note ? ` - ${escapeHtml([c.docs, c.note].filter(Boolean).join(" "))}` : ""}</li>`).join("")}</ul>
      <p class="muted">OpenVAS/GVM reads the results of a finished task here; launching and tracking a scan stays on its own page under Connectors / Adaptors.</p>`;
    container.querySelector("#add-conn").addEventListener("click", () => openEditor(data, null, load));
    container.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => openEditor(data, data.connections.find((c) => String(c.id) === b.dataset.edit), load)));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Delete this connection and its stored credentials? Findings already pulled stay in the queue.")) return;
      try { await api.deleteConnection(Number(b.dataset.del)); flash("Connection deleted.", "success"); load(); } catch (err) { flash(err.message, "error"); }
    }));
    container.querySelectorAll("[data-sync]").forEach((b) => b.addEventListener("click", async () => {
      try { await api.syncConnection(Number(b.dataset.sync)); flash("Sync started.", "info"); setTimeout(load, 1500); } catch (err) { flash(err.message, "error"); }
    }));
    const simLoad = container.querySelector("#sim-load");
    if (simLoad) simLoad.addEventListener("click", async () => {
      try {
        const plan = await api.simulationLoad({ confirm: false });
        const names = plan.connections.map((c) => c.name).join(", ");
        if (!window.confirm(`Load demonstration data through ${names}? ${plan.estate.hosts} fictional hosts, ${plan.estate.detections} vulnerabilities. Each record is marked Simulated.`)) return;
        simLoad.disabled = true;
        const r = await api.simulationLoad({ confirm: true });
        const bad = r.results.filter((x) => !x.ok);
        flash(bad.length ? `Loaded with ${bad.length} failure(s): ${bad[0].message}` : "Demonstration data loaded.", bad.length ? "error" : "success");
        load();
      } catch (err) { flash(err.message, "error"); simLoad.disabled = false; }
    });
    const simRemove = container.querySelector("#sim-remove");
    if (simRemove) simRemove.addEventListener("click", async () => {
      if (!window.confirm("Remove the simulation connections and every simulated record? Live data is not touched.")) return;
      try { const r = await api.simulationRemove(); flash(`Removed ${r.connections_removed} connection(s) and ${r.findings_removed} simulated finding(s).`, "success"); load(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#add-key").addEventListener("click", () => openKeyEditor(load));
    container.querySelector("#import-file").addEventListener("click", () => openImport(load));
    container.querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Revoke this key? Anything using it stops working immediately.")) return;
      try { await api.revokeApiKey(Number(b.dataset.revoke)); flash("Key revoked.", "success"); load(); } catch (err) { flash(err.message, "error"); }
    }));
    clearTimeout(polling);
    if (data.connections.some((c) => c.last_status === "running")) polling = setTimeout(load, 3000);
  }
  await load();
}
