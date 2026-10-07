import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { icon } from "../icons.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, debounce } from "../ui.js";
import { modal, liveBadge } from "../sxKit.js";
import { selectableTable, autoRefresh, pageActions, skeletonPage, replaceSearch } from "../mxKit.js";
import { connectionHealth, nextRun, connectionKpis, HEALTH_LABEL, HEALTH_TONE, filterRecords } from "../moduleLogic.js";
import { ageLabel } from "../tableMath.js";

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
  ["asm:write", "Send attack-surface discovery output"],
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
  let alive = true;
  let polling = null;
  onCleanup(() => { alive = false; clearTimeout(polling); });
  const $ = (s) => container.querySelector(s);
  const S = { data: null, keys: null, mcp: null, sim: null, q: new URLSearchParams(window.location.search).get("q") || "", state: new URLSearchParams(window.location.search).get("state") || "", loadedAt: 0, testing: new Set(), syncing: new Set() };
  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Connections</h2><p>Connect your scanners and asset sources once. Quanta stores the credentials encrypted, pulls on the schedule you choose, merges new findings into the queue, enriches them with CISA KEV and EPSS, and records every run.</p></div>
    <div class="sx-row"><span id="cn-live"></span><span id="cn-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="cn-refresh">${icon("clock", 14)} Refresh</button></div></div><div id="cn-body">${skeletonPage(5)}</div></div>`;
  const setLive = (m) => { const el = $("#cn-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");
  const url = () => { const p = new URLSearchParams(); if (S.q) p.set("q", S.q); if (S.state) p.set("state", S.state); replaceSearch(p.toString() ? `?${p}` : ""); };

  async function load() {
    const data = await api.connections();
    const keys = await api.apiKeys();
    let mcp = null; try { mcp = await api.mcpStatus(); } catch { mcp = null; }
    let sim = null; try { sim = await api.simulationStatus(); } catch { sim = null; } // null when simulation is not allowed here (403)
    if (!alive) return;
    S.data = data; S.keys = keys; S.mcp = mcp; S.sim = sim; S.loadedAt = Date.now();
  }
  const view = () => {
    const now = Date.now();
    return filterRecords(S.data.connections.filter((c) => !S.state || connectionHealth(c, now) === S.state), S.q, [(c) => c.name, (c) => c.label, (c) => c.output, (c) => c.last_message]);
  };
  function cardHtml(c) {
    const now = Date.now(); const h = connectionHealth(c, now); const nr = nextRun(c, now);
    const sched = (SCHEDULES.find(([v]) => v === c.schedule_minutes) || [0, `${c.schedule_minutes} min`])[1];
    const t = Date.parse(c.last_run_at || "");
    return `<article class="mx-card mx-conn mx-conn-${h}" data-conn="${c.id}" aria-label="${escapeHtml(c.name)}, ${escapeHtml(HEALTH_LABEL[h])}">
      <div class="mx-card-head"><h4>${escapeHtml(c.name)}</h4>${chip(HEALTH_LABEL[h], { tone: HEALTH_TONE[h] })}</div>
      <div class="mx-sub">${escapeHtml(c.label)}${c.output ? ` &middot; provides ${escapeHtml(c.output)}` : ""}${c.mode === "simulation" ? ` ${chip("Simulated", { tone: "info", title: "Recorded vendor responses replayed through the real connector code" })}` : ""}</div>
      <dl class="mx-facts mx-facts-tight"><div class="mx-fact"><dt>Last sync</dt><dd>${Number.isFinite(t) ? `${escapeHtml(ageLabel(now - t))}<span class="ui-muted mx-sub"> ${escapeHtml(c.last_run_at)}</span>` : '<span class="ui-muted">never</span>'}</dd></div>
        <div class="mx-fact"><dt>Schedule</dt><dd>${escapeHtml(sched)}</dd></div><div class="mx-fact"><dt>Next</dt><dd class="${nr.overdue ? "mx-clock-warn" : ""}">${escapeHtml(nr.label)}</dd></div></dl>
      ${c.last_message ? `<div class="mx-note" title="${escapeHtml(c.last_message)}">${escapeHtml(c.last_message)}</div>` : ""}
      <div class="mx-actions"><button type="button" class="ui-btn sx-btn-sm" data-sync="${c.id}" ${S.syncing.has(c.id) || h === "running" ? "disabled" : ""}>${S.syncing.has(c.id) || h === "running" ? "Syncing..." : "Sync now"}</button>
        <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-test="${c.id}" ${S.testing.has(c.id) ? "disabled" : ""}>${S.testing.has(c.id) ? "Testing..." : "Test"}</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-edit="${c.id}">Edit</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-del="${c.id}">Delete</button></div></article>`;
  }
  function paint() {
    if (!alive || !S.data) return;
    const d = S.data; const k = connectionKpis(d.connections); const keys = S.keys.keys; const sim = S.sim; const mcp = S.mcp;
    const tile = (label, value, extra = {}) => `<div class="sx-kpi-cell">${kpiTile({ label, value, ...extra })}</div>`;
    const list = view();
    const age = $("#cn-age"); if (age) { age.innerHTML = dataAgeBadge(S.loadedAt); mountDataAge(age); }
    const states = ["ok", "failing", "stale", "never", "running", "disabled"].filter((x) => k[x]);
    $("#cn-body").innerHTML = `${d.encryption_available ? "" : `<div class="mx-callout mx-callout-warn"><strong>Credential storage is off.</strong> Set <code>QUANTA_ENCRYPTION_KEY</code> (<code>python cli/quanta_admin.py gen-key</code>) and restart to add connections. Each connector's own page still works without it.</div>`}
      <div class="sx-kpis mx-kpis">${tile("Connections", k.total)}${tile("Healthy", k.ok, { tone: "good", hint: "Last sync succeeded and is recent for its schedule." })}${tile("Failing", k.failing, { tone: k.failing ? "danger" : "good", hint: "The last sync ended in an error. The card shows the message." })}${tile("Not syncing", k.stale, { tone: k.stale ? "warn" : "good", hint: "Enabled and scheduled, but the last success is older than twice the schedule." })}${tile("API keys", keys.filter((x) => !x.revoked_at).length)}</div>
      <div class="sx-toolbar" role="search" aria-label="Filter connections"><input type="search" class="sx-field" id="cn-q" placeholder="Search name, source, message" value="${escapeHtml(S.q)}" aria-label="Search connections">
        <span class="mx-chips" role="group" aria-label="Filter by health"><button type="button" class="mx-fchip${S.state ? "" : " on"}" data-state="" aria-pressed="${!S.state}">All <b>${k.total}</b></button>${states.map((x) => `<button type="button" class="mx-fchip${S.state === x ? " on" : ""}" data-state="${x}" aria-pressed="${S.state === x}">${HEALTH_LABEL[x]} <b>${k[x]}</b></button>`).join("")}</span>
        <button type="button" class="ui-btn sx-btn-sm" id="add-conn" ${d.encryption_available ? "" : "disabled"}>Add a connection</button>
        ${sim ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="sim-load">Load demonstration data</button>${sim.simulated_findings || sim.connections.length ? '<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="sim-remove">Remove demonstration data</button>' : ""}` : ""}</div>
      ${sim ? `<p class="ui-muted">Demonstration data is not stored in a file: recorded vendor-format responses are replayed through each connector's real code, then merged, enriched and stored exactly like live data. Every such record is marked ${chip("Simulated", { tone: "info" })} and is never allowed to overwrite a live one.${sim.simulated_findings ? ` Currently ${sim.simulated_findings} simulated and ${sim.live_findings} live finding(s).` : ""}</p>` : ""}
      ${list.length ? `<div class="mx-grid-cards" role="list">${list.map(cardHtml).join("")}</div>` : emptyState({ title: d.connections.length ? "No connection matches" : "No connections yet", body: d.connections.length ? "Clear the search or the health filter." : "Add a scanner or an asset source and Quanta pulls on the schedule you choose. Or load demonstration data to see the pages with data in them.", iconName: "adaptor" })}
      <h3 class="mx-h3">Send data to Quanta</h3><p class="ui-muted">For tools that call Quanta instead of being polled: a scanner export, a SOAR playbook, a CI job or ServiceNow reporting a ticket change. Each caller gets its own key with only the access it needs. A key is shown once.</p>
      <p class="sx-row"><button type="button" class="ui-btn sx-btn-sm" id="add-key">Create an API key</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="import-file">Import a scanner file</button></p><div id="cn-keys"></div>
      ${mcp ? mcpPanel(mcp) : ""}
      <details class="sx-panel mx-details"><summary>Supported sources (${d.catalog.length})</summary><ul class="mx-list">${d.catalog.map((c) => `<li><strong>${escapeHtml(c.label)}</strong> (${escapeHtml(c.category)})${c.docs || c.note ? ` - ${escapeHtml([c.docs, c.note].filter(Boolean).join(" "))}` : ""}</li>`).join("")}</ul><p class="ui-muted">OpenVAS/GVM reads the results of a finished task here; launching and tracking a scan stays on its own page under Connectors.</p></details>`;
    selectableTable($("#cn-keys"), { rows: keys, rowKey: (x) => x.id, caption: "API keys", csvName: "quanta-api-keys", storageKey: "conn-keys", rowHeight: 52, maxHeight: 360, emptyHtml: emptyState({ title: "No API keys yet", body: "Create one for each caller that sends data in.", iconName: "signal" }),
      columns: [{ key: "n", label: "Name", width: 220, csv: (x) => x.name, render: (x) => `${escapeHtml(x.name)}${x.revoked_at ? ` ${chip("revoked", { tone: "neutral" })}` : ""}` }, { key: "k", label: "Key", width: 150, csv: (x) => `qk_${x.prefix}`, render: (x) => `<code>qk_${escapeHtml(x.prefix)}...</code>` },
        { key: "a", label: "Access", width: 300, csv: (x) => x.scopes.join(" "), render: (x) => `<span class="mx-clip" title="${escapeHtml(x.scopes.join(", "))}">${x.scopes.map(escapeHtml).join(", ")}</span>${x.team ? `<div class="mx-sub">team: ${escapeHtml(x.team)}</div>` : ""}` },
        { key: "u", label: "Last used", width: 160, csv: (x) => x.last_used_at || "", render: (x) => escapeHtml(x.last_used_at || "Never") }, { key: "e", label: "Expires", width: 140, csv: (x) => x.expires_at || "", render: (x) => escapeHtml(x.expires_at || "Never") },
        { key: "r", label: "", width: 90, csv: () => "", render: (x) => (x.revoked_at ? "" : `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-revoke="${x.id}">Revoke</button>`) }] });
    clearTimeout(polling);
    if (d.connections.some((c) => c.last_status === "running") || S.syncing.size) polling = setTimeout(() => reload(true), 3000);
  }
  const reload = async (quiet = false) => { try { await load(); S.syncing = new Set([...S.syncing].filter((id) => (S.data.connections.find((c) => c.id === id) || {}).last_status === "running")); paint(); if (!quiet) toast("Refreshed.", { tone: "good", ms: 1600 }); } catch (e) { if (!quiet) toast(`Could not refresh: ${e.message}`, { tone: "bad" }); } };

  async function testConn(id) {
    const c = S.data.connections.find((x) => x.id === id); if (!c) return;
    S.testing.add(id); paint();
    try { const r = await api.testConnectionValues({ type: c.type, values: {}, connection_id: id }); toast(`${c.name}: ${r.message}`, { tone: "good", ms: 6000 }); }
    catch (e) { toast(`${c.name}: ${e.message}`, { tone: "bad", ms: 10000 }); }
    finally { S.testing.delete(id); paint(); }
  }
  async function syncConn(id) {
    S.syncing.add(id); const c = S.data.connections.find((x) => x.id === id); if (c) c.last_status = "running"; paint();
    try { await api.syncConnection(id); toast("Sync started.", { tone: "info", ms: 2500 }); } catch (e) { S.syncing.delete(id); if (c) c.last_status = "error"; toast(e.message, { tone: "bad" }); paint(); }
  }
  const typeSearch = debounce((v) => { S.q = v; url(); paint(); const i = $("#cn-q"); if (i) { i.focus(); i.setSelectionRange(v.length, v.length); } }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "cn-q") typeSearch(e.target.value); });
  container.addEventListener("click", async (e) => {
    const t = e.target;
    const st = t.closest("[data-state]"); if (st) { S.state = st.dataset.state; url(); paint(); return; }
    if (t.closest("#cn-refresh")) { reload(false); return; }
    if (t.closest("#add-conn")) { openEditor(S.data, null, reload); return; }
    const ed = t.closest("[data-edit]"); if (ed) { openEditor(S.data, S.data.connections.find((c) => String(c.id) === ed.dataset.edit), reload); return; }
    const ts = t.closest("[data-test]"); if (ts) { testConn(Number(ts.dataset.test)); return; }
    const sy = t.closest("[data-sync]"); if (sy) { syncConn(Number(sy.dataset.sync)); return; }
    const del = t.closest("[data-del]");
    if (del) {
      const c = S.data.connections.find((x) => String(x.id) === del.dataset.del);
      const ok = await modal({ title: `Delete ${c ? c.name : "this connection"}?`, confirmLabel: "Delete", danger: true, description: "Its stored credentials are deleted. Findings already pulled stay in the queue.", body: "" });
      if (!ok) return;
      try { await api.deleteConnection(Number(del.dataset.del)); toast("Connection deleted.", { tone: "good" }); reload(true); } catch (er) { toast(er.message, { tone: "bad" }); }
      return;
    }
    if (t.closest("#add-key")) { openKeyEditor(reload); return; }
    if (t.closest("#import-file")) { openImport(reload); return; }
    const rv = t.closest("[data-revoke]");
    if (rv) {
      const ok = await modal({ title: "Revoke this key?", confirmLabel: "Revoke", danger: true, description: "Anything using it stops working immediately.", body: "" });
      if (!ok) return;
      try { await api.revokeApiKey(Number(rv.dataset.revoke)); toast("Key revoked.", { tone: "good" }); reload(true); } catch (er) { toast(er.message, { tone: "bad" }); }
      return;
    }
    if (t.closest("#sim-load")) {
      const btn = t.closest("#sim-load");
      try {
        const plan = await api.simulationLoad({ confirm: false });
        const ok = await modal({ title: "Load demonstration data?", confirmLabel: "Load it", description: `${plan.estate.hosts} fictional hosts and ${plan.estate.detections} vulnerabilities go through ${plan.connections.map((c) => c.name).join(", ")}. Each record is marked Simulated and can be removed again.`, body: "" });
        if (!ok) return;
        btn.disabled = true;
        const r = await api.simulationLoad({ confirm: true });
        const bad = r.results.filter((x) => !x.ok);
        toast(bad.length ? `Loaded with ${bad.length} failure(s): ${bad[0].message}` : "Demonstration data loaded.", { tone: bad.length ? "warn" : "good", ms: 8000 }); reload(true);
      } catch (er) { toast(er.message, { tone: "bad" }); if (btn) btn.disabled = false; }
      return;
    }
    if (t.closest("#sim-remove")) {
      const ok = await modal({ title: "Remove demonstration data?", confirmLabel: "Remove", danger: true, description: "The simulation connections and every simulated record go. Live data is not touched.", body: "" });
      if (!ok) return;
      try { const r = await api.simulationRemove(); toast(`Removed ${r.connections_removed} connection(s) and ${r.findings_removed} simulated finding(s).`, { tone: "good" }); reload(true); } catch (er) { toast(er.message, { tone: "bad" }); }
    }
  });

  try { await load(); } catch (e) { $("#cn-body").innerHTML = emptyState({ title: e.status === 401 || e.status === 403 ? "Connections are for administrators" : "Connections could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" }); return; }
  paint();
  pageActions([{ label: "Connections: add a connection", icon: "adaptor", run: () => openEditor(S.data, null, reload) }, { label: "Connections: show the failing ones", icon: "adaptor", run: () => { S.state = "failing"; url(); paint(); } }, { label: "Connections: create an API key", icon: "adaptor", run: () => openKeyEditor(reload) }, { label: "Connections: refresh", icon: "adaptor", run: () => reload(false) }]);
  autoRefresh(() => reload(true), { every: 30000, onMode: setLive });
}
