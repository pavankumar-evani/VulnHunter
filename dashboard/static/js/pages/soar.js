import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "SOAR Playbooks";

const TABS = [["playbooks", "Playbooks"], ["runs", "Runs"], ["build", "Build or edit"]];
const STATUS = { running: "badge-medium", "waiting-approval": "badge-high", completed: "badge-low", failed: "badge-critical", rejected: "badge-outline", cancelled: "badge-outline" };
const STEP_STATUS = { ok: "badge-low", "dry-run": "badge-outline", skipped: "badge-outline", waiting: "badge-high", approved: "badge-low", rejected: "badge-critical", failed: "badge-critical", cancelled: "badge-outline" };
const OPS = ["eq", "ne", "in", "gte", "truthy", "falsy"];
const NOTE = "A playbook is a short list of steps run against an alert. Quanta never acts on your systems itself: steps that change something send a signed request to an endpoint you own, and only after a second person approves. Start with a dry run, which contacts nothing.";

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "playbooks";
  let catalog = null;
  let draft = null;
  let openRun = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="soar-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; openRun = null; show(); }));
  };
  const blank = () => ({ id: null, name: "", description: "", trigger: { mode: "manual", min_severity: "High" }, enabled: true, steps: [{ type: "investigate", params: { reputation: false, siem: false } }] });
  const fromTemplate = (t) => ({ id: null, name: t.name, description: t.description, trigger: { mode: t.trigger.mode, min_severity: t.trigger.min_severity || "High" }, enabled: true, steps: JSON.parse(JSON.stringify(t.steps)) });

  async function playbooks() {
    const [c, al] = await Promise.all([api.soarPlaybooks(), api.socAlerts()]);
    catalog = c;
    const open = al.alerts.filter((a) => a.status !== "closed");
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Playbook</th><th>Starts</th><th>Steps</th><th></th></tr></thead><tbody>
      ${c.playbooks.length ? c.playbooks.map((p) => `<tr><td class="wrap-cell"><strong>${escapeHtml(p.name)}</strong>${p.enabled ? "" : ' <span class="badge badge-outline">off</span>'}<br><span class="muted">${escapeHtml(p.description || "")}</span></td>
        <td>${p.trigger.mode === "manual" ? "By a person" : "Automatically, " + escapeHtml(p.trigger.min_severity) + " and above"}</td><td class="wrap-cell">${p.steps.map((s) => escapeHtml(s.type)).join(" &rarr; ")}</td>
        <td><button type="button" data-run="${p.id}">Run on an alert</button> <button type="button" class="link-button" data-edit="${p.id}">Edit</button> <button type="button" class="link-button danger-link" data-del="${p.id}">Delete</button></td></tr>`).join("")
        : '<tr><td colspan="4" class="empty-state">No playbooks yet. Start from a template below.</td></tr>'}</tbody></table></div>
      <h3>Start from a template</h3>
      ${c.templates.map((t, i) => `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:6px 16px 12px;margin:10px 0"><strong>${escapeHtml(t.name)}</strong><p class="muted">${escapeHtml(t.description)}</p>
        <button type="button" class="secondary-button" data-tpl="${i}">Use this template</button></div>`).join("")}
      <div id="run-box"></div>
      <p class="muted">Limits set by policy: at most ${c.policy.max_steps} steps; ${c.policy.require_second_person ? "a different person must approve" : "the starter may approve"}; ${c.policy.auto_runs_per_hour} automatic runs an hour.
      Add a "Response endpoint" and a "Notification webhook" on the Connections page for steps that reach your systems.</p>`);
    container.querySelectorAll("[data-tpl]").forEach((b) => b.addEventListener("click", () => { draft = fromTemplate(c.templates[Number(b.dataset.tpl)]); tab = "build"; show(); }));
    container.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => { draft = JSON.parse(JSON.stringify(c.playbooks.find((p) => p.id === Number(b.dataset.edit)))); tab = "build"; show(); }));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (window.confirm("Delete this playbook?")) { try { await api.soarDelete(Number(b.dataset.del)); show(); } catch (e) { flash(e.message, "error"); } } }));
    container.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", () => {
      const pb = c.playbooks.find((p) => p.id === Number(b.dataset.run));
      container.querySelector("#run-box").innerHTML = `<h3>Run "${escapeHtml(pb.name)}"</h3>
        <form id="rf" class="run-form"><label>Alert <select name="alert">${open.map((a) => `<option value="${a.id}">#${a.id} ${escapeHtml(a.title)} (${escapeHtml(a.asset || "no host")})</option>`).join("") || "<option value=''>No open alerts</option>"}</select></label>
        <label><input type="checkbox" name="dry" checked> Dry run: show what would happen, contact nothing, change nothing</label><div><button type="submit">Start</button></div></form>`;
      container.querySelector("#rf").addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = e.target, body = { alert_id: Number(f.alert.value), dry_run: f.dry.checked };
        try {
          if (!body.dry_run) {
            const pre = await api.soarRun(pb.id, body);
            if (!window.confirm(pre.message + "\n\nSteps: " + pre.steps.map((s) => s.type).join(", "))) return;
            body.confirm = true;
          }
          const run = await api.soarRun(pb.id, body);
          openRun = run.id; tab = "runs"; flash(`Run ${run.status}.`, "success"); show();
        } catch (err) { flash(err.message, "error"); }
      });
    }));
  }

  function runDetail(r, me) {
    const waiting = r.status === "waiting-approval";
    return `<p><button type="button" class="link-button" id="back">&larr; All runs</button></p>
      <h3>${escapeHtml(r.playbook_name)} <span class="badge ${STATUS[r.status]}">${escapeHtml(r.status)}</span>${r.dry_run ? ' <span class="badge badge-outline">dry run</span>' : ""}</h3>
      <p class="muted">Alert #${r.alert_id} &middot; started by ${escapeHtml(r.started_by)} ${escapeHtml(r.started_at)}${r.finished_at ? ", finished " + escapeHtml(r.finished_at) : ""}</p>
      ${waiting ? `<div class="callout callout-warn"><strong>Waiting for approval.</strong> ${escapeHtml((r.context.pending || {}).message || "")}
        <p>${r.started_by === me ? "You started this run, so someone else has to approve it." : '<button type="button" id="approve">Approve</button> <button type="button" class="secondary-button" id="reject">Reject</button>'} <button type="button" class="link-button" id="cancel">Cancel run</button></p></div>` : ""}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>#</th><th>Step</th><th>Result</th><th>What happened</th><th>When</th></tr></thead><tbody>
      ${r.log.map((l) => `<tr><td>${l.step}</td><td>${escapeHtml(l.type)}</td><td><span class="badge ${STEP_STATUS[l.status] || "badge-outline"}">${escapeHtml(l.status)}</span></td><td class="wrap-cell">${escapeHtml(l.detail)}</td><td>${escapeHtml(l.at)}</td></tr>`).join("")}</tbody></table></div>`;
  }

  async function runs() {
    const { runs: rs } = await api.soarRuns();
    let me = "";
    try { me = ((await api.authMe()).user || {}).email || ""; } catch { me = ""; }
    const r = openRun && rs.find((x) => x.id === openRun);
    if (r) {
      shell(runDetail(r, me));
      container.querySelector("#back").addEventListener("click", () => { openRun = null; show(); });
      const act = (fn, msg) => async () => { try { await fn(); flash(msg, "success"); show(); } catch (e) { flash(e.message, "error"); } };
      const a = container.querySelector("#approve"), j = container.querySelector("#reject"), c = container.querySelector("#cancel");
      if (a) a.addEventListener("click", act(() => api.soarApprove(r.id), "Approved."));
      if (j) j.addEventListener("click", act(() => api.soarReject(r.id, { reason: window.prompt("Why? (optional)") || "" }), "Rejected."));
      if (c) c.addEventListener("click", act(() => api.soarCancel(r.id), "Cancelled."));
      return;
    }
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Run</th><th>Playbook</th><th>Alert</th><th>Status</th><th>Started by</th><th></th></tr></thead><tbody>
      ${rs.length ? rs.map((x) => `<tr><td>#${x.id}${x.dry_run ? ' <span class="badge badge-outline">dry</span>' : ""}</td><td>${escapeHtml(x.playbook_name)}</td><td>#${x.alert_id}</td>
        <td><span class="badge ${STATUS[x.status]}">${escapeHtml(x.status)}</span></td><td>${escapeHtml(x.started_by)}</td><td><button type="button" class="link-button" data-open="${x.id}">Open</button></td></tr>`).join("")
        : '<tr><td colspan="6" class="empty-state">No runs yet.</td></tr>'}</tbody></table></div>`);
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { openRun = Number(b.dataset.open); show(); }));
  }

  function paramFields(s, i) {
    const p = s.params, actions = Object.entries(catalog.actions).filter(([, v]) => v.allowed);
    const inp = (k, label, ph = "") => `<label>${label} <input data-p="${i}:${k}" value="${escapeHtml(p[k] || "")}" placeholder="${escapeHtml(ph)}"></label>`;
    switch (s.type) {
      case "investigate": return `<label><input type="checkbox" data-pc="${i}:reputation"${p.reputation ? " checked" : ""}> Look up indicators</label> <label><input type="checkbox" data-pc="${i}:siem"${p.siem ? " checked" : ""}> Search the SIEM</label>`;
      case "add-note": return inp("text", "Note", "e.g. Quanta recommends {verdict}");
      case "update-alert": return `<label>Status <select data-p="${i}:status"><option value="">(leave)</option><option${p.status === "investigating" ? " selected" : ""}>investigating</option></select></label> ${inp("assignee", "Assign to", "name@company.com")}`;
      case "notify": return `<label>Channel <select data-p="${i}:channel"><option${p.channel === "webhook" ? " selected" : ""}>webhook</option><option${p.channel === "email" ? " selected" : ""}>email</option></select></label> ${p.channel === "email" ? inp("to", "To (comma separated)") : ""} ${inp("text", "Message", "{severity} alert on {asset}: {title}")}`;
      case "request-approval": return inp("message", "Question for the approver", "Isolate {asset}?");
      case "response-action": return `<label>Action <select data-p="${i}:action">${actions.map(([k, v]) => `<option value="${k}"${p.action === k ? " selected" : ""}>${escapeHtml(v.label)}${v.destructive ? " (needs approval)" : ""}</option>`).join("")}</select></label> ${inp("target", "Target", "{asset}, {user}, {first_ip}")} ${inp("reason", "Reason (sent with the request)")}`;
      default: return '<span class="muted">No settings.</span>';
    }
  }

  function builder() {
    const d = draft;
    const body = `<form id="bf" class="run-form"><label>Name <input name="name" value="${escapeHtml(d.name)}" required maxlength="120"></label>
      <label>Description <input name="description" value="${escapeHtml(d.description || "")}" maxlength="500"></label>
      <label>Starts <select name="mode"><option value="manual"${d.trigger.mode === "manual" ? " selected" : ""}>when a person starts it</option><option value="on-alert"${d.trigger.mode === "on-alert" ? " selected" : ""}>automatically on new alerts</option></select></label>
      ${d.trigger.mode === "on-alert" ? `<label>For alerts at or above <select name="min_severity">${["Medium", "High", "Critical"].map((s) => `<option${d.trigger.min_severity === s ? " selected" : ""}>${s}</option>`).join("")}</select></label>
        <p class="muted">An automatic playbook may only investigate locally, add notes, mark an alert investigating, notify, and open tickets. Looking outside Quanta or changing your environment is always started by a person.</p>` : ""}
      <label><input type="checkbox" name="enabled"${d.enabled ? " checked" : ""}> Enabled</label>
      <h3>Steps</h3>
      ${d.steps.map((s, i) => `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:8px 14px;margin:8px 0"><strong>${i + 1}. ${escapeHtml(catalog.step_types[s.type] || s.type)}</strong>
        <div>${paramFields(s, i)}</div>
        <div class="muted">Only if: <input data-wp="${i}" value="${escapeHtml(s.when ? s.when.path : "")}" placeholder="investigation.verdict" size="28">
          <select data-wo="${i}"><option value="">(always)</option>${OPS.map((o) => `<option${s.when && s.when.op === o ? " selected" : ""}>${o}</option>`).join("")}</select>
          <input data-wv="${i}" value="${s.when && s.when.value !== undefined && s.when.value !== null ? escapeHtml(String(s.when.value)) : ""}" placeholder="value" size="22"></div>
        <button type="button" class="link-button" data-up="${i}">Up</button> <button type="button" class="link-button" data-down="${i}">Down</button> <button type="button" class="link-button danger-link" data-rm="${i}">Remove</button></div>`).join("")}
      <p><label>Add a step <select id="addtype">${Object.entries(catalog.step_types).map(([k, v]) => `<option value="${k}">${escapeHtml(v)}</option>`).join("")}</select></label> <button type="button" class="secondary-button" id="add">Add</button></p>
      <div><button type="submit">${d.id ? "Save changes" : "Save playbook"}</button></div></form>`;
    shell(body);
    const sync = () => {
      const f = container.querySelector("#bf");
      d.name = f.name.value; d.description = f.description.value; d.trigger.mode = f.mode.value; if (f.min_severity) d.trigger.min_severity = f.min_severity.value; d.enabled = f.enabled.checked;
      container.querySelectorAll("[data-p]").forEach((el) => { const [i, k] = el.dataset.p.split(":"); d.steps[Number(i)].params[k] = el.value; });
      container.querySelectorAll("[data-pc]").forEach((el) => { const [i, k] = el.dataset.pc.split(":"); d.steps[Number(i)].params[k] = el.checked; });
      d.steps.forEach((s, i) => {
        const path = container.querySelector(`[data-wp="${i}"]`).value.trim(), op = container.querySelector(`[data-wo="${i}"]`).value, val = container.querySelector(`[data-wv="${i}"]`).value;
        if (path && op) s.when = { path, op, value: op === "in" ? val.split(",").map((x) => x.trim()) : val === "true" ? true : val === "false" ? false : val };
        else delete s.when;
        if (s.type === "notify" && s.params.to && !Array.isArray(s.params.to)) s.params.to = String(s.params.to).split(",").map((x) => x.trim()).filter(Boolean);
      });
    };
    container.querySelector("#bf [name=mode]").addEventListener("change", () => { sync(); builder(); });
    container.querySelectorAll("select[data-p]").forEach((el) => el.addEventListener("change", () => { sync(); builder(); }));
    container.querySelector("#add").addEventListener("click", () => {
      sync();
      const t = container.querySelector("#addtype").value;
      d.steps.push({ type: t, params: t === "notify" ? { channel: "webhook", text: "" } : t === "response-action" ? { action: "create-ticket", target: "{title}" } : {} });
      builder();
    });
    const mv = (i, dir) => { sync(); const j = i + dir; if (j >= 0 && j < d.steps.length) { [d.steps[i], d.steps[j]] = [d.steps[j], d.steps[i]]; } builder(); };
    container.querySelectorAll("[data-up]").forEach((b) => b.addEventListener("click", () => mv(Number(b.dataset.up), -1)));
    container.querySelectorAll("[data-down]").forEach((b) => b.addEventListener("click", () => mv(Number(b.dataset.down), 1)));
    container.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { sync(); d.steps.splice(Number(b.dataset.rm), 1); builder(); }));
    container.querySelector("#bf").addEventListener("submit", async (e) => {
      e.preventDefault(); sync();
      const trig = d.trigger.mode === "on-alert" ? { mode: "on-alert", min_severity: d.trigger.min_severity } : { mode: "manual" };
      const payload = { name: d.name, description: d.description, trigger: trig, steps: d.steps, enabled: d.enabled };
      try {
        const saved = d.id ? await api.soarUpdate(d.id, payload) : await api.soarAdd(payload);
        flash("Playbook saved.", "success"); draft = null; tab = "playbooks"; show(); return saved;
      } catch (err) { flash(err.message, "error"); }
    });
  }

  async function build() {
    catalog = catalog || await api.soarPlaybooks();
    if (!draft) draft = blank();
    builder();
  }

  async function show() {
    try { await { playbooks, runs, build }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
