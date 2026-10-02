import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Firewall Rules";

const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const RECERT = { current: "badge-low", "due-soon": "badge-medium", overdue: "badge-critical", "removal-requested": "badge-high", "change-requested": "badge-high" };
const REQ = { submitted: "badge-medium", approved: "badge-low", rejected: "badge-critical", implemented: "badge-low", withdrawn: "badge-outline" };
const RISK = { low: "badge-low", medium: "badge-medium", high: "badge-critical" };
const VERDICT = { "already-allowed": ["badge-low", "Already allowed"], "blocked-by-rule": ["badge-critical", "Blocked by a deny rule"], "needs-new-rule": ["badge-medium", "Needs a new rule"] };
const NOTE = "Firewall rules read from your exports: what is overly broad, unused, shadowed or exposed to the internet, who must re-confirm each rule, and access requests checked against the rules before anyone reviews them. Quanta never changes a firewall; it tells you what to change.";

export async function render(container) {
  let admin = false;
  try { admin = ((await api.authMe()).user || {}).role === "admin"; } catch { admin = false; }
  const TABS = admin ? [["overview", "Overview"], ["findings", "Findings"], ["recert", "Recertification"], ["requests", "Access requests"], ["import", "Import rules"]] : [["requests", "Access requests"]];
  let tab = new URLSearchParams(window.location.search).get("tab") || TABS[0][0];
  if (!TABS.find(([k]) => k === tab)) tab = TABS[0][0];
  let data = null;
  let sev = "all";
  let dev = "all";

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="fw-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };
  const load = async () => { data = await api.firewallOverview(); return data; };

  async function overview() {
    const d = await load(), s = d.summary, e = d.exposure;
    shell(`<div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">rules held</div><div class="kpi-value">${s.rules}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">critical findings</div><div class="kpi-value">${s.by_severity.Critical}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">risky ports open to the internet</div><div class="kpi-value">${e.risky_exposed}</div></div>
        <div class="kpi-card"><div class="kpi-label">rules overdue for recertification</div><div class="kpi-value">${d.recert.counts.overdue}</div></div></div>
      ${s.rules ? "" : '<p class="callout">No firewall rules yet. Use Import rules to load a CSV, JSON, PAN-OS XML or FortiGate policy export.</p>'}
      <h3>Devices</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Device</th><th>Rules</th><th>Enabled</th><th>Allow rules</th><th>Risk score</th><th></th></tr></thead><tbody>
      ${s.devices.length ? s.devices.map((x) => `<tr><td>${escapeHtml(x.device)}</td><td>${x.rules}</td><td>${x.enabled}</td><td>${x.allow}</td><td>${x.score}</td><td><button type="button" class="link-button danger-link" data-del="${escapeHtml(x.device)}">Remove</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">None.</td></tr>'}</tbody></table></div>
      <h3>What the internet can reach</h3>
      <p class="muted">Ports opened by enabled allow rules with an any source on an internet-facing zone. Zone names are matched by words like untrust, wan, internet and outside.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Port</th><th>Rules</th><th>Use</th></tr></thead><tbody>
      ${e.ports.length ? e.ports.map((p) => `<tr><td>${p.port} ${p.name ? "(" + escapeHtml(p.name) + ")" : ""}</td><td class="wrap-cell">${p.rules.map((r) => escapeHtml(r.rule) + " on " + escapeHtml(r.device)).join("; ")}</td>
        <td>${p.risky ? '<span class="badge badge-critical">management / database</span> ' : ""}${p.all_unused ? '<span class="badge badge-outline">no recent hits</span>' : ""}</td></tr>`).join("") : '<tr><td colspan="3" class="empty-state">No specific ports exposed.</td></tr>'}</tbody></table></div>
      ${e.wide_open_rules.length ? `<p class="callout callout-warn">Open on every port to the internet: ${e.wide_open_rules.map((r) => escapeHtml(r.rule) + " (" + escapeHtml(r.device) + ")").join(", ")}</p>` : ""}
      <h3>Access requests</h3>
      <p>${d.requests.total} total &middot; median ${d.requests.median_hours_to_decision ?? "n/a"} h to a decision, ${d.requests.median_hours_to_implemented ?? "n/a"} h to done &middot; ${d.requests.already_allowed} were already allowed.</p>`);
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (window.confirm(`Remove ${b.dataset.del} and its rules from Quanta? (The firewall itself is not touched.)`)) { try { await api.firewallDeleteDevice(b.dataset.del); show(); } catch (e2) { flash(e2.message, "error"); } } }));
  }

  async function findings() {
    const d = data || await load();
    const devs = d.devices;
    const rows = d.findings.filter((f) => (sev === "all" || f.severity === sev) && (dev === "all" || f.device === dev));
    shell(`<p><label>Severity <select id="sev"><option value="all">All</option>${["Critical", "High", "Medium", "Low"].map((x) => `<option${x === sev ? " selected" : ""}>${x}</option>`).join("")}</select></label>
        <label>Device <select id="dev"><option value="all">All</option>${devs.map((x) => `<option${x === dev ? " selected" : ""}>${escapeHtml(x)}</option>`).join("")}</select></label> ${rows.length} of ${d.summary.findings} finding(s)</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>What to do</th></tr></thead><tbody>
      ${rows.length ? rows.slice(0, 300).map((f) => `<tr><td><span class="badge ${SEV[f.severity]}">${f.severity}</span><br><span class="muted">${f.id}</span></td><td class="wrap-cell">${escapeHtml(f.rule)}<br><span class="muted">${escapeHtml(f.device)} #${f.position}</span></td>
        <td class="wrap-cell"><strong>${escapeHtml(f.title)}</strong><br><span class="muted">${escapeHtml(f.detail)}</span></td><td class="wrap-cell">${escapeHtml(f.recommendation)}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No findings.</td></tr>'}</tbody></table></div>`);
    container.querySelector("#sev").addEventListener("change", (e) => { sev = e.target.value; findings(); });
    container.querySelector("#dev").addEventListener("change", (e) => { dev = e.target.value; findings(); });
  }

  async function recert() {
    const d = await load(), r = d.recert;
    shell(`<p class="muted">Every enabled allow rule is re-confirmed by its owner every ${r.interval_days} days. A person's decision is recorded here; the change itself is made on the firewall by whoever manages it.</p>
      <div class="kpi-grid">${Object.entries(r.counts).map(([k, v]) => `<div class="kpi-card ${k === "overdue" && v ? "kpi-danger" : ""}"><div class="kpi-label">${k.replace("-", " ")}</div><div class="kpi-value">${v}</div></div>`).join("")}</div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Rule</th><th>Owner</th><th>State</th><th>Due</th><th>Last decision</th><th></th></tr></thead><tbody>
      ${r.rules.length ? r.rules.slice(0, 300).map((x, i) => `<tr><td class="wrap-cell">${escapeHtml(x.rule)}<br><span class="muted">${escapeHtml(x.device)}</span></td><td>${escapeHtml(x.owner || "none")}</td><td><span class="badge ${RECERT[x.state]}">${x.state.replace("-", " ")}</span></td><td>${escapeHtml(x.due)}</td>
        <td class="wrap-cell">${x.decision ? escapeHtml(x.decision) + " by " + escapeHtml(x.certified_by || "") + "<br><span class='muted'>" + escapeHtml(x.decision_note || "") + "</span>" : "-"}</td>
        <td><button type="button" class="link-button" data-cert="${i}">Decide</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No allow rules to recertify.</td></tr>'}</tbody></table></div>`);
    container.querySelectorAll("[data-cert]").forEach((b) => b.addEventListener("click", async () => {
      const x = r.rules[Number(b.dataset.cert)];
      const decision = window.prompt(`Rule "${x.rule}": keep, modify or remove?`, "keep");
      if (!decision) return;
      const note = decision === "keep" ? window.prompt("Note (optional)") || "" : window.prompt("What should change, or why should it go? (required)") || "";
      try { await api.firewallCertify({ device: x.device, key: x.key, decision, note }); flash("Recorded.", "success"); show(); } catch (e) { flash(e.message, "error"); }
    }));
  }

  async function requests() {
    const { requests: rs } = await api.firewallRequests();
    shell(`<h3>Ask for access</h3>
      <p class="muted">Say who needs to reach what. Quanta checks the request against the firewall rules it holds: already allowed, blocked by a deny rule, or a new rule is needed, and how risky it is.</p>
      <form id="rf" class="run-form"><label>From (addresses or networks, comma separated) <input name="sources" required placeholder="10.0.5.5, 10.0.6.0/24"></label>
        <label>To <input name="destinations" required placeholder="10.1.1.9"></label><label>Services <input name="services" required placeholder="tcp/9000, https"></label>
        <label>Needed for (days, blank for no end date) <input name="days" type="number" min="1" max="3650"></label>
        <label>From zone (optional) <input name="src_zone" placeholder="trust"></label><label>To zone (optional) <input name="dst_zone" placeholder="dmz"></label>
        <label>Why <textarea name="justification" rows="2" required></textarea></label><div><button type="submit">Check and submit</button></div></form>
      <h3>${admin ? "All requests" : "Your requests"}</h3>
      ${rs.length ? rs.map((r) => { const c = r.check, v = VERDICT[c.verdict]; return `<div class="card" style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:6px 16px 12px;margin:10px 0">
        <p><span class="badge ${REQ[r.status]}">${r.status}</span> <span class="badge ${v[0]}">${v[1]}</span> <span class="badge ${RISK[c.risk]}">${c.risk} risk</span>${c.auto_approvable ? ' <span class="badge badge-low">could be approved without review</span>' : ""} #${r.id} by ${escapeHtml(r.requester)} ${escapeHtml(r.created_at)}</p>
        <p>${c.asked.sources.map(escapeHtml).join(", ")} &rarr; ${c.asked.destinations.map(escapeHtml).join(", ")} on ${c.asked.services.map(escapeHtml).join(", ")}${r.request.days ? " for " + r.request.days + " days" : " (no end date)"}</p>
        <p class="muted">${escapeHtml(r.justification)}</p><ul class="guidance-list">${c.reasons.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
        ${c.path ? `<p class="muted">Path to the internet: ${c.path.map((p) => escapeHtml(p.asset) + " " + escapeHtml(p.verdict)).join("; ")}</p>` : ""}
        ${r.decided_by ? `<p class="muted">Decided by ${escapeHtml(r.decided_by)}: ${escapeHtml(r.decision_note || "")}</p>` : ""}
        ${admin && (r.status === "submitted" || r.status === "approved") ? `<p>${r.status === "submitted" ? `<button type="button" data-d="${r.id}:approved">Approve</button> <button type="button" class="secondary-button" data-d="${r.id}:rejected">Reject</button>` : `<button type="button" data-d="${r.id}:implemented">Mark implemented on the firewall</button>`}</p>` : ""}</div>`; }).join("") : '<p class="empty-state">None yet.</p>'}`);
    container.querySelector("#rf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, list = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);
      try {
        await api.firewallRequest({ sources: list(f.sources.value), destinations: list(f.destinations.value), services: list(f.services.value), days: f.days.value ? Number(f.days.value) : null,
          justification: f.justification.value, src_zone: f.src_zone.value || null, dst_zone: f.dst_zone.value || null });
        flash("Request submitted.", "success"); show();
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-d]").forEach((b) => b.addEventListener("click", async () => {
      const [id, status] = b.dataset.d.split(":");
      const note = status === "implemented" ? "" : window.prompt(status === "rejected" ? "Why? (required)" : "Note (optional)") || "";
      try { await api.firewallDecide(Number(id), { status, note }); show(); } catch (e) { flash(e.message, "error"); }
    }));
  }

  async function importTab() {
    shell(`<p class="muted">Load a firewall's rules from an export. CSV (common Palo Alto and FortiGate column names), JSON, PAN-OS configuration XML, or FortiGate <code>config firewall policy</code> text. Importing replaces that device's rules; rules whose match has not changed keep their recertification. Address and service objects are kept by name because an export of rules does not contain what they hold.</p>
      <form id="imp" class="run-form"><label>Firewall name <input name="device" required placeholder="edge-fw-1"></label>
        <label>Format <select name="format"><option value="">Detect</option><option>csv</option><option>json</option><option>panos</option><option>fortigate</option></select></label>
        <label>Export file <input type="file" name="file" required></label><div><button type="submit">Import</button></div></form>`);
    container.querySelector("#imp").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const r = await api.firewallImport(f.device.value, f.format.value, await f.file.files[0].text()); flash(`${r.rules} rules read (${r.format}); ${r.added} new, ${r.removed} gone.`, "success"); tab = "overview"; show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show() {
    try { await { overview, findings, recert, requests, import: importTab }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
