import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Attack Surface";

const TABS = [["overview", "Overview"], ["assets", "Assets"], ["changes", "Changes"], ["findings", "Findings"], ["import", "Import and scope"], ["feed", "How to feed it"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const KINDS = ["domain", "subdomain", "ip", "service", "url"];
const CHANGE = { new: "badge-medium", reappeared: "badge-medium", changed: "badge-outline", disappeared: "badge-low" };
const NOTE = "The part of your estate that is visible from the internet, built only from the output of discovery tools that you run against your own infrastructure (subfinder, dnsx, httpx, naabu, nuclei). Quanta never scans and never contacts a target, so it cannot see anything you did not import. Every view shows how old the data is.";

const ageBanner = (a) => {
  if (!a) return "";
  const cls = a.stale || a.never_imported ? "callout callout-warn" : "callout";
  return `<p class="${cls}"><strong>Data age.</strong> ${escapeHtml(a.message)}${a.last_import_at ? ` Last import: ${escapeHtml(a.last_import_at)}.` : ""}</p>`;
};
const card = (label, value, cls = "") => `<div class="kpi-card ${cls}"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div></div>`;

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  if (!TABS.find(([k]) => k === tab)) tab = "overview";
  const f = { kind: "", scope: "in", status: "active", q: "", change: "" };

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="asm-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };

  async function overview() {
    const s = await api.asmSummary(7);
    const k = s.assets.by_kind;
    shell(`${ageBanner(s.data_age)}
      ${s.scope.declared ? "" : '<p class="callout callout-warn">No scope is declared, so everything imported is treated as yours. Declare your domains and ranges on the Import and scope tab so anything else is flagged instead of included.</p>'}
      <div class="kpi-grid">${card("domains", k.domain + k.subdomain)}${card("addresses", k.ip)}${card("services", k.service)}${card("web endpoints", k.url)}
        ${card("new, last " + s.period_days + " days", s.changes.new, s.changes.new ? "kpi-warn" : "")}${card("disappeared", s.changes.disappeared)}
        ${card("risky services exposed", s.exposed_risky_services, s.exposed_risky_services ? "kpi-danger" : "")}${card("not in the asset inventory", s.shadow_assets, s.shadow_assets ? "kpi-warn" : "")}
        ${card("outside your scope", s.assets.out_of_scope)}${card("stale data", s.stale ? "yes" : "no", s.stale ? "kpi-danger" : "")}</div>
      ${s.gaps.length ? `<h3>What this view cannot judge yet</h3><ul>${s.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul>` : ""}
      <h3>Findings by rule</h3>
      ${Object.keys(s.findings.by_rule).length ? `<p>${Object.entries(s.findings.by_rule).map(([r, n]) => `<span class="badge badge-outline">${escapeHtml(r)}: ${n}</span>`).join(" ")}</p>` : '<p class="muted">None raised from the data imported so far. That is not the same as clean: see the gaps above and the data age.</p>'}
      <p class="muted">${escapeHtml(s.note)}</p>`);
  }

  async function assets() {
    const params = { limit: 500 };
    if (f.kind) params.kind = f.kind;
    if (f.status) params.status = f.status;
    if (f.scope === "in") params.in_scope = "true";
    if (f.scope === "out") params.in_scope = "false";
    if (f.q) params.q = f.q;
    const d = await api.asmAssets(params);
    shell(`${ageBanner(d.data_age)}
      <p><label>Kind <select id="f-kind"><option value="">All</option>${KINDS.map((x) => `<option${x === f.kind ? " selected" : ""}>${x}</option>`).join("")}</select></label>
        <label>Scope <select id="f-scope"><option value="in"${f.scope === "in" ? " selected" : ""}>In scope</option><option value="out"${f.scope === "out" ? " selected" : ""}>Outside scope</option><option value="all"${f.scope === "all" ? " selected" : ""}>Both</option></select></label>
        <label>State <select id="f-status"><option value="active"${f.status === "active" ? " selected" : ""}>Active</option><option value="gone"${f.status === "gone" ? " selected" : ""}>Disappeared</option><option value=""${f.status === "" ? " selected" : ""}>Both</option></select></label>
        <label>Search <input id="f-q" value="${escapeHtml(f.q)}" placeholder="name, title, technology"></label> ${d.total} asset(s)</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Asset</th><th>Kind</th><th>Seen by</th><th>Technologies</th><th>Last seen</th><th>Owner</th><th></th></tr></thead><tbody>
      ${d.assets.length ? d.assets.map((a) => `<tr><td class="wrap-cell"><strong>${escapeHtml(a.value)}</strong>${a.title ? `<br><span class="muted">${escapeHtml(a.title)}</span>` : ""}${a.cname.length ? `<br><span class="muted">CNAME ${escapeHtml(a.cname.join(", "))}</span>` : ""}${a.tls_expires ? `<br><span class="muted">certificate until ${escapeHtml(a.tls_expires)}</span>` : ""}</td>
        <td>${a.kind}</td><td>${escapeHtml(a.sources.join(", "))}</td><td class="wrap-cell">${escapeHtml(a.technologies.slice(0, 6).join(", "))}</td>
        <td>${escapeHtml(a.last_seen.slice(0, 10))}<br><span class="muted">${a.age_days ?? "?"} days ago</span></td><td>${a.owner || a.team ? escapeHtml([a.owner, a.team].filter(Boolean).join(" / ")) : '<span class="muted">none</span>'}</td>
        <td>${a.in_scope ? "" : '<span class="badge badge-outline">outside scope</span> '}${a.status === "gone" ? '<span class="badge badge-low">disappeared</span> ' : ""}${a.vulns ? `<span class="badge badge-high">${a.vulns} check(s)</span>` : ""}</td></tr>`).join("") : '<tr><td colspan="7" class="empty-state">No assets match. Import discovery output on the Import and scope tab.</td></tr>'}</tbody></table></div>`);
    const again = () => assets();
    container.querySelector("#f-kind").addEventListener("change", (e) => { f.kind = e.target.value; again(); });
    container.querySelector("#f-scope").addEventListener("change", (e) => { f.scope = e.target.value; again(); });
    container.querySelector("#f-status").addEventListener("change", (e) => { f.status = e.target.value; again(); });
    container.querySelector("#f-q").addEventListener("change", (e) => { f.q = e.target.value.trim(); again(); });
  }

  async function changes() {
    const d = await api.asmChanges({ limit: 300 });
    shell(`${ageBanner(d.data_age)}
      <h3>Change feed</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>When</th><th>Change</th><th>Asset</th><th>Detail</th></tr></thead><tbody>
      ${d.changes.length ? d.changes.map((c) => `<tr><td>${escapeHtml(c.at.replace("T", " ").replace("Z", ""))}</td><td><span class="badge ${CHANGE[c.change] || ""}">${escapeHtml(c.change)}</span>${c.in_scope ? "" : ' <span class="badge badge-outline">outside scope</span>'}</td>
        <td class="wrap-cell">${escapeHtml(c.asset_key)}</td><td class="wrap-cell">${escapeHtml(c.detail || "")}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No changes recorded yet.</td></tr>'}</tbody></table></div>
      <h3>Imports</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>When</th><th>Tool</th><th>Records</th><th>New</th><th>Changed</th><th>Disappeared</th><th>Outside scope</th><th>By</th></tr></thead><tbody>
      ${d.runs.map((r) => `<tr><td>${escapeHtml(r.imported_at.replace("T", " ").replace("Z", ""))}</td><td>${escapeHtml(r.tool)}${r.complete ? " (complete" + (r.scope_label ? " for " + escapeHtml(r.scope_label) : "") + ")" : ""}</td><td>${r.records}${r.skipped ? ` (${r.skipped} skipped)` : ""}</td><td>${r.new_count}</td><td>${r.changed_count}</td><td>${r.gone_count}</td><td>${r.out_of_scope}</td><td>${escapeHtml(r.actor || "")}</td></tr>`).join("") || '<tr><td colspan="8" class="empty-state">No imports yet.</td></tr>'}</tbody></table></div>`);
  }

  async function findings() {
    const d = await api.asmFindings();
    shell(`${ageBanner(d.data_age)}
      ${d.gaps.length ? `<p class="callout callout-warn">${d.gaps.map(escapeHtml).join("<br>")}</p>` : ""}
      <p>${d.findings.length} finding(s) raised by explicit rules from the imported data. ${d.skipped_info ? `${d.skipped_info} informational check result(s) were counted, not raised. ` : ""}<button type="button" id="publish">Send to the main queue</button></p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>
      ${d.findings.length ? d.findings.slice(0, 400).map((x) => `<tr><td><span class="badge ${SEV[x.severity] || ""}">${x.severity}</span><br><span class="muted">${escapeHtml(x.rule)}</span></td>
        <td class="wrap-cell"><strong>${escapeHtml(x.title)}</strong>${x.cve ? `<br><span class="muted">${escapeHtml(x.cve)}</span>` : ""}</td><td class="wrap-cell">${escapeHtml(x.evidence)}<br><span class="muted">${escapeHtml(x.fresh)}</span></td><td class="wrap-cell">${escapeHtml(x.next_step)}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No findings from the data imported so far.</td></tr>'}</tbody></table></div>`);
    container.querySelector("#publish").addEventListener("click", async () => {
      try {
        const r = await api.asmPublish({ confirm: false });
        if (!window.confirm(r.message + `\n\n${r.findings} finding(s) would be published.`)) return;
        const out = await api.asmPublish({ confirm: true });
        flash(`Published ${out.published} finding(s): ${out.added} new, ${out.updated} updated, ${out.removed} removed.`, "success");
      } catch (e) { flash(e.message, "error"); }
    });
  }

  async function importTab() {
    const sc = await api.asmScope();
    const age = (await api.asmAssets({ limit: 1 })).data_age;
    shell(`${ageBanner(age)}
      <h3>Import tool output</h3>
      <p class="muted">Choose the tool and the file it wrote (JSON lines or a JSON array). Tick complete only when the file is the whole answer for the scope you name (a domain or a range): assets the file omits are then marked disappeared. A partial file never removes anything.</p>
      <form id="imp" class="run-form"><label>Tool <select name="tool"><option>subfinder</option><option>dnsx</option><option>httpx</option><option>naabu</option><option>nuclei</option><option value="seeds">seeds (declares scope)</option></select></label>
        <label>Scope for a complete import <input name="scope" placeholder="example.com or 203.0.113.0/24"></label>
        <label><input type="checkbox" name="complete"> This file is complete for that scope</label>
        <label><input type="checkbox" name="publish"> Refresh the main-queue findings afterwards</label>
        <label>File <input type="file" name="file" required></label><div><button type="submit">Import</button></div></form>
      <div id="imp-result"></div>
      <h3>Scope</h3>
      <p class="muted">What you declare as yours. Anything else that turns up is recorded and flagged, never silently included, and never raises a finding.</p>
      <form id="scope" class="run-form"><label>Domains (one per line) <textarea name="domains" rows="4">${escapeHtml(sc.domains.join("\n"))}</textarea></label>
        <label>Address ranges (one per line) <textarea name="cidrs" rows="4">${escapeHtml(sc.cidrs.join("\n"))}</textarea></label><div><button type="submit">Save scope</button></div></form>
      <h3>Expected import cadence</h3>
      <p class="muted">If no import arrives within this many hours Quanta raises a "stale attack-surface data" alert, and every view says the data is out of date. Leave empty for no expectation.</p>
      <form id="cad" class="run-form"><label>Hours <input name="hours" type="number" min="1" step="1" value="${sc.expected_cadence_hours ?? ""}"></label><div><button type="submit">Save</button></div></form>`);
    container.querySelector("#imp").addEventListener("submit", async (e) => {
      e.preventDefault();
      const el = e.target;
      try {
        const r = await api.asmImport(el.tool.value, el.scope.value.trim(), el.complete.checked, el.publish.checked, await el.file.files[0].text());
        container.querySelector("#imp-result").innerHTML = `<p class="callout">Read ${r.records} record(s)${r.skipped ? `, skipped ${r.skipped}` : ""}: ${r.new} new, ${r.changed} changed, ${r.disappeared} disappeared, ${r.out_of_scope} outside scope.${r.notes.length ? "<br>" + r.notes.map(escapeHtml).join("<br>") : ""}</p>`;
        flash("Imported.", "success");
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#scope").addEventListener("submit", async (e) => {
      e.preventDefault();
      const lines = (v) => v.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      try { const r = await api.asmSetScope({ domains: lines(e.target.domains.value), cidrs: lines(e.target.cidrs.value) }); flash(`Scope saved; ${r.rescoped} asset(s) moved in or out.`, "success"); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#cad").addEventListener("submit", async (e) => {
      e.preventDefault();
      const v = e.target.hours.value;
      try { await api.asmSettings({ expected_cadence_hours: v ? Number(v) : null }); flash("Saved.", "success"); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function feed() {
    const d = await api.asmHowToFeed();
    shell(`<p class="callout callout-warn">${escapeHtml(d.safety)}</p>
      <p class="muted">Example commands, with placeholders only. Replace example.com and the address range with your own, run them on infrastructure you are authorised to test, then import the file on the Import and scope tab, or post it from your pipeline.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Tool</th><th>What it gives Quanta</th><th>Command</th></tr></thead><tbody>
      ${d.examples.map((x) => `<tr><td><strong>${escapeHtml(x.tool)}</strong></td><td class="wrap-cell">${escapeHtml(x.what)}<br><span class="muted">${escapeHtml(x.complete)}</span></td><td class="wrap-cell"><code>${escapeHtml(x.command)}</code> <button type="button" class="link-button" data-copy="${escapeHtml(x.command)}">Copy</button></td></tr>`).join("")}</tbody></table></div>
      <h3>From a pipeline</h3><p><code>${escapeHtml(d.post_example)}</code></p>
      <p class="muted">Limits: built against the tools' public documentation of their JSON output and unit-tested on sample lines; not yet run against live output at scale. Quanta does no active discovery of its own.</p>`);
    container.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); flash("Copied.", "success"); } catch { flash("Select the command and copy it.", "error"); }
    }));
  }

  async function show() {
    try {
      await ({ overview, assets, changes, findings, import: importTab, feed }[tab])();
    } catch (e) { flash(e.message, "error"); }
  }
  await show();
}
