import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Dark Web Watch";

const TABS = [["hits", "Hits"], ["sources", "Sources"], ["terms", "Watch terms"], ["import", "Import"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low", Informational: "badge-outline" };
const MODE = { feed: "Feed, active", lookup: "Lookup, your key", import: "Import tool output", guide: "Reference" };
const NOTE = "Quanta watches for your organization's name in public ransomware leak-site lists and in credential-exposure services, and takes in the output of the crawlers and platforms your analysts run. It never connects to Tor, crawls an onion site, or stores a password. A new hit raises a SOC alert, which flows into triage, cases and playbooks.";

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "hits";
  let data = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}${k === "hits" && data ? ` (${data.hit_counts.new || 0} new)` : ""}</button>`).join(" ")}</p><div id="dw-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };
  const act = (fn, msg) => async () => { try { const r = await fn(); if (msg) flash(typeof msg === "function" ? msg(r) : msg, "success"); await show(true); } catch (e) { flash(e.message, "error"); } };

  function hits() {
    shell(`${data.has_terms ? "" : '<p class="empty-state">No watch terms yet. Add your domains and brand names on the Watch terms tab; until then nothing is matched.</p>'}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>What</th><th>Source</th><th>Matched</th><th>Status</th><th></th></tr></thead><tbody>
      ${data.hits.map((h) => `<tr><td><span class="badge ${SEV[h.severity] || ""}">${escapeHtml(h.severity)}</span></td>
        <td class="wrap-cell"><strong>${escapeHtml(h.title)}</strong><br><span class="muted">${escapeHtml(h.detail || "")}</span>${h.url ? `<br><span class="muted">${escapeHtml(h.url)}</span>` : ""}${h.note ? `<br><em>${escapeHtml(h.note)}</em>` : ""}</td>
        <td>${escapeHtml(h.source)}<br><span class="muted">${escapeHtml(h.kind)}</span></td><td>${escapeHtml(h.term_kind)}: ${escapeHtml(h.term)}</td><td>${escapeHtml(h.status)}${h.alert_id ? `<br><span class="muted">alert #${h.alert_id}</span>` : ""}</td>
        <td>${["reviewing", "actioned", "dismissed"].filter((s) => s !== h.status).map((s) => `<button type="button" class="link-button" data-hit="${h.id}" data-st="${s}">${s}</button>`).join(" ")}</td></tr>`).join("")
        || '<tr><td colspan="6" class="empty-state">No hits. That is the good outcome: nothing public matched your terms yet.</td></tr>'}</tbody></table></div>`);
    container.querySelectorAll("[data-hit]").forEach((b) => b.addEventListener("click", act(async () => {
      const st = b.dataset.st;
      const note = st === "reviewing" ? "" : window.prompt(st === "actioned" ? "What did you do?" : "Why is this not you or not a risk?") || "";
      if (st !== "reviewing" && !note) throw new Error("A note is needed to record this decision.");
      return api.darkwebHitStatus(Number(b.dataset.hit), { status: st, note });
    }, "Saved.")));
  }

  function sources() {
    shell(`<p class="muted">Four ways in. <strong>Feed</strong>: Quanta reads a public list on a schedule. <strong>Lookup</strong>: Quanta asks a service about your domains, with your key. <strong>Import</strong>: you paste or post what a tool produced. <strong>Reference</strong>: for analysts; not ingested.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Source</th><th>How it is used</th><th>Mode</th><th>State</th><th></th></tr></thead><tbody>
      ${data.sources.map((s) => `<tr><td class="wrap-cell"><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.category)}${s.needs ? " &middot; needs " + escapeHtml(s.needs) : ""}</span></td>
        <td class="wrap-cell">${escapeHtml(s.how)}</td><td>${MODE[s.mode]}</td>
        <td>${s.mode === "feed" || s.mode === "lookup" ? `${s.enabled ? '<span class="badge badge-low">on</span>' : '<span class="badge badge-outline">off</span>'}${s.mode === "lookup" && !s.connected ? '<br><span class="muted">no connection</span>' : ""}${s.last_status ? `<br><span class="muted">${escapeHtml(s.last_status)}</span>` : ""}` : ""}</td>
        <td>${s.mode === "feed" || (s.mode === "lookup" && s.connected) ? `<button type="button" class="secondary-button" data-toggle="${s.id}" data-on="${s.enabled ? 0 : 1}">${s.enabled ? "Turn off" : "Turn on"}</button> <button type="button" data-run="${s.id}" data-mode="${s.mode}">Run now</button>` : s.mode === "lookup" ? '<a href="/connections" data-link>Add connection</a>' : ""}</td></tr>`).join("")}</tbody></table></div>`);
    container.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", act(() => api.darkwebEnable(b.dataset.toggle, { enabled: b.dataset.on === "1" }), "Saved.")));
    container.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", act(async () => {
      let r = await api.darkwebRun(b.dataset.run, { confirm: false });
      if (r.preview_only) {
        if (!window.confirm(r.message + "\n\nDomains: " + (r.domains_that_would_be_sent.join(", ") || "none"))) return null;
        r = await api.darkwebRun(b.dataset.run, { confirm: true });
      }
      return r;
    }, (r) => (r ? `Done: ${r.new} new hit(s), ${r.known} already known.${r.note ? " " + r.note : ""}` : "Cancelled."))));
  }

  function terms() {
    const lines = (a) => (a || []).join("\n");
    const s = data.settings;
    shell(`<p class="muted">Terms never leave Quanta: feeds are downloaded whole and matched here. Only your <strong>domains</strong> are ever sent to a credential-exposure service. One per line.</p>
      <form id="tf" class="run-form">
        <label>Your domains <textarea name="domains" rows="3">${escapeHtml(lines(data.terms.domains))}</textarea></label>
        <label>Brand, product and subsidiary names <textarea name="brands" rows="3">${escapeHtml(lines(data.terms.brands))}</textarea></label>
        <label>Suppliers and partners (rated one level lower) <textarea name="vendors" rows="3">${escapeHtml(lines(data.terms.vendors))}</textarea></label>
        <label>Other keywords <textarea name="keywords" rows="3">${escapeHtml(lines(data.terms.keywords))}</textarea></label>
        <label><input type="checkbox" name="auto" ${s.auto_alert ? "checked" : ""}> A new hit also raises a SOC alert</label>
        <div><button type="submit">Save</button></div></form>
        <p class="muted">A name shorter than four characters only matches when it is the whole victim name. Severity, polling interval and other settings are in remediation/config/darkweb_watch.yaml.</p>`);
    container.querySelector("#tf").addEventListener("submit", act(async () => {
      const f = container.querySelector("#tf"), split = (v) => v.split("\n").map((x) => x.trim()).filter(Boolean);
      return api.darkwebTerms({ domains: split(f.domains.value), brands: split(f.brands.value), vendors: split(f.vendors.value), keywords: split(f.keywords.value), settings: { auto_alert: f.auto.checked } });
    }, "Saved."));
    container.querySelector("#tf").addEventListener("submit", (e) => e.preventDefault());
  }

  function importTab() {
    const imp = data.sources.filter((s) => s.mode === "import" || s.mode === "guide");
    shell(`<p class="muted">Run your crawlers and monitoring tools in an isolated environment you control, then paste their output here, or have your pipeline post it to <code>POST /api/ingest/darkweb</code> with an API key that has the <code>darkweb:write</code> scope. Quanta keeps only the lines that name your watch terms and the onion addresses beside them; the rest is discarded.</p>
      <form id="imf" class="run-form"><label>Which tool or platform produced it <select name="source">${imp.map((s) => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)}</option>`).join("")}</select></label>
        <label>Output <textarea name="text" rows="10" required></textarea></label><div><button type="submit">Match against my terms</button></div></form><div id="imout"></div>`);
    container.querySelector("#imf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        const r = await api.darkwebImport({ source: f.source.value, text: f.text.value });
        container.querySelector("#imout").innerHTML = `<p>${r.lines} lines read, ${r.onion_addresses} onion addresses seen: <strong>${r.new} new hit(s)</strong>, ${r.known} already known, ${r.alerts} alert(s) raised.</p>`;
        flash("Imported.", "success");
      } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show(reload) {
    try {
      if (!data || reload) data = await api.darkwebOverview();
      ({ hits, sources, terms, import: importTab }[tab] || hits)();
    } catch (e) { container.innerHTML = `<p class="empty-state">${escapeHtml(e.message)}</p>`; }
  }
  await show(true);
}
