import { api } from "../api.js";
import { escapeHtml as esc, flash, openModal, closeModal } from "../dom.js";

export const title = "API Security";

const TABS = [["overview", "Overview"], ["inventory", "Inventory"], ["import", "Import"], ["findings", "Findings"], ["callers", "Callers"], ["data", "Data classes"],
  ["policies", "Protection policies"], ["metrics", "Metrics"], ["ci", "CI and rollout"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const STATE = { documented: ["badge-low", "documented"], shadow: ["badge-critical", "shadow"], undocumented: ["badge-medium", "no spec for service"], "spec-only": ["badge-outline", "documented, not seen"] };
const NOTE = "An inventory of your APIs built from the specifications you load and the gateway, WAF or access logs you import, checked against the OWASP API Security Top 10 (2023). Quanta reads exports and records; it cannot see traffic nobody gives it, and it never changes a firewall or WAF. Everything here is built against public documentation and has not been run against a live traffic source.";
const ago = (d) => (d ? d : "never");
const num = (n) => (n === null || n === undefined ? "n/a" : Number(n).toLocaleString());
const pct = (r) => (r === null || r === undefined ? "n/a" : `${(r * 100).toFixed(1)}%`);
const bytes = (n) => { n = Number(n || 0); if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} GB`; if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`; if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`; return `${n} B`; };
const badge = (cls, text) => `<span class="badge ${cls}">${esc(text)}</span>`;
const sevBadge = (s) => badge(SEV[s] || "badge-outline", s);
const table = (heads, rows, empty = "None.") => `<div class="table-scroll"><table class="data-table"><thead><tr>${heads.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${
  rows.length ? rows.join("") : `<tr><td colspan="${heads.length}" class="empty-state">${empty}</td></tr>`}</tbody></table></div>`;
const kpi = (label, value, cls = "") => `<div class="kpi-card ${cls}"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div></div>`;
const pre = (text) => `<pre class="code-block">${esc(text)}</pre>`;
const readFile = (input) => new Promise((resolve, reject) => {
  const f = input.files && input.files[0];
  if (!f) { resolve(null); return; }
  const r = new FileReader();
  r.onload = () => resolve(String(r.result));
  r.onerror = () => reject(new Error("Could not read the file"));
  r.readAsText(f);
});
const download = (name, text) => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
};

function evidenceHtml(f) {
  const steps = f.evidence.map((e, i) => `<li><strong>${esc(e.step)}</strong> <span class="muted">(${esc(e.source)})</span><br>${esc(e.detail)}</li>`).join("");
  let req = "";
  if (f.request) {
    req = f.request.command
      ? `<p><strong>Request to confirm a true or false positive</strong></p>${pre(f.request.command)}<p class="muted">Expect: ${esc(f.request.expect)} ${esc(f.request.note || "")}${f.request.placeholders && f.request.placeholders.length ? ` Replace: ${f.request.placeholders.map((p) => "$" + p).join(", ")}.` : ""}</p>`
      : `<p class="muted">${esc(f.request.note || "")}</p>`;
  }
  return `<p>${esc(f.why)}</p><p><strong>Evidence chain</strong></p><ol>${steps}</ol>${req}<p><strong>How to fix it</strong><br>${esc(f.fix)}</p>`;
}

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  if (!TABS.find(([k]) => k === tab)) tab = "overview";
  let busy = false;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="api-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };
  const fail = (e) => flash(e && e.message ? e.message : String(e), "error");
  const guard = async (fn) => { if (busy) return; busy = true; try { await fn(); } catch (e) { fail(e); } finally { busy = false; } };

  // ------------------------------------------------------------ overview
  async function overview() {
    const d = await api.apiSecOverview(), s = d.summary;
    const open = (s.by_auth["open-observed"] || 0);
    shell(`<div class="kpi-grid">${kpi("endpoints", num(s.endpoints))}${kpi("services", num(s.services))}${kpi("shadow endpoints", num(s.by_state.shadow || 0), (s.by_state.shadow ? "kpi-danger" : ""))}
        ${kpi("open without credentials (observed)", num(open), open ? "kpi-danger" : "")}${kpi("critical or high findings", num((s.by_severity.Critical || 0) + (s.by_severity.High || 0)), "kpi-danger")}
        ${kpi("gaps to close", num(s.gaps), s.gaps ? "kpi-warn" : "")}</div>
      ${s.endpoints ? "" : '<p class="callout">Nothing in the inventory yet. Use the Import tab to upload an OpenAPI file and import an access-log export, or push records from your log shipper.</p>'}
      <p class="muted">Onboarding checklist: ${d.rollout.done} of ${d.rollout.total} steps done. <a href="/api-security?tab=ci" data-link>Open the checklist</a>.</p>
      <h3>By OWASP API Security Top 10 category</h3>
      <p>${Object.entries(s.by_rule).map(([k, v]) => `<span class="badge badge-outline">${esc(k)}: ${v}</span>`).join(" ") || '<span class="muted">No findings.</span>'}</p>
      <h3>Specifications</h3>
      ${table(["Service", "Title", "Version", "Operations", "Source", "Loaded", ""], d.specs.map((x) => `<tr><td>${esc(x.service)}</td><td>${esc(x.title)}</td><td>${esc(x.version)}</td><td>${x.endpoints}</td><td>${esc(x.source)}</td>
        <td>${esc((x.uploaded_at || "").slice(0, 10))}<br><span class="muted">${esc(x.uploaded_by || "")}</span></td><td><button type="button" class="link-button danger-link" data-delspec="${esc(x.service)}">Remove</button></td></tr>`), "No specifications loaded yet.")}
      <h3>Gaps</h3><p class="muted">What the data could not decide. Nothing here is treated as fine.</p>
      ${table(["Kind", "Subject", "Detail"], d.gaps.slice(0, 60).map((g) => `<tr><td>${esc(g.kind)}</td><td class="wrap-cell">${esc(g.subject)}</td><td class="wrap-cell">${esc(g.detail)}</td></tr>`), "No gaps.")}
      <h3>Service-to-service dependencies</h3>
      ${table(["Caller", "Destination", "Exposure of destination", "Calls", "Last seen"], d.dependencies.map((x) => `<tr><td>${esc(x.source_service)}</td><td>${esc(x.dest_service)}</td><td>${esc(x.dest_exposure || "unknown")}</td><td>${num(x.calls)}</td><td>${esc(x.last_seen)}</td></tr>`),
        "None recorded. Records that name a source service (source_service) populate this.")}
      <ul class="muted">${d.limits.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`);
    container.querySelectorAll("[data-delspec]").forEach((b) => b.addEventListener("click", () => guard(async () => {
      if (!window.confirm(`Remove the specification for ${b.dataset.delspec}? Endpoints stay in the inventory as observed only.`)) return;
      await api.apiSecSpecDelete(b.dataset.delspec); flash("Removed.", "success"); show();
    })));
  }

  // ------------------------------------------------------------ inventory
  const filt = { service: "", state: "", exposure: "", auth: "", q: "" };
  async function inventory() {
    const d = await api.apiSecEndpoints(filt);
    const opt = (list, cur, blank) => `<option value="">${blank}</option>${list.map((x) => `<option${x === cur ? " selected" : ""}>${esc(x)}</option>`).join("")}`;
    shell(`<p><select id="f-service">${opt(d.services, filt.service, "All services")}</select> <select id="f-state">${opt(d.states, filt.state, "Any state")}</select>
        <select id="f-exposure">${opt(d.exposures, filt.exposure, "Any exposure")}</select>
        <select id="f-auth">${opt(["authenticated", "open-observed", "open-declared", "unknown"], filt.auth, "Any authentication")}</select>
        <input id="f-q" placeholder="Search path" value="${esc(filt.q)}"> <span class="muted">${d.total} endpoint(s)</span></p>
      ${table(["Endpoint", "State", "Exposure", "Authentication", "Data (your classes)", "Owner", "Calls", "Last seen", "Findings", ""], d.endpoints.map((v) => {
        const st = STATE[v.state] || ["badge-outline", v.state];
        const cls = v.data.classes.map((c) => badge(c.priority <= 2 ? "badge-high" : "badge-outline", `${c.name}`)).join(" ") + (v.data.unclassified.length ? ` <span class="muted" title="Seen, not mapped to any of your classes">${v.data.unclassified.length} unclassified</span>` : "");
        const au = v.auth_state === "open-observed" ? badge("badge-critical", "open (observed)") : v.auth_state === "open-declared" ? badge("badge-high", "open (declared)") : v.auth_state === "authenticated" ? badge("badge-low", v.auth_mechanisms.join(", ") || "authenticated") : badge("badge-outline", "unknown");
        return `<tr><td class="wrap-cell"><strong>${esc(v.method)}</strong> ${esc(v.template)}<br><span class="muted">${esc(v.service)}${v.deprecated ? " &middot; deprecated" : ""}</span></td><td>${badge(st[0], st[1])}</td>
          <td>${esc(v.exposure)}</td><td>${au}</td><td class="wrap-cell">${cls || '<span class="muted">none seen</span>'}</td><td>${esc(v.owner || "-")}</td><td>${num(v.calls)}</td><td>${esc(ago(v.last_seen))}</td>
          <td>${v.findings || ""}</td><td><button type="button" class="link-button" data-ep="${v.id}">Details</button></td></tr>`;
      }), "No endpoints match.")}`);
    const bind = (id, key) => container.querySelector(id).addEventListener("change", (e) => { filt[key] = e.target.value; inventory().catch(fail); });
    bind("#f-service", "service"); bind("#f-state", "state"); bind("#f-exposure", "exposure"); bind("#f-auth", "auth");
    container.querySelector("#f-q").addEventListener("change", (e) => { filt.q = e.target.value; inventory().catch(fail); });
    container.querySelectorAll("[data-ep]").forEach((b) => b.addEventListener("click", () => guard(() => endpointModal(Number(b.dataset.ep), d))));
  }

  async function endpointModal(id, list) {
    const d = await api.apiSecEndpoint(id), v = d.endpoint, o = d.observed;
    const body = openModal(`<h3>${esc(v.method)} ${esc(v.template)}</h3><p class="muted">${esc(v.service)} &middot; ${esc(v.exposure)} (${esc(v.exposure_basis)}) &middot; first seen ${esc(ago(v.first_seen))}, last ${esc(ago(v.last_seen))}</p>
      <form id="ep-form" class="run-form"><label>Owner <input name="owner" value="${esc(v.owner || "")}" placeholder="team or person"></label>
        <label>Exposure <select name="exposure"><option value="">(from the data)</option>${list.exposures.map((x) => `<option${x === v.exposure && v.exposure_basis === "set by a person" ? " selected" : ""}>${esc(x)}</option>`).join("")}</select></label>
        <label>Status <select name="status">${list.statuses.map((x) => `<option${x === v.status ? " selected" : ""}>${esc(x)}</option>`).join("")}</select></label>
        <label>Notes <input name="notes" value="${esc(v.notes || "")}"></label><div><button type="submit">Save</button></div></form>
      <p><strong>Authentication</strong>: ${esc(v.auth_state)} ${v.auth_mechanisms.length ? "(" + esc(v.auth_mechanisms.join(", ")) + ")" : ""}. Statuses seen: ${Object.entries(o.status_counts).map(([k, n]) => `${esc(k)} x${n}`).join(", ") || "none"}.</p>
      <p><strong>Data</strong>: ${v.data.classes.map((c) => esc(c.name) + " (priority " + c.priority + ")").join(", ") || "no class of yours"}${v.data.unclassified.length ? "; unclassified: " + esc(v.data.unclassified.join(", ")) : ""}. Fields seen: ${esc((o.response_fields || []).slice(0, 25).join(", ")) || "none"}.</p>
      ${d.policies.length ? `<p><strong>Policies covering it</strong>: ${d.policies.map((p) => esc(p.name) + " (" + esc(p.mode) + ")").join(", ")}</p>` : ""}
      <h4>Findings</h4>${d.findings.length ? d.findings.map((f) => `<details><summary>${sevBadge(f.severity)} ${esc(f.rule)} ${esc(f.title)}</summary>${evidenceHtml(f)}</details>`).join("") : '<p class="muted">None.</p>'}
      <h4>Daily metrics</h4>${table(["Day", "Calls", "Error rate", "Avg latency", "Bytes out", "Events"], d.series.slice(-14).reverse().map((x) => `<tr><td>${esc(x.day)}</td><td>${num(x.calls)}</td><td>${pct(x.error_rate)}</td><td>${x.avg_latency_ms ?? "n/a"} ms</td><td>${bytes(x.bytes_out)}</td><td>${x.security_events}</td></tr>`), "No metrics.")}
      ${d.trend.flags && d.trend.flags.length ? `<p class="callout callout-warn">Moved: ${d.trend.flags.map((f) => esc(f.metric) + " " + esc(f.change)).join("; ")}</p>` : ""}
      <h4>Callers</h4>${table(["Caller", "Calls", "Bytes out", "Most distinct objects in a day"], d.callers.map((c) => `<tr><td>${esc(c.actor)}</td><td>${num(c.calls)}</td><td>${bytes(c.bytes_out)}</td><td>${c.max_distinct_objects}</td></tr>`), "No caller activity.")}`);
    body.querySelector("#ep-form").addEventListener("submit", (e) => {
      e.preventDefault();
      guard(async () => {
        const f = e.target;
        await api.apiSecEndpointUpdate(id, { owner: f.owner.value, exposure: f.exposure.value || null, status: f.status.value, notes: f.notes.value });
        flash("Saved.", "success"); closeModal(); inventory().catch(fail);
      });
    });
  }

  // ------------------------------------------------------------ import
  async function importTab() {
    const services = (await api.apiSecOverview()).services;
    shell(`<h3>1. Load an OpenAPI or Swagger specification</h3>
      <form id="spec-form" class="run-form"><label>Service name <input name="service" placeholder="shop-api (default: from the spec title)"></label>
        <label>File <input type="file" name="file" accept=".json,.yaml,.yml,.txt"></label><label>Or paste it <textarea name="content" rows="5" placeholder="openapi: 3.0.0 ..."></textarea></label>
        <div><button type="submit">Import specification</button></div></form>
      <form id="fetch-form" class="run-form"><label>Or fetch it from a URL <input name="url" placeholder="https://specs.example.com/shop/openapi.yaml"></label><label>Service name <input name="service"></label>
        <div><button type="submit" class="secondary-button">Fetch specification</button> <span class="muted">Quanta's server makes this request, so you are asked to confirm. Redirects are not followed.</span></div></form>
      <div id="spec-result"></div>
      <h3>2. Import an access-log export</h3>
      <p class="muted">From your API gateway, load balancer, WAF or proxy. JSON lines, a JSON array, common or combined log format, or CSV with a header row. Query-string values, bodies and tokens are never kept.</p>
      <form id="log-form" class="run-form"><label>Service name (for records that carry no host) <input name="service"></label>
        <label>Format <select name="format"><option value="">Detect</option><option>jsonl</option><option>json</option><option>clf</option><option>csv</option></select></label>
        <label>File <input type="file" name="file"></label><label>Or paste <textarea name="content" rows="4"></textarea></label><div><button type="submit">Import records</button></div></form>
      <div id="log-result"></div>
      <h3>3. Or have your log shipper push them</h3>
      ${pre(`curl -sS -X POST "$QUANTA_URL/api/ingest/api-traffic" -H "Authorization: Bearer $QUANTA_API_KEY" -H "Content-Type: application/json" \\\n  -d '{"service":"shop-api","records":[{"method":"GET","path":"/v1/users/42","status":200,"latency_ms":12,"bytes_out":512,"actor":"u-17","client_ip":"203.0.113.9","auth":"bearer"}]}'`)}
      <p class="muted">Create the key on the Connections page with the api:write scope. The same key uploads specifications from a pipeline (POST /api/ingest/openapi?service=...). See docs/INTEGRATION_API.md.</p>
      <h3>4. Drift and generated specification</h3>
      <p><select id="drift-service">${services.length ? services.map((x) => `<option>${esc(x)}</option>`).join("") : "<option value=''>(no services yet)</option>"}</select>
        <button type="button" id="drift-go" class="secondary-button">Show drift against traffic</button> <button type="button" id="gen-go" class="secondary-button">Download specification generated from traffic</button></p>
      <div id="drift-out"></div>`);
    const showSpec = (r) => { container.querySelector("#spec-result").innerHTML = `<p class="callout">${esc(r.service)}: ${r.operations} operations (${r.added} new, ${r.updated} updated${r.removed_from_spec ? ", " + r.removed_from_spec + " no longer in the spec" : ""}). ${r.drift.shadow.length} shadow endpoint(s) seen in traffic, ${r.drift.documented_never_seen.length} documented but never seen.${r.plain_http_servers.length ? " The spec lists a plain-HTTP server: " + esc(r.plain_http_servers.join(", ")) : ""}</p>`; };
    container.querySelector("#spec-form").addEventListener("submit", (e) => { e.preventDefault(); guard(async () => {
      const f = e.target, text = (await readFile(f.file)) || f.content.value;
      if (!text.trim()) throw new Error("Choose a file or paste a specification");
      showSpec(await api.apiSecSpecUpload({ content: text, service: f.service.value || null })); flash("Specification imported.", "success");
    }); });
    container.querySelector("#fetch-form").addEventListener("submit", (e) => { e.preventDefault(); guard(async () => {
      const f = e.target, body = { url: f.url.value.trim(), service: f.service.value || null };
      const pre1 = await api.apiSecSpecFetch(body);
      if (pre1.preview_only && window.confirm(`${pre1.message}\n\n${pre1.url}`)) { showSpec(await api.apiSecSpecFetch({ ...body, confirm: true })); flash("Specification fetched.", "success"); }
    }); });
    container.querySelector("#log-form").addEventListener("submit", (e) => { e.preventDefault(); guard(async () => {
      const f = e.target, text = (await readFile(f.file)) || f.content.value;
      if (!text.trim()) throw new Error("Choose a file or paste records");
      const r = await api.apiSecImportLogs(f.service.value, f.format.value, text);
      container.querySelector("#log-result").innerHTML = `<p class="callout">${num(r.records)} records read (${num(r.read.skipped)} skipped, format ${esc(r.read.format)}): ${r.endpoints} endpoint(s), ${r.new_endpoints} new. ${Object.entries(r.drift).map(([s, x]) => esc(s) + ": " + x.shadow.length + " shadow").join("; ")}</p>`;
      flash("Records imported.", "success");
    }); });
    container.querySelector("#drift-go").addEventListener("click", () => guard(async () => {
      const s = container.querySelector("#drift-service").value; if (!s) return;
      const dr = await api.apiSecDrift(s);
      container.querySelector("#drift-out").innerHTML = `${dr.note ? `<p class="callout">${esc(dr.note)}</p>` : ""}<p>${dr.documented} documented, ${dr.observed} observed.</p><h4>Shadow (in traffic, not in the spec)</h4>${table(["Endpoint", "Calls", "Last seen"], dr.shadow.map((x) => `<tr><td>${esc(x.method)} ${esc(x.template)}</td><td>${num(x.calls)}</td><td>${esc(x.last_seen)}</td></tr>`))}
        <h4>Documented but never seen</h4>${table(["Endpoint"], dr.documented_never_seen.map((x) => `<tr><td>${esc(x.method)} ${esc(x.template)}</td></tr>`))}`;
    }));
    container.querySelector("#gen-go").addEventListener("click", () => guard(async () => {
      const s = container.querySelector("#drift-service").value; if (!s) return;
      download(`${s}-observed.openapi.json`, JSON.stringify(await api.apiSecGeneratedSpec(s), null, 2));
    }));
  }

  // ------------------------------------------------------------ findings
  const ff = { sev: "", rule: "" };
  async function findings() {
    const d = await api.apiSecFindings();
    const rows = d.findings.filter((f) => (!ff.sev || f.severity === ff.sev) && (!ff.rule || f.rule === ff.rule));
    shell(`<p><select id="ff-sev"><option value="">All severities</option>${["Critical", "High", "Medium", "Low"].map((x) => `<option${x === ff.sev ? " selected" : ""}>${x}</option>`).join("")}</select>
        <select id="ff-rule"><option value="">All categories</option>${Object.entries(d.owasp).map(([k, v]) => `<option value="${k}"${k === ff.rule ? " selected" : ""}>${esc(k)} ${esc(v)}</option>`).join("")}</select>
        <span class="muted">${rows.length} of ${d.findings.length}</span> <button type="button" id="pub">Publish to the main queue</button></p>
      <p class="muted">${esc(d.note)} Publishing sends the complete current set (source api-security, scan type DAST); a finding leaves the queue when the data no longer shows it.</p>
      ${table(["Severity", "Finding", "Evidence, request and fix"], rows.slice(0, 300).map((f) => `<tr><td>${sevBadge(f.severity)}<br><span class="muted">${esc(f.rule)}</span></td><td class="wrap-cell"><strong>${esc(f.title)}</strong><br><span class="muted">${esc(f.service)}</span></td>
        <td class="wrap-cell"><details><summary>Evidence chain (${f.evidence.length} steps)${f.request && f.request.testable ? " and request" : ""}</summary>${evidenceHtml(f)}</details></td></tr>`), "No findings. Rules raise nothing when the data they need is missing; see the Overview gaps.")}`);
    container.querySelector("#ff-sev").addEventListener("change", (e) => { ff.sev = e.target.value; findings().catch(fail); });
    container.querySelector("#ff-rule").addEventListener("change", (e) => { ff.rule = e.target.value; findings().catch(fail); });
    container.querySelector("#pub").addEventListener("click", () => guard(async () => {
      const pre1 = await api.apiSecPublish({});
      if (pre1.preview_only && window.confirm(pre1.message + ` (${pre1.findings} findings)`)) { const r = await api.apiSecPublish({ confirm: true }); flash(`Published ${r.published} finding(s).`, "success"); }
    }));
  }

  // ------------------------------------------------------------ callers
  async function callers() {
    const d = await api.apiSecCallers(30);
    shell(`<p class="muted">What each caller reached. Indicators fire on thresholds in api_security.yaml: ${num(d.thresholds.scraping_calls_per_actor_day)} calls to one endpoint in a day, ${bytes(d.thresholds.exfil_bytes_per_actor_day)} returned in a day, ${d.thresholds.bola_distinct_objects_per_actor_day} distinct object ids on one endpoint in a day. They are reasons to look, not verdicts. Caller identities are stored ${d.actor_handling === "hash" ? "as one-way hashes" : "as received"}.</p>
      ${table(["Caller", "Calls", "Bytes returned", "Endpoints", "Days", "Indicators", ""], d.callers.map((c) => `<tr><td class="wrap-cell">${esc(c.actor)}</td><td>${num(c.calls)}</td><td>${bytes(c.bytes_out)}</td><td>${c.endpoints}</td><td>${c.days}</td>
        <td>${c.indicators.map((i) => badge(i === "sensitive" ? "badge-outline" : "badge-high", i)).join(" ")}</td><td><button type="button" class="link-button" data-actor="${esc(c.actor)}">Investigate</button></td></tr>`), "No caller activity. Records need an actor or a client address.")}`);
    container.querySelectorAll("[data-actor]").forEach((b) => b.addEventListener("click", () => guard(() => callerModal(b.dataset.actor))));
  }
  async function callerModal(actor) {
    const d = await api.apiSecCaller(actor);
    const body = openModal(`<h3>${esc(d.actor)}</h3><p class="muted">${esc(d.first_day)} to ${esc(d.last_day)} (${d.days} day(s)) &middot; ${num(d.calls)} calls &middot; ${bytes(d.bytes_out)} returned${d.addresses.length ? " &middot; from " + esc(d.addresses.join(", ")) : ""}</p>
      <p><strong>Your data classes reached</strong>: ${d.data_classes.map((c) => esc(c.name) + " (priority " + c.priority + ")").join(", ") || "none"}</p>
      <h4>Indicators</h4>${d.indicators.length ? `<ul>${d.indicators.map((i) => `<li>${badge("badge-outline", i.type)} ${esc(i.detail)}</li>`).join("")}</ul>` : '<p class="muted">None.</p>'}
      <h4>Endpoints reached</h4>${table(["Endpoint", "Calls", "Errors", "Bytes returned", "Most objects in a day", "Data"], d.endpoints.map((e) => `<tr><td class="wrap-cell">${esc(e.method)} ${esc(e.template)}<br><span class="muted">${esc(e.service)} &middot; ${esc(e.exposure)}</span></td><td>${num(e.calls)}</td><td>${num(e.errors)}</td><td>${bytes(e.bytes_out)}</td><td>${e.max_distinct_objects}</td><td>${esc(e.data_classes.join(", "))}</td></tr>`))}
      <h4>Draft protection policies</h4><p class="muted">${esc(d.note)}</p>
      ${d.suggested_policies.length ? d.suggested_policies.map((p, i) => `<p>${esc(p.name)} <span class="muted">(${esc(p.kind)}, ${esc(p.mode)})</span> <button type="button" class="link-button" data-draft="${i}">Save as a policy</button></p>`).join("") : '<p class="muted">None suggested.</p>'}`);
    body.querySelectorAll("[data-draft]").forEach((b) => b.addEventListener("click", () => guard(async () => {
      await api.apiSecPolicyAdd(d.suggested_policies[Number(b.dataset.draft)]); flash("Saved as a policy in monitor mode. Review it on the Protection policies tab.", "success");
    })));
  }

  // ------------------------------------------------------------ data classes
  async function dataTab() {
    const d = await api.apiSecClassification();
    shell(`<p class="callout">${esc(d.note)}</p>
      <h3>Your framework</h3>
      ${table(["Class", "Priority", "Detectors", "Your own field patterns", "Endpoints", "Description"], d.classes.map((c) => `<tr><td>${esc(c.name)}</td><td>${c.priority}</td><td class="wrap-cell">${esc(c.detectors.join(", "))}</td><td class="wrap-cell">${esc(c.field_patterns.join(", "))}</td><td>${d.endpoints_by_class[c.name] || 0}</td><td class="wrap-cell">${esc(c.description || "")}</td></tr>`), "No framework imported. Data seen in APIs is reported as unclassified.")}
      ${d.classes.length ? '<p><button type="button" class="secondary-button danger-link" id="clear">Remove the framework</button></p>' : ""}
      <h3>Import</h3><p class="muted">${esc(d.format)}</p>
      <form id="cls-form" class="run-form"><label>File <input type="file" name="file"></label><label>Or paste <textarea name="content" rows="6" placeholder="name,priority,description,detectors,field_patterns&#10;Restricted,1,Highest,payment-card;national-id,loyaltyid&#10;Internal,3,,email;phone,"></textarea></label>
        <label><input type="checkbox" name="replace" checked> Replace the current framework</label><div><button type="submit">Import</button></div></form>
      <h3>Kinds of data seen and not yet mapped</h3>
      ${table(["Detector", "Endpoints"], Object.entries(d.unclassified).map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n}</td></tr>`), "Everything seen is mapped to one of your classes.")}
      <h3>What Quanta can recognise</h3><p class="muted">${d.detectors.map((x) => esc(x.id)).join(", ")}. Add your own field-name patterns for data only you know about.</p>`);
    container.querySelector("#cls-form").addEventListener("submit", (e) => { e.preventDefault(); guard(async () => {
      const f = e.target, text = (await readFile(f.file)) || f.content.value;
      if (!text.trim()) throw new Error("Choose a file or paste your framework");
      await api.apiSecClassificationImport({ content: text, replace: f.replace.checked }); flash("Framework imported.", "success"); show();
    }); });
    const clr = container.querySelector("#clear");
    if (clr) clr.addEventListener("click", () => guard(async () => { if (window.confirm("Remove your classification framework?")) { await api.apiSecClassificationClear(); show(); } }));
  }

  // ------------------------------------------------------------ policies
  const WINDOWS = [60, 120, 300, 600];
  const DL_WINDOWS = [60, 300, 3600, 86400];
  function policyForm(meta, p) {
    const x = p || { name: "", kind: "rate-limit", mode: "monitor", enabled: true, scope: {}, params: {}, description: "" }, pr = x.params || {};
    const opt = (list, cur) => list.map((o) => `<option value="${esc(o)}"${String(o) === String(cur) ? " selected" : ""}>${esc(o)}</option>`).join("");
    const classes = `<option value="">(none)</option>${meta.classes.map((c) => `<option${pr.data_class === c ? " selected" : ""}>${esc(c)}</option>`).join("")}`;
    return `<form id="pol-form" class="run-form"><label>Name <input name="name" value="${esc(x.name)}" required maxlength="120"></label>
      <label>Kind <select name="kind" ${p ? "disabled" : ""}>${meta.kinds.map((k) => `<option value="${k.id}"${k.id === x.kind ? " selected" : ""}>${esc(k.label)}</option>`).join("")}</select></label>
      <label>Mode <select name="mode">${opt(meta.modes, x.mode)}</select></label><label><input type="checkbox" name="enabled"${x.enabled ? " checked" : ""}> Enabled</label>
      <label>Endpoints it applies to, one per line (blank for all) <textarea name="endpoints" rows="3" placeholder="GET /users/{id}&#10;* /admin/*">${esc((x.scope.endpoints || []).join("\n"))}</textarea></label>
      <label>Services (comma separated, optional) <input name="services" value="${esc((x.scope.services || []).join(", "))}"></label>
      <div data-kind="rate-limit"><label>Requests allowed <input name="limit" type="number" value="${esc(pr.limit ?? 100)}"></label><label>Per window (seconds) <select name="window">${opt(WINDOWS, pr.window_seconds ?? 60)}</select></label>
        <label>Count by <select name="by_rl">${opt(["ip", "actor"], pr.by ?? "ip")}</select></label><label>Header carrying the caller identity (when counting by actor) <input name="actor_header" value="${esc(pr.actor_header || "")}"></label></div>
      <div data-kind="malicious-source"><label>Addresses or CIDR ranges, one per line <textarea name="cidrs" rows="3">${esc((pr.cidrs || []).join("\n"))}</textarea></label><label>Reason <input name="reason" value="${esc(pr.reason || "")}"></label></div>
      <div data-kind="geo-restriction"><label>Countries (two-letter codes, comma separated) <input name="countries" value="${esc((pr.countries || []).join(", "))}"></label><label>Type <select name="geo_type">${opt(["deny", "allow-only"], pr.type ?? "deny")}</select></label>
        <label>Only for data class <select name="geo_class">${classes}</select></label></div>
      <div data-kind="data-loss"><label>Count by <select name="by_dl">${opt(["actor", "ip"], pr.by ?? "actor")}</select></label><label>Window (seconds) <select name="dl_window">${opt(DL_WINDOWS, pr.window_seconds ?? 86400)}</select></label>
        <label>Most records <input name="max_records" type="number" value="${esc(pr.max_records ?? "")}"></label><label>Most bytes <input name="max_bytes" type="number" value="${esc(pr.max_bytes ?? "")}"></label>
        <label>Data class <select name="dl_class">${classes}</select></label><p class="muted">Counts what leaves in responses, so it needs an enforcement point that sees responses (a gateway or sidecar). No web application firewall rule is generated for it.</p></div>
      <div data-kind="custom-signature"><label>Inspect <select name="target">${opt(["header", "query", "body", "uri_path"], pr.target ?? "header")}</select></label><label>Header name (for a header) <input name="header_name" value="${esc(pr.header_name || "")}"></label>
        <label>Match <select name="match">${opt(["contains", "exact", "starts_with", "regex"], pr.match ?? "contains")}</select></label><label>Pattern <input name="pattern" value="${esc(pr.pattern || "")}" maxlength="400"></label></div>
      <label>Description <input name="description" value="${esc(x.description || "")}"></label>
      <div><button type="submit">Save</button> <button type="button" class="secondary-button" id="pol-cancel">Cancel</button></div></form>`;
  }
  function policyBody(f, kind) {
    const lines = (v) => v.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const num1 = (v) => (v === "" ? null : Number(v));
    const params = {};
    if (kind === "rate-limit") Object.assign(params, { limit: num1(f.limit.value), window_seconds: Number(f.window.value), by: f.by_rl.value, ...(f.by_rl.value === "actor" ? { actor_header: f.actor_header.value } : {}) });
    if (kind === "malicious-source") Object.assign(params, { cidrs: lines(f.cidrs.value), reason: f.reason.value });
    if (kind === "geo-restriction") Object.assign(params, { countries: f.countries.value.split(",").map((s) => s.trim()).filter(Boolean), type: f.geo_type.value, ...(f.geo_class.value ? { data_class: f.geo_class.value } : {}) });
    if (kind === "data-loss") Object.assign(params, { by: f.by_dl.value, window_seconds: Number(f.dl_window.value), ...(f.max_records.value ? { max_records: num1(f.max_records.value) } : {}), ...(f.max_bytes.value ? { max_bytes: num1(f.max_bytes.value) } : {}), ...(f.dl_class.value ? { data_class: f.dl_class.value } : {}) });
    if (kind === "custom-signature") Object.assign(params, { target: f.target.value, match: f.match.value, pattern: f.pattern.value, ...(f.target.value === "header" ? { header_name: f.header_name.value } : {}) });
    return { name: f.name.value, kind, mode: f.mode.value, enabled: f.enabled.checked, description: f.description.value, scope: { endpoints: lines(f.endpoints.value), services: f.services.value.split(",").map((s) => s.trim()).filter(Boolean) }, params };
  }

  let editing = null;
  async function policies() {
    const d = await api.apiSecPolicies();
    if (editing !== null) {
      shell(`<h3>${editing.id ? "Edit policy" : "New policy"}</h3>${policyForm(d.meta, editing.id ? editing : null)}`);
      const form = container.querySelector("#pol-form");
      const showKind = () => form.querySelectorAll("[data-kind]").forEach((el) => { el.style.display = el.dataset.kind === (editing.id ? editing.kind : form.kind.value) ? "" : "none"; });
      form.kind.addEventListener("change", showKind); showKind();
      container.querySelector("#pol-cancel").addEventListener("click", () => { editing = null; show(); });
      form.addEventListener("submit", (e) => { e.preventDefault(); guard(async () => {
        const body = policyBody(form, editing.id ? editing.kind : form.kind.value);
        if (editing.id) await api.apiSecPolicyUpdate(editing.id, body); else await api.apiSecPolicyAdd(body);
        editing = null; flash("Saved.", "success"); show();
      }); });
      return;
    }
    const stateBadge = (p) => badge({ draft: "badge-outline", sent: "badge-medium", applied: "badge-low", rejected: "badge-critical", failed: "badge-critical", "pending-push": "badge-high" }[p.push_state] || "badge-outline", p.push_state);
    shell(`<p class="callout">${esc(d.note)} New policies start in monitor mode. A blocking policy can only be sent after a different administrator approves that version, and any edit voids the approval. Connect the endpoint on the Connections page (type: API protection policy endpoint).</p>
      <p><button type="button" id="new-pol">New policy</button></p>
      ${table(["Policy", "Kind", "Mode", "Version", "State", "Approval", ""], d.policies.map((p) => `<tr><td class="wrap-cell"><strong>${esc(p.name)}</strong>${p.enabled ? "" : ' <span class="badge badge-outline">disabled</span>'}<br><span class="muted">${esc((p.scope.endpoints || []).join("; ") || (p.scope.services || []).join("; ") || "all endpoints")}</span></td>
        <td>${esc((d.meta.kinds.find((k) => k.id === p.kind) || {}).label || p.kind)}</td><td>${badge(p.mode === "block" ? "badge-critical" : "badge-low", p.mode)}</td><td>${p.version}</td><td>${stateBadge(p)}</td>
        <td>${p.mode === "block" ? (p.approved ? "approved by " + esc(p.approved_by) : "needs a second administrator") : "not needed"}</td>
        <td class="wrap-cell"><button type="button" class="link-button" data-act="edit" data-id="${p.id}">Edit</button> ${p.mode === "block" && !p.approved ? `<button type="button" class="link-button" data-act="approve" data-id="${p.id}">Approve</button> ` : ""}
          <button type="button" class="link-button" data-act="art" data-id="${p.id}">Rules to review</button> <button type="button" class="link-button" data-act="push" data-id="${p.id}">Send to my endpoint</button>
          <button type="button" class="link-button" data-act="hist" data-id="${p.id}">History</button> <button type="button" class="link-button danger-link" data-act="del" data-id="${p.id}">Delete</button></td></tr>`), "No policies yet.")}
      <h3>Audit trail</h3><p class="muted">Every change, approval, send and reported edge result.</p>
      ${table(["When", "Policy", "Action", "By", "Detail"], d.log.events.slice(0, 40).map((e) => `<tr><td>${esc(e.at)}</td><td>${esc(e.policy_name)} v${e.version ?? ""}</td><td>${esc(e.action)}</td><td>${esc(e.actor || "")}</td><td class="wrap-cell">${esc(JSON.stringify(e.detail || {}))}</td></tr>`), "Nothing yet.")}
      <h3>Sends</h3>
      ${table(["When", "Policy", "Mode", "Status", "Endpoint answered", "Edge result reported by", "Detail"], d.log.pushes.slice(0, 30).map((x) => `<tr><td>${esc(x.sent_at)}</td><td>${esc(x.policy_name)} v${x.version}</td><td>${esc(x.mode)}</td><td>${esc(x.status)}</td><td>${x.http_status ?? ""}</td><td>${esc(x.reported_by || "")}</td><td class="wrap-cell">${esc(x.message || "")}</td></tr>`), "Nothing sent yet.")}
      <p class="muted">Your automation can report the edge result with POST /api/inbound/api-policy-status (API key with the api:write scope): {"push_id": N, "status": "applied" or "rejected", "detail": "..."}. Each result raises an alert on the notification webhook and by email (set QUANTA_ALERT_EMAIL and SMTP).</p>`);
    container.querySelector("#new-pol").addEventListener("click", () => { editing = {}; policies().catch(fail); });
    container.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", () => guard(async () => {
      const id = Number(b.dataset.id), p = d.policies.find((x) => x.id === id), act = b.dataset.act;
      if (act === "edit") { editing = p; await policies(); return; }
      if (act === "approve") { await api.apiSecPolicyApprove(id); flash("Approved this version.", "success"); show(); return; }
      if (act === "del") { if (window.confirm("Delete this policy? Nothing already applied at your edge is changed.")) { await api.apiSecPolicyDelete(id); show(); } return; }
      if (act === "art") { await artifactModal(p, d.meta); return; }
      if (act === "hist") { const h = await api.apiSecPolicyHistory(id); openModal(`<h3>${esc(p.name)}</h3>${table(["When", "Action", "By", "Detail"], h.events.map((e) => `<tr><td>${esc(e.at)}</td><td>${esc(e.action)}</td><td>${esc(e.actor || "")}</td><td class="wrap-cell">${esc(JSON.stringify(e.detail || {}))}</td></tr>`))}`); return; }
      if (act === "push") {
        const pre1 = await api.apiSecPolicyPush(id, {});
        if (pre1.preview_only && window.confirm(`${pre1.message}\n\nEndpoint: ${pre1.connection || "(connected endpoint)"}\nPolicy: ${p.name}, version ${p.version}, ${p.mode} mode`)) {
          const r = await api.apiSecPolicyPush(id, { confirm: true });
          flash(r.push.status === "sent" ? "Sent. Your automation decides whether to apply it." : `Not delivered: ${r.push.message}`, r.push.status === "sent" ? "success" : "error"); show();
        }
      }
    })));
  }
  async function artifactModal(p, meta) {
    const targets = Object.entries(meta.targets);
    const first = await api.apiSecPolicyArtifact(p.id, targets[0][0]);
    const body = openModal(`<h3>Rules to review: ${esc(p.name)}</h3><p><select id="art-target">${targets.map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("")}</select></p><div id="art-out"></div>`);
    const paint = (a) => { body.querySelector("#art-out").innerHTML = `${a.supported ? pre(JSON.stringify(a.artifact, null, 2)) : '<p class="callout callout-warn">No rule can be generated for this target.</p>'}<ul>${a.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`; };
    paint(first);
    body.querySelector("#art-target").addEventListener("change", (e) => guard(async () => paint(await api.apiSecPolicyArtifact(p.id, e.target.value))));
  }

  // ------------------------------------------------------------ metrics
  let mdays = 30;
  async function metricsTab() {
    const d = await api.apiSecMetrics(mdays, "");
    const t = d.total;
    shell(`<p><select id="m-days">${[7, 14, 30, 90].map((x) => `<option${x === mdays ? " selected" : ""}>${x}</option>`).join("")}</select> days</p>
      ${t ? `<div class="kpi-grid">${kpi("calls", num(t.calls))}${kpi("error rate", pct(t.error_rate))}${kpi("average latency", t.avg_latency_ms === null ? "n/a" : t.avg_latency_ms + " ms")}${kpi("bytes returned", bytes(t.bytes_out))}${kpi("security events", num(t.security_events))}</div>` : '<p class="callout">No traffic metrics yet. Import an access-log export on the Import tab.</p>'}
      ${d.moved.length ? `<p class="callout callout-warn">${d.moved.length} endpoint(s) moved compared with the previous window: ${d.moved.slice(0, 6).map((m) => esc(m.method + " " + m.template) + " (" + m.flags.map((f) => esc(f.metric) + " " + esc(f.change)).join(", ") + ")").join("; ")}</p>` : ""}
      ${table(["Endpoint", "Calls", "Errors", "Error rate", "Avg latency", "Max latency", "Bytes in", "Bytes out", "Distinct callers", "Security events"], d.endpoints.map((e) => `<tr><td class="wrap-cell">${esc(e.method)} ${esc(e.template)}<br><span class="muted">${esc(e.service)}</span></td><td>${num(e.calls)}</td><td>${num(e.errors)}</td><td>${pct(e.error_rate)}</td>
        <td>${e.avg_latency_ms === null ? "n/a" : e.avg_latency_ms + " ms"}</td><td>${e.max_latency_ms === null ? "n/a" : e.max_latency_ms + " ms"}</td><td>${bytes(e.bytes_in)}</td><td>${bytes(e.bytes_out)}</td><td>${e.distinct_actors}</td><td>${e.security_events}</td></tr>`), "No endpoint has traffic in this period.")}
      <p class="muted">${esc(d.definition)}</p>`);
    container.querySelector("#m-days").addEventListener("change", (e) => { mdays = Number(e.target.value); metricsTab().catch(fail); });
  }

  // ------------------------------------------------------------ CI and rollout
  let track = "";
  async function ciTab() {
    const [t, r] = await Promise.all([api.apiSecCiTemplates(), api.apiSecRollout(track)]);
    track = r.track;
    shell(`<h3>Shift-left: API tests in the pipeline</h3>
      <p>Your pipeline runs an API security tester against a staging deployment and posts the results to <code>POST /api/ingest/api-test-results</code> with an API key (scope api:write). The response carries <code>gate.passed</code>; the job fails when it is false. Failures become findings in the queue and a passing run counts as evidence for the DevSecOps control "APIs are tested against the OWASP API Security Top 10". Gate: fail on <strong>${esc(t.gate.fail_on)}</strong> or above (override with <code>?fail_on=</code>; use <code>?report_only=true</code> to start without blocking). A SARIF file can go to <code>/api/ingest/sarif?scan_type=dast</code> instead. ${esc(t.note)}</p>
      <p><select id="tpl">${Object.keys(t.templates).map((k) => `<option>${esc(k)}</option>`).join("")}</select></p><div id="tpl-out">${pre(t.templates["github-actions"])}</div>
      <h3>Onboarding and rollout</h3>
      <p><select id="track">${r.tracks.map((x) => `<option value="${x.id}"${x.id === r.track ? " selected" : ""}>${esc(x.title)}</option>`).join("")}</select> <span class="muted">${esc((r.tracks.find((x) => x.id === r.track) || {}).note || "")}</span></p>
      <p>${r.done} of ${r.total} steps done. Steps marked <em>observed</em> are ticked from data; <em>stated</em> steps are ticked by an administrator.</p>
      ${r.phases.map((ph) => `<h4>${esc(ph.phase)} (${ph.done}/${ph.total})</h4>${table(["", "Step", "Basis", "Note"], ph.items.map((i) => `<tr><td>${i.basis === "stated" ? `<input type="checkbox" data-step="${esc(i.id)}"${i.done ? " checked" : ""}>` : (i.done ? "&#10003;" : "&#9675;")}</td>
        <td class="wrap-cell"><strong>${esc(i.title)}</strong><br><span class="muted">${esc(i.detail)}</span></td><td>${esc(i.basis)}</td><td class="wrap-cell">${esc(i.note || "")}${i.set_by ? `<br><span class="muted">${esc(i.set_by)}</span>` : ""}</td></tr>`))}`).join("")}
      <h3>Maturity journey</h3><p>${r.maturity.map((m) => `<span class="badge ${m.reached ? "badge-low" : "badge-outline"}">${m.reached ? "&#10003; " : ""}${esc(m.title)}${m.observed ? "" : " (not measured)"}</span>`).join(" ")}</p>
      <h3>Who does what</h3>${table(["Team", "Uses", "In Quanta"], r.roles.map((x) => `<tr><td>${esc(x.role)}</td><td class="wrap-cell">${esc(x.uses)}</td><td class="wrap-cell">${esc(x.quanta)}</td></tr>`))}
      <p class="muted">${esc(r.sso_note)}</p>`);
    container.querySelector("#tpl").addEventListener("change", (e) => { container.querySelector("#tpl-out").innerHTML = pre(t.templates[e.target.value]); });
    container.querySelector("#track").addEventListener("change", (e) => { track = e.target.value; ciTab().catch(fail); });
    container.querySelectorAll("[data-step]").forEach((c) => c.addEventListener("change", () => guard(async () => {
      const note = c.checked ? (window.prompt("Add a note (optional)", "") || "") : "";
      await api.apiSecRolloutSet(c.dataset.step, { done: c.checked, note }); ciTab().catch(fail);
    })));
  }

  const views = { overview, inventory, import: importTab, findings, callers, data: dataTab, policies, metrics: metricsTab, ci: ciTab };
  async function show() {
    try { await views[tab](); } catch (e) { container.innerHTML = `<p class="subtitle">${NOTE}</p><p class="callout callout-danger">${esc(e.message)}</p>`; }
  }
  await show();
}
