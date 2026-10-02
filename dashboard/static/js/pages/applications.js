// Applications & SBOM: each application with its deployment context, its SBOM, an interactive dependency and exposure graph, and its findings ranked
// (with the single upgrade that closes the most). Backed by /api/applications* (dashboard/appsec_api.py, remediation/appsec/).
import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { openFindingDetail } from "../findingDetail.js";
import { renderDependencyGraph } from "../depGraph.js";

export const title = "Applications & SBOM";

const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const TABS = [["work", "Ranked work"], ["graph", "Dependency graph"], ["components", "Components"], ["context", "Context & SBOM"], ["prs", "Pull requests"]];
const FIELDS = [["environment", "Environment", "select", "environments"], ["business_criticality", "Business criticality", "select", "criticality"], ["internet_facing", "Internet facing", "bool"],
  ["platform", "Platform (for example AWS ECS, on-premises VM)", "text"], ["os", "Operating system", "text"], ["owner", "Owner", "text"], ["team", "Team", "text"],
  ["data_classification", "Data classification", "text"], ["repo_provider", "Git provider", "select", "providers"], ["repo", "Repository (group/project)", "text"],
  ["default_branch", "Default branch", "text"], ["manifest_paths", "Dependency files (one path per line)", "area"], ["connection_id", "Git connection id (blank = the first enabled one)", "text"]];

export async function render(container) {
  const params = new URLSearchParams(window.location.search);
  let name = params.get("app");
  let tab = params.get("tab") || "work";
  let admin = false;
  try { admin = ((await api.authMe()).user || {}).role === "admin"; } catch { admin = false; }
  let queue = null;
  const findingById = async (id) => { if (!queue) queue = new Map((await api.queue()).findings.map((f) => [f.id, f])); return queue.get(id); };
  const openFinding = async (id) => { const f = await findingById(id); if (f) openFindingDetail(f); else flash("That finding is no longer in the queue.", "error"); };
  const go = (n, t) => { const u = new URL(window.location.href); n ? u.searchParams.set("app", n) : u.searchParams.delete("app"); t ? u.searchParams.set("tab", t) : u.searchParams.delete("tab"); window.history.pushState({}, "", u); name = n; tab = t || "work"; show(); };

  function fieldHtml([key, label, kind, optKey], app, lists) {
    const v = app ? app[key] : null;
    if (kind === "select") return `<label>${label}<select name="${key}"><option value="">(not recorded)</option>${(lists[optKey] || []).map((o) => `<option${v === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select></label>`;
    if (kind === "bool") return `<label>${label}<select name="${key}"><option value="">(not recorded)</option><option value="true"${v === true ? " selected" : ""}>Yes</option><option value="false"${v === false ? " selected" : ""}>No</option></select></label>`;
    if (kind === "area") return `<label>${label}<textarea name="${key}" rows="3">${escapeHtml((v || []).join("\n"))}</textarea></label>`;
    return `<label>${label}<input name="${key}" value="${escapeHtml(v ?? "")}"></label>`;
  }
  function readForm(form) {
    const out = {};
    for (const [key, , kind] of FIELDS) {
      const el = form.elements[key];
      if (!el) continue;
      let v = el.value.trim();
      if (kind === "bool") out[key] = v === "" ? null : v === "true";
      else if (key === "connection_id") out[key] = v === "" ? null : Number(v);
      else out[key] = v === "" ? null : v;
    }
    return out;
  }

  // ------------------------------------------------------------------ list
  async function list() {
    const d = await api.applications();
    const withSbom = d.applications.filter((a) => a.sbom).length;
    container.innerHTML = `<p class="subtitle">Applications with their deployment context and software bill of materials (SBOM). Open one for the interactive dependency graph, its findings ranked by how much they matter here, and the fix. An application's findings are the ones whose asset name matches its name.</p>
      <div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">applications</div><div class="kpi-value">${d.applications.length}</div></div>
        <div class="kpi-card"><div class="kpi-label">with an SBOM</div><div class="kpi-value">${withSbom}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">known-exploited findings</div><div class="kpi-value">${d.applications.reduce((a, x) => a + x.kev, 0)}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">dependency findings</div><div class="kpi-value">${d.applications.reduce((a, x) => a + x.dependency_findings, 0)}</div></div></div>
      ${admin ? '<p class="inline-actions"><button type="button" class="btn-primary" id="add-app">Add an application</button></p>' : ""}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Application</th><th>Environment</th><th>Owner / team</th><th>Criticality</th><th>Exposure</th><th>SBOM</th><th>Findings</th><th></th></tr></thead><tbody>
      ${d.applications.length ? d.applications.map((a) => `<tr><td><strong>${escapeHtml(a.name)}</strong><br><span class="muted">${escapeHtml(a.platform || "")}</span></td><td>${escapeHtml(a.environment || "-")}</td>
        <td>${escapeHtml(a.owner || "-")}<br><span class="muted">${escapeHtml(a.team || "")}</span></td><td>${escapeHtml(a.business_criticality || "-")}</td>
        <td>${a.internet_facing === true ? "internet facing" : a.internet_facing === false ? "internal" : '<span class="muted">not recorded</span>'}</td>
        <td>${a.sbom ? `${a.sbom.components} components<br><span class="muted">${escapeHtml(a.sbom.format)}, ${escapeHtml((a.sbom.uploaded_at || "").slice(0, 10))}</span>` : '<span class="muted">none</span>'}</td>
        <td>${a.findings} <span class="muted">(${a.dependency_findings} dependency, ${a.code_findings} code)</span>${a.kev ? ` <span class="badge badge-critical">${a.kev} KEV</span>` : ""}</td>
        <td><button type="button" class="link-button" data-open="${escapeHtml(a.name)}">Open</button></td></tr>`).join("") : '<tr><td colspan="8" class="empty-state">No application is registered yet. Add one, or send an SBOM from CI with <code>POST /api/ingest/sbom?application=NAME</code> and it appears here.</td></tr>'}</tbody></table></div>
      ${d.unregistered.length ? `<h3>Seen in findings, not registered</h3><p class="muted">These asset names carry code or dependency findings but have no application record, so Quanta knows nothing of their environment, owner or exposure.</p>
        <p>${d.unregistered.slice(0, 40).map((n) => (admin ? `<button type="button" class="secondary-button" data-reg="${escapeHtml(n)}">${escapeHtml(n)}</button> ` : `<span class="badge badge-outline">${escapeHtml(n)}</span> `)).join("")}</p>` : ""}`;
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => go(b.dataset.open, "work")));
    container.querySelectorAll("[data-reg]").forEach((b) => b.addEventListener("click", async () => { try { await api.applicationSave(b.dataset.reg, {}); go(b.dataset.reg, "context"); } catch (e) { flash(e.message, "error"); } }));
    const add = container.querySelector("#add-app");
    if (add) add.addEventListener("click", () => {
      const body = openModal(`<h3>Add an application</h3><form id="addf"><label>Name (the asset name its findings carry)<input name="name" required></label><div class="form-grid">${FIELDS.slice(0, 7).map((f) => fieldHtml(f, null, d)).join("")}</div><p><button type="submit" class="btn-primary">Save</button></p></form>`);
      body.querySelector("#addf").addEventListener("submit", async (e) => {
        e.preventDefault();
        const n = e.target.elements.name.value.trim();
        try { await api.applicationSave(n, readForm(e.target)); closeModal(); go(n, "context"); } catch (err) { flash(err.message, "error"); }
      });
    });
  }

  // ------------------------------------------------------------------ detail
  async function detail() {
    let a;
    try { a = await api.applicationAnalysis(name, tab === "graph" ? "focus" : "focus"); } catch (e) { container.innerHTML = `<p><button type="button" class="link-button" id="back">&larr; All applications</button></p><p class="callout callout-warn">${escapeHtml(e.message)}</p>`; container.querySelector("#back").addEventListener("click", () => go(null)); return; }
    const c = a.context, st = a.stats;
    const head = `<p><button type="button" class="link-button" id="back">&larr; All applications</button></p>
      <h2 style="margin:4px 0">${escapeHtml(a.application)}</h2>
      <p class="muted">${[c.environment, c.platform, c.owner && "owner " + c.owner, c.team && "team " + c.team, c.business_criticality && c.business_criticality + " criticality"].filter(Boolean).map(escapeHtml).join(" &middot; ") || "No deployment context is recorded yet."}
        &middot; exposure: <strong>${escapeHtml(a.reachability.exposure)}</strong> (${escapeHtml(a.reachability.exposure_reason)})</p>
      <div class="kpi-grid"><div class="kpi-card kpi-danger"><div class="kpi-label">P1 items</div><div class="kpi-value">${st.p1}</div></div>
        <div class="kpi-card"><div class="kpi-label">vulnerable components</div><div class="kpi-value">${st.vulnerable_components}<span class="muted"> of ${st.components}</span></div></div>
        <div class="kpi-card"><div class="kpi-label">dependency / code findings</div><div class="kpi-value">${st.dependency_findings} / ${st.code_findings}</div></div>
        <div class="kpi-card ${st.unmatched ? "kpi-warn" : ""}"><div class="kpi-label">findings not in the SBOM</div><div class="kpi-value">${st.unmatched}</div></div></div>
      <p class="tab-row">${TABS.map(([k, l]) => `<button type="button" class="secondary-button${k === tab ? " active" : ""}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="tab-body"></div>`;
    container.innerHTML = head;
    container.querySelector("#back").addEventListener("click", () => go(null));
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => go(name, b.dataset.tab)));
    const body = container.querySelector("#tab-body");
    ({ work: () => work(body, a), graph: () => graph(body, a), components: () => components(body, a), context: () => context(body, a), prs: () => prs(body, a) })[tab]();
  }

  function work(body, a) {
    body.innerHTML = `<p class="muted">Dependency findings are grouped by package, because one upgrade closes all of a package's findings. The score combines CVSS, exploit probability, known exploitation, the application's criticality and exposure, how sensitive the package is, and attack-chain position; open "Why" for each factor. The weights are in <code>remediation/config/appsec_scoring.yaml</code>.</p>
      ${a.reachability.note ? `<p class="callout">${escapeHtml(a.reachability.note)}</p>` : ""}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Priority</th><th>What to fix</th><th>Closes</th><th></th></tr></thead><tbody>
      ${a.work_items.length ? a.work_items.map((i) => `<tr><td class="nowrap"><span class="tier-${i.tier}">${i.tier}</span> <span class="score-bar" style="width:${Math.round(i.score * 0.6)}px"></span>${i.score}</td>
        <td class="wrap-cell">${i.kind === "dependency-upgrade"
          ? `<strong>${escapeHtml(i.package)}</strong> ${escapeHtml(i.current_version || "?")} &rarr; <strong>${escapeHtml(i.target_version || "no fixed version known")}</strong>${i.crosses_major ? ' <span class="badge badge-medium">major version</span>' : ""}${i.kev ? ' <span class="badge badge-critical">known exploited</span>' : ""}
             <br><span class="muted">${i.direct === true ? "direct dependency" : i.direct === false ? "transitive dependency" + (i.pulled_in_by.length ? ", pulled in by " + i.pulled_in_by.map(escapeHtml).join(", ") : "") : "direct or transitive not known"}${i.in_sbom ? "" : "; not found in the SBOM"}</span>${i.note ? `<br><span class="muted">${escapeHtml(i.note)}</span>` : ""}`
          : `<strong>${escapeHtml(i.title)}</strong>${i.kev ? ' <span class="badge badge-critical">known exploited</span>' : ""}<br><span class="muted">${escapeHtml(i.scan_type || "")} ${escapeHtml(typeof i.location === "string" ? i.location : (i.location && i.location.file ? i.location.file + (i.location.line ? ":" + i.location.line : "") : ""))}</span>`}</td>
        <td class="wrap-cell">${i.finding_ids.slice(0, 4).map((f) => `<button type="button" class="link-button" data-finding="${escapeHtml(f)}">${escapeHtml(f)}</button>`).join(" ")}${i.finding_ids.length > 4 ? ` +${i.finding_ids.length - 4}` : ""}${i.cves && i.cves.length ? `<br><span class="muted">${i.cves.slice(0, 3).map(escapeHtml).join(", ")}${i.cves.length > 3 ? ", ..." : ""}</span>` : ""}</td>
        <td class="nowrap"><button type="button" class="link-button" data-why="${escapeHtml(i.id)}">Why</button>
          ${admin ? (i.kind === "dependency-upgrade" ? (i.target_version ? ` <button type="button" class="link-button" data-propose="${escapeHtml(i.id)}">Propose PR</button>` : "") : ` <button type="button" class="link-button" data-code="${escapeHtml(i.id)}">Propose fix</button>`) : ""}</td></tr>
        <tr class="why-row" id="why-${escapeHtml(i.id)}" style="display:none"><td colspan="4"></td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No open findings for this application.</td></tr>'}</tbody></table></div>
      ${a.unmatched_findings.length ? `<p class="callout callout-warn">${a.unmatched_findings.length} dependency finding(s) name a package that is not in this SBOM (${a.unmatched_findings.slice(0, 6).map(escapeHtml).join(", ")}). The scanner and the SBOM disagree about what is installed: refresh the SBOM from the same build.</p>` : ""}`;
    body.querySelectorAll("[data-finding]").forEach((b) => b.addEventListener("click", () => openFinding(b.dataset.finding)));
    body.querySelectorAll("[data-why]").forEach((b) => b.addEventListener("click", () => {
      const item = a.work_items.find((x) => x.id === b.dataset.why);
      const f = a.findings.find((x) => x.id === item.top_finding || x.id === item.id);
      const row = body.querySelector(`[id="why-${CSS.escape(item.id)}"]`);
      row.style.display = row.style.display === "none" ? "" : "none";
      row.firstElementChild.innerHTML = `<strong>Score ${f.score} (${f.tier}) for ${escapeHtml(f.id)}</strong><div class="table-scroll"><table class="data-table"><thead><tr><th>Factor</th><th>Value</th><th>Weight</th><th>Points</th></tr></thead><tbody>
        ${f.breakdown.map((r) => `<tr><td>${escapeHtml(r.factor)}</td><td class="wrap-cell">${escapeHtml(r.note)}</td><td>${r.weight}</td><td>${r.points}</td></tr>`).join("")}</tbody></table></div>
        <p class="muted">Multipliers: ${f.modifiers.map((m) => `${escapeHtml(m.name)} x${m.value} (${escapeHtml(m.note)})`).join("; ")}.${item.kind === "dependency-upgrade" && item.resolves > 1 ? ` The upgrade scores the highest finding plus a small bonus for each extra finding it closes (${item.resolves}).` : ""}</p>
        ${f.assumptions.length ? `<ul class="guidance-list">${f.assumptions.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>` : ""}`;
    }));
    body.querySelectorAll("[data-propose]").forEach((b) => b.addEventListener("click", () => proposeDependency(a, a.work_items.find((x) => x.id === b.dataset.propose))));
    body.querySelectorAll("[data-code]").forEach((b) => b.addEventListener("click", () => proposeCode(a, a.work_items.find((x) => x.id === b.dataset.code))));
  }

  function proposeDependency(a, item) {
    const c = a.context, canFetch = !!(c.repo && c.repo_provider && (c.manifest_paths || []).length);
    const m = openModal(`<h3>Propose an upgrade pull request</h3><p><strong>${escapeHtml(item.package)}</strong> ${escapeHtml(item.current_version || "?")} &rarr; <strong>${escapeHtml(item.target_version)}</strong>, closing ${item.resolves} finding(s).</p>
      <p class="muted">Nothing is sent to your Git host by this step. Quanta prepares the edit and the description; you review the diff on the Fix pull requests page and approve it before anything is opened.</p>
      <form id="pf"><label><input type="radio" name="src" value="fetch"${canFetch ? " checked" : " disabled"}> Read the dependency files from the repository (${canFetch ? escapeHtml(c.repo + ": " + c.manifest_paths.join(", ")) : "set the repository, provider and dependency files on the Context tab first"})</label>
      <label><input type="radio" name="src" value="paste"${canFetch ? "" : " checked"}> Paste a dependency file</label>
      <div id="paste" style="display:${canFetch ? "none" : "block"}"><label>File name (requirements.txt, package.json, pom.xml or go.mod)<input name="fname" value="${item.ecosystem === "maven" ? "pom.xml" : item.ecosystem === "npm" ? "package.json" : item.ecosystem === "golang" ? "go.mod" : "requirements.txt"}"></label><label>Contents<textarea name="text" rows="8"></textarea></label>
      <label>Does the repository have a lock file? <select name="lock"><option value="">I do not know</option><option value="yes">Yes</option><option value="no">No</option></select></label></div>
      <p><button type="submit" class="btn-primary">Prepare the proposal</button></p></form>`);
    m.querySelectorAll("[name=src]").forEach((r) => r.addEventListener("change", () => { m.querySelector("#paste").style.display = m.querySelector("[name=src]:checked").value === "paste" ? "block" : "none"; }));
    m.querySelector("#pf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, paste = f.elements.src.value === "paste";
      const bodyReq = { application: a.application, item_id: item.id };
      if (paste) { bodyReq.manifests = { [f.elements.fname.value.trim()]: f.elements.text.value }; if (f.elements.lock.value === "yes") bodyReq.lockfiles = ["lock file"]; } else bodyReq.fetch = true;
      try { const p = await api.gitopsProposeDependency(bodyReq); closeModal(); flash("Proposal prepared. Review the diff before approving.", "success"); window.history.pushState({}, "", `/fix-prs?id=${p.id}`); window.dispatchEvent(new PopStateEvent("popstate")); } catch (err) { flash(err.message, "error"); }
    });
  }

  function proposeCode(a, item) {
    const f0 = typeof item.location === "string" ? item.location : (item.location && item.location.file) || "";
    const m = openModal(`<h3>Propose a code fix for ${escapeHtml(item.id)}</h3><p>${escapeHtml(item.title)}</p>
      <p class="muted">Give the fix as a unified diff for the file the finding points at (a developer's patch, or the one the code-fix agent wrote to <code>remediation/output/code-fixes/${escapeHtml(item.id)}.json</code>). Quanta applies it strictly to the file's current content, shows the result as a diff, and refuses anything that does not fit or touches other files.</p>
      <form id="cf"><label><input type="checkbox" name="agent"> Use the agent's fix file instead of pasting</label>
      <div id="manual"><label>File<input name="path" value="${escapeHtml(f0)}"></label><label>Unified diff<textarea name="patch" rows="9" placeholder="--- a/file&#10;+++ b/file&#10;@@ -1,3 +1,3 @@"></textarea></label>
      <label><input type="checkbox" name="fetch"${a.context.repo ? " checked" : ""}> Read the file's current content from the repository</label><label>Current content (if not read from the repository)<textarea name="orig" rows="5"></textarea></label></div>
      <label>What the fix does and what must not change<textarea name="why" rows="3"></textarea></label><p><button type="submit" class="btn-primary">Prepare the proposal</button></p></form>`);
    m.querySelector("[name=agent]").addEventListener("change", (e) => { m.querySelector("#manual").style.display = e.target.checked ? "none" : "block"; });
    m.querySelector("#cf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target.elements;
      const req = { application: a.application, finding_id: item.id, explanation: f.why.value, validation: f.why.value ? { business_logic: f.why.value } : null };
      if (f.agent.checked) req.from_output = true;
      else { req.patches = { [f.path.value.trim()]: f.patch.value }; if (f.fetch.checked) req.fetch = true; else req.originals = { [f.path.value.trim()]: f.orig.value }; }
      try { const p = await api.gitopsProposeCode(req); closeModal(); window.history.pushState({}, "", `/fix-prs?id=${p.id}`); window.dispatchEvent(new PopStateEvent("popstate")); } catch (err) { flash(err.message, "error"); }
    });
  }

  function graph(body, a) {
    if (!a.sbom) { body.innerHTML = `<p class="callout">No SBOM is stored for this application, so there is no graph to draw. Generate one from its dependency files, upload one, or send one from CI on the <strong>Context &amp; SBOM</strong> tab.</p>`; return; }
    body.innerHTML = `<p class="muted">The path from the internet into the application, then its direct dependencies and what they pull in. Click a package for its findings, the version that fixes it and what depends on it. ${a.sbom.format}, ${a.sbom.components} components, stored ${escapeHtml((a.sbom.uploaded_at || "").slice(0, 10))}.</p><div id="graph-host"></div>
      ${a.hidden ? `<p><button type="button" class="secondary-button" id="all">Draw every component</button></p>` : ""}`;
    const draw = (data) => renderDependencyGraph(body.querySelector("#graph-host"), data, { onFinding: openFinding, onPropose: admin ? (n) => { const it = a.work_items.find((x) => x.kind === "dependency-upgrade" && (x.package || "").toLowerCase().endsWith(String(n.name).toLowerCase())); if (it && it.target_version) proposeDependency(a, it); else flash("No fixed version is known for this package, so there is nothing to propose.", "error"); } : null });
    draw(a);
    const all = body.querySelector("#all");
    if (all) all.addEventListener("click", async () => { try { draw(await api.applicationAnalysis(a.application, "all")); all.remove(); } catch (e) { flash(e.message, "error"); } });
  }

  function components(body, a) {
    const nodes = a.nodes.filter((n) => n.kind !== "application");
    if (!a.sbom) { body.innerHTML = '<p class="callout">No SBOM is stored for this application.</p>'; return; }
    let only = false;
    const paint = () => {
      const rows = nodes.filter((n) => !only || n.vulnerable).sort((x, y) => (y.top_score || 0) - (x.top_score || 0) || (x.depth || 99) - (y.depth || 99) || String(x.name).localeCompare(String(y.name)));
      body.querySelector("#cbody").innerHTML = rows.map((n) => `<tr><td><strong>${escapeHtml(n.name)}</strong><br><span class="muted">${escapeHtml(n.ecosystem || "")}</span></td><td>${escapeHtml(n.version || "-")}</td>
        <td>${n.direct === true ? "direct" : n.direct === false ? "transitive" : '<span class="muted">unknown</span>'}${n.depth ? ` <span class="muted">(level ${n.depth})</span>` : ""}</td><td>${escapeHtml(n.criticality ? n.criticality.level : "-")}<br><span class="muted">${escapeHtml(n.criticality ? n.criticality.category : "")}</span></td>
        <td>${n.vulnerable ? `<span class="badge ${SEV[n.worst_severity] || ""}">${escapeHtml(n.worst_severity)}</span> <span class="tier-${n.top_tier}">${n.top_tier}</span> ${n.findings.length}` : '<span class="muted">none</span>'}</td><td>${escapeHtml((n.licenses || []).join(", ") || "-")}</td></tr>`).join("")
        || '<tr><td colspan="6" class="empty-state">Nothing to show.</td></tr>';
    };
    body.innerHTML = `<p class="muted">${a.hidden ? `${a.hidden} component(s) with no findings are not listed because the SBOM is large. ` : ""}${a.sbom.has_graph ? "" : "This SBOM does not say which package depends on which, so direct or transitive is unknown. "}Sensitivity comes from what the package does (<code>appsec_criticality.yaml</code>).</p>
      <label><input type="checkbox" id="only"> Vulnerable only</label>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Dependency</th><th>Sensitivity</th><th>Findings</th><th>License</th></tr></thead><tbody id="cbody"></tbody></table></div>`;
    body.querySelector("#only").addEventListener("change", (e) => { only = e.target.checked; paint(); });
    paint();
  }

  async function context(body, a) {
    const lists = await api.applications();
    body.innerHTML = `<h3>Deployment context</h3>
      <p class="muted">What a CMDB would hold. Exposure, criticality and environment feed the ranking; the repository, provider and dependency files tell Quanta where a fix pull request goes.</p>
      <form id="ctx"><div class="form-grid">${FIELDS.map((f) => fieldHtml(f, a.context, lists)).join("")}</div>${admin ? '<p class="inline-actions"><button type="submit" class="btn-primary">Save context</button><button type="button" class="secondary-button" id="del">Remove application</button></p>' : '<p class="muted">Only an administrator can change this.</p>'}</form>
      <h3>SBOM</h3>
      ${a.sbom ? `<p>${escapeHtml(a.sbom.format)}, ${a.sbom.components} components, ${a.sbom.has_graph ? "with dependency edges" : "<strong>without dependency edges</strong>"}. Stored ${escapeHtml((a.sbom.uploaded_at || "").slice(0, 10))} by ${escapeHtml(a.sbom.uploaded_by || "?")} (${escapeHtml(a.sbom.source || "")}).</p>${(a.sbom.notes || []).map((n) => `<p class="callout callout-warn">${escapeHtml(n)}</p>`).join("")}` : '<p class="muted">None stored.</p>'}
      <p class="muted">CI can send one on every build: <code>curl -H "Authorization: Bearer $QUANTA_API_KEY" --data-binary @bom.json "…/api/ingest/sbom?application=${escapeHtml(a.application)}"</code> (an API key with the ingest:write scope).</p>
      ${admin ? `<div class="inline-actions"><label class="secondary-button" style="cursor:pointer">Upload CycloneDX or SPDX JSON<input type="file" id="sbomfile" accept=".json,application/json" hidden></label>
        <button type="button" class="secondary-button" id="gen">Generate from dependency files</button>
        <button type="button" class="secondary-button" id="osv"${a.sbom ? "" : " disabled"}>Check against public advisories (OSV)</button></div>
        <p class="muted">Generating reads the text you give it; Quanta never runs a package manager. A lock file (<code>package-lock.json</code>) gives the full tree; <code>requirements.txt</code>, <code>pom.xml</code> and <code>go.mod</code> give what is declared. The OSV check sends package URLs and versions to osv.dev, asks first, and creates findings from the advisories.</p>` : ""}`;
    const form = body.querySelector("#ctx");
    if (admin) {
      form.addEventListener("submit", async (e) => { e.preventDefault(); try { await api.applicationSave(a.application, readForm(form)); flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); } });
      body.querySelector("#del").addEventListener("click", async () => { if (window.confirm("Remove this application's record and SBOM? Its findings are not deleted.")) { try { await api.applicationDelete(a.application); go(null); } catch (err) { flash(err.message, "error"); } } });
      body.querySelector("#sbomfile").addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try { const r = await api.applicationSbomUpload(a.application, await file.text()); flash(`SBOM stored: ${r.components} components (${r.format}).`, "success"); show(); } catch (err) { flash(err.message, "error"); }
      });
      body.querySelector("#gen").addEventListener("click", () => {
        const m = openModal(`<h3>Generate an SBOM from dependency files</h3><p class="muted">Paste each file with its name. Supported: requirements.txt, package.json, package-lock.json, pom.xml, go.mod.</p><form id="gf"><div id="files"></div>
          <p class="inline-actions"><button type="button" class="secondary-button" id="more">Add another file</button><button type="submit" class="btn-primary">Generate and store</button></p></form>`);
        const add = () => { const d = document.createElement("div"); d.innerHTML = '<label>File name<input name="fname" placeholder="package-lock.json"></label><label>Contents<textarea name="ftext" rows="6"></textarea></label>'; m.querySelector("#files").appendChild(d); };
        add();
        m.querySelector("#more").addEventListener("click", add);
        m.querySelector("#gf").addEventListener("submit", async (e) => {
          e.preventDefault();
          const files = {};
          m.querySelectorAll("#files > div").forEach((d) => { const n = d.querySelector("[name=fname]").value.trim(); if (n) files[n] = d.querySelector("[name=ftext]").value; });
          try { const r = await api.applicationSbomGenerate(a.application, { files }); closeModal(); flash(`SBOM generated: ${r.components} components.${r.notes.length ? " " + r.notes[0] : ""}`, "success"); show(); } catch (err) { flash(err.message, "error"); }
        });
      });
      body.querySelector("#osv").addEventListener("click", async () => {
        try {
          const pre = await api.applicationOsvCheck(a.application, false);
          if (!window.confirm(`${pre.message}\n\n${pre.components} components. ${pre.sends}\n\nExample: ${pre.example.join(", ")}\n\nSend them to ${pre.service}?`)) return;
          const r = await api.applicationOsvCheck(a.application, true);
          flash(`${r.advisories} advisories found; ${r.added} finding(s) added, ${r.updated} updated, ${r.removed} cleared.`, "success"); show();
        } catch (err) { flash(err.message, "error"); }
      });
    } else form.querySelectorAll("input,select,textarea").forEach((el) => { el.disabled = true; });
  }

  async function prs(body, a) {
    const d = await api.gitopsProposals(a.application);
    body.innerHTML = `<p class="muted">Pull requests proposed for this application. Open the Fix pull requests page to review, approve and open them.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>#</th><th>Change</th><th>Status</th><th>Pull request</th></tr></thead><tbody>
      ${d.proposals.length ? d.proposals.map((p) => `<tr><td><a href="/fix-prs?id=${p.id}" data-link>${p.id}</a></td><td class="wrap-cell">${escapeHtml(p.title)}<br><span class="muted">${p.finding_ids.map(escapeHtml).join(", ")}</span></td><td>${escapeHtml(p.status)}</td>
        <td>${p.pr_url ? `<a href="${escapeHtml(p.pr_url)}" target="_blank" rel="noopener">${escapeHtml(p.pr_url)}</a>` : '<span class="muted">not opened</span>'}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">None yet. Use "Propose PR" on the Ranked work tab.</td></tr>'}</tbody></table></div>`;
  }

  async function show() {
    try { name ? await detail() : await list(); } catch (err) { container.innerHTML = `<p class="callout callout-warn">${escapeHtml(err.message)}</p>`; }
  }
  await show();
}
