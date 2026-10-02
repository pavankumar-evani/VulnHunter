import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Access Governance";

const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const NOTE = "Who has access to what, and whether they should: leavers who still have access, dormant and unowned accounts, separation-of-duties conflicts, and periodic reviews where each manager certifies or revokes their people's access. Quanta records the decisions; your identity team removes the access.";

export async function render(container) {
  let admin = false;
  let me = "";
  try { const u = (await api.authMe()).user || {}; admin = u.role === "admin"; me = u.email || ""; } catch { admin = false; }
  const TABS = admin ? [["overview", "Overview"], ["campaigns", "Access reviews"], ["mine", "My reviews"], ["precheck", "Pre-check"], ["import", "Import"]] : [["mine", "My reviews"], ["precheck", "Pre-check"]];
  let tab = new URLSearchParams(window.location.search).get("tab") || TABS[0][0];
  if (!TABS.find(([k]) => k === tab)) tab = TABS[0][0];
  let openCampaign = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="iam-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; openCampaign = null; show(); }));
  };

  async function overview() {
    const o = await api.iamOverview(), s = o.summary;
    shell(`<div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">people / entitlements</div><div class="kpi-value">${s.people} / ${s.entitlements}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">critical findings</div><div class="kpi-value">${s.by_severity.Critical}</div></div>
        <div class="kpi-card"><div class="kpi-label">privileged entitlements</div><div class="kpi-value">${s.privileged}</div></div>
        <div class="kpi-card"><div class="kpi-label">HR roster</div><div class="kpi-value">${s.roster_loaded ? "loaded" : "not loaded"}</div></div></div>
      ${s.entitlements ? "" : '<p class="callout">Nothing imported yet. Use Import to load an export from your identity provider, directory or ERP.</p>'}
      ${s.roster_loaded ? "" : '<p class="muted">Load an HR roster to find access that outlived the job and accounts nobody owns.</p>'}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>Person</th><th>Finding</th><th>What to do</th></tr></thead><tbody>
      ${o.findings.length ? o.findings.map((f) => `<tr><td><span class="badge ${SEV[f.severity]}">${f.severity}</span><br><span class="muted">${f.id}</span></td><td>${escapeHtml(f.user)}</td>
        <td class="wrap-cell"><strong>${escapeHtml(f.title)}</strong><br><span class="muted">${escapeHtml(f.detail)}</span></td><td class="wrap-cell">${escapeHtml(f.recommendation)}</td></tr>`).join("") : '<tr><td colspan="4" class="empty-state">No findings.</td></tr>'}</tbody></table></div>`);
  }

  async function campaigns() {
    if (openCampaign) return campaignDetail();
    const { campaigns: cs } = await api.iamCampaigns();
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Review</th><th>Status</th><th>Due</th><th>Progress</th><th>Revocations</th><th></th></tr></thead><tbody>
      ${cs.length ? cs.map((c) => `<tr><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.status)}</td><td>${escapeHtml(c.due_date)}</td><td>${c.decided} of ${c.total} (${c.pct}%)${c.unassigned ? `<br><span class="muted">${c.unassigned} have no reviewer</span>` : ""}</td><td>${c.revoke}</td>
        <td><button type="button" class="link-button" data-open="${c.id}">Open</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No access reviews yet.</td></tr>'}</tbody></table></div>
      <h3>Start a review</h3>
      <form id="cf" class="run-form"><label>Name <input name="name" required placeholder="Q4 privileged access"></label><label>Due <input name="due" type="date" required></label>
        <label>Systems (comma separated, blank for all) <input name="systems" placeholder="SAP, AD"></label><label><input type="checkbox" name="priv"> Privileged entitlements only</label>
        <div><button type="submit">Create</button></div></form>`);
    container.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { openCampaign = Number(b.dataset.open); show(); }));
    container.querySelector("#cf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const c = await api.iamCampaignAdd({ name: f.name.value, due_date: f.due.value, privileged_only: f.priv.checked, systems: f.systems.value.split(",").map((x) => x.trim()).filter(Boolean) }); flash(`${c.total} entitlement(s) to review.`, "success"); openCampaign = c.id; show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function campaignDetail() {
    const c = await api.iamCampaign(openCampaign);
    shell(`<p><button type="button" class="link-button" id="back">&larr; All reviews</button></p><h3>${escapeHtml(c.name)} <span class="badge badge-outline">${escapeHtml(c.status)}</span></h3>
      <p>${c.decided} of ${c.total} decided: ${c.certified} certified, ${c.revoke} to revoke. Due ${escapeHtml(c.due_date)}. ${c.status === "open" ? '<button type="button" class="secondary-button" id="close">Close the review</button>' : ""}
        <a style="color:var(--brand-accent)" href="#" id="rev">Show what to revoke</a></p><div id="revbox"></div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Person</th><th>Access</th><th>Reviewer</th><th>Decision</th>${c.status === "open" ? "<th></th>" : ""}</tr></thead><tbody>
      ${c.items.map((i) => `<tr><td>${escapeHtml(i.entitlement.user)}</td><td class="wrap-cell">${escapeHtml(i.entitlement.entitlement)} on ${escapeHtml(i.entitlement.system)}${i.entitlement.privileged ? ' <span class="badge badge-high">privileged</span>' : ""}<br><span class="muted">last used ${escapeHtml(i.entitlement.last_login || "never")}</span></td>
        <td>${escapeHtml(i.reviewer)}</td><td>${i.decision ? escapeHtml(i.decision) + "<br><span class='muted'>" + escapeHtml(i.note || "") + "</span>" : "-"}</td>
        ${c.status === "open" ? `<td>${i.decision ? "" : `<button type="button" class="link-button" data-re="${i.id}">Reassign</button> <button type="button" class="link-button" data-ok="${i.id}">Certify</button> <button type="button" class="link-button danger-link" data-no="${i.id}">Revoke</button>`}</td>` : ""}</tr>`).join("")}</tbody></table></div>`);
    container.querySelector("#back").addEventListener("click", () => { openCampaign = null; show(); });
    const cl = container.querySelector("#close");
    if (cl) cl.addEventListener("click", async () => { if (window.confirm("Close this review? Undecided items stay undecided.")) { try { await api.iamClose(c.id); show(); } catch (e) { flash(e.message, "error"); } } });
    container.querySelector("#rev").addEventListener("click", async (e) => {
      e.preventDefault();
      const r = await api.iamRevocations(c.id);
      container.querySelector("#revbox").innerHTML = r.revocations.length ? `<ul class="guidance-list">${r.revocations.map((x) => `<li>${escapeHtml(x.user)}: ${escapeHtml(x.entitlement)} on ${escapeHtml(x.system)} (decided by ${escapeHtml(x.decided_by)}: ${escapeHtml(x.note)})</li>`).join("")}</ul><p class="muted">${escapeHtml(r.note)}</p>` : '<p class="muted">Nothing to revoke so far.</p>';
    });
    const decide = (id, decision) => async () => {
      const note = decision === "revoke" ? window.prompt("Why should this access be removed? (required)") : "";
      if (decision === "revoke" && !note) return;
      try { await api.iamDecide(id, { decision, note: note || "" }); show(); } catch (e) { flash(e.message, "error"); }
    };
    container.querySelectorAll("[data-ok]").forEach((b) => b.addEventListener("click", decide(Number(b.dataset.ok), "certify")));
    container.querySelectorAll("[data-no]").forEach((b) => b.addEventListener("click", decide(Number(b.dataset.no), "revoke")));
    container.querySelectorAll("[data-re]").forEach((b) => b.addEventListener("click", async () => { const r = window.prompt("Reviewer's email"); if (r) { try { await api.iamReassign(Number(b.dataset.re), { reviewer: r }); show(); } catch (e) { flash(e.message, "error"); } } }));
  }

  async function mine() {
    const { reviews } = await api.iamMyReviews();
    shell(reviews.length ? reviews.map((r) => `<h3>${escapeHtml(r.campaign.name)} <span class="muted">due ${escapeHtml(r.campaign.due_date)}</span></h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Person</th><th>Access</th><th>Last used</th><th></th></tr></thead><tbody>
      ${r.items.map((i) => `<tr><td>${escapeHtml(i.entitlement.user)}</td><td class="wrap-cell">${escapeHtml(i.entitlement.entitlement)} on ${escapeHtml(i.entitlement.system)}${i.entitlement.privileged ? ' <span class="badge badge-high">privileged</span>' : ""}</td><td>${escapeHtml(i.entitlement.last_login || "never")}</td>
        <td>${i.decision ? escapeHtml(i.decision) : `<button type="button" data-ok="${i.id}">Still needed</button> <button type="button" class="secondary-button" data-no="${i.id}">Remove</button>`}</td></tr>`).join("")}</tbody></table></div>`).join("")
      : '<p class="empty-state">Nothing is waiting for your review.</p>');
    const decide = (id, decision) => async () => {
      const note = decision === "revoke" ? window.prompt("Why should this access be removed? (required)") : "";
      if (decision === "revoke" && !note) return;
      try { await api.iamDecide(id, { decision, note: note || "" }); flash("Recorded.", "success"); show(); } catch (e) { flash(e.message, "error"); }
    };
    container.querySelectorAll("[data-ok]").forEach((b) => b.addEventListener("click", decide(Number(b.dataset.ok), "certify")));
    container.querySelectorAll("[data-no]").forEach((b) => b.addEventListener("click", decide(Number(b.dataset.no), "revoke")));
  }

  async function precheck() {
    shell(`<p class="muted">Before granting access, check whether it would give someone a conflicting pair of duties or add privilege.</p>
      <form id="pf" class="run-form"><label>Person <input name="user" required placeholder="alice@company.com"></label><label>System <input name="system" required placeholder="SAP"></label>
        <label>Entitlement <input name="entitlement" required placeholder="Release Payment Run"></label><div><button type="submit">Check</button></div></form><div id="pout"></div>`);
    container.querySelector("#pf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        const r = await api.iamPrecheck({ user: f.user.value, system: f.system.value, entitlement: f.entitlement.value });
        container.querySelector("#pout").innerHTML = `<h3>${escapeHtml(r.verdict)}</h3>${r.already_held ? "<p>They already hold this.</p>" : ""}${r.privileged ? "<p>This looks like privileged access.</p>" : ""}
          ${r.conflicts.length ? `<ul class="guidance-list">${r.conflicts.map((c) => `<li><span class="badge ${SEV[c.severity]}">${c.severity}</span> ${escapeHtml(c.name)} - conflicts with ${escapeHtml(c.conflicts_with)}</li>`).join("")}</ul>` : "<p>No conflict found in the access Quanta has loaded for this person.</p>"}`;
      } catch (err) { flash(err.message, "error"); }
    });
  }

  async function importTab() {
    shell(`<p class="muted">Load entitlements (user, system, role or group, last login, status, manager) as CSV or JSON from your identity provider, directory or ERP security report. Importing again from the same source replaces what it sent before. Optionally load an HR roster (user, status, manager, department, end date) to find leavers who still have access.</p>
      <form id="ef" class="run-form"><label>Source name <input name="source" required placeholder="okta, sap, active-directory"></label><label>Entitlements file <input type="file" name="file" required></label><div><button type="submit">Import</button></div></form>
      <form id="rf" class="run-form"><label>HR roster (CSV) <input type="file" name="file" required></label><div><button type="submit">Load roster</button></div></form>
      <p><button type="button" class="link-button danger-link" id="clear">Remove everything loaded</button></p>`);
    container.querySelector("#ef").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const r = await api.iamImport(f.source.value, await f.file.files[0].text()); flash(`${r.rows} entitlement(s) loaded (${r.replaced} replaced).`, "success"); tab = "overview"; show(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#rf").addEventListener("submit", async (e) => {
      e.preventDefault();
      try { const r = await api.iamRoster(await e.target.file.files[0].text()); flash(`${r.people} people in the roster.`, "success"); tab = "overview"; show(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#clear").addEventListener("click", async () => { if (window.confirm("Remove all entitlements and the roster from Quanta? Reviews already created are kept.")) { try { await api.iamClear(); show(); } catch (e) { flash(e.message, "error"); } } });
  }

  async function show() {
    try { await { overview, campaigns, mine, precheck, import: importTab }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  void me;
  await show();
}
