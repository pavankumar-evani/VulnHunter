import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Risk & Compliance";

const TABS = [["overview", "Overview"], ["controls", "Controls"], ["evidence", "Evidence"], ["risks", "Risk register"], ["policies", "Policies"]];
const STATUS = {
  satisfied: ["badge-auto_approvable", "Satisfied"], partially: ["badge-high", "Partly"], "not-satisfied": ["badge-critical", "Not satisfied"],
  "no-evidence": ["badge-outline", "No usable evidence"], "not-evidenced": ["badge-outline", "Not observed by Quanta"],
};
const RESULT = { pass: "badge-auto_approvable", fail: "badge-critical", warn: "badge-high", na: "badge-outline", error: "badge-critical" };
const LEVEL = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const NOTE = "Quanta supplies evidence and workflow. It does not certify compliance, and a passing test shows that Quanta observed something, not that an auditor would agree.";

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let framework = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="grc-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };

  async function overview() {
    const o = await api.grcOverview();
    shell(`<div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">control tests passing</div><div class="kpi-value">${o.evidence.pass}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">failing</div><div class="kpi-value">${o.evidence.fail}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">warnings</div><div class="kpi-value">${o.evidence.warn}</div></div>
        <div class="kpi-card"><div class="kpi-label">open risks (critical or high)</div><div class="kpi-value">${o.risks.by_level.Critical + o.risks.by_level.High}</div></div>
      </div>
      <p class="muted">${o.evidence_collected_at ? `Evidence last collected ${escapeHtml(o.evidence_collected_at)}.` : "No evidence has been collected yet."} <button type="button" class="link-button" id="run">Collect now</button></p>
      <h3>Frameworks</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Framework</th><th>Controls</th><th>Evidenced</th><th>Satisfied</th><th>Partly</th><th>Not satisfied</th><th>Not observed by Quanta</th></tr></thead><tbody>
      ${o.frameworks.map((f) => `<tr><td>${escapeHtml(f.name)}<br><span class="muted">${escapeHtml(f.source)}</span></td><td>${f.total}</td><td>${f.evidenced_pct === null ? "-" : f.evidenced_pct + "%"}</td>
        <td>${f.counts.satisfied}</td><td>${f.counts.partially}</td><td>${f.counts["not-satisfied"]}</td><td>${f.counts["not-evidenced"]}</td></tr>`).join("")}</tbody></table></div>
      <h3>Risk register</h3>
      <p>${o.risks.total} open &middot; ${o.risks.review_overdue} review(s) overdue &middot; ${o.risks.treatment_overdue} treatment(s) overdue &middot; ${o.risks.no_owner} without an owner &middot; ${o.risks.accepted} accepted.</p>`);
    container.querySelector("#run").addEventListener("click", async () => { try { await api.grcRunEvidence(); flash("Evidence collected.", "success"); show(); } catch (e) { flash(e.message, "error"); } });
  }

  async function controls() {
    const { frameworks } = await api.grcFrameworks();
    if (!framework || !frameworks.find((f) => f.id === framework)) framework = frameworks[0] && frameworks[0].id;
    const rep = framework ? await api.grcReport(framework) : null;
    shell(`<label>Framework <select id="fw">${frameworks.map((f) => `<option value="${escapeHtml(f.id)}"${f.id === framework ? " selected" : ""}>${escapeHtml(f.name)} (${f.control_count})</option>`).join("")}</select></label>
      ${rep ? `<p>${rep.evidenced} of ${rep.total} controls have evidence or a current attestation (${rep.evidenced_pct}%). <a style="color:var(--accent)" href="/api/grc/frameworks/${encodeURIComponent(framework)}/oscal">Download OSCAL assessment results</a></p>
      <p class="muted">${escapeHtml(rep.note)}</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Control</th><th>Status</th><th>Evidence</th><th>Attestation</th></tr></thead><tbody>
      ${rep.controls.map((c) => `<tr><td class="wrap-cell"><strong>${escapeHtml(c.control_id)}</strong> ${escapeHtml(c.title)}<br><span class="muted">${escapeHtml(c.family || "")}</span></td>
        <td><span class="badge ${STATUS[c.status][0]}">${STATUS[c.status][1]}</span></td>
        <td class="wrap-cell">${c.tests.length ? c.tests.map((t) => `<span class="badge ${RESULT[t.result]}">${escapeHtml(t.result)}</span> ${escapeHtml(t.title)}`).join("<br>") : '<span class="muted">none</span>'}</td>
        <td class="wrap-cell">${c.attestation ? `${escapeHtml(c.attestation.result)} by ${escapeHtml(c.attestation.attested_by)}${c.attestation.current ? "" : " (expired)"}<br><span class="muted">${escapeHtml(c.attestation.statement || "")}</span>` : ""}
          <br><button type="button" class="link-button" data-attest="${escapeHtml(c.control_id)}">Attest</button></td></tr>`).join("")}</tbody></table></div>` : ""}
      <h3>Import a full catalog</h3>
      <p class="muted">Upload NIST's official OSCAL JSON (SP 800-53, CSF) to work against every control. Licensed standards: import your licensed copy in OSCAL form.</p>
      <form id="imp" class="run-form"><label>Framework id <input name="id" required placeholder="nist-800-53-r5" pattern="[a-z0-9][a-z0-9-]{1,59}"></label>
        <label>Name <input name="name" placeholder="NIST SP 800-53 Rev. 5"></label><label>OSCAL catalog (JSON) <input type="file" name="file" accept=".json" required></label>
        <div><button type="submit">Import</button></div></form>`);
    const fw = container.querySelector("#fw");
    if (fw) fw.addEventListener("change", () => { framework = fw.value; show(); });
    container.querySelectorAll("[data-attest]").forEach((b) => b.addEventListener("click", async () => {
      const result = window.prompt("Is this control effective, partially-effective or ineffective?", "effective");
      if (!result) return;
      const statement = window.prompt("What does that rest on? (required)");
      if (!statement) return;
      try { await api.grcAttest(framework, b.dataset.attest, { result, statement }); flash("Attestation recorded.", "success"); show(); } catch (e) { flash(e.message, "error"); }
    }));
    container.querySelector("#imp").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { const r = await api.grcImportFramework(f.id.value, f.name.value, f.file.files[0]); flash(`${r.controls} controls imported.`, "success"); framework = r.id; show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function evidence() {
    const { tests } = await api.grcEvidence();
    shell(`<p><button type="button" id="run">Collect evidence now</button> <span class="muted">Collected automatically about once a day.</span></p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Test</th><th>Result</th><th>Measured</th><th>Threshold</th><th>What was seen</th><th>When</th></tr></thead><tbody>
      ${tests.length ? tests.map((t) => `<tr><td>${escapeHtml(t.title)}</td><td><span class="badge ${RESULT[t.result]}">${escapeHtml(t.result)}</span></td><td>${t.metric === null ? "-" : escapeHtml(String(t.metric))}</td>
        <td>${t.threshold === null ? "-" : escapeHtml(String(t.threshold))}</td><td class="wrap-cell">${escapeHtml(t.detail || "")}</td><td>${escapeHtml(t.collected_at)}</td></tr>`).join("") : `<tr><td colspan="6" class="empty-state">No evidence collected yet.</td></tr>`}</tbody></table></div>`);
    container.querySelector("#run").addEventListener("click", async () => { try { await api.grcRunEvidence(); show(); } catch (e) { flash(e.message, "error"); } });
  }

  async function risks() {
    const r = await api.grcRisks();
    shell(`<p>${r.summary.total} open &middot; ${r.summary.review_overdue} review(s) overdue &middot; ${r.summary.no_owner} without an owner</p>
      ${r.suggestions.length ? `<div class="callout"><strong>Worth registering</strong> (drawn from live findings and threat models)<ul class="guidance-list">${r.suggestions.map((s) => `<li>${escapeHtml(s.title)} <button type="button" class="link-button" data-sug="${escapeHtml(s.source)}|${escapeHtml(s.source_ref)}">Add to register</button></li>`).join("")}</ul></div>` : ""}
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Risk</th><th>Inherent</th><th>Residual</th><th>Owner</th><th>Status</th><th>Review</th><th></th></tr></thead><tbody>
      ${r.risks.length ? r.risks.map((k) => `<tr><td class="wrap-cell"><strong>${escapeHtml(k.title)}</strong><br><span class="muted">${escapeHtml(k.category || "")} &middot; from ${escapeHtml(k.source)}</span></td>
        <td><span class="badge ${LEVEL[k.inherent_level]}">${escapeHtml(k.inherent_level)}</span> ${k.inherent_score}</td>
        <td>${k.residual_level ? `<span class="badge ${LEVEL[k.residual_level]}">${escapeHtml(k.residual_level)}</span> ${k.residual_score}` : "-"}</td>
        <td>${escapeHtml(k.owner || "")}</td><td>${escapeHtml(k.status)}${k.treatment ? `<br><span class="muted">${escapeHtml(k.treatment)}</span>` : ""}</td>
        <td>${escapeHtml(k.review_date || "-")}${k.review_overdue ? ' <span class="badge badge-critical">overdue</span>' : ""}</td>
        <td><button type="button" class="link-button danger-link" data-del="${k.id}">Delete</button></td></tr>`).join("") : `<tr><td colspan="7" class="empty-state">The register is empty.</td></tr>`}</tbody></table></div>
      <h3>Add a risk</h3>
      <form id="rf" class="run-form"><label>Title <input name="title" required maxlength="200"></label><label>Owner <input name="owner" placeholder="name@company.com"></label>
        <label>Likelihood (1-5) <input name="inherent_likelihood" type="number" min="1" max="5" value="3" required></label><label>Impact (1-5) <input name="inherent_impact" type="number" min="1" max="5" value="3" required></label>
        <label>Treatment <select name="treatment"><option value="">(decide later)</option><option>mitigate</option><option>accept</option><option>transfer</option><option>avoid</option></select></label>
        <label>Plan or reason <input name="treatment_plan"></label><label>Review by <input name="review_date" type="date"></label><div><button type="submit">Add</button></div></form>`);
    container.querySelectorAll("[data-sug]").forEach((b) => b.addEventListener("click", async () => {
      const [source, source_ref] = b.dataset.sug.split("|");
      try { await api.grcRiskFromSuggestion({ source, source_ref }); show(); } catch (e) { flash(e.message, "error"); }
    }));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Delete this risk?")) return;
      try { await api.grcDeleteRisk(Number(b.dataset.del)); show(); } catch (e) { flash(e.message, "error"); }
    }));
    container.querySelector("#rf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, body = {};
      for (const el of f.elements) if (el.name && el.value !== "") body[el.name] = el.type === "number" ? Number(el.value) : el.value;
      try { await api.grcAddRisk(body); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function policies() {
    const { policies: ps } = await api.grcPolicies();
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Policy</th><th>Version</th><th>Status</th><th>Acknowledged</th><th></th></tr></thead><tbody>
      ${ps.length ? ps.map((p) => `<tr><td class="wrap-cell"><strong>${escapeHtml(p.title)}</strong><br><span class="muted">${escapeHtml(p.owner || "")}${p.review_overdue ? " &middot; review overdue" : ""}</span></td><td>${p.version}</td><td>${escapeHtml(p.status)}</td>
        <td>${p.ack_pct !== undefined ? (p.ack_pct === null ? "-" : p.ack_pct + "%") : (p.acknowledged_by_me ? "Yes" : "Not yet")}</td>
        <td>${p.status === "active" && p.acknowledged_by_me === false ? `<button type="button" data-ack="${p.id}">I have read this</button>` : ""}</td></tr>`).join("") : `<tr><td colspan="5" class="empty-state">No policies yet.</td></tr>`}</tbody></table></div>
      <h3>Add a policy</h3>
      <form id="pf" class="run-form"><label>Title <input name="title" required></label><label>Owner <input name="owner"></label><label>Status <select name="status"><option>draft</option><option>active</option></select></label>
        <label>Review by <input name="review_date" type="date"></label><label>Text <textarea name="body" rows="6" required></textarea></label><div><button type="submit">Add</button></div></form>`);
    container.querySelectorAll("[data-ack]").forEach((b) => b.addEventListener("click", async () => { try { await api.grcAckPolicy(Number(b.dataset.ack)); show(); } catch (e) { flash(e.message, "error"); } }));
    container.querySelector("#pf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try { await api.grcAddPolicy({ title: f.title.value, owner: f.owner.value, status: f.status.value, review_date: f.review_date.value || null, body: f.body.value }); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function show() {
    try { await { overview, controls, evidence, risks, policies }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
