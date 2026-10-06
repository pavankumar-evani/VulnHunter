// Integrity tab of the Activity Log page (admin only): the code baseline, store consistency checks and the safe repairs.
// Read-only until an administrator previews a repair and then confirms it. See docs/INTEGRITY.md.
import { api } from "./api.js";
import { escapeHtml, flash } from "./dom.js";

const LEVEL = { ok: "badge-low", info: "badge-outline", warn: "badge-high", fail: "badge-critical" };

function fileList(label, items, note = "") {
  if (!items.length) return "";
  return `<p><strong>${escapeHtml(label)}</strong> (${items.length})${note ? ` <span class="muted">${escapeHtml(note)}</span>` : ""}</p>
    <ul style="margin:0 0 8px; padding-left:18px">${items.slice(0, 30).map((f) => `<li><code>${escapeHtml(f)}</code></li>`).join("")}${items.length > 30 ? `<li>... and ${items.length - 30} more</li>` : ""}</ul>`;
}

function manifestHtml(m) {
  const head = {
    "no-baseline": `<div class="callout"><strong>No baseline.</strong> ${escapeHtml(m.message)} Nothing can be said about whether the code is the released code.</div>`,
    ok: `<div class="callout"><strong>Matches the baseline.</strong> ${m.files_checked} tracked files checked against the manifest built ${escapeHtml((m.baseline || {}).generated_at || "")}.</div>`,
    "policy-changed": `<div class="callout"><strong>Policy files changed (expected).</strong> ${escapeHtml(m.message)}</div>`,
    "code-modified": `<div class="callout" style="border-color:#b91c1c"><strong>Application code differs from the baseline.</strong> ${escapeHtml(m.message)}</div>`,
  }[m.state] || "";
  const ed = m.policy.editors || {};
  const policyRows = [...m.policy.modified, ...m.policy.missing, ...m.policy.unexpected];
  return `${head}
    ${fileList("Code files modified", m.code.modified, "must not change")}
    ${fileList("Code files missing", m.code.missing)}
    ${fileList("Code files not in the baseline", m.code.unexpected)}
    ${policyRows.length ? `<p><strong>Policy files changed</strong> (${policyRows.length}) <span class="muted">expected to change; who is shown only where the activity log recorded it</span></p>
      <ul style="margin:0 0 8px; padding-left:18px">${policyRows.slice(0, 30).map((f) => `<li><code>${escapeHtml(f)}</code>${ed[f] ? ` - ${escapeHtml(ed[f].actor)} (${escapeHtml(ed[f].action)}, ${escapeHtml(ed[f].at)})` : ""}</li>`).join("")}</ul>` : ""}`;
}

export async function renderIntegrity(container) {
  container.innerHTML = `<div class="empty-state">Checking...</div>`;
  let report;
  try {
    report = await api.integrity();
  } catch (e) {
    container.innerHTML = `<div class="callout">The integrity report needs an administrator sign-in (${escapeHtml(e.message || "failed")}).</div>`;
    return;
  }
  const c = report.counts;
  container.innerHTML = `
    <p class="subtitle">Whether the running code matches the release, whether the stores are consistent, and the few repairs that are safe to make automatically. Nothing here changes anything until you preview a repair and confirm it; every repair is written to the activity log and no customer data is ever deleted.</p>
    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${escapeHtml(report.status)}</div><div class="kpi-label">Overall (${escapeHtml(report.checked_at)})</div></div>
      <div class="kpi-card"><div class="kpi-value">${c.fail}</div><div class="kpi-label">Failing</div></div>
      <div class="kpi-card"><div class="kpi-value">${c.warn}</div><div class="kpi-label">Warnings</div></div>
      <div class="kpi-card"><div class="kpi-value">${escapeHtml(report.code_state)}</div><div class="kpi-label">Code baseline</div></div>
    </div>
    <h3>Code baseline</h3>${manifestHtml(report.manifest)}
    <h3>Store and host checks</h3>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Check</th><th>Result</th><th>Detail</th><th>Repair</th></tr></thead><tbody>
      ${report.checks.map((k) => `<tr><td>${escapeHtml(k.title)}</td><td><span class="badge ${LEVEL[k.level]}">${escapeHtml(k.level)}</span></td>
        <td class="wrap-cell">${escapeHtml(k.detail)}${k.manual && (k.level === "warn" || k.level === "fail") ? `<br><span class="muted">Manual step: ${escapeHtml(k.manual)}</span>` : ""}</td>
        <td>${k.fix ? `<code>${escapeHtml(k.fix)}</code>` : "-"}</td></tr>`).join("")}
    </tbody></table></div>
    <h3>Safe repairs</h3>
    <p class="subtitle">${escapeHtml(Object.values(report.heal_actions).map((a) => a.title).join("; "))}.</p>
    <p><button type="button" id="heal-preview">Preview repairs</button> <button type="button" id="heal-confirm" class="secondary-button" disabled>Apply previewed repairs</button> <button type="button" id="integrity-refresh" class="secondary-button">Re-check</button></p>
    <div id="heal-result"></div>`;
  const out = container.querySelector("#heal-result");
  const applyBtn = container.querySelector("#heal-confirm");
  const show = (r) => {
    out.innerHTML = `<p><strong>${r.preview ? "Preview (nothing changed)" : "Applied"}</strong></p>
      <ul style="padding-left:18px">${r.results.map((x) => `<li><strong>${escapeHtml(x.title)}</strong>: ${escapeHtml(x.status)}${x.planned.length ? `<br><code>${escapeHtml(JSON.stringify(x.planned).slice(0, 400))}</code>` : ""}</li>`).join("")}</ul>
      ${r.manual.length ? `<p><strong>Needs a person</strong></p><ul style="padding-left:18px">${r.manual.map((m) => `<li>${escapeHtml(m.title)}: ${escapeHtml(m.manual)}</li>`).join("")}</ul>` : ""}`;
  };
  container.querySelector("#heal-preview").addEventListener("click", async () => {
    try {
      const r = await api.integrityHeal(false);
      show(r);
      applyBtn.disabled = !r.results.some((x) => x.planned.length);
    } catch (e) { flash(e.message || "Preview failed", "error"); }
  });
  applyBtn.addEventListener("click", async () => {
    if (!window.confirm("Apply the previewed repairs? Each one is recorded in the activity log.")) return;
    try {
      show(await api.integrityHeal(true));
      flash("Repairs applied.", "success");
      applyBtn.disabled = true;
    } catch (e) { flash(e.message || "Repair failed", "error"); }
  });
  container.querySelector("#integrity-refresh").addEventListener("click", () => renderIntegrity(container));
}
