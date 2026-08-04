// Read-only "finding detail" modal, opened by clicking a finding ID anywhere findings
// are listed (queue.js today; appsec/infrastructure/aiVulnerabilities hub tables can
// reuse it too). Reuses the same openModal/closeModal pattern as assets.js's edit-owner
// modal (see dom.js) - this one just renders, it never submits anything.
import { escapeHtml, openModal, closeModal } from "./dom.js";

function row(label, valueHtml) {
  if (valueHtml === null || valueHtml === undefined || valueHtml === "") return "";
  return `<tr><th>${escapeHtml(label)}</th><td>${valueHtml}</td></tr>`;
}

export function openFindingDetail(f) {
  const kev = f.kev && f.kev.listed
    ? `<span class="badge badge-critical">KEV-listed</span>` +
      (f.kev.vulnerability_name ? ` — ${escapeHtml(f.kev.vulnerability_name)}` : "") +
      (f.kev.due_date ? `<br><span class="muted">CISA remediation due ${escapeHtml(f.kev.due_date)}</span>` : "")
    : (f.kev ? `<span class="muted">Not KEV-listed</span>` : `<span class="muted">—</span>`);

  const epss = f.epss
    ? `${(f.epss.score * 100).toFixed(1)}% exploit probability (${(f.epss.percentile * 100).toFixed(0)}th percentile)`
    : `<span class="muted">—</span>`;

  let sla = `<span class="muted">—</span>`;
  if (f.sla && f.sla.due_date) {
    sla = f.sla.breached
      ? `<span class="sla-breached">${escapeHtml(f.sla.due_date)} (breached)</span>`
      : `<span class="sla-ok">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d remaining)</span>`;
  }

  const attack = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) =>
        `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join(" ")
    : null;

  const exception = f.exception
    ? `Risk-accepted until <strong>${escapeHtml(f.exception.expires_on)}</strong> — ${escapeHtml(f.exception.reason)}`
    : null;

  const asset = f.asset || {};

  const body = `
    <h2>${escapeHtml(f.title)}</h2>
    <p class="subtitle">
      <span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority || "—")}</span>
      &nbsp;<code>${escapeHtml(f.id)}</code>
      ${f.scan_type_label ? `&nbsp;<span class="category-tag">${escapeHtml(f.scan_type_label)}</span>` : ""}
    </p>

    ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ""}

    <div class="table-scroll">
      <table class="data-table finding-detail-table">
        <tbody>
          ${row("Source", f.source ? `${escapeHtml(f.source)}${f.source_ref ? ` <span class="muted">(${escapeHtml(f.source_ref)})</span>` : ""}` : null)}
          ${row("Severity", f.severity ? escapeHtml(f.severity) : null)}
          ${row("CVE", f.cve ? `<code>${escapeHtml(f.cve)}</code>` : null)}
          ${row("CVSS", f.cvss !== undefined && f.cvss !== null ? escapeHtml(String(f.cvss)) : null)}
          ${row("CISA KEV", kev)}
          ${row("EPSS", epss)}
          ${row("MITRE ATT&CK", attack)}
          ${row("Asset", asset.name ? `${escapeHtml(asset.name)}${asset.ip ? ` <span class="muted">(${escapeHtml(asset.ip)})</span>` : ""}` : null)}
          ${row("Asset type", asset.type ? escapeHtml(asset.type) : null)}
          ${row("OS", asset.os ? escapeHtml(asset.os) : null)}
          ${row("First seen", f.first_seen ? escapeHtml(f.first_seen) : null)}
          ${row("Last seen", f.last_seen ? escapeHtml(f.last_seen) : null)}
          ${row("SLA due", sla)}
          ${row("Exception", exception)}
        </tbody>
      </table>
    </div>

    ${f.recommended_fix ? `
      <h3>Recommended fix</h3>
      <p>${escapeHtml(f.recommended_fix)}</p>` : ""}

    <p class="subtitle" style="margin-top:16px">
      <a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link>Ask AI about this finding</a>
      &nbsp;·&nbsp;
      <a href="/remediate" data-link>See it in the remediation plan</a>
    </p>`;

  const modalBody = openModal(body);
  // The two links above navigate away via app.js's document-level [data-link]
  // handler - close the modal first so it doesn't stay open over the new page.
  modalBody.querySelectorAll("a[data-link]").forEach((a) => {
    a.addEventListener("click", () => closeModal());
  });
}
