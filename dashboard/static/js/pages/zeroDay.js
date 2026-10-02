import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Zero-day Watch";

const NOTE = "Vulnerabilities CISA has just confirmed are being exploited, in products your estate appears to run, that your scanners have not reported yet. A name match, not a version check: it tells you where to look first.";

export async function render(container) {
  let days = 30;
  async function show() {
    container.innerHTML = `<p class="subtitle">${NOTE}</p><p><label>Added in the last <select id="days">${[7, 14, 30, 90].map((d) => `<option value="${d}"${d === days ? " selected" : ""}>${d} days</option>`).join("")}</select></label></p><div id="zd">Loading...</div>`;
    container.querySelector("#days").addEventListener("change", (e) => { days = Number(e.target.value); show(); });
    const out = container.querySelector("#zd");
    try {
      const r = await api.zeroDayWatch(days);
      out.innerHTML = `<p>${r.catalog_entries_in_window} entries were added to the catalog in this window. ${r.already_tracked} are already findings in your queue; <strong>${r.total_matches}</strong> look like products you run and have no finding.</p>
        <div class="table-scroll"><table class="data-table"><thead><tr><th>CVE</th><th>Product</th><th>Added</th><th>Why it matched</th><th>Required action</th></tr></thead><tbody>
        ${r.items.length ? r.items.map((i) => `<tr><td class="wrap-cell"><strong>${escapeHtml(i.cve)}</strong> ${i.ransomware ? '<span class="badge badge-critical">ransomware</span>' : ""}<br><span class="muted">${escapeHtml(i.name || "")}</span></td>
          <td>${escapeHtml(i.vendor)} ${escapeHtml(i.product)}</td><td>${escapeHtml(i.date_added)}<br><span class="muted">due ${escapeHtml(i.due_date || "-")}</span></td>
          <td class="wrap-cell"><span class="muted">${i.matched_on.map(escapeHtml).join(", ")} (seen in ${i.seen_in.map(escapeHtml).join(", ")})</span></td><td class="wrap-cell">${escapeHtml(i.required_action || "")}</td></tr>`).join("")
          : '<tr><td colspan="5" class="empty-state">Nothing new matches your estate.</td></tr>'}</tbody></table></div><p class="muted">${escapeHtml(r.note)}</p>`;
    } catch (e) { out.innerHTML = `<p class="callout callout-warn">${escapeHtml(e.message)}</p>`; }
  }
  await show();
}
