import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Zero-day Watch";

const NOTE = "Vulnerabilities CISA has just confirmed are being exploited, in products your estate appears to run, that your scanners have not reported yet. A name match, not a version check: it tells you where to look first.";

export async function render(container) {
  let days = 30;
  async function show() {
    container.innerHTML = `<p class="subtitle">${NOTE}</p><div id="cvd"></div><p><label>Added in the last <select id="days">${[7, 14, 30, 90].map((d) => `<option value="${d}"${d === days ? " selected" : ""}>${d} days</option>`).join("")}</select></label></p><div id="zd">Loading...</div>`;
    container.querySelector("#days").addEventListener("change", (e) => { days = Number(e.target.value); show(); });
    const out = container.querySelector("#zd");
    renderCvd(container.querySelector("#cvd"));
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

const CVD_NOTE = "Anthropic's public coordinated-vulnerability-disclosure feed (red.anthropic.com/2026/cvd). Read only; nothing about your estate is sent. A CVE match is exact; a name match is not a version check. Built against public docs and never run against the live feed: the payload schema is assumed, so check the first fetch.";

async function renderCvd(el) {
  async function draw() {
    let r;
    try { r = await api.cvdAdvisories(); } catch (e) { el.innerHTML = `<p class="callout callout-warn">${escapeHtml(e.message)}</p>`; return; }
    el.innerHTML = `<h3>Anthropic CVD feed</h3><p class="muted">${escapeHtml(CVD_NOTE)}</p>
      <p><button class="btn" id="cvd-test">Test connection</button> <button class="btn" id="cvd-fetch">Fetch feed</button> <span id="cvd-msg" class="muted"></span></p>
      <p>${r.total} stored advisories, ${r.with_cve} with a CVE, <strong>${r.matched}</strong> matching your estate.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Advisory</th><th>CVEs</th><th>Project</th><th>Severity</th><th>State</th><th>Match</th></tr></thead><tbody>
      ${r.matches.length ? r.matches.map((m) => `<tr><td class="wrap-cell"><a href="${escapeHtml(m.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(m.title || m.id)}</a><br><span class="muted">${escapeHtml(m.published)}</span></td>
        <td class="wrap-cell">${m.cves.map(escapeHtml).join(", ")}</td><td>${escapeHtml(m.vendor)} ${escapeHtml(m.product)}</td><td>${escapeHtml(m.severity || "-")}</td><td>${escapeHtml(m.state)}</td>
        <td class="wrap-cell">${m.match_basis.map(escapeHtml).join(" + ")}<br><span class="muted">${m.finding_ids.length ? "findings " + m.finding_ids.map(escapeHtml).join(", ") : m.matched_on.map(escapeHtml).join(", ")}</span></td></tr>`).join("")
        : '<tr><td colspan="6" class="empty-state">No stored advisory matches your estate (fetch the feed first if none are stored).</td></tr>'}</tbody></table></div><p class="muted">${escapeHtml(r.note)}</p>`;
    const msg = el.querySelector("#cvd-msg");
    el.querySelector("#cvd-test").addEventListener("click", async () => {
      try { await api.cvdTest(); msg.textContent = "The feed answered."; } catch (e) { msg.textContent = e.message; }
    });
    el.querySelector("#cvd-fetch").addEventListener("click", async () => {
      try {
        const p = await api.cvdFetch({ confirm: false });
        if (!window.confirm(p.message)) return;
        const res = await api.cvdFetch({ confirm: true });
        msg.textContent = `${res.fetched} fetched, ${res.new} new, ${res.updated} updated.`;
        draw();
      } catch (e) { msg.textContent = e.message; }
    });
  }
  await draw();
}
