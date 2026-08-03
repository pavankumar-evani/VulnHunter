import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "/vulnhunt — Code Scan Results";

export async function render(container) {
  const vh = await api.vulnhunt();

  if (!vh.available) {
    container.innerHTML = `<p class="empty-state">
      No scan results found yet. Run <code>/vulnhunt &lt;path&gt; --fix</code> in Claude Code,
      or use the <a href="/run" data-link>Run Pipeline</a> page.
    </p>`;
    return;
  }

  const rows = vh.findings.map((f) => `
    <tr>
      <td>${escapeHtml(f.ID)}</td>
      <td>${escapeHtml(f.Title)}</td>
      <td><span class="badge badge-${(f.Severity || "").toLowerCase()}">${escapeHtml(f.Severity)}</span></td>
      <td>${escapeHtml(f.CWE)}</td>
      <td><code>${escapeHtml(f.File)}</code></td>
      <td>${f["Auto-fixable?"] === "Yes"
        ? `<span class="badge badge-auto_approvable">Yes</span>`
        : `<span class="badge badge-manual_only">No</span>`}</td>
    </tr>`).join("");

  container.innerHTML = `
    <p class="subtitle">${escapeHtml(vh.title)} &middot; branch <code>${escapeHtml(vh.branch)}</code></p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CWE</th><th>File</th><th>Auto-fixable?</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}
