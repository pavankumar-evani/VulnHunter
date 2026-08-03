import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "/vulnhunt — Code Scan Results";

// A coarse, honest categorization by CWE - matches .claude/agents/vuln-scanner.md's own
// "What to look for" taxonomy (Injection / Secrets / Auth-Crypto / Insecure Config).
// Unmapped CWEs (e.g. container/dependency findings without one of these IDs) fall back
// to "Other" rather than guessing.
const CWE_CATEGORY = {
  "CWE-89": "Injection", "CWE-78": "Injection", "CWE-95": "Injection", "CWE-502": "Injection",
  "CWE-79": "Injection", "CWE-611": "Injection", "CWE-98": "Injection",
  "CWE-798": "Secrets",
  "CWE-256": "Auth/Crypto", "CWE-347": "Auth/Crypto",
  "CWE-489": "Insecure Config", "CWE-1321": "Insecure Config", "CWE-276": "Insecure Config",
};

function categoryFor(cwe) {
  if (!cwe) return "Other";
  const key = cwe.split(/[,\s]/)[0];
  return CWE_CATEGORY[key] || "Other";
}

function rowHtml(f) {
  return `
    <tr>
      <td>${escapeHtml(f.ID)}</td>
      <td>${escapeHtml(f.Title)}</td>
      <td><span class="badge badge-${(f.Severity || "").toLowerCase()}">${escapeHtml(f.Severity)}</span></td>
      <td>${escapeHtml(f._category)}</td>
      <td>${escapeHtml(f.CWE)}</td>
      <td><code>${escapeHtml(f.File)}</code></td>
      <td>${f["Auto-fixable?"] === "Yes"
        ? `<span class="badge badge-auto_approvable">Yes</span>`
        : `<span class="badge badge-manual_only">No</span>`}</td>
    </tr>`;
}

export async function render(container) {
  const vh = await api.vulnhunt();

  if (!vh.available) {
    container.innerHTML = `<p class="empty-state">
      No scan results found yet. Run <code>/vulnhunt &lt;path&gt; --fix</code> in Claude Code,
      or use the <a href="/run" data-link>Run Pipeline</a> page.
    </p>`;
    return;
  }

  const findings = vh.findings.map((f) => ({ ...f, _category: categoryFor(f.CWE) }));
  const categories = [...new Set(findings.map((f) => f._category))].sort();
  const filters = { severity: "all", category: "all" };

  container.innerHTML = `
    <p class="subtitle">${escapeHtml(vh.title)} &middot; branch <code>${escapeHtml(vh.branch)}</code></p>

    <div class="filter-bar">
      <label>Severity
        <select id="f-severity">
          <option value="all">All</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </label>
      <label>Category
        <select id="f-category">
          <option value="all">All</option>
          ${categories.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="scan-count"></span>
    </div>

    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Category</th><th>CWE</th><th>File</th><th>Auto-fixable?</th></tr></thead>
        <tbody id="scan-body"></tbody>
      </table>
    </div>`;

  const tbody = container.querySelector("#scan-body");
  const countEl = container.querySelector("#scan-count");

  function renderRows() {
    const filtered = findings.filter((f) =>
      (filters.severity === "all" || f.Severity === filters.severity) &&
      (filters.category === "all" || f._category === filters.category));
    tbody.innerHTML = filtered.length
      ? filtered.map(rowHtml).join("")
      : `<tr><td colspan="7" class="empty-state">No findings match the current filters.</td></tr>`;
    countEl.textContent = `${filtered.length} of ${findings.length} finding(s)`;
  }

  container.querySelector("#f-severity").addEventListener("change", (e) => { filters.severity = e.target.value; renderRows(); });
  container.querySelector("#f-category").addEventListener("change", (e) => { filters.category = e.target.value; renderRows(); });
  renderRows();
}
