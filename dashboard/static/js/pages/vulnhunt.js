import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination, DEFAULT_PAGE_SIZE } from "../pagination.js";

export const title = "/vulnhunt — Code Scan Results";

const EXPORT_COLUMNS = [
  { label: "ID", value: (f) => f.ID },
  { label: "Title", value: (f) => f.Title },
  { label: "Severity", value: (f) => f.Severity },
  { label: "Category", value: (f) => f._category },
  { label: "CWE", value: (f) => f.CWE },
  { label: "File", value: (f) => f.File },
  { label: "Auto-fixable?", value: (f) => f["Auto-fixable?"] },
];

// A coarse, honest categorization by CWE - matches .claude/agents/vuln-scanner.md's own
// "What to look for" taxonomy (Injection / Secrets / Auth-Crypto / Insecure Config /
// Container / API). Unmapped CWEs with no other signal fall back to "Other" rather
// than guessing.
const CWE_CATEGORY = {
  "CWE-89": "Injection", "CWE-78": "Injection", "CWE-95": "Injection", "CWE-502": "Injection",
  "CWE-79": "Injection", "CWE-611": "Injection", "CWE-98": "Injection",
  "CWE-798": "Secrets",
  "CWE-256": "Auth/Crypto", "CWE-347": "Auth/Crypto",
  "CWE-489": "Insecure Config", "CWE-1321": "Insecure Config", "CWE-276": "Insecure Config",
  "CWE-250": "Container",
  "CWE-284": "API", "CWE-863": "API", "CWE-942": "API", "CWE-915": "API",
};

// A Dockerfile/compose finding with no CWE at all (e.g. "unpinned base image" has no
// CWE to assign) still deserves "Container" over the "Other" catch-all - this is a
// file-path signal, not a guess about the finding's actual nature, so it only applies
// when the CWE lookup above found nothing.
function isDockerFile(file) {
  return /^dockerfile\b|docker-compose/i.test(file || "");
}

export function categoryFor(cwe, file) {
  if (cwe) {
    const key = cwe.split(/[,\s]/)[0];
    if (CWE_CATEGORY[key]) return CWE_CATEGORY[key];
  }
  if (isDockerFile(file)) return "Container";
  return "Other";
}

function rowHtml(f) {
  return `
    <tr data-finding-id="${escapeHtml(f.ID)}">
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

  const findings = vh.findings.map((f) => ({ ...f, _category: categoryFor(f.CWE, f.File) }));
  const categories = [...new Set(findings.map((f) => f._category))].sort();
  // A nav deep-link (e.g. /vulnhunt?category=Secrets from the Security Domains menu) can
  // preselect the category filter on load.
  const requestedCategory = new URLSearchParams(window.location.search).get("category");
  const filters = { severity: "all", category: categories.includes(requestedCategory) ? requestedCategory : "all" };
  // A global-search result (search.js) deep-links here with ?highlight=<id> - the
  // matching row gets scrolled into view and visually marked once on load.
  const highlightId = new URLSearchParams(window.location.search).get("highlight");

  container.innerHTML = `
    <p class="subtitle">${escapeHtml(vh.title)} &middot; branch <code>${escapeHtml(vh.branch)}</code></p>

    <div id="highlight-note"></div>

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
          <option value="all" ${filters.category === "all" ? "selected" : ""}>All</option>
          ${categories.map((c) => `<option value="${escapeHtml(c)}" ${c === filters.category ? "selected" : ""}>${escapeHtml(c)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="scan-count"></span>
    </div>

    ${exportButtonsHtml("scan")}

    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Category</th><th>CWE</th><th>File</th><th>Auto-fixable?</th></tr></thead>
        <tbody id="scan-body"></tbody>
      </table>
    </div>
    <div id="scan-pagination"></div>`;

  const tbody = container.querySelector("#scan-body");
  const countEl = container.querySelector("#scan-count");
  let currentFiltered = findings;
  let page = 1;

  let hasScrolledToHighlight = false;

  function renderRows() {
    const filtered = findings.filter((f) =>
      (filters.severity === "all" || f.Severity === filters.severity) &&
      (filters.category === "all" || f._category === filters.category));
    currentFiltered = filtered;
    if (highlightId && !hasScrolledToHighlight) {
      const idx = filtered.findIndex((f) => f.ID === highlightId);
      if (idx !== -1) page = Math.floor(idx / DEFAULT_PAGE_SIZE) + 1;
    }
    const paged = paginate(filtered, page);
    page = paged.page;
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="7" class="empty-state">No findings match the current filters.</td></tr>`;
    countEl.textContent = `${filtered.length} of ${findings.length} finding(s)`;
    container.querySelector("#scan-pagination").innerHTML = paginationHtml(paged.page, paged.totalPages);

    if (highlightId) applyHighlight(filtered);
  }
  wirePagination(container, (p) => { page = p; renderRows(); });

  wireExportButtons(container, "scan", {
    getRows: () => currentFiltered,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-code-scan",
  });

  // Scrolls to and marks the finding a global-search result linked to (?highlight=<id>).
  // If the finding exists but the current severity/category filter hides it, says so
  // instead of silently showing nothing.
  function applyHighlight(filtered) {
    const noteEl = container.querySelector("#highlight-note");
    const row = container.querySelector(`[data-finding-id="${CSS.escape(highlightId)}"]`);
    if (row) {
      row.classList.add("row-highlight");
      if (!hasScrolledToHighlight) {
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        hasScrolledToHighlight = true;
      }
      if (noteEl) noteEl.innerHTML = "";
      return;
    }
    if (!noteEl) return;
    const existsAtAll = findings.some((f) => f.ID === highlightId);
    noteEl.innerHTML = existsAtAll
      ? `<div class="callout callout-warn">Finding <code>${escapeHtml(highlightId)}</code> exists but is hidden by ` +
        `the current filter selection above - clear filters to see it.</div>`
      : `<div class="callout callout-warn">Finding <code>${escapeHtml(highlightId)}</code> was not found.</div>`;
  }

  container.querySelector("#f-severity").addEventListener("change", (e) => { filters.severity = e.target.value; page = 1; renderRows(); });
  container.querySelector("#f-category").addEventListener("change", (e) => { filters.category = e.target.value; page = 1; renderRows(); });
  renderRows();
}
