// Global search: lives in the topbar (outside #app, like #flash-container and
// #modal-root) so it survives client-side page navigation instead of being wiped out
// by each page's render(). Searches across the two real finding data sources - Code
// Scan (/api/vulnhunt) and the Remediation Queue (/api/queue) - by ID, title, CVE, or
// asset name, and links each result into the matching page with a `?highlight=<id>`
// deep link that page scrolls to and highlights (see queue.js/vulnhunt.js).
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";

const MAX_RESULTS_PER_SOURCE = 5;
const CACHE_TTL_MS = 20000;

let cache = null; // { at: Date, vulnhunt: [...], queue: [...] }

async function loadIndex() {
  if (cache && Date.now() - cache.at < CACHE_TTL_MS) return cache;
  const [vh, queue] = await Promise.all([api.vulnhunt(), api.queue()]);
  cache = {
    at: Date.now(),
    vulnhunt: vh.available ? vh.findings : [],
    queue: queue.findings,
  };
  return cache;
}

function matches(haystackParts, query) {
  const q = query.toLowerCase();
  return haystackParts.some((part) => String(part || "").toLowerCase().includes(q));
}

function searchResults(index, query) {
  const codeScan = index.vulnhunt
    .filter((f) => matches([f.ID, f.Title, f.CWE, f.File], query))
    .slice(0, MAX_RESULTS_PER_SOURCE)
    .map((f) => ({
      href: `/vulnhunt?highlight=${encodeURIComponent(f.ID)}`,
      source: "Code Scan", id: f.ID, title: f.Title, tag: f.Severity,
    }));

  const queue = index.queue
    .filter((f) => matches([f.id, f.title, f.cve, f.asset && f.asset.name], query))
    .slice(0, MAX_RESULTS_PER_SOURCE)
    .map((f) => ({
      href: `/queue?highlight=${encodeURIComponent(f.id)}`,
      source: "Queue", id: f.id, title: f.title, tag: f.priority,
    }));

  return [...codeScan, ...queue];
}

function resultsHtml(results, query) {
  if (!results.length) {
    return `<div class="search-empty">No matches for "${escapeHtml(query)}" in Code Scan or the Remediation Queue.</div>`;
  }
  return results.map((r) => `
    <a class="search-result" href="${r.href}" data-link>
      <span class="search-result-source">${escapeHtml(r.source)}</span>
      <span class="search-result-id">${escapeHtml(r.id)}</span>
      <span class="search-result-title">${escapeHtml(r.title)}</span>
      ${r.tag ? `<span class="badge badge-${String(r.tag).toLowerCase().replace(/\s+/g, "_")}">${escapeHtml(r.tag)}</span>` : ""}
    </a>`).join("");
}

export function initGlobalSearch() {
  const root = document.getElementById("topbar-search");
  if (!root || root.dataset.initialized) return; // survives router re-renders, init once
  root.dataset.initialized = "true";

  root.innerHTML = `
    <div class="global-search">
      ${icon("search", 16)}
      <input type="search" id="global-search-input" placeholder="Search findings by ID, title, CVE, or asset…" autocomplete="off">
      <div class="search-dropdown" id="global-search-dropdown" hidden></div>
    </div>`;

  const input = root.querySelector("#global-search-input");
  const dropdown = root.querySelector("#global-search-dropdown");
  let debounceTimer = null;

  async function runSearch() {
    const query = input.value.trim();
    if (query.length < 2) {
      dropdown.hidden = true;
      return;
    }
    dropdown.hidden = false;
    dropdown.innerHTML = `<div class="search-empty">Searching…</div>`;
    try {
      const index = await loadIndex();
      const results = searchResults(index, query);
      dropdown.innerHTML = resultsHtml(results, query);
    } catch (err) {
      dropdown.innerHTML = `<div class="search-empty">Search failed: ${escapeHtml(err.message || String(err))}</div>`;
    }
  }

  input.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runSearch, 200);
  });
  input.addEventListener("focus", () => { if (input.value.trim().length >= 2) dropdown.hidden = false; });
  // A short delay lets a click on a result register before the dropdown hides on blur.
  input.addEventListener("blur", () => { setTimeout(() => { dropdown.hidden = true; }, 150); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { input.blur(); dropdown.hidden = true; }
  });
  // Any in-app navigation (clicking a result) should clear the box for next time -
  // app.js's own click handler does the actual routing since results are [data-link].
  dropdown.addEventListener("click", (e) => {
    if (e.target.closest("[data-link]")) {
      input.value = "";
      dropdown.hidden = true;
    }
  });
}
