// Global search: lives in the topbar (outside #app, like #flash-container and
// #modal-root) so it survives client-side page navigation instead of being wiped out
// by each page's render(). Real, live-as-you-type predictions (debounced, no
// fabricated suggestions - every result is an actual match against already-loaded real
// data) across three real sources - Code Scan (/api/vulnhunt), the Remediation Queue
// (/api/queue), and Asset Inventory (/api/assets) - by ID, title, CVE, or asset name,
// linking each result into the matching page with a `?highlight=<id>` deep link that
// page scrolls to and highlights (see queue.js/vulnhunt.js), or straight to /assets for
// an asset match.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";

const MAX_RESULTS_PER_SOURCE = 5;
const CACHE_TTL_MS = 20000;

let cache = null; // { at: Date, vulnhunt: [...], queue: [...], assets: [...] }

async function loadIndex() {
  if (cache && Date.now() - cache.at < CACHE_TTL_MS) return cache;
  const [vh, queue, assetsData] = await Promise.all([api.vulnhunt(), api.queue(), api.assetsList()]);
  cache = {
    at: Date.now(),
    vulnhunt: vh.available ? vh.findings : [],
    queue: queue.findings,
    assets: assetsData.assets,
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

  const assets = index.assets
    .filter((a) => matches([a.name, a.type, a.owner, a.team], query))
    .slice(0, MAX_RESULTS_PER_SOURCE)
    .map((a) => ({
      href: `/assets?highlight=${encodeURIComponent(a.name)}`,
      source: "Assets", id: a.name, title: a.type, tag: a.risk_tier,
    }));

  return [...codeScan, ...queue, ...assets];
}

// Wraps the first case-insensitive match of `query` within `text` in <mark> so the
// dropdown visually shows *why* a result matched, not just that it did - the
// underlying match logic (matches(), above) is unchanged, this only affects display.
function highlightMatch(text, query) {
  const safe = escapeHtml(String(text || ""));
  const idx = safe.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return safe;
  return safe.slice(0, idx) + "<mark>" + safe.slice(idx, idx + query.length) + "</mark>" + safe.slice(idx + query.length);
}

function resultsHtml(results, query) {
  if (!results.length) {
    return `<div class="search-empty">No matches for "${escapeHtml(query)}" in Code Scan or the Remediation Queue.</div>`;
  }
  let lastSource = null;
  return results.map((r) => {
    const header = r.source !== lastSource
      ? `<div class="search-source-header">${escapeHtml(r.source)}</div>` : "";
    lastSource = r.source;
    return `${header}
    <a class="search-result" href="${r.href}" data-link>
      <span class="search-result-id">${escapeHtml(r.id)}</span>
      <span class="search-result-title">${highlightMatch(r.title, query)}</span>
      ${r.tag ? `<span class="badge badge-${String(r.tag).toLowerCase().replace(/\s+/g, "_")}">${escapeHtml(r.tag)}</span>` : ""}
    </a>`;
  }).join("");
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

  // Keyboard navigation over the real rendered results - ArrowDown/ArrowUp move a
  // visual "active" selection, Enter follows it (or the first result if none is yet
  // selected). Pure UI convenience over the same searchResults() output; it changes
  // nothing about what matches.
  function activeResults() {
    return [...dropdown.querySelectorAll(".search-result")];
  }

  function setActive(index) {
    const results = activeResults();
    results.forEach((el) => el.classList.remove("search-result-active"));
    if (!results.length) return;
    const clamped = Math.max(0, Math.min(index, results.length - 1));
    const el = results[clamped];
    el.classList.add("search-result-active");
    el.scrollIntoView({ block: "nearest" });
  }

  input.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runSearch, 200);
  });
  input.addEventListener("focus", () => { if (input.value.trim().length >= 2) dropdown.hidden = false; });
  // A short delay lets a click on a result register before the dropdown hides on blur.
  input.addEventListener("blur", () => { setTimeout(() => { dropdown.hidden = true; }, 150); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { input.blur(); dropdown.hidden = true; return; }
    if (dropdown.hidden) return;
    const results = activeResults();
    if (!results.length) return;
    const currentIndex = results.findIndex((el) => el.classList.contains("search-result-active"));
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive(currentIndex + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive(currentIndex - 1);
    } else if (e.key === "Enter" && currentIndex !== -1) {
      e.preventDefault();
      results[currentIndex].click();
    }
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
