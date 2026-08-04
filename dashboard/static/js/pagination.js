// Reusable client-side pagination - a page-size-aware slicer plus a rendered page bar
// (Prev / 1 2 3 … N / Next). This module owns no state of its own; the current page
// number lives in the calling page's own closure, same pattern as sort/filter state
// elsewhere in this app (see queue.js). Event wiring uses delegation on the page's
// outer container so it only needs to be attached once, even though the pagination
// bar's own DOM gets replaced on every re-render.
export const DEFAULT_PAGE_SIZE = 15;

export function paginate(rows, page, pageSize = DEFAULT_PAGE_SIZE) {
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const clampedPage = Math.min(Math.max(1, page), totalPages);
  const start = (clampedPage - 1) * pageSize;
  return {
    rows: rows.slice(start, start + pageSize),
    page: clampedPage,
    totalPages,
    totalRows: rows.length,
  };
}

export function paginationHtml(page, totalPages) {
  if (totalPages <= 1) return "";
  // A bounded window of page numbers around the current page, plus first/last with
  // ellipses in between - avoids rendering a button per page on a huge table.
  const windowSize = 2;
  const pages = new Set([1, totalPages]);
  for (let p = page - windowSize; p <= page + windowSize; p++) {
    if (p >= 1 && p <= totalPages) pages.add(p);
  }
  const sorted = [...pages].sort((a, b) => a - b);

  let buttons = "";
  let prevPage = 0;
  for (const p of sorted) {
    if (p - prevPage > 1) buttons += `<span class="pagination-ellipsis">…</span>`;
    buttons += `<button type="button" class="pagination-page ${p === page ? "active" : ""}" data-page="${p}">${p}</button>`;
    prevPage = p;
  }

  return `
    <div class="pagination-bar">
      <button type="button" class="pagination-nav" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹ Prev</button>
      ${buttons}
      <button type="button" class="pagination-nav" data-page="${page + 1}" ${page >= totalPages ? "disabled" : ""}>Next ›</button>
    </div>`;
}

// Call once per page render() call (not per re-render) - delegates on the page's
// outer container, so it keeps working even though the pagination bar itself is
// replaced on every renderRows()-style re-render.
export function wirePagination(container, onPageChange) {
  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".pagination-page, .pagination-nav");
    if (!btn || btn.disabled) return;
    onPageChange(Number(btn.dataset.page));
  });
}
