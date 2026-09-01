// Shared "Columns ▾" picker for wide data tables (queue.js's finding table has 22
// columns today - the screenshot behind this module's existence showed exactly that
// kind of table with far more columns visible than useful at once). Same
// pure-functions-plus-one-wire-call convention as export.js/pagination.js: this module
// owns no page state itself, just a small per-table localStorage record of which
// column ids the user last chose to see - a real subtractive filter (hidden columns
// are `display:none`, not just narrower), so it helps at any viewport, not only wide
// screens.
import { escapeHtml } from "./dom.js";

const STORAGE_PREFIX = "vulnhunter-columns:";

// `columns` is [{id, label, defaultVisible}] - defaultVisible defaults to true, so a
// caller only needs to mark the ones that should start hidden.
export function loadVisibleColumns(tableId, columns) {
  const known = new Set(columns.map((c) => c.id));
  try {
    const stored = localStorage.getItem(STORAGE_PREFIX + tableId);
    if (stored) {
      const ids = JSON.parse(stored);
      if (Array.isArray(ids)) return new Set(ids.filter((id) => known.has(id)));
    }
  } catch {
    // Corrupt/old localStorage value - fall through to the column list's own defaults.
  }
  return new Set(columns.filter((c) => c.defaultVisible !== false).map((c) => c.id));
}

function save(tableId, visible) {
  localStorage.setItem(STORAGE_PREFIX + tableId, JSON.stringify([...visible]));
}

// A native <details>/<summary> disclosure, not a hand-rolled popover - the browser
// gives open/close-on-click for free with zero JS state, same convention faq.js's own
// <details class="faq-item"> already uses elsewhere in this app. It doesn't auto-close
// on an outside click (unlike the tenant/notification dropdowns), which is an
// acceptable, common pattern for a settings-style checkbox menu - the tradeoff buys
// real simplicity: see wireColumnPicker() below for why that matters here.
export function columnPickerHtml(tableId, columns, visible) {
  return `
    <details class="column-picker" data-column-picker="${tableId}">
      <summary class="secondary-button">Columns ▾</summary>
      <div class="column-picker-menu">
        ${columns.map((c) => `
          <label class="checkbox-label">
            <input type="checkbox" data-column-id="${c.id}" ${visible.has(c.id) ? "checked" : ""}>
            ${escapeHtml(c.label)}
          </label>`).join("")}
      </div>
    </details>`;
}

// Toggles every [data-col="<id>"] element under tableRoot (both the <th>s in a static
// header and the <td>s a row-render function emits) to match `visible`. Call once
// after the header renders, and again after every row re-render, since row cells are
// recreated each time - cheap enough (one querySelectorAll + style write per column)
// that there's no need to special-case "did visibility actually change."
export function applyColumnVisibility(tableRoot, visible) {
  if (!tableRoot) return;
  tableRoot.querySelectorAll("[data-col]").forEach((el) => {
    el.style.display = visible.has(el.dataset.col) ? "" : "none";
  });
}

// Call once every time the picker's own HTML (from columnPickerHtml() above) has just
// been inserted into `container` - same call-site convention as wireExportButtons() in
// export.js (found fresh via querySelector, listener attached directly to that
// element). Some pages call this only once per page visit (findingsTable.js's
// consumers); others rebuild their whole table shell repeatedly (queue.js's 20s
// auto-refresh, assets.js's post-mutation re-render) and so call this again each time -
// either is safe, because the listener lives on `root` itself, which is torn down and
// recreated together with the rest of that shell, not on `container` or `document`
// (which would otherwise accumulate a duplicate listener on every repeated call).
export function wireColumnPicker(container, tableId, onChange) {
  const root = container.querySelector(`[data-column-picker="${tableId}"]`);
  if (!root) return;
  root.addEventListener("change", (e) => {
    const checkbox = e.target.closest("[data-column-id]");
    if (!checkbox) return;
    const visible = new Set(
      [...root.querySelectorAll("[data-column-id]:checked")].map((el) => el.dataset.columnId),
    );
    save(tableId, visible);
    onChange(visible);
  });
}
