// Real, working "arrange charts as you like" customization - drag any chart-block to
// reorder it within its own .chart-row/.chart-row-grid, and that order is remembered
// (effectively "pinning" your own layout) the next time this page loads. Honestly
// scoped: persisted via localStorage, so it's per-browser, not per-account or synced
// across devices - this app has no per-user settings store for dashboard layout today,
// and localStorage is the real, working option that doesn't need one. A block only
// ever moves within the row it started in (never across rows/sections) - rearranging
// within a row is a real, bounded interaction; letting a chart migrate to an unrelated
// section would raise "does the wrong data now sit under the wrong heading" questions
// this feature doesn't need to answer.
const STORAGE_PREFIX = "vulnhunter-chart-order:";

function loadAllOrders(pageKey) {
  try {
    const raw = localStorage.getItem(`${STORAGE_PREFIX}${pageKey}`);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {}; // private-mode/quota/parse failure - reordering still works this visit
  }
}

function saveOrder(pageKey, rowIndex, order) {
  try {
    const all = loadAllOrders(pageKey);
    all[rowIndex] = order;
    localStorage.setItem(`${STORAGE_PREFIX}${pageKey}`, JSON.stringify(all));
  } catch {
    // Not persisted this time (private mode/quota) - not fatal, just doesn't stick.
  }
}

// The block's own heading text is used as its identity key across reloads - simpler
// than adding a new data-attribute to every chart-block on every page, and every real
// chart-block already has a real, distinct <h3>.
function blockKey(block) {
  return block.querySelector("h3")?.textContent?.trim() || "";
}

// Restores any previously-saved order for each row, then makes every real chart-block
// (not a .chart-block-link card - those are plain navigation links, and native
// drag-and-drop on an <a> conflicts with the browser's own "drag this link" gesture)
// drag-reorderable within its own row. Call once, after a page's real markup
// (including every .chart-row/.chart-row-grid) is in the DOM.
export function makeChartsReorderable(container, pageKey) {
  const rows = [...container.querySelectorAll(".chart-row, .chart-row-grid")];
  const savedOrders = loadAllOrders(pageKey);

  rows.forEach((row, rowIndex) => {
    const saved = savedOrders[rowIndex];
    if (saved) {
      const byKey = new Map([...row.children].map((b) => [blockKey(b), b]));
      saved.forEach((key) => {
        const b = byKey.get(key);
        if (b) row.appendChild(b); // moves to the end, in saved order - real DOM reorder
      });
    }

    const draggableBlocks = [...row.children].filter((b) => b.tagName !== "A");
    draggableBlocks.forEach((block) => {
      block.classList.add("chart-block-draggable");
      block.setAttribute("draggable", "true");
      if (!block.querySelector(".chart-drag-handle")) {
        const handle = document.createElement("span");
        handle.className = "chart-drag-handle";
        handle.title = "Drag to rearrange - remembered in this browser only";
        handle.textContent = "⠿";
        block.prepend(handle);
      }
    });
    if (!draggableBlocks.length) return;

    let dragged = null;
    row.addEventListener("dragstart", (e) => {
      const block = e.target.closest(".chart-block-draggable");
      if (!block) return;
      dragged = block;
      block.classList.add("chart-block-dragging");
      e.dataTransfer.effectAllowed = "move";
    });
    row.addEventListener("dragend", () => {
      if (dragged) dragged.classList.remove("chart-block-dragging");
      dragged = null;
      saveOrder(pageKey, rowIndex, [...row.children].map(blockKey));
    });
    row.addEventListener("dragover", (e) => {
      if (!dragged) return;
      e.preventDefault();
      const target = e.target.closest(".chart-block-draggable");
      if (!target || target === dragged) return;
      const rect = target.getBoundingClientRect();
      const before = (e.clientX - rect.left) < rect.width / 2;
      row.insertBefore(dragged, before ? target : target.nextSibling);
    });
  });
}
