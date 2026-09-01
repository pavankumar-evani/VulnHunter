// Small "click to scroll" affordance for the sidebar nav (.side-nav) - it already has a
// native overflow-y:auto scrollbar (see style.css), but the native thumb is thin and
// easy to miss, especially with a plain desktop mouse (no trackpad/scroll wheel handy).
// Adds up/down chevron buttons above/below .side-nav that scroll it by a fixed step per
// click - shown only while the nav genuinely overflows, and only for the direction that
// still has room to scroll.
const SCROLL_STEP = 168; // roughly a couple of nav items per click

function updateChevronVisibility(sideNav, upBtn, downBtn) {
  const overflows = sideNav.scrollHeight - sideNav.clientHeight > 2;
  const atTop = sideNav.scrollTop <= 1;
  const atBottom = sideNav.scrollTop >= sideNav.scrollHeight - sideNav.clientHeight - 1;
  upBtn.classList.toggle("visible", overflows && !atTop);
  downBtn.classList.toggle("visible", overflows && !atBottom);
}

// Call every time nav.js's renderSidebar() rebuilds #sidebar's innerHTML (it calls this
// itself, right after setting it) - .side-nav and the two buttons are fresh elements
// each time, so attaching listeners directly to them here is safe on repeated calls,
// same convention as export.js's wireExportButtons(). Deliberately no window-level
// "resize" listener: that would attach to something that outlives this call and
// accumulate a duplicate on every navigation - renderSidebar() already re-runs (and so
// re-wires this) on every route change, which is enough to self-correct after a resize.
export function wireSidebarScroll() {
  const sideNav = document.querySelector(".side-nav");
  const upBtn = document.querySelector("[data-nav-scroll='up']");
  const downBtn = document.querySelector("[data-nav-scroll='down']");
  if (!sideNav || !upBtn || !downBtn) return;

  const refresh = () => updateChevronVisibility(sideNav, upBtn, downBtn);
  refresh();
  sideNav.addEventListener("scroll", refresh);

  upBtn.addEventListener("click", () => sideNav.scrollBy({ top: -SCROLL_STEP, behavior: "smooth" }));
  downBtn.addEventListener("click", () => sideNav.scrollBy({ top: SCROLL_STEP, behavior: "smooth" }));
}
