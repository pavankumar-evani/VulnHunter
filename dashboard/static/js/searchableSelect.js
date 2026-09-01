// Progressively enhances a native <select> that has many options (e.g. one row per
// finding, thousands of them) into a type-to-filter combobox - same interaction model
// as commandPalette.js (type, arrow keys, Enter, Escape). The native <select> stays in
// the DOM (visually hidden, not display:none, so it keeps its layout box and any
// existing `form.fieldName.value` read or `.addEventListener("change", ...)` on it
// keeps working with zero changes at the call site - this only replaces how a value
// gets INTO the select, never how the rest of the form reads it back out.
//
// Why this exists: a native <select> with thousands of long "ID - Title" options
// renders as an unstyleable OS popup (can't control row height, truncation, or
// max-height) and forces the user to scroll through everything with no way to search -
// exactly the overflow/visual problem reported on the AI Assist finding picker.

const MAX_VISIBLE_RESULTS = 150;

function optionLabel(optionEl) {
  return optionEl.textContent;
}

export function enhanceSelect(selectEl, { placeholder = "Type to search…" } = {}) {
  if (selectEl.dataset.enhanced === "true") return;
  selectEl.dataset.enhanced = "true";

  const options = Array.from(selectEl.options).map((o) => ({ value: o.value, label: optionLabel(o) }));
  const selected = options.find((o) => o.value === selectEl.value) || options[0];

  selectEl.classList.add("searchable-select-native");
  selectEl.setAttribute("aria-hidden", "true");
  selectEl.setAttribute("tabindex", "-1");

  const wrap = document.createElement("div");
  wrap.className = "searchable-select";
  wrap.innerHTML = `
    <input type="text" class="searchable-select-input" autocomplete="off" placeholder="${placeholder}"
           value="${selected ? selected.label.replace(/"/g, "&quot;") : ""}">
    <div class="searchable-select-results" hidden></div>`;
  selectEl.insertAdjacentElement("afterend", wrap);

  const input = wrap.querySelector(".searchable-select-input");
  const resultsEl = wrap.querySelector(".searchable-select-results");
  let filtered = options;
  let selectedIndex = Math.max(0, options.indexOf(selected));
  let open = false;

  function renderResults() {
    const shown = filtered.slice(0, MAX_VISIBLE_RESULTS);
    resultsEl.innerHTML = shown.length
      ? shown.map((o, i) => `
          <div class="searchable-select-item ${i === selectedIndex ? "active" : ""}" data-value="${o.value.replace(/"/g, "&quot;")}">
            ${o.label}
          </div>`).join("") +
        (filtered.length > MAX_VISIBLE_RESULTS
          ? `<div class="searchable-select-more">+ ${filtered.length - MAX_VISIBLE_RESULTS} more - keep typing to narrow down</div>`
          : "")
      : `<div class="searchable-select-empty">No matches</div>`;
    const activeEl = resultsEl.querySelector(".searchable-select-item.active");
    if (activeEl) activeEl.scrollIntoView({ block: "nearest" });
  }

  function openList() {
    if (open) return;
    open = true;
    resultsEl.hidden = false;
  }

  function closeList() {
    open = false;
    resultsEl.hidden = true;
  }

  function commit(option) {
    if (!option) return;
    selectEl.value = option.value;
    input.value = option.label;
    selectEl.dispatchEvent(new Event("change", { bubbles: true }));
    closeList();
  }

  function activate() {
    input.select();
    filtered = options;
    selectedIndex = Math.max(0, options.indexOf(options.find((o) => o.value === selectEl.value)));
    renderResults();
    openList();
  }

  // Both events are needed: "focus" covers tabbing/first click in; "click" covers a
  // user clicking back into a box that was already focused (e.g. to search again
  // after picking something), where a second click alone would not re-fire focus and
  // would otherwise just drop a caret into the middle of the previous label.
  input.addEventListener("focus", activate);
  input.addEventListener("click", activate);

  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    filtered = q ? options.filter((o) => o.label.toLowerCase().includes(q)) : options;
    selectedIndex = 0;
    renderResults();
    openList();
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeList();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!open) { openList(); return; }
      selectedIndex = Math.min(selectedIndex + 1, Math.min(filtered.length, MAX_VISIBLE_RESULTS) - 1);
      renderResults();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      renderResults();
    } else if (e.key === "Enter") {
      e.preventDefault();
      commit(filtered[selectedIndex]);
    }
  });

  resultsEl.addEventListener("mousedown", (e) => {
    const itemEl = e.target.closest(".searchable-select-item");
    if (!itemEl) return;
    e.preventDefault();
    commit(options.find((o) => o.value === itemEl.dataset.value));
  });

  document.addEventListener("click", (e) => {
    if (!wrap.contains(e.target)) closeList();
  });

  // If something else in the app changes the underlying select's value directly
  // (e.g. a future deep-link handler), keep the visible text box in sync.
  selectEl.addEventListener("change", () => {
    const match = options.find((o) => o.value === selectEl.value);
    if (match && input.value !== match.label) input.value = match.label;
  });
}
