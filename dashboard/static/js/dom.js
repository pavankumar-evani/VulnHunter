// Small shared DOM helpers used by every page module. Kept dependency-free (no
// framework, no build step) - see dashboard/README.md for why.

export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// Renders a transient message into the persistent #flash-container (which lives
// in the shell, outside #app, so it survives page-to-page re-renders).
export function flash(message, category = "info") {
  const container = document.getElementById("flash-container");
  if (!container) return;
  const el = document.createElement("div");
  el.className = `flash flash-${category}`;
  el.textContent = message;
  container.prepend(el);
  setTimeout(() => el.remove(), 8000);
}

// A minimal modal, used by the AI-assist panel. Lives in #modal-root (in the
// shell, outside #app) so it isn't wiped out by a page re-render.
export function openModal(bodyHtml) {
  const root = document.getElementById("modal-root");
  root.innerHTML = `
    <div class="modal-backdrop" id="modal-backdrop">
      <div class="modal-card" role="dialog" aria-modal="true">
        <button type="button" class="modal-close" id="modal-close" aria-label="Close">&times;</button>
        <div class="modal-body">${bodyHtml}</div>
      </div>
    </div>`;
  const backdrop = document.getElementById("modal-backdrop");
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(); });
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.addEventListener("keydown", onEscape);
  return root.querySelector(".modal-body");
}

function onEscape(e) {
  if (e.key === "Escape") closeModal();
}

export function closeModal() {
  const root = document.getElementById("modal-root");
  if (root) root.innerHTML = "";
  document.removeEventListener("keydown", onEscape);
}

// Formats "Xs/Xm ago" for the live-refresh indicators.
export function timeAgo(date) {
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.floor(seconds / 60)}m ago`;
}
