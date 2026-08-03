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
