// Renders the (illustrative demo) tenant switcher into the topbar's far-right slot -
// a custom popover (button + rounded-item dropdown), not a native <select>, so each
// tenant row can show its generated avatar and get a real hover/active highlight -
// a native <select>'s own dropdown can't render anything but plain option text and
// can't be styled at all. Same open/close/outside-click pattern already established
// by auth.js's account-chip popover and notifications.js's bell dropdown.
// tenant.js's own state logic (getTenant/setTenant/filterByTenant, and the
// "tenant-changed" event queue.js listens for) is untouched - only how the picker is
// drawn changed.
import { listTenants, getTenant, setTenant } from "./tenant.js";
import { icon } from "./icons.js";
import { escapeHtml } from "./dom.js";

// Generated-initials avatar (like GitHub/Slack show for an org with no uploaded logo) -
// these demo tenants aren't real companies, so this is the honest stand-in for a
// company logo, not a fabricated real one. "All Tenants" has no single logo, so it
// falls back to a generic tenant glyph.
function avatarHtml(tenant) {
  return tenant.initials
    ? `<span class="tenant-avatar" style="background:${tenant.avatarColor}">${escapeHtml(tenant.initials)}</span>`
    : `<span class="tenant-avatar tenant-avatar-generic" style="background:${tenant.avatarColor}">${icon("tenant", 14)}</span>`;
}

export function initTopbarTenant() {
  const root = document.getElementById("topbar-tenant");
  if (!root) return;

  // Registered once (not inside render()) so switching tenants - which re-renders -
  // never accumulates duplicate document-level listeners.
  document.addEventListener("click", (e) => {
    const dropdown = root.querySelector("#tenant-dropdown");
    if (dropdown && !dropdown.hidden && !root.contains(e.target)) dropdown.hidden = true;
  });

  render();

  function render() {
    const tenant = getTenant();
    const tenants = listTenants();

    root.innerHTML = `
      <div class="tenant-pill-wrap">
        <button type="button" class="tenant-pill" id="tenant-pill-button" aria-label="Switch tenant (demo)">
          ${avatarHtml(tenant)}
          <span class="tenant-pill-label">${escapeHtml(tenant.label)}</span>
          <span class="tenant-pill-caret">${icon("chevronDown", 12)}</span>
        </button>
        <div class="search-dropdown tenant-dropdown" id="tenant-dropdown" hidden>
          ${tenants.map((t) => `
            <button type="button" class="tenant-dropdown-item ${t.id === tenant.id ? "active" : ""}" data-tenant="${t.id}">
              ${avatarHtml(t)}
              <span class="tenant-dropdown-item-label">${escapeHtml(t.label)}</span>
            </button>`).join("")}
        </div>
      </div>`;

    root.querySelector("#tenant-pill-button").addEventListener("click", (e) => {
      e.stopPropagation();
      const dropdown = root.querySelector("#tenant-dropdown");
      dropdown.hidden = !dropdown.hidden;
    });
    root.querySelectorAll(".tenant-dropdown-item").forEach((item) => {
      item.addEventListener("click", () => {
        setTenant(item.dataset.tenant);
        render();
      });
    });
  }
}
