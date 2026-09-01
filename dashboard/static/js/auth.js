// Client-side auth state helper - a thin wrapper over /api/auth/* (see
// dashboard/auth/ for the real PBKDF2 + signed-cookie-session + OIDC backend). The
// actual security boundary is server-side (see app.py's Depends(rbac.require_*) on
// sensitive routes); this module exists so the SPA can show/hide UI based on who's
// logged in, and gate client-side navigation to /login when nobody is.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";

let cachedUser; // undefined = not yet fetched, null = fetched and logged out

export async function getCurrentUser(force = false) {
  if (!force && cachedUser !== undefined) return cachedUser;
  try {
    const data = await api.authMe();
    cachedUser = data.user;
  } catch {
    cachedUser = null;
  }
  return cachedUser;
}

export function setCurrentUser(user) {
  cachedUser = user;
}

// Clicking the account avatar opens a small popover (name/email/role, a link to the
// full /profile page, and log out) instead of navigating away - /profile itself still
// works as a direct, bookmarkable full-page route for the change-password form. The
// popover reuses the exact open/close/outside-click pattern notifications.js already
// established for the bell dropdown (see its initNotificationBell()), styled via the
// same .search-dropdown panel class plus .account-dropdown's own rules.
export function initAccountChip() {
  const root = document.getElementById("topbar-account");
  if (!root) return;

  async function render() {
    const user = await getCurrentUser();
    if (!user) {
      root.innerHTML = "";
      return;
    }
    const initials = (user.name || user.email).split(/\s+/).map((p) => p[0]).slice(0, 2).join("").toUpperCase();
    root.innerHTML = `
      <div class="account-chip-wrap">
        <button type="button" class="account-chip" id="account-chip-button"
          data-tooltip="${escapeHtml(user.email)} (${escapeHtml(user.role)})">
          <span class="account-avatar">${escapeHtml(initials)}</span>
        </button>
        <div class="search-dropdown account-dropdown" id="account-dropdown" hidden>
          <div class="account-dropdown-header">
            <div class="account-dropdown-name">${escapeHtml(user.name || user.email)}</div>
            <div class="account-dropdown-email">${escapeHtml(user.email)}</div>
            <div class="account-dropdown-role">${escapeHtml(user.role)}</div>
          </div>
          <a class="account-dropdown-item" href="/profile" data-link id="account-dropdown-profile">Profile &amp; change password</a>
          <button type="button" class="account-dropdown-item danger" id="account-dropdown-logout">Log out</button>
        </div>
      </div>`;

    const button = root.querySelector("#account-chip-button");
    const dropdown = root.querySelector("#account-dropdown");

    button.addEventListener("click", (e) => {
      e.stopPropagation();
      dropdown.hidden = !dropdown.hidden;
    });
    document.addEventListener("click", (e) => {
      if (!dropdown.hidden && !root.contains(e.target)) dropdown.hidden = true;
    });
    root.querySelector("#account-dropdown-profile").addEventListener("click", () => { dropdown.hidden = true; });
    root.querySelector("#account-dropdown-logout").addEventListener("click", async () => {
      dropdown.hidden = true;
      await api.authLogout();
      setCurrentUser(null);
      window.dispatchEvent(new CustomEvent("vulnhunter-auth-changed"));
      window.history.pushState({}, "", "/logout");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
  }

  render();
  window.addEventListener("vulnhunter-auth-changed", render);
}
