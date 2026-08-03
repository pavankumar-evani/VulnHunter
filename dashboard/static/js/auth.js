// Client-side auth state helper - a thin wrapper over /api/auth/* (see
// dashboard/auth/ for the real PBKDF2 + signed-cookie-session + OIDC backend). The
// actual security boundary is server-side (see app.py's Depends(rbac.require_*) on
// sensitive routes); this module exists so the SPA can show/hide UI based on who's
// logged in, and gate client-side navigation to /login when nobody is.
import { api } from "./api.js";

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
      <a class="account-chip" href="/profile" data-link data-tooltip="${user.email} (${user.role})">
        <span class="account-avatar">${initials}</span>
      </a>`;
  }

  render();
  window.addEventListener("vulnhunter-auth-changed", render);
}
