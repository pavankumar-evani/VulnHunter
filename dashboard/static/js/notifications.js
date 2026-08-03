// System-notification feed: real, system-generated events computed from live data
// (SLA breaches, KEV-listed findings, expiring exceptions, pending generic-ingested
// findings - see dashboard_data.build_notifications()). This is deliberately NOT
// person-to-person messaging between users - there's no auth/user system yet for that
// to mean anything (see KNOWLEDGE_TRANSFER.md). "Read" state is tracked client-side in
// localStorage only, since there's no per-user server state to track it against; it's
// per-browser, not per-account.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";

const READ_KEY = "vulnhunter_read_notifications";
const CACHE_TTL_MS = 20000;
const READ_CHANGED_EVENT = "notifications-read-changed";

let cache = null; // { at, notifications }

function getReadIds() {
  try {
    return new Set(JSON.parse(localStorage.getItem(READ_KEY) || "[]"));
  } catch {
    return new Set();
  }
}

function saveReadIds(ids) {
  localStorage.setItem(READ_KEY, JSON.stringify([...ids]));
  window.dispatchEvent(new CustomEvent(READ_CHANGED_EVENT));
}

export function markRead(id) {
  const ids = getReadIds();
  ids.add(id);
  saveReadIds(ids);
}

export function markAllRead(notifications) {
  const ids = getReadIds();
  notifications.forEach((n) => ids.add(n.id));
  saveReadIds(ids);
}

export async function loadNotifications(force = false) {
  if (!force && cache && Date.now() - cache.at < CACHE_TTL_MS) return cache.notifications;
  const data = await api.notifications();
  cache = { at: Date.now(), notifications: data.notifications };
  return cache.notifications;
}

export function unreadCount(notifications) {
  const readIds = getReadIds();
  return notifications.filter((n) => !readIds.has(n.id)).length;
}

export function notificationItemHtml(n, { compact = false } = {}) {
  const readIds = getReadIds();
  const isRead = readIds.has(n.id);
  const body = `
      <span class="notif-category">${escapeHtml(n.category)}</span>
      <span class="notif-message">${escapeHtml(n.message)}</span>
      ${n.date ? `<span class="notif-date">${escapeHtml(n.date)}</span>` : ""}`;
  const classes = `notif-item notif-${n.severity}${isRead ? " notif-read" : ""}${compact ? " notif-compact" : ""}`;
  if (n.link) {
    return `<a class="${classes}" href="${n.link}" data-link data-notif-id="${escapeHtml(n.id)}">${body}</a>`;
  }
  return `<div class="${classes}" data-notif-id="${escapeHtml(n.id)}">${body}</div>`;
}

export function initNotificationBell() {
  const root = document.getElementById("topbar-notifications");
  if (!root || root.dataset.initialized) return;
  root.dataset.initialized = "true";

  root.innerHTML = `
    <div class="notif-bell-wrap">
      <button type="button" class="notif-bell" id="notif-bell-button" aria-label="Notifications">
        ${icon("bell", 18)}
        <span class="notif-badge" id="notif-badge" hidden>0</span>
      </button>
      <div class="search-dropdown notif-dropdown" id="notif-dropdown" hidden></div>
    </div>`;

  const button = root.querySelector("#notif-bell-button");
  const badge = root.querySelector("#notif-badge");
  const dropdown = root.querySelector("#notif-dropdown");

  async function refreshBadge() {
    const notifications = await loadNotifications();
    const count = unreadCount(notifications);
    badge.hidden = count === 0;
    badge.textContent = count > 9 ? "9+" : String(count);
  }

  async function renderDropdown() {
    const notifications = await loadNotifications();
    if (!notifications.length) {
      dropdown.innerHTML = `<div class="search-empty">No notifications - everything is on track.</div>`;
      return;
    }
    const top = notifications.slice(0, 8);
    dropdown.innerHTML = top.map((n) => notificationItemHtml(n, { compact: true })).join("") +
      `<a class="notif-view-all" href="/inbox" data-link>View all in Inbox</a>`;
  }

  button.addEventListener("click", async (e) => {
    e.stopPropagation();
    const opening = dropdown.hidden;
    dropdown.hidden = !opening;
    if (opening) await renderDropdown();
  });
  document.addEventListener("click", (e) => {
    if (!dropdown.hidden && !root.contains(e.target)) dropdown.hidden = true;
  });
  dropdown.addEventListener("click", (e) => {
    const item = e.target.closest("[data-notif-id]");
    if (item) {
      markRead(item.dataset.notifId);
      if (e.target.closest("[data-link]")) dropdown.hidden = true;
    }
  });
  window.addEventListener(READ_CHANGED_EVENT, refreshBadge);

  refreshBadge();
  setInterval(refreshBadge, CACHE_TTL_MS);
}
