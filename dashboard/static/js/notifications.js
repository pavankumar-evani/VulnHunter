// System-notification feed: real, system-generated events computed from live data
// (SLA breaches, KEV-listed findings, expiring exceptions, pending generic-ingested
// findings - see dashboard_data.build_notifications()). This is deliberately NOT
// person-to-person messaging between users - the auth/user system this app has doesn't
// extend to messaging anyone (see KNOWLEDGE_TRANSFER.md). "Read" state is tracked client-side in
// localStorage only, since there's no per-user server state to track it against; it's
// per-browser, not per-account.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { live } from "./live.js";
import { toast } from "./ui.js";

const READ_KEY = "quanta_read_notifications";
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

  let seen = null; // ids already known; the first load is a silent baseline so opening the app never toasts the whole backlog
  async function refreshBadge() {
    const notifications = await loadNotifications();
    if (seen) {
      const fresh = notifications.filter((n) => !seen.has(n.id) && n.severity === "danger");
      fresh.slice(0, 2).forEach((n) => toast(n.message, { tone: "bad", href: n.link || "/inbox", action: "Open" }));
      if (fresh.length > 2) toast(`${fresh.length - 2} more critical notifications`, { tone: "bad", href: "/inbox", action: "Inbox" });
    }
    seen = new Set(notifications.map((n) => n.id));
    const count = unreadCount(notifications);
    badge.hidden = count === 0;
    badge.textContent = count > 9 ? "9+" : String(count);
  }

  // Grouped by category (SLA, Threat intel, Exception ...), unread first inside each group, with a mark-all-read control.
  async function renderDropdown() {
    const notifications = await loadNotifications();
    if (!notifications.length) {
      dropdown.innerHTML = `<div class="search-empty">No notifications - everything is on track.</div>`;
      return;
    }
    const readIds = getReadIds();
    const groups = new Map();
    for (const n of notifications) {
      if (!groups.has(n.category)) groups.set(n.category, []);
      groups.get(n.category).push(n);
    }
    const unread = unreadCount(notifications);
    let shown = 0;
    const body = [...groups.entries()].map(([cat, list]) => {
      const sorted = [...list].sort((a, b) => Number(readIds.has(a.id)) - Number(readIds.has(b.id)));
      const take = sorted.slice(0, Math.max(0, 10 - shown));
      shown += take.length;
      if (!take.length) return "";
      return `<div class="notif-group-head" role="presentation">${escapeHtml(cat)} (${list.length})</div>` + take.map((n) => notificationItemHtml(n, { compact: true })).join("");
    }).join("");
    dropdown.innerHTML = `<div class="notif-tools"><span class="notif-live" data-mode="${live.state.mode}" title="${live.state.mode === "sse" ? "Live" : "Checking regularly"}">${unread} unread</span><button type="button" id="notif-mark-all"${unread ? "" : " disabled"}>Mark all read</button></div>` +
      body + `<a class="notif-view-all" href="/inbox" data-link>View all in Inbox</a>`;
    const markAll = dropdown.querySelector("#notif-mark-all");
    if (markAll) markAll.addEventListener("click", (ev) => { ev.stopPropagation(); markAllRead(notifications); renderDropdown(); });
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
  // Live: any recorded activity or notification event re-checks straight away; otherwise a slow, backing-off poll (live.js pauses it in a hidden tab).
  const recheck = () => { cache = null; refreshBadge().catch(() => {}); };
  live.subscribe("activity", recheck);
  live.subscribe("notifications", recheck);
  live.poll("notifications.poll", async () => { const n = await loadNotifications(true); return n.map((x) => x.id); }, { every: 30000 });
  live.subscribe("notifications.poll", () => refreshBadge().catch(() => {}));
}
