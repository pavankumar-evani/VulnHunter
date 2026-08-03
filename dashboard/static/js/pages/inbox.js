import { loadNotifications, markAllRead, markRead, notificationItemHtml } from "../notifications.js";

export const title = "Inbox";

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const notifications = await loadNotifications(true);

  container.innerHTML = `
    <p class="subtitle">Real, system-generated events - SLA breaches, actively-exploited
    (CISA KEV) findings, expiring risk-acceptance exceptions, and pending generic-ingested
    findings. Not person-to-person messages - there's no user/auth system for that yet
    (see the <a href="/faq" data-link>FAQ</a>). "Read" is tracked in this browser only.</p>

    ${notifications.length ? `<button type="button" class="secondary-button" id="mark-all-read">Mark all read</button>` : ""}

    <div class="notif-list" id="notif-list">
      ${notifications.length
        ? notifications.map((n) => notificationItemHtml(n)).join("")
        : `<p class="empty-state">No notifications - everything is on track.</p>`}
    </div>`;

  const list = container.querySelector("#notif-list");
  list.addEventListener("click", (e) => {
    const item = e.target.closest("[data-notif-id]");
    if (item) markRead(item.dataset.notifId);
  });

  const markAllBtn = container.querySelector("#mark-all-read");
  if (markAllBtn) {
    markAllBtn.addEventListener("click", () => {
      markAllRead(notifications);
      list.querySelectorAll("[data-notif-id]").forEach((el) => el.classList.add("notif-read"));
    });
  }
}
