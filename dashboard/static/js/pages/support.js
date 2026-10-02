import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";

export const title = "Support";

const KINDS = [["bug", "Something isn't working"], ["question", "A question"], ["feature", "A feature request"],
  ["access", "Access or account"], ["other", "Something else"]];
const SEVERITIES = [["low", "Low"], ["normal", "Normal"], ["high", "High"], ["urgent", "Urgent"]];
const STATUS_LABEL = { open: "Open", in_progress: "In progress", waiting_on_requester: "Waiting on requester",
  resolved: "Resolved", closed: "Closed" };

const opts = (pairs, selected) => pairs.map(([v, l]) =>
  `<option value="${v}"${v === selected ? " selected" : ""}>${escapeHtml(l)}</option>`).join("");

function pill(status) {
  return `<span class="badge badge-outline">${escapeHtml(STATUS_LABEL[status] || status)}</span>`;
}

function ticketRows(tickets, isAdmin) {
  if (!tickets.length) return `<tr><td colspan="${isAdmin ? 7 : 5}" class="empty">No tickets yet.</td></tr>`;
  return tickets.map((t) => `<tr>
    <td><a href="#" data-ticket="${escapeHtml(t.ref)}">${escapeHtml(t.ref)}</a></td>
    <td>${escapeHtml(t.subject)}</td>
    <td>${escapeHtml(t.kind)}</td>
    <td>${escapeHtml(t.severity)}</td>
    <td>${pill(t.status)}</td>
    ${isAdmin ? `<td>${escapeHtml(t.requester_email)}</td><td>${escapeHtml(t.assignee_email || "-")}</td>` : ""}
  </tr>`).join("");
}

export async function render(container) {
  let me = null;
  try { me = (await api.authMe()).user; } catch { me = null; }

  container.innerHTML = `
    <p class="subtitle">Open a ticket and your administrators triage it here, in your own
    deployment - nothing is sent to a public tracker. Your tickets, and the replies to
    them, stay in this system's database under the same access controls as everything else.</p>

    <div class="callout" style="margin-bottom:18px">
      <strong>Looking for how to do something specific?</strong> Try
      <a href="/ask" data-link>Ask Quanta</a> first - type your question in plain
      English and it searches this app's own How-To content live, at no cost. It is not a
      chatbot and never guesses.
    </div>

    <div id="support-tickets"></div>

    <h2>Before you open a ticket</h2>
    <ul>
      <li><a href="/faq" data-link>FAQ</a> - direct answers about what this does and doesn't do</li>
      <li><span class="doc-ref">User &amp; Operations Guide</span> - how-to answers for every real workflow</li>
      <li><span class="doc-ref">Full enterprise documentation suite</span> - architecture, connectors, RBAC, pricing, and more</li>
      <li><strong>Security issue in Quanta itself:</strong> do not file a ticket - see
        <code>SECURITY.md</code> for the private disclosure contact.</li>
    </ul>

    <h2>Known limitations (read before reporting these as bugs)</h2>
    <ul>
      <li>Reads stay open by default even though real login/RBAC exists - mutations
        (admin settings, connector actions, approvals) require a real session, but anyone
        who can reach this port can view findings unless
        <code>QUANTA_REQUIRE_LOGIN_FOR_READS=true</code> is set. Don't expose this beyond
        localhost or a trusted network without setting it.</li>
      <li>Record stores live in a single local database; there is no historical trend view.</li>
      <li>The tenant switcher in the sidebar is a UI-only demo, not real per-tenant
        authentication or data isolation.</li>
      <li>Vendor connectors are built against each vendor's public API docs and tested
        against simulated responses - not yet exercised against a live vendor tenant.</li>
    </ul>`;

  const host = container.querySelector("#support-tickets");
  if (!me) {
    host.innerHTML = `<div class="callout"><a href="/login" data-link>Sign in</a> to open a ticket or see your tickets.</div>`;
    return;
  }

  async function refresh() {
    const data = await api.supportTickets();
    const isAdmin = data.is_admin;
    const s = data.summary;
    host.innerHTML = `
      <h2>Open a ticket</h2>
      <form id="ticket-form" class="run-form" style="max-width:720px;margin-bottom:22px">
        <label>Type <select name="kind">${opts(KINDS, "question")}</select></label>
        <label>Severity <select name="severity">${opts(SEVERITIES, "normal")}</select></label>
        <label>Subject <input name="subject" maxlength="200" required></label>
        <label>What happened, and what did you expect?
          <textarea name="description" rows="5" maxlength="8000" required
            placeholder="Include the page or command, the exact error, and what you expected."></textarea></label>
        <div><button type="submit">Submit ticket</button></div>
      </form>
      <h2>${isAdmin ? "Support queue" : "My tickets"}</h2>
      ${isAdmin ? `<div class="kpi-grid" style="margin-bottom:12px">
        <div class="kpi-card"><div class="kpi-label">Open</div><div class="kpi-value">${s.open}</div></div>
        <div class="kpi-card"><div class="kpi-label">Unassigned</div><div class="kpi-value">${s.unassigned_open}</div></div>
        <div class="kpi-card"><div class="kpi-label">Urgent</div><div class="kpi-value">${s.urgent_open}</div></div>
        <div class="kpi-card"><div class="kpi-label">Total</div><div class="kpi-value">${s.total}</div></div></div>` : ""}
      <div class="table-scroll"><table class="data-table">
        <thead><tr><th>Ref</th><th>Subject</th><th>Type</th><th>Severity</th><th>Status</th>
        ${isAdmin ? "<th>Requester</th><th>Assignee</th>" : ""}</tr></thead>
        <tbody>${ticketRows(data.tickets, isAdmin)}</tbody></table></div>`;

    host.querySelector("#ticket-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const t = await api.createSupportTicket(Object.fromEntries(f.entries()));
        flash(`Ticket ${t.ref} opened.`, "success");
        await refresh();
      } catch (err) { flash(err.message, "error"); }
    });
    host.querySelectorAll("[data-ticket]").forEach((a) => a.addEventListener("click", (e) => {
      e.preventDefault();
      showTicket(a.dataset.ticket, data, refresh);
    }));
  }

  await refresh();
}

async function showTicket(ref, listData, refresh) {
  const isAdmin = listData.is_admin;
  let t;
  try { t = await api.supportTicket(ref); } catch (err) { flash(err.message, "error"); return; }

  const body = openModal("");
  const draw = (t) => {
    const comments = t.comments.map((c) => `<div class="comment${c.internal ? " comment-internal" : ""}">
      <div class="meta">${escapeHtml(c.author_email)} &middot; ${escapeHtml(c.created_at)}${c.internal ? " &middot; <strong>internal note</strong>" : ""}</div>
      <div>${escapeHtml(c.body).replaceAll("\n", "<br>")}</div></div>`).join("") || "<p>No replies yet.</p>";
    body.innerHTML = `
      <h2>${escapeHtml(t.ref)} - ${escapeHtml(t.subject)}</h2>
      <p>${pill(t.status)} &nbsp; ${escapeHtml(t.kind)} &middot; ${escapeHtml(t.severity)} &middot;
        from ${escapeHtml(t.requester_email)} &middot; opened ${escapeHtml(t.created_at)}</p>
      <p>${escapeHtml(t.description).replaceAll("\n", "<br>")}</p>
      ${t.resolution ? `<div class="callout"><strong>Resolution:</strong> ${escapeHtml(t.resolution)}</div>` : ""}
      <h3>Conversation</h3>${comments}
      <form id="comment-form" style="margin-top:10px">
        <textarea name="body" rows="3" maxlength="8000" required placeholder="Write a reply"></textarea>
        ${isAdmin ? `<label><input type="checkbox" name="internal"> Internal note (not shown to the requester)</label>` : ""}
        <div><button class="secondary-button" type="submit">Reply</button></div>
      </form>
      ${isAdmin ? `<h3>Triage</h3>
      <form id="triage-form" class="run-form">
        <label>Status <select name="status">${opts(Object.entries(STATUS_LABEL), t.status)}</select></label>
        <label>Severity <select name="severity">${opts(SEVERITIES, t.severity)}</select></label>
        <label>Assignee (email) <input name="assignee_email" value="${escapeHtml(t.assignee_email || "")}"></label>
        <label>Resolution <textarea name="resolution" rows="2">${escapeHtml(t.resolution || "")}</textarea></label>
        <div><button type="submit">Save</button>
          ${listData.escalation_configured ? `<button class="secondary-button" type="button" id="escalate">Escalate to vendor by email</button>` : ""}</div>
      </form>` : ""}`;

    body.querySelector("#comment-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        draw(await api.commentSupportTicket(t.ref, { body: f.get("body"), internal: f.get("internal") === "on" }));
        refresh();
      } catch (err) { flash(err.message, "error"); }
    });
    const triage = body.querySelector("#triage-form");
    if (triage) {
      triage.addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = new FormData(e.target);
        const assignee = (f.get("assignee_email") || "").trim();
        try {
          draw(await api.updateSupportTicket(t.ref, {
            status: f.get("status"), severity: f.get("severity"), resolution: f.get("resolution"),
            assignee_email: assignee || null, clear_assignee: !assignee }));
          flash("Ticket updated.", "success");
          refresh();
        } catch (err) { flash(err.message, "error"); }
      });
      const esc = body.querySelector("#escalate");
      if (esc) esc.addEventListener("click", async () => {
        try {
          const p = await api.escalateSupportTicket(t.ref, false);
          if (!window.confirm(`Send this ticket by email to ${p.to}?\n\nSubject: ${p.subject}`)) return;
          await api.escalateSupportTicket(t.ref, true);
          flash("Escalated by email.", "success");
          closeModal();
          refresh();
        } catch (err) { flash(err.message, "error"); }
      });
    }
  };
  draw(t);
}
