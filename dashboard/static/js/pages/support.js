import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { barChartSvg } from "../charts.js";

export const title = "Support";

const KINDS = [["bug", "Something isn't working"], ["question", "A question"], ["feature", "A feature request"],
  ["access", "Access or account"], ["other", "Something else"]];
const SEVERITIES = [["low", "Low"], ["normal", "Normal"], ["high", "High"], ["urgent", "Urgent"]];
const IMPACTS = [["individual", "Just me"], ["team", "My team"], ["organization", "The whole organization"]];
const STATUS_LABEL = { open: "Open", in_progress: "In progress", waiting_on_requester: "Waiting on requester",
  resolved: "Resolved", closed: "Closed" };

const opts = (pairs, selected) => pairs.map(([v, l]) =>
  `<option value="${escapeHtml(v)}"${v === selected ? " selected" : ""}>${escapeHtml(l)}</option>`).join("");

const statusBadge = (s) => `<span class="badge badge-outline">${escapeHtml(STATUS_LABEL[s] || s)}</span>`;
const prioBadge = (p) => p ? `<span class="badge badge-priority-${p === "P1" ? "critical" : p === "P2" ? "high" : p === "P3" ? "medium" : "low"}">${escapeHtml(p)}</span>` : "-";

function fmtMinutes(m) {
  if (m === null || m === undefined) return "";
  const a = Math.abs(m);
  const t = a >= 1440 ? `${Math.round(a / 1440)}d` : a >= 60 ? `${Math.round(a / 60)}h` : `${a}m`;
  return m < 0 ? `${t} over` : `${t} left`;
}

function clockHtml(c, label) {
  if (!c || c.state === "n/a") return `<span class="muted">${label}: -</span>`;
  const cls = { ok: "", at_risk: "sla-risk", breached: "sla-breach", met: "sla-met", missed: "sla-breach", paused: "muted" }[c.state] || "";
  const word = { ok: fmtMinutes(c.minutes_remaining), at_risk: `at risk, ${fmtMinutes(c.minutes_remaining)}`, breached: `breached, ${fmtMinutes(c.minutes_remaining)}`,
    met: "met", missed: "missed", paused: "paused" }[c.state];
  return `<span class="${cls}">${label}: ${escapeHtml(word)}</span>`;
}

function slaCell(t) {
  if (!t.sla || !t.sla.priority) return `<span class="muted">-</span>`;
  const done = t.status === "resolved" || t.status === "closed";
  return done ? clockHtml(t.sla.resolution, "Resolve") : `${clockHtml(t.sla.response, "Respond")}<br>${clockHtml(t.sla.resolution, "Resolve")}`;
}

function ticketRows(tickets, staff) {
  if (!tickets.length) return `<tr><td colspan="${staff ? 9 : 6}" class="empty-state">No tickets match.</td></tr>`;
  return tickets.map((t) => `<tr>
    <td><a href="#" data-ticket="${escapeHtml(t.ref)}">${escapeHtml(t.ref)}</a></td>
    <td>${prioBadge(t.priority)}</td>
    <td>${escapeHtml(t.subject)}${t.finding_id ? ` <span class="muted">(${escapeHtml(t.finding_id)})</span>` : ""}</td>
    <td>${statusBadge(t.status)}</td>
    <td class="nowrap">${slaCell(t)}</td>
    <td>${escapeHtml(t.team || "-")}</td>
    ${staff ? `<td>${escapeHtml(t.assignee_email || "-")}</td><td>${escapeHtml(t.requester_email)}</td><td>${escapeHtml(t.kind)}</td>` : ""}
  </tr>`).join("");
}

const kpi = (label, value, cls = "") => `<div class="kpi-card ${cls}"><div class="kpi-label">${escapeHtml(label)}</div><div class="kpi-value">${value}</div></div>`;
const num = (v, suffix = "") => (v === null || v === undefined ? "-" : `${v}${suffix}`);

export async function render(container) {
  let me = null;
  try { me = (await api.authMe()).user; } catch { me = null; }
  const prefillFinding = new URLSearchParams(location.search).get("finding_id") || "";

  container.innerHTML = `
    <p class="subtitle">Open a ticket and it is routed to the right team, prioritised by impact and urgency, and tracked against an
    SLA - all inside your own deployment. Nothing is sent to a public tracker.</p>
    <div class="callout" style="margin-bottom:18px">
      <strong>Looking for how to do something specific?</strong> Try <a href="/ask" data-link>Ask Quanta</a> first - it searches this app's
      own How-To content live, at no cost. It is not a chatbot and never guesses.
    </div>
    <div id="support-tickets"></div>
    <h2>Before you open a ticket</h2>
    <ul>
      <li><a href="/faq" data-link>FAQ</a> - direct answers about what this does and doesn't do</li>
      <li><span class="doc-ref">User &amp; Operations Guide</span> - how-to answers for every real workflow</li>
      <li><strong>Security issue in Quanta itself:</strong> do not file a ticket - see <code>SECURITY.md</code> for the private disclosure contact.</li>
    </ul>
    <h2>Known limitations (read before reporting these as bugs)</h2>
    <ul>
      <li>Reads stay open by default even though real login/RBAC exists - set <code>QUANTA_REQUIRE_LOGIN_FOR_READS=true</code> and do not
        expose this beyond localhost or a trusted network without it.</li>
      <li>Record stores live in a single local database; SLA clocks run on calendar time (business-hours calendars are not built yet).</li>
      <li>The tenant switcher is a UI-only demo, not real per-tenant isolation.</li>
      <li>Vendor connectors are built to public API docs and tested against simulated responses, not yet against a live vendor tenant.</li>
    </ul>`;

  const host = container.querySelector("#support-tickets");
  if (!me) {
    host.innerHTML = `<div class="callout"><a href="/login" data-link>Sign in</a> to open a ticket or see your tickets.</div>`;
    return;
  }

  window.__quantaMe = me;
  let tab = new URLSearchParams(location.search).get("tab") === "analytics" ? "analytics" : "queue";
  let filters = { status: "", team: "", breached: "", mine: false };

  async function refresh() {
    const params = {};
    if (filters.status) params.status = filters.status;
    if (filters.team) params.team = filters.team;
    if (filters.breached) params.breached = "true";
    if (filters.mine) params.mine = "true";
    const data = await api.supportTickets(params);
    const staff = data.is_admin || data.is_agent;
    const s = data.summary;
    const scopeName = data.is_admin ? "Support queue" : data.is_agent ? `${data.team} queue` : "My tickets";

    host.innerHTML = `
      <details class="ticket-new"${prefillFinding || !data.tickets.length ? " open" : ""}>
      <summary><h2 style="display:inline">Open a ticket</h2></summary>
      <form id="ticket-form" class="run-form">
        <label>Type <select name="kind">${opts(KINDS, prefillFinding ? "bug" : "question")}</select></label>
        <label>Who is affected <select name="impact">${opts(IMPACTS, "individual")}</select></label>
        <label>Urgency <select name="severity">${opts(SEVERITIES, "normal")}</select></label>
        <label>Related finding (optional) <input name="finding_id" value="${escapeHtml(prefillFinding)}" placeholder="e.g. FIND-12"></label>
        <label>Subject <input name="subject" maxlength="200" required></label>
        <label>What happened, and what did you expect?
          <textarea name="description" rows="5" maxlength="8000" required placeholder="Include the page or command, the exact error, and what you expected."></textarea></label>
        <div><button type="submit">Submit ticket</button></div>
      </form>
      </details>

      <h2>${escapeHtml(scopeName)}</h2>
      ${staff ? `<div class="tab-row" style="margin-bottom:10px">
        <button type="button" class="secondary-button${tab === "queue" ? " active" : ""}" data-tab="queue">Queue</button>
        <button type="button" class="secondary-button${tab === "analytics" ? " active" : ""}" data-tab="analytics">Analytics</button></div>` : ""}
      <div id="tab-body"></div>`;

    host.querySelector("#ticket-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = Object.fromEntries(new FormData(e.target).entries());
      if (!f.finding_id) delete f.finding_id;
      try {
        const t = await api.createSupportTicket(f);
        flash(`Ticket ${t.ref} opened${t.team ? ` and routed to ${t.team}` : ""} as ${t.priority}.`, "success");
        history.replaceState(null, "", "/support");
        await refresh();
      } catch (err) { flash(err.message, "error"); }
    });
    host.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; refresh(); }));

    const body = host.querySelector("#tab-body");
    if (tab === "analytics" && staff) {
      await renderAnalytics(body);
    } else {
      body.innerHTML = `
        ${staff && s ? `<div class="kpi-grid" style="margin-bottom:12px">
          ${kpi("Open", s.open)}${kpi("Breached SLA", s.breached_open, s.breached_open ? "kpi-bad" : "")}${kpi("At risk", s.at_risk_open)}
          ${kpi("Unassigned", s.unassigned_open)}${kpi("Unrouted", s.unrouted_open)}${kpi("Urgent", s.urgent_open)}</div>` : ""}
        <div class="filter-row" style="margin-bottom:10px">
          <label>Status <select id="f-status"><option value="">All</option><option value="open_all"${filters.status === "open_all" ? " selected" : ""}>Open work</option>${opts(Object.entries(STATUS_LABEL), filters.status)}</select></label>
          ${data.is_admin ? `<label>Team <select id="f-team"><option value="">All</option>${(data.teams || []).map((t) => `<option${t === filters.team ? " selected" : ""}>${escapeHtml(t)}</option>`).join("")}</select></label>` : ""}
          <label><input type="checkbox" id="f-breached"${filters.breached ? " checked" : ""}> SLA breached only</label>
          ${data.is_admin ? `<button type="button" class="secondary-button" id="run-escalations">Run SLA escalations</button>` : ""}
          ${staff ? `<label><input type="checkbox" id="f-mine"${filters.mine ? " checked" : ""}> Only tickets I opened</label>` : ""}
        </div>
        <div class="table-scroll"><table class="data-table">
          <thead><tr><th>Ref</th><th>Priority</th><th>Subject</th><th>Status</th><th>SLA</th><th>Team</th>
          ${staff ? "<th>Assignee</th><th>Requester</th><th>Type</th>" : ""}</tr></thead>
          <tbody>${ticketRows(data.tickets, staff)}</tbody></table></div>`;
      const bind = (id, fn) => { const el = body.querySelector(id); if (el) el.addEventListener("change", fn); };
      bind("#f-status", (e) => { filters.status = e.target.value; refresh(); });
      bind("#f-team", (e) => { filters.team = e.target.value; refresh(); });
      bind("#f-breached", (e) => { filters.breached = e.target.checked; refresh(); });
      bind("#f-mine", (e) => { filters.mine = e.target.checked; refresh(); });
      const runEsc = body.querySelector("#run-escalations");
      if (runEsc) runEsc.addEventListener("click", async () => {
        try {
          const p = await api.runSlaEscalations(false);
          if (!p.alerts.length) { flash("No new SLA alerts to raise.", "info"); return; }
          const lines = p.alerts.map((x) => `${x.ref} (${x.level}) -> ${x.recipients.join(", ") || "nobody"}`).join("\n");
          if (!window.confirm(`Raise ${p.alerts.length} SLA alert(s)?${p.smtp_configured ? "" : " (SMTP not configured: recorded in-app only)"}\n\n${lines}`)) return;
          await api.runSlaEscalations(true);
          flash(`${p.alerts.length} SLA alert(s) raised.`, "success");
          refresh();
        } catch (err) { flash(err.message, "error"); }
      });
      body.querySelectorAll("[data-ticket]").forEach((a) => a.addEventListener("click", (e) => {
        e.preventDefault();
        showTicket(a.dataset.ticket, data, refresh);
      }));
    }
  }

  await refresh();
}

async function renderAnalytics(body) {
  let a;
  try { a = await api.supportAnalytics(); } catch (err) { body.innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`; return; }
  const t = a.totals;
  const teamBars = a.by_team.filter((x) => x.open).slice(0, 8).map((x) => ({ label: x.name, value: x.open,
    detail: `${x.breached} breached, ${x.at_risk} at risk` }));
  const ageBars = a.ageing.map((x) => ({ label: x.bucket, value: x.count }));
  const trendBars = a.trend.map((d) => ({ label: d.date.slice(5), value: d.created, detail: `${d.created} opened, ${d.resolved} resolved` }));
  body.innerHTML = `
    <p class="muted">Scope: ${escapeHtml(a.scope)}</p>
    <div class="kpi-grid" style="margin-bottom:14px">
      ${kpi("SLA compliance", num(a.sla_compliance_pct, "%"))}${kpi("Avg first response", num(a.first_response_avg_minutes, " min"))}
      ${kpi("Mean time to resolve", num(a.mttr_hours, " h"))}${kpi("Reopen rate", num(a.reopen_rate_pct, "%"))}
      ${kpi("Open", t.open)}${kpi("Breached now", t.breached_open, t.breached_open ? "kpi-bad" : "")}
      ${kpi("Satisfaction", a.csat.average === null ? "-" : `${a.csat.average} / 5`)}${kpi("Rated", `${a.csat.responses}`)}
      ${kpi("Linked to findings", t.linked_to_findings)}${kpi("Resolved", t.resolved)}</div>
    <div class="chart-row">
      <div class="chart-block"><h3>Open tickets by team</h3>${teamBars.length ? barChartSvg(teamBars, { width: 420, height: 210 }) : `<p class="muted">No open tickets.</p>`}</div>
      <div class="chart-block"><h3>Open backlog by age</h3>${barChartSvg(ageBars, { width: 420, height: 210, barColor: "#6d97f7" })}</div>
      <div class="chart-block"><h3>Opened per day (14 days)</h3>${barChartSvg(trendBars, { width: 420, height: 210, barColor: "#3fd0b6" })}</div>
    </div>
    <h3>By priority</h3>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Priority</th><th>Tickets</th><th>Open</th><th>Avg first response</th><th>Mean time to resolve</th></tr></thead><tbody>
      ${Object.entries(a.by_priority).map(([p, r]) => `<tr><td>${prioBadge(p)}</td><td>${r.total}</td><td>${r.open}</td><td>${num(r.first_response_minutes, " min")}</td><td>${num(r.mttr_hours, " h")}</td></tr>`).join("")}</tbody></table></div>
    <h3>By team</h3>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Team</th><th>Tickets</th><th>Open</th><th>Breached</th><th>At risk</th><th>Avg resolve</th><th>SLA met</th></tr></thead><tbody>
      ${a.by_team.map((r) => `<tr><td>${escapeHtml(r.name)}</td><td>${r.total}</td><td>${r.open}</td><td>${r.breached}</td><td>${r.at_risk}</td><td>${num(r.avg_resolution_hours, " h")}</td><td>${num(r.sla_compliance_pct, "%")}</td></tr>`).join("")}</tbody></table></div>
    <h3>Open work by assignee</h3>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Assignee</th><th>Open</th><th>Breached</th><th>At risk</th></tr></thead><tbody>
      ${a.by_assignee.map((r) => `<tr><td>${escapeHtml(r.name)}</td><td>${r.open}</td><td>${r.breached}</td><td>${r.at_risk}</td></tr>`).join("") || `<tr><td colspan="4" class="empty-state">No open tickets.</td></tr>`}</tbody></table></div>`;
}

function csatHtml(t) {
  if (t.csat_score) {
    return `<div class="callout"><strong>Satisfaction:</strong> ${"&#9733;".repeat(t.csat_score)}${"&#9734;".repeat(5 - t.csat_score)} (${t.csat_score}/5)${t.csat_comment ? ` - ${escapeHtml(t.csat_comment)}` : ""}</div>`;
  }
  if (t.role !== "requester" && t.role !== "admin" && t.role !== "agent") return "";
  const isRequester = t.requester_email && window.__quantaMe && window.__quantaMe.email === t.requester_email;
  if (!isRequester || !(t.status === "resolved" || t.status === "closed")) return "";
  return `<div class="callout"><strong>How did we do?</strong> Rate this resolution:
    <span class="csat-buttons">${[1, 2, 3, 4, 5].map((n) => `<button type="button" class="secondary-button" data-score="${n}">${n}</button>`).join(" ")}</span>
    <input id="csat-comment" maxlength="1000" placeholder="Optional comment" style="margin-top:8px;width:100%"></div>`;
}

async function showTicket(ref, listData, refresh) {
  let t;
  try { t = await api.supportTicket(ref); } catch (err) { flash(err.message, "error"); return; }
  const isAdmin = listData.is_admin;
  const body = openModal("");
  const draw = (t) => {
    const staff = t.role === "admin" || t.role === "agent";
    const comments = t.comments.map((c) => `<div class="comment${c.internal ? " comment-internal" : ""}">
      <div class="meta">${escapeHtml(c.author_email)} &middot; ${escapeHtml(c.created_at)}${c.internal ? " &middot; <strong>internal note</strong>" : ""}</div>
      <div>${escapeHtml(c.body).replaceAll("\n", "<br>")}</div></div>`).join("") || "<p>No replies yet.</p>";
    body.innerHTML = `
      <h2>${escapeHtml(t.ref)} - ${escapeHtml(t.subject)}</h2>
      <p>${prioBadge(t.priority)} ${statusBadge(t.status)} &nbsp; ${escapeHtml(t.kind)} &middot; impact ${escapeHtml(t.impact || "-")} &middot; urgency ${escapeHtml(t.severity)}
        &middot; team <strong>${escapeHtml(t.team || "unrouted")}</strong> &middot; from ${escapeHtml(t.requester_email)}</p>
      <p class="sla-line">${slaCell(t).replace("<br>", " &nbsp;&middot;&nbsp; ")}${t.reopen_count ? ` &nbsp;&middot;&nbsp; reopened ${t.reopen_count}x` : ""}</p>
      ${t.finding_id ? `<p>Related finding: <strong>${escapeHtml(t.finding_id)}</strong></p>` : ""}
      <p>${escapeHtml(t.description).replaceAll("\n", "<br>")}</p>
      ${t.resolution ? `<div class="callout"><strong>Resolution:</strong> ${escapeHtml(t.resolution)}</div>` : ""}
      ${t.escalation ? `<div class="callout callout-warn"><strong>SLA ${t.escalation.level === "breached" ? "breached" : "at risk"}.</strong>
        ${t.escalation.notify.length ? `Alerts go to ${t.escalation.notify.map(escapeHtml).join(", ")}.` : "No assignee or team manager is set, so nobody is being alerted."}</div>` : ""}
      ${csatHtml(t)}
      <h3>Conversation</h3>${comments}
      <form id="comment-form" style="margin-top:10px">
        <textarea name="body" rows="3" maxlength="8000" required placeholder="Write a reply"></textarea>
        ${staff ? `<label><input type="checkbox" name="internal"> Internal note (not shown to the requester)</label>` : ""}
        <div><button class="secondary-button" type="submit">Reply</button></div>
      </form>
      ${staff ? `<h3>Triage</h3>
      <form id="triage-form" class="run-form">
        <label>Status <select name="status">${opts(Object.entries(STATUS_LABEL), t.status)}</select></label>
        <label>Assignee (email) <input name="assignee_email" value="${escapeHtml(t.assignee_email || "")}"></label>
        ${isAdmin ? `<label>Team <select name="team"><option value="">Unrouted</option>${(listData.teams || []).map((x) => `<option${x === t.team ? " selected" : ""}>${escapeHtml(x)}</option>`).join("")}</select></label>
        <label>Who is affected <select name="impact">${opts(IMPACTS, t.impact || "individual")}</select></label>
        <label>Urgency <select name="severity">${opts(SEVERITIES, t.severity)}</select></label>` : ""}
        <label>Resolution <textarea name="resolution" rows="2">${escapeHtml(t.resolution || "")}</textarea></label>
        <div><button type="submit">Save</button>
          ${isAdmin && listData.escalation_configured ? `<button class="secondary-button" type="button" id="escalate">Escalate to vendor by email</button>` : ""}</div>
      </form>` : ""}`;

    body.querySelectorAll("[data-score]").forEach((b) => b.addEventListener("click", async () => {
      try {
        draw(await api.rateSupportTicket(t.ref, { score: Number(b.dataset.score), comment: (body.querySelector("#csat-comment") || {}).value || null }));
        flash("Thanks for the feedback.", "success");
        refresh();
      } catch (err) { flash(err.message, "error"); }
    }));
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
        const payload = { status: f.get("status"), resolution: f.get("resolution"), assignee_email: assignee || null, clear_assignee: !assignee };
        if (isAdmin) Object.assign(payload, { team: f.get("team") || "", impact: f.get("impact"), severity: f.get("severity") });
        try {
          draw(await api.updateSupportTicket(t.ref, payload));
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
