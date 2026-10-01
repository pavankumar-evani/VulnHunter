// Assignments: the ITSM-style work queue. Where Remediation Queue answers "what is the
// riskiest thing in the estate?", this answers "what is mine to do, what is my team's,
// and what has nobody picked up yet?" - assign, hand off, and move work through
// Open -> In progress -> Blocked -> Resolved. Resolved means the owner reports it fixed;
// the finding leaves the live queue only when the next scan stops seeing it.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { getCurrentUser } from "../auth.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";
import { openAssignModal, statusPillHtml, assigneeLabel, STATUS_LABELS } from "../assignModal.js";
import { openFindingById } from "../findingLookup.js";

export const title = "Assignments";

const VIEWS = [
  { id: "mine", label: "My work", hint: "Findings assigned to you" },
  { id: "team", label: "My team", hint: "Routed to your team, by assignment or by asset ownership" },
  { id: "needs_owner", label: "Needs an owner", hint: "No individual assignee yet - a team may own it, nobody has picked it up" },
  { id: "unowned", label: "Unowned", hint: "No person and no team - nothing routes this anywhere yet" },
  { id: "all", label: "All", hint: "Everything you are allowed to see" },
];
const COLSPAN = 10;

function daysSince(dateStr) {
  const t = new Date(`${String(dateStr).slice(0, 10)}T00:00:00`).getTime();
  return Number.isNaN(t) ? null : Math.max(0, Math.round((Date.now() - t) / 86400000));
}

function slaCellHtml(sla) {
  if (!sla) return `<span class="muted">-</span>`;
  if (sla.breached) {
    const d = sla.days_remaining != null ? Math.abs(sla.days_remaining) : null;
    return `<span class="badge badge-critical" data-tooltip="Due ${escapeHtml(sla.due_date)}">Breached${d != null ? ` ${d}d` : ""}</span>`;
  }
  if (sla.days_remaining != null && sla.days_remaining <= 3) {
    return `<span class="badge badge-medium" data-tooltip="Due ${escapeHtml(sla.due_date)}">Due in ${sla.days_remaining}d</span>`;
  }
  return `<span class="muted">${escapeHtml(sla.due_date || "-")}</span>`;
}

export async function render(container) {
  const me = await getCurrentUser(true);
  if (!me) {
    window.history.pushState({}, "", "/login?redirect=/assignments");
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }
  const isAdmin = me.role === "admin";
  const params = new URLSearchParams(window.location.search);
  const explicitView = params.get("view");
  const state = {
    view: VIEWS.some((v) => v.id === explicitView) ? explicitView : "mine",
    team: params.get("team") || "", priority: params.get("priority") || "",
    status: params.get("status") || "", includeResolved: params.get("include_resolved") === "true",
    page: 1,
  };
  let data = null;
  const selected = new Set();

  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ teams }, { users: people }] = await Promise.all([api.teams(), api.assignableUsers()]);

  async function fetchData() {
    return api.assignments({
      view: state.view, team: state.team, priority: state.priority, status: state.status,
      include_resolved: state.includeResolved, limit: 500,
    });
  }

  function syncUrl() {
    const q = new URLSearchParams();
    if (state.view !== "mine") q.set("view", state.view);
    for (const k of ["team", "priority", "status"]) if (state[k]) q.set(k, state[k]);
    if (state.includeResolved) q.set("include_resolved", "true");
    window.history.replaceState({}, "", `/assignments${q.toString() ? `?${q}` : ""}`);
  }

  function rowHtml(r) {
    const a = r.assignment;
    const canChangeStatus = a && (isAdmin || a.assignee_email === me.email.toLowerCase());
    const statusCell = canChangeStatus
      ? `<select class="status-select status-${escapeHtml(a.status)}" data-status-for="${escapeHtml(r.id)}" aria-label="Status of ${escapeHtml(r.id)}">
           ${Object.entries(STATUS_LABELS).map(([v, l]) => `<option value="${v}" ${v === a.status ? "selected" : ""}>${l}</option>`).join("")}
         </select>`
      : statusPillHtml(a && a.status);
    const age = daysSince(r.first_seen);
    return `
      <tr data-finding-id="${escapeHtml(r.id)}">
        ${isAdmin ? `<td><input type="checkbox" data-select="${escapeHtml(r.id)}" ${selected.has(r.id) ? "checked" : ""} aria-label="Select ${escapeHtml(r.id)}"></td>` : ""}
        <td><span class="badge badge-priority-${escapeHtml((r.priority || "").toLowerCase())}">${escapeHtml(r.priority)}</span></td>
        <td class="assign-finding-cell">
          <button type="button" class="link-button" data-open="${escapeHtml(r.id)}">${escapeHtml(r.id)}</button>
          <div class="assign-finding-title" title="${escapeHtml(r.title)}">${escapeHtml(r.title)}</div>
        </td>
        <td>${escapeHtml(r.asset)}</td>
        <td>${r.team ? escapeHtml(r.team) : `<span class="muted">-</span>`}</td>
        <td>${a && a.assignee_email
          ? `${escapeHtml(assigneeLabel(a))}<div class="muted assign-sub">${escapeHtml(a.assignee_email)}</div>`
          : `<span class="muted">${r.team ? "Team only" : "Nobody"}</span>`}</td>
        <td>${statusCell}</td>
        <td>${slaCellHtml(r.sla)}</td>
        <td>${age == null ? "-" : `${age}d`}</td>
        <td><button type="button" class="secondary-button compact" data-assign="${escapeHtml(r.id)}">${a ? "Reassign" : "Assign"}</button></td>
      </tr>`;
  }

  function paint() {
    const counts = data.counts;
    const paged = paginate(data.rows, state.page);
    state.page = paged.page;
    container.querySelector("#assign-tabs").innerHTML = VIEWS.map((v) => `
      <button type="button" role="tab" class="tab ${v.id === state.view ? "active" : ""}" data-view="${v.id}"
              aria-selected="${v.id === state.view}" data-tooltip="${escapeHtml(v.hint)}">
        ${v.label} <span class="tab-count">${(counts[v.id] ?? 0).toLocaleString()}</span>
      </button>`).join("");
    container.querySelector("#assign-body").innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="${COLSPAN}" class="empty-state">${emptyMessage()}</td></tr>`;
    container.querySelector("#assign-pagination").innerHTML = paginationHtml(paged.page, paged.totalPages);
    container.querySelector("#assign-count").textContent = data.truncated
      ? `Showing the top ${data.rows.length.toLocaleString()} of ${data.total.toLocaleString()} - narrow the filters to see the rest`
      : `${data.total.toLocaleString()} finding(s)`;
    const bar = container.querySelector("#bulk-bar");
    if (bar) {
      bar.hidden = selected.size === 0;
      container.querySelector("#bulk-count").textContent = `${selected.size} selected`;
    }
  }

  function emptyMessage() {
    if (state.view === "mine") return "Nothing is assigned to you right now. Pick something from <a href=\"/assignments?view=needs_owner\" data-link>Needs an owner</a>, or check <a href=\"/assignments?view=team\" data-link>My team</a>.";
    if (state.view === "unowned") return "Every finding in view has an owner or a team. Nothing is falling through the cracks.";
    return "No findings match the current filters.";
  }

  async function load(resetPage = true) {
    if (resetPage) state.page = 1;
    data = await fetchData();
    paint();
    syncUrl();
  }

  container.innerHTML = `
    <p class="subtitle">
      Your work queue. Every finding has an owner state - assigned to a person, routed to
      a team (by assignment, or by who owns its asset), or not owned at all. Take work,
      hand it off, and move it through <strong>Open → In progress → Blocked → Resolved</strong>;
      every change is recorded in the Activity Log.
    </p>
    <div class="tabbar" id="assign-tabs" role="tablist" aria-label="Assignment views"></div>

    <div class="filter-bar">
      <label>Priority
        <select id="f-priority">
          <option value="">All</option>
          ${["Critical", "High", "Medium", "Low"].map((p) => `<option ${state.priority === p ? "selected" : ""}>${p}</option>`).join("")}
        </select>
      </label>
      <label>Status
        <select id="f-status">
          <option value="">Any</option>
          <option value="unassigned" ${state.status === "unassigned" ? "selected" : ""}>Unassigned</option>
          ${Object.entries(STATUS_LABELS).map(([v, l]) => `<option value="${v}" ${state.status === v ? "selected" : ""}>${l}</option>`).join("")}
        </select>
      </label>
      <label>Team
        <select id="f-team">
          <option value="">All</option>
          ${teams.map((t) => `<option ${state.team === t.name ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}
        </select>
      </label>
      <label class="inline-check"><input type="checkbox" id="f-resolved" ${state.includeResolved ? "checked" : ""}> Include resolved</label>
      <span class="filter-count" id="assign-count"></span>
      ${isAdmin ? `<button type="button" class="secondary-button" id="auto-route"
          data-tooltip="Assignment rule: route every still-unassigned finding to the team that owns its asset. Previews the count first; never overwrites an existing assignment.">Auto-route to asset owners' teams</button>` : ""}
    </div>

    ${isAdmin ? `
    <div class="bulk-bar" id="bulk-bar" hidden>
      <strong id="bulk-count"></strong>
      <label>Assign to
        <select id="bulk-user">
          <option value="">(no individual)</option>
          ${people.map((u) => `<option value="${escapeHtml(u.email)}">${escapeHtml(u.name)}</option>`).join("")}
        </select>
      </label>
      <label>Team
        <select id="bulk-team">
          <option value="">(assignee's team)</option>
          ${teams.map((t) => `<option>${escapeHtml(t.name)}</option>`).join("")}
        </select>
      </label>
      <button type="button" id="bulk-apply">Assign selected</button>
      <button type="button" class="secondary-button" id="bulk-clear">Clear</button>
    </div>` : ""}

    <div class="table-scroll">
      <table class="data-table assign-table">
        <thead>
          <tr>
            ${isAdmin ? `<th><input type="checkbox" id="select-page" aria-label="Select all on this page"></th>` : ""}
            <th>Priority</th><th>Finding</th><th>Asset</th><th>Team</th><th>Assignee</th>
            <th>Status</th><th>SLA</th><th>Age</th><th></th>
          </tr>
        </thead>
        <tbody id="assign-body"></tbody>
      </table>
    </div>
    <div id="assign-pagination"></div>`;

  // Fall back to the most useful non-empty view on a first visit with nothing assigned.
  data = await fetchData();
  if (!explicitView && data.total === 0) {
    const fallback = isAdmin ? "needs_owner" : (me.team ? "team" : "needs_owner");
    if ((data.counts[fallback] || 0) > 0) {
      state.view = fallback;
      data = await fetchData();
    }
  }
  paint();
  syncUrl();

  const bind = (sel, ev, fn) => container.querySelector(sel).addEventListener(ev, fn);
  bind("#f-priority", "change", (e) => { state.priority = e.target.value; load(); });
  bind("#f-status", "change", (e) => { state.status = e.target.value; load(); });
  bind("#f-team", "change", (e) => { state.team = e.target.value; load(); });
  bind("#f-resolved", "change", (e) => { state.includeResolved = e.target.checked; load(); });
  wirePagination(container.querySelector("#assign-pagination"), (p) => { state.page = p; paint(); });

  container.querySelector("#assign-tabs").addEventListener("click", (e) => {
    const tab = e.target.closest("[data-view]");
    if (!tab) return;
    state.view = tab.dataset.view;
    selected.clear();
    load();
  });

  if (container._assignClick) container.removeEventListener("click", container._assignClick);
  if (container._assignChange) container.removeEventListener("change", container._assignChange);

  const onClick = (e) => {
    const open = e.target.closest("[data-open]");
    if (open) return openFindingById(open.dataset.open);
    const assign = e.target.closest("[data-assign]");
    if (assign) {
      const row = data.rows.find((r) => r.id === assign.dataset.assign);
      return openAssignModal({ findingId: assign.dataset.assign, title: row && row.title, onSaved: () => load(false) });
    }
  };
  const onChange = async (e) => {
    const statusSel = e.target.closest("[data-status-for]");
    if (statusSel) {
      try {
        await api.setAssignmentStatus(statusSel.dataset.statusFor, { status: statusSel.value });
        flash(`${statusSel.dataset.statusFor} marked ${STATUS_LABELS[statusSel.value].toLowerCase()}.`, "success");
        await load(false);
      } catch (err) {
        flash(err.message, "error");
        await load(false);
      }
      return;
    }
    const pick = e.target.closest("[data-select]");
    if (pick) {
      pick.checked ? selected.add(pick.dataset.select) : selected.delete(pick.dataset.select);
      paint();
    }
    if (e.target.id === "select-page") {
      container.querySelectorAll("[data-select]").forEach((box) => {
        box.checked = e.target.checked;
        e.target.checked ? selected.add(box.dataset.select) : selected.delete(box.dataset.select);
      });
      paint();
    }
  };
  container._assignClick = onClick;
  container._assignChange = onChange;
  container.addEventListener("click", onClick);
  container.addEventListener("change", onChange);

  if (isAdmin) {
    bind("#bulk-clear", "click", () => { selected.clear(); paint(); });
    bind("#bulk-apply", "click", async () => {
      const assignee = container.querySelector("#bulk-user").value || null;
      const team = container.querySelector("#bulk-team").value || null;
      if (!assignee && !team) { flash("Choose a person, a team, or both.", "error"); return; }
      try {
        const res = await api.bulkAssign({ finding_ids: [...selected], assignee_email: assignee, team });
        flash(`${res.assigned} finding(s) assigned.`, "success");
        selected.clear();
        await load(false);
      } catch (err) {
        flash(err.message, "error");
      }
    });
    bind("#auto-route", "click", async () => {
      try {
        const preview = await api.autoAssign(false);
        if (!preview.would_assign) {
          flash(`Nothing to route: ${preview.already_assigned} already assigned, ${preview.skipped_no_team} have no asset team.`, "info");
          return;
        }
        const ok = window.confirm(
          `Route ${preview.would_assign.toLocaleString()} unassigned finding(s) to their asset owner's team?\n\n` +
          `${preview.already_assigned.toLocaleString()} already assigned stay untouched; ` +
          `${preview.skipped_no_team.toLocaleString()} have no asset team and are skipped.`);
        if (!ok) return;
        const done = await api.autoAssign(true);
        flash(`${done.assigned.toLocaleString()} finding(s) routed to their teams.`, "success");
        await load(false);
      } catch (err) {
        flash(err.message, "error");
      }
    });
  }
}
