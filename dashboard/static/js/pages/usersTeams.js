// Users & Teams: the admin's people-and-ownership console. Accounts and roles, first-
// class teams (assignment groups) with an accountable manager, who sits on which team,
// each person's live workload, and the auto-routing rule that sends unassigned findings
// to the team that owns their asset. It is the admin counterpart to the Assignments work
// queue and the Ownership Analytics page.
//
// A user's team is also the field the server enforces to scope Queue, Assets, Exceptions,
// Remediation Approvals and Assignments to that team's findings (see dashboard/app.py's
// _scope_to_team) - leave it blank for unfiltered, organisation-wide access.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { getCurrentUser } from "../auth.js";

export const title = "Users & Teams";

const VALID_ROLES = ["user", "admin"];

function userOptions(users, selectedEmail, blankLabel = "(no manager)") {
  return `<option value="">${blankLabel}</option>` + users.map((u) =>
    `<option value="${escapeHtml(u.email)}" ${u.email === selectedEmail ? "selected" : ""}>${escapeHtml(u.name)} (${escapeHtml(u.email)})</option>`).join("");
}

function teamOptions(teams, selected) {
  return `<option value="">(none - unfiltered)</option>` + teams.map((t) =>
    `<option value="${escapeHtml(t.name)}" ${t.name === selected ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("");
}

export async function render(container) {
  const me = await getCurrentUser(true);
  if (!me) {
    window.history.pushState({}, "", "/login?redirect=/admin/people");
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }
  if (me.role !== "admin") {
    container.innerHTML = `
      <div class="callout callout-warn">
        Admins only - this page manages accounts, roles and team ownership for everyone.
        Signed in as <strong>${escapeHtml(me.email)}</strong> (role: ${escapeHtml(me.role)}).
        You can still see your own work under <a href="/assignments" data-link>Assignments</a>.
      </div>`;
    return;
  }

  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ users }, { teams }, analytics] = await Promise.all([
    api.listUsers(), api.teams(), api.ownershipAnalytics().catch(() => null),
  ]);
  const workload = new Map(((analytics && analytics.by_user) || []).map((u) => [u.email, u]));
  const teamLoad = new Map(((analytics && analytics.by_team) || []).map((t) => [t.name, t]));

  const admins = users.filter((u) => u.role === "admin").length;
  const noTeam = users.filter((u) => !u.team && u.role !== "admin").length;
  const noManager = teams.filter((t) => !t.manager_email).length;

  const teamRow = (t) => {
    const load = teamLoad.get(t.name);
    const mgrSelect = t.explicit
      ? `<select data-team-manager="${escapeHtml(t.name)}">${userOptions(users, t.manager_email)}</select>`
      : `<span class="muted">-</span>`;
    const desc = t.explicit
      ? `<input type="text" data-team-desc="${escapeHtml(t.name)}" value="${escapeHtml(t.description || "")}" placeholder="What this team owns" maxlength="200">`
      : `<span class="muted">Exists only as a name on users or assets</span>`;
    return `
      <tr data-team-row="${escapeHtml(t.name)}">
        <td><strong>${escapeHtml(t.name)}</strong>
          ${t.explicit ? "" : `<span class="badge badge-outline muted">implied</span>`}</td>
        <td>${desc}</td>
        <td>${mgrSelect}</td>
        <td>${t.members}</td>
        <td>${load ? `${load.open.toLocaleString()}` : "-"}${load && load.breached ? ` <span class="badge badge-critical" data-tooltip="Open findings breaching SLA">${load.breached.toLocaleString()}</span>` : ""}</td>
        <td>${t.open_assignments}</td>
        <td class="row-actions">
          ${t.explicit
            ? `<button type="button" class="link-button" data-save-team-record="${escapeHtml(t.name)}">Save</button>
               <button type="button" class="link-button danger-link" data-delete-team="${escapeHtml(t.name)}">Delete</button>`
            : `<button type="button" class="link-button" data-formalize-team="${escapeHtml(t.name)}">Formalize</button>`}
        </td>
      </tr>`;
  };

  const userRow = (u) => {
    const w = workload.get(u.email);
    return `
      <tr data-user-email="${escapeHtml(u.email)}">
        <td>${escapeHtml(u.name)}<div class="muted assign-sub">${escapeHtml(u.email)}</div></td>
        <td><select class="user-role-select" data-user-email="${escapeHtml(u.email)}">
          ${VALID_ROLES.map((r) => `<option value="${r}" ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}</select></td>
        <td><select class="user-team-select" data-user-email="${escapeHtml(u.email)}">${teamOptions(teams, u.team)}</select></td>
        <td>${w ? w.open.toLocaleString() : "0"}</td>
        <td>${w && w.critical ? `<span class="badge badge-priority-critical">${w.critical.toLocaleString()}</span>` : "0"}</td>
        <td>${w && w.breached ? `<span class="badge badge-critical">${w.breached.toLocaleString()}</span>` : "0"}</td>
        <td>${w ? w.in_progress.toLocaleString() : "0"}</td>
      </tr>`;
  };

  function paint() {
    container.querySelector("#teams-body").innerHTML = teams.length
      ? teams.map(teamRow).join("")
      : `<tr><td colspan="7" class="empty-state">No teams yet - add one below, or assign people a team name and formalize it here.</td></tr>`;
    container.querySelector("#users-body").innerHTML = users.length
      ? users.map(userRow).join("")
      : `<tr><td colspan="7" class="empty-state">No users found.</td></tr>`;
  }

  async function refresh() {
    await render(container);
  }

  container.innerHTML = `
    <p class="subtitle">
      Who can sign in, what they can do, and which team each person belongs to - plus the
      team records that findings are assigned to. This is the admin side of the
      <a href="/assignments" data-link>Assignments</a> work queue and
      <a href="/ownership" data-link>Ownership Analytics</a>.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${users.length}</div><div class="kpi-label">User accounts (${admins} admin)</div></div>
      <div class="kpi-card"><div class="kpi-value">${teams.length}</div><div class="kpi-label">Teams</div></div>
      <div class="kpi-card ${noTeam ? "kpi-warn" : "kpi-good"}"><div class="kpi-value">${noTeam}</div><div class="kpi-label">Non-admin users with no team (unfiltered access)</div></div>
      <div class="kpi-card ${noManager ? "kpi-warn" : "kpi-good"}"><div class="kpi-value">${noManager}</div><div class="kpi-label">Teams without an accountable manager</div></div>
    </div>

    <h2>Teams</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      A team is an assignment group: findings can be routed to it, and its manager may update
      the status of work assigned to it. Teams that exist only as a name on a user or an
      asset are listed as <em>implied</em> - <strong>Formalize</strong> gives one a description
      and a manager. A team with members or open assignments can't be deleted.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Team</th><th>Description</th><th>Manager</th><th>Members</th>
          <th>Open findings</th><th>Open assignments</th><th></th></tr></thead>
        <tbody id="teams-body"></tbody>
      </table>
    </div>
    <form class="run-form" id="add-team-form" style="margin-top:12px">
      <label>New team name<input type="text" name="name" maxlength="60" required placeholder="e.g. Platform Engineering"></label>
      <label>Description<input type="text" name="description" maxlength="200" placeholder="What this team owns"></label>
      <label>Manager<select name="manager_email">${userOptions(users, "")}</select></label>
      <button type="submit">Add team</button>
    </form>

    <h2 style="margin-top:28px">Users</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Setting a team restricts that account's Queue, Assets, Exceptions, Remediation Approvals
      and Assignments to that team's findings. Leave it empty for organisation-wide access
      (the default for every account today). Workload columns are live, from the same
      figures as Ownership Analytics.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>User</th><th>Role</th><th>Team</th><th>Open</th><th>Critical</th><th>Breached</th><th>In progress</th></tr></thead>
        <tbody id="users-body"></tbody>
      </table>
    </div>
    <form class="run-form" id="add-user-form" style="margin-top:12px">
      <label>Email<input type="email" name="email" placeholder="user@example.com" required></label>
      <label>Name<input type="text" name="name" required></label>
      <label>Password (min. 8 characters)<input type="password" name="password" minlength="8" required></label>
      <label>Role<select name="role">${VALID_ROLES.map((r) => `<option value="${r}">${r}</option>`).join("")}</select></label>
      <label>Team<select name="team">${teamOptions(teams, "")}</select></label>
      <button type="submit">Add user</button>
    </form>

    <h2 style="margin-top:28px">Auto-routing rule</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Every finding is scanned against an asset, and every asset can have an owning team (set under
      Asset Inventory or Asset Policy). This rule sends each <strong>still-unassigned</strong> finding to
      the team that owns its asset - the way an ITSM assignment rule routes a new ticket to a
      group. It only fills gaps: it never overwrites an assignment, and findings whose asset has no
      team are left alone for you to triage.
    </p>
    <div id="route-result" class="callout" hidden></div>
    <button type="button" class="secondary-button" id="route-preview">Preview what would be routed</button>
    <button type="button" id="route-apply" hidden>Apply routing</button>`;

  paint();
  const q = (sel) => container.querySelector(sel);

  if (container._peopleClick) container.removeEventListener("click", container._peopleClick);
  if (container._peopleChange) container.removeEventListener("change", container._peopleChange);

  const act = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) flash(okMsg, "success");
      await refresh();
    } catch (err) {
      flash(err.message, "error");
    }
  };

  container._peopleClick = (e) => {
    const save = e.target.closest("[data-save-team-record]");
    if (save) {
      const name = save.dataset.saveTeamRecord;
      const desc = q(`[data-team-desc="${CSS.escape(name)}"]`).value.trim() || null;
      const mgr = q(`[data-team-manager="${CSS.escape(name)}"]`).value || null;
      return act(() => api.updateTeam(name, { description: desc, manager_email: mgr }), `Team ${name} saved.`);
    }
    const del = e.target.closest("[data-delete-team]");
    if (del) {
      const name = del.dataset.deleteTeam;
      if (!window.confirm(`Delete team ${name}? This only removes the team record.`)) return;
      return act(() => api.deleteTeam(name), `Team ${name} deleted.`);
    }
    const formalize = e.target.closest("[data-formalize-team]");
    if (formalize) {
      const name = formalize.dataset.formalizeTeam;
      return act(() => api.createTeam({ name }), `Team ${name} formalized - add a manager and description.`);
    }
  };
  container._peopleChange = async (e) => {
    const role = e.target.closest(".user-role-select");
    if (role) {
      return act(() => api.setUserRole(role.dataset.userEmail, role.value), `Role updated for ${role.dataset.userEmail}.`);
    }
    const team = e.target.closest(".user-team-select");
    if (team) {
      return act(() => api.setUserTeam(team.dataset.userEmail, team.value), `Team updated for ${team.dataset.userEmail}.`);
    }
  };
  container.addEventListener("click", container._peopleClick);
  container.addEventListener("change", container._peopleChange);

  q("#add-team-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.target;
    act(() => api.createTeam({
      name: f.name.value.trim(), description: f.description.value.trim() || null,
      manager_email: f.manager_email.value || null,
    }), `Team ${f.name.value.trim()} created.`);
  });

  q("#add-user-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.target;
    act(() => api.createUser({
      email: f.email.value.trim(), password: f.password.value, name: f.name.value.trim(),
      role: f.role.value, team: f.team.value || null,
    }), `User ${f.email.value.trim()} created.`);
  });

  q("#route-preview").addEventListener("click", async () => {
    try {
      const p = await api.autoAssign(false);
      const out = q("#route-result");
      out.hidden = false;
      out.innerHTML = p.would_assign
        ? `<strong>${p.would_assign.toLocaleString()}</strong> finding(s) would be routed to their asset owner's team.
           ${p.already_assigned.toLocaleString()} already assigned stay untouched; ${p.skipped_no_team.toLocaleString()} have no asset team and are skipped.`
        : `Nothing to route - ${p.already_assigned.toLocaleString()} already assigned, ${p.skipped_no_team.toLocaleString()} have no asset team.`;
      q("#route-apply").hidden = !p.would_assign;
    } catch (err) {
      flash(err.message, "error");
    }
  });
  q("#route-apply").addEventListener("click", async () => {
    if (!window.confirm("Route every unassigned finding to its asset owner's team? Existing assignments are never changed.")) return;
    try {
      const r = await api.autoAssign(true);
      flash(`${r.assigned.toLocaleString()} finding(s) routed to their teams.`, "success");
      await refresh();
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
