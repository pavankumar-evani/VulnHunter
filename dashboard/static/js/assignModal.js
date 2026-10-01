// The one "assign this finding" dialog, shared by the Assignments queue, Ownership
// Analytics' unowned-urgent list, and the finding-detail panel - so assigning a finding
// is the same form, with the same rules, wherever you start from. The server is the
// authority on who may assign what (an admin anyone; a team member only within their
// team) - this dialog just offers the choices the server will accept (see
// /api/assignable-users and /api/teams, both already scoped to the caller).
import { api } from "./api.js";
import { escapeHtml, flash, openModal, closeModal } from "./dom.js";
import { getCurrentUser } from "./auth.js";

export const STATUS_LABELS = { open: "Open", in_progress: "In progress", blocked: "Blocked", resolved: "Resolved" };

export function statusPillHtml(status) {
  if (!status) return `<span class="status-pill status-unassigned">Unassigned</span>`;
  return `<span class="status-pill status-${escapeHtml(status)}">${escapeHtml(STATUS_LABELS[status] || status)}</span>`;
}

export function assigneeLabel(assignment) {
  if (!assignment || !assignment.assignee_email) return "";
  return assignment.assignee_name || assignment.assignee_email;
}

export async function openAssignModal({ findingId, title = "", onSaved = () => {} }) {
  const me = await getCurrentUser();
  let people, teams, detail;
  try {
    [{ users: people }, { teams }, detail] = await Promise.all([
      api.assignableUsers(), api.teams(), api.findingAssignment(findingId),
    ]);
  } catch (err) {
    flash(err.message, "error");
    return;
  }
  const current = detail.assignment;
  const isAdmin = me && me.role === "admin";

  const body = openModal(`
    <h2 style="margin-top:0">Assign ${escapeHtml(findingId)}</h2>
    ${title ? `<p class="filter-count" style="margin:-6px 0 12px">${escapeHtml(title)}</p>` : ""}
    <form class="run-form assign-form" id="assign-form">
      <label>Assignee
        <select name="assignee_email">
          <option value="">Nobody yet - route to a team only</option>
          ${people.map((u) => `
            <option value="${escapeHtml(u.email)}" ${current && current.assignee_email === u.email ? "selected" : ""}>
              ${escapeHtml(u.name)} (${escapeHtml(u.email)})${u.team ? ` - ${escapeHtml(u.team)}` : ""}
            </option>`).join("")}
        </select>
      </label>
      <label>Team (assignment group)
        <select name="team">
          <option value="">Assignee's own team</option>
          ${teams.map((t) => `
            <option value="${escapeHtml(t.name)}" ${(current && current.assigned_team) === t.name ? "selected" : ""}>
              ${escapeHtml(t.name)}
            </option>`).join("")}
        </select>
      </label>
      <label>Note for the assignee (optional)
        <textarea name="notes" rows="3" maxlength="2000"
          placeholder="Context, a link, or what to do first">${escapeHtml((current && current.notes) || "")}</textarea>
      </label>
      <p class="filter-count" style="margin:0">
        ${isAdmin
          ? "As an admin you can assign to anyone, in any team."
          : "You can assign to yourself or a teammate, within your own team."}
        Assigning to a different team moves this finding into that team's view.
      </p>
      <div class="assign-form-actions">
        <button type="submit">${current ? "Save reassignment" : "Assign"}</button>
        <button type="button" class="secondary-button" id="assign-cancel">Cancel</button>
        ${current && isAdmin ? `<button type="button" class="link-button danger-link" id="assign-clear">Remove assignment</button>` : ""}
      </div>
    </form>`);

  body.querySelector("#assign-cancel").addEventListener("click", closeModal);
  const clear = body.querySelector("#assign-clear");
  if (clear) {
    clear.addEventListener("click", async () => {
      if (!window.confirm(`Remove the assignment on ${findingId}? It goes back to its asset owner's team.`)) return;
      try {
        await api.unassignFinding(findingId);
        flash(`${findingId} unassigned.`, "success");
        closeModal();
        onSaved();
      } catch (err) {
        flash(err.message, "error");
      }
    });
  }
  body.querySelector("#assign-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    try {
      await api.assignFinding(findingId, {
        assignee_email: form.assignee_email.value || null,
        team: form.team.value || null,
        notes: form.notes.value.trim() || null,
      });
      flash(`${findingId} assigned.`, "success");
      closeModal();
      onSaved();
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
