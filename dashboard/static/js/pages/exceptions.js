import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Vulnerability Exceptions";

const STATUS_CLASS = { active: "badge-auto_approvable", expired: "badge-manual_only", revoked: "badge-critical" };

function exceptionRow(e) {
  const status = e.computed_status;
  return `
    <tr>
      <td>${escapeHtml(e.id)}</td>
      <td>${escapeHtml(e.finding_id)}</td>
      <td class="reason-cell" title="${escapeHtml(e.reason)}">${escapeHtml(e.reason)}</td>
      <td>${escapeHtml(e.requested_by)}</td>
      <td>${escapeHtml(e.approved_by)}</td>
      <td>${escapeHtml(e.created_on)}</td>
      <td>${escapeHtml(e.expires_on)}</td>
      <td><span class="badge ${STATUS_CLASS[status] || ""}">${escapeHtml(status)}</span></td>
      <td>${status === "active" ? `<button type="button" class="link-button" data-revoke="${escapeHtml(e.id)}">Revoke</button>` : `<span class="muted">—</span>`}</td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ exceptions }, queue] = await Promise.all([api.exceptionsList(), api.queue()]);
  const findingOptions = queue.findings.map((f) => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.id)} - ${escapeHtml(f.title)}</option>`).join("");

  container.innerHTML = `
    <p class="subtitle">
      A documented, time-boxed risk-acceptance workflow for findings that can't be
      remediated on schedule - a compensating control is in place, no vendor patch
      exists yet, or the asset is being decommissioned.
    </p>
    <div class="callout callout-warn">
      An active exception is shown here and on the Remediation Queue, but does not yet
      pause SLA-breach counting in the priority engine - see
      <code>remediation/exceptions/store.py</code>'s module docstring for that scope
      limit.
    </div>

    <h2>Request an exception</h2>
    <form class="run-form" id="exception-form">
      <label>Finding
        <select name="finding_id">${findingOptions}</select>
      </label>
      <label>Reason / compensating control
        <textarea name="reason" rows="3" required></textarea>
      </label>
      <label>Requested by
        <input type="text" name="requested_by" placeholder="you@example.com" required>
      </label>
      <label>Approved by
        <input type="text" name="approved_by" placeholder="approver@example.com" required>
      </label>
      <label>Expires on
        <input type="date" name="expires_on" required>
      </label>
      <button type="submit">Request Exception</button>
    </form>

    <h2>Existing exceptions</h2>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Finding</th><th>Reason</th><th>Requested By</th>
            <th>Approved By</th><th>Created</th><th>Expires</th><th>Status</th><th></th>
          </tr>
        </thead>
        <tbody id="exceptions-body">${exceptions.length ? exceptions.map(exceptionRow).join("") : ""}</tbody>
      </table>
      ${!exceptions.length ? `<p class="empty-state">No exceptions requested yet.</p>` : ""}
    </div>`;

  const form = container.querySelector("#exception-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api.exceptionCreate({
        finding_id: form.finding_id.value,
        reason: form.reason.value,
        requested_by: form.requested_by.value,
        approved_by: form.approved_by.value,
        expires_on: form.expires_on.value,
      });
      flash("Exception recorded.", "success");
      render(container);
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api.exceptionRevoke(btn.dataset.revoke);
        flash(`${btn.dataset.revoke} revoked.`, "success");
        render(container);
      } catch (err) {
        flash(err.message, "error");
      }
    });
  });
}
