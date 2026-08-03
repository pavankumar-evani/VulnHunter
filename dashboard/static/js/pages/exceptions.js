import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";

export const title = "Vulnerability Exceptions";

const EXPORT_COLUMNS = [
  { label: "ID", value: (e) => e.id },
  { label: "Finding", value: (e) => e.finding_id },
  { label: "Reason", value: (e) => e.reason },
  { label: "Requested By", value: (e) => e.requested_by },
  { label: "Approved By", value: (e) => e.approved_by },
  { label: "Created", value: (e) => e.created_on },
  { label: "Expires", value: (e) => e.expires_on },
  { label: "Status", value: (e) => e.computed_status },
];

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

      <div class="callout" id="suggested-controls" style="margin:4px 0 0"></div>

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
    ${exceptions.length ? exportButtonsHtml("exceptions") : ""}
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

  const findingsById = new Map(queue.findings.map((f) => [f.id, f]));

  function renderSuggestedControls(findingId) {
    const panel = container.querySelector("#suggested-controls");
    if (!panel) return;
    const finding = findingsById.get(findingId);
    const controls = (finding && finding.compensating_controls) || [];
    if (!controls.length) {
      panel.innerHTML = "";
      return;
    }
    panel.innerHTML = `
      <strong>Suggested compensating controls</strong> (keyword heuristic, not certified
      - see <code>remediation/enrichment/compensating_controls.py</code>):
      <ul style="margin:8px 0 0; padding-left:20px">
        ${controls.map((c) => `
          <li style="margin-bottom:4px">
            ${escapeHtml(c)}
            <button type="button" class="link-button" data-insert-control="${escapeHtml(c)}">Insert</button>
          </li>`).join("")}
      </ul>`;
  }

  const form = container.querySelector("#exception-form");
  renderSuggestedControls(form.finding_id.value);
  form.finding_id.addEventListener("change", () => renderSuggestedControls(form.finding_id.value));
  container.querySelector("#suggested-controls").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-insert-control]");
    if (!btn) return;
    const reasonField = form.reason;
    reasonField.value = reasonField.value ? `${reasonField.value}\n${btn.dataset.insertControl}` : btn.dataset.insertControl;
    reasonField.focus();
  });

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

  wireExportButtons(container, "exceptions", {
    getRows: () => exceptions,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-exceptions",
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
