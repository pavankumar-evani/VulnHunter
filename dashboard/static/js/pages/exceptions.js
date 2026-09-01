import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";
import { groupLabelFor } from "../domainGrouping.js";

export const title = "Vulnerability Exceptions";

const EXPORT_COLUMNS = [
  { label: "ID", value: (e) => e.id },
  { label: "Finding", value: (e) => e.finding_id },
  { label: "Domain", value: (e) => e.groupLabel },
  { label: "Reason", value: (e) => e.reason },
  { label: "Requested By", value: (e) => e.requested_by },
  { label: "Approved By", value: (e) => e.approved_by },
  { label: "Created", value: (e) => e.created_on },
  { label: "Expires", value: (e) => e.expires_on },
  { label: "Status", value: (e) => e.computed_status },
];

const STATUS_CLASS = { active: "badge-auto_approvable", expired: "badge-manual_only", revoked: "badge-critical" };
const EXPIRING_SOON_DAYS = 14;
const COLSPAN = 9;

// Real days-until-expiry from each exception's own `expires_on` (no snapshot storage
// needed - a plain date diff against "today"). Only meaningful for a currently-active
// exception; an already-expired/revoked one has nothing left to warn about.
function daysUntil(dateStr) {
  const ms = new Date(`${dateStr}T00:00:00`).getTime() - new Date(new Date().toDateString()).getTime();
  return Math.round(ms / 86400000);
}

function expiryCellHtml(e) {
  if (e.computed_status !== "active") return escapeHtml(e.expires_on);
  const days = daysUntil(e.expires_on);
  if (days <= EXPIRING_SOON_DAYS) {
    return `<span class="badge badge-medium" data-tooltip="Time-boxed risk acceptance - review before it lapses">` +
      `${escapeHtml(e.expires_on)} (${days <= 0 ? "expires today" : `${days}d left`})</span>`;
  }
  return escapeHtml(e.expires_on);
}

// A finding can independently be in the remediation-approval pipeline (see
// remediationApprovals.js) - the two workflows are deliberately different concepts
// (accept the risk vs. schedule the fix) but can end up running in parallel on the
// same finding without either side knowing about the other. Surfacing the real
// approval record here (if one exists) closes that gap without merging the two stores.
function approvalCellHtml(approval) {
  if (!approval) return `<span class="muted">—</span>`;
  return `<a href="/remediation-approvals" data-link data-tooltip="Also has a remediation approval in progress">` +
    `${escapeHtml(approval.computed_status)}</a>`;
}

function exceptionRow(e, approval) {
  const status = e.computed_status;
  return `
    <tr data-exception-id="${escapeHtml(e.id)}">
      <td>${escapeHtml(e.id)}</td>
      <td>${escapeHtml(e.finding_id)}</td>
      <td class="reason-cell" title="${escapeHtml(e.reason)}">${escapeHtml(e.reason)}</td>
      <td>${escapeHtml(e.requested_by)}</td>
      <td>${escapeHtml(e.approved_by)}</td>
      <td>${escapeHtml(e.created_on)}</td>
      <td>${expiryCellHtml(e)}</td>
      <td><span class="badge ${STATUS_CLASS[status] || ""}">${escapeHtml(status)}</span></td>
      <td>${approvalCellHtml(approval)}</td>
      <td>${status === "active" ? `<button type="button" class="link-button" data-revoke="${escapeHtml(e.id)}">Revoke</button>` : `<span class="muted">—</span>`}</td>
    </tr>`;
}

// Same divider-row-per-group pattern remediationApprovals.js/compensatingControls.js/
// threatIntel.js already use - `allFilteredRows` (pre-pagination) keeps each divider's
// own count accurate even when a group spans multiple pages. Each row's HTML is
// pre-baked onto it (see exceptionsAll below, which needs each row's approval lookup
// too), so this only has to stitch divider rows in, not render each row itself.
function groupedRowsHtml(pagedRows, allFilteredRows) {
  let lastGroupKey = null;
  const parts = [];
  for (const row of pagedRows) {
    if (row.groupLabel !== lastGroupKey) {
      const groupCount = allFilteredRows.filter((r) => r.groupLabel === row.groupLabel).length;
      parts.push(`<tr class="table-section-row"><td colspan="${COLSPAN}">${escapeHtml(row.groupLabel)} (${groupCount})</td></tr>`);
      lastGroupKey = row.groupLabel;
    }
    parts.push(row.rowHtml);
  }
  return parts.join("");
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ exceptions }, queue, { approvals }] = await Promise.all([
    api.exceptionsList(), api.queue(), api.remediationApprovalsList(),
  ]);

  // A finding-detail modal (findingDetail.js) can deep-link here with
  // ?finding_id=<id>&reason=<encoded text> - e.g. its EOL/EOS callout's "Request
  // exception" link - to preselect the finding and pre-fill the reason, so the person
  // doesn't have to re-find the finding or retype why. Both params are optional; the
  // form works exactly the same as before when neither is present.
  const params = new URLSearchParams(window.location.search);
  const prefillFindingId = params.get("finding_id") || "";
  const prefillReason = params.get("reason") || "";
  // A ?highlight=<exception-id> deep-link (from the Remediation Queue or Compensating
  // Controls' own exception badge) scrolls to and marks the matching row.
  const highlightId = params.get("highlight");

  const findingsById = new Map(queue.findings.map((f) => [f.id, f]));
  const approvalsByFindingId = new Map(approvals.map((a) => [a.finding_id, a]));

  const findingOptions = queue.findings.map((f) =>
    `<option value="${escapeHtml(f.id)}" ${f.id === prefillFindingId ? "selected" : ""}>${escapeHtml(f.id)} - ${escapeHtml(f.title)}</option>`).join("");

  // Each exception's domain is its finding's real domain (same taxonomy as
  // Compensating Controls/Threat Intel/Remediation Approvals) - a since-superseded
  // finding (rare) honestly falls back to "Unknown" rather than crashing or guessing.
  const exceptionsAll = exceptions.map((e) => {
    const finding = findingsById.get(e.finding_id);
    return { ...e, groupLabel: finding ? groupLabelFor(finding) : "Unknown", rowHtml: exceptionRow(e, approvalsByFindingId.get(e.finding_id)) };
  });
  const groupLabels = [...new Set(exceptionsAll.map((e) => e.groupLabel))].sort();

  let page = 1;
  let groupFilter = "all";

  function renderExceptionRows() {
    const filtered = groupFilter === "all" ? exceptionsAll : exceptionsAll.filter((e) => e.groupLabel === groupFilter);
    const paged = paginate(filtered, page);
    page = paged.page;
    const tbody = container.querySelector("#exceptions-body");
    tbody.innerHTML = paged.rows.length
      ? groupedRowsHtml(paged.rows, filtered)
      : `<tr><td colspan="${COLSPAN}" class="empty-state">No exceptions match the current filter.</td></tr>`;
    const paginationEl = container.querySelector("#exceptions-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#exceptions-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${exceptionsAll.length} exception(s)`;
  }

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

    <div id="highlight-note"></div>

    <h2>Request an exception</h2>
    <form class="run-form exception-form" id="exception-form">
      <fieldset class="exception-form-section">
        <legend>1. What needs an exception</legend>
        <label>Finding
          <select name="finding_id">${findingOptions}</select>
        </label>
        <div class="callout" id="approval-conflict-warning" style="margin:8px 0 0"></div>
      </fieldset>

      <fieldset class="exception-form-section">
        <legend>2. Why (reason / compensating control)</legend>
        <div class="callout" id="suggested-controls" style="margin:0 0 8px"></div>
        <textarea name="reason" rows="3" required>${escapeHtml(prefillReason)}</textarea>
      </fieldset>

      <fieldset class="exception-form-section">
        <legend>3. Approval chain</legend>
        <label>Requested by
          <input type="text" name="requested_by" placeholder="you@example.com" required>
        </label>
        <label>Approved by
          <input type="text" name="approved_by" placeholder="approver@example.com" required>
        </label>
      </fieldset>

      <fieldset class="exception-form-section">
        <legend>4. Time-box this exception</legend>
        <div class="exception-expiry-picker">
          <button type="button" class="secondary-button" data-expires-in="30">+30 days</button>
          <button type="button" class="secondary-button" data-expires-in="90">+90 days</button>
          <button type="button" class="secondary-button" data-expires-in="180">+180 days</button>
          <label>or pick a date
            <input type="date" name="expires_on" required>
          </label>
        </div>
        <p class="filter-count" id="expiry-preview" style="margin:6px 0 0"></p>
      </fieldset>

      <button type="submit">Request Exception</button>
    </form>

    <h2 style="margin-top:28px">Existing exceptions</h2>
    <div class="filter-bar">
      <label>Domain
        <select id="exceptions-f-group">
          <option value="all">All (${exceptionsAll.length})</option>
          ${groupLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="exceptions-count"></span>
      ${exceptions.length ? exportButtonsHtml("exceptions") : ""}
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Finding</th><th>Reason</th><th>Requested By</th>
            <th>Approved By</th><th>Created</th><th>Expires</th><th>Status</th>
            <th>Remediation Approval</th><th></th>
          </tr>
        </thead>
        <tbody id="exceptions-body"></tbody>
      </table>
    </div>
    <div id="exceptions-pagination"></div>`;

  function renderSuggestedControls(findingId) {
    const panel = container.querySelector("#suggested-controls");
    if (!panel) return;
    const finding = findingsById.get(findingId);
    const controls = (finding && finding.compensating_controls) || [];
    if (!controls.length) {
      panel.innerHTML = `<span class="muted">No suggested compensating controls for this finding.</span>`;
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

  // The exception and remediation-approval workflows are deliberately separate (see
  // remediation/exceptions/store.py's module docstring) - this only makes the overlap
  // VISIBLE when it exists, it never blocks either action, since both can legitimately
  // apply depending on context (e.g. an exception covering the gap until an already-
  // approved fix's next maintenance window arrives).
  function renderApprovalConflictWarning(findingId) {
    const panel = container.querySelector("#approval-conflict-warning");
    if (!panel) return;
    const approval = approvalsByFindingId.get(findingId);
    if (!approval) {
      panel.innerHTML = "";
      return;
    }
    panel.innerHTML = `
      This finding already has a <a href="/remediation-approvals" data-link>remediation
      approval</a> in progress (status: <strong>${escapeHtml(approval.computed_status)}</strong>,
      requested by ${escapeHtml(approval.requested_by)}) - requesting a risk-acceptance
      exception here runs in parallel with that scheduled-fix workflow rather than
      replacing it. Make sure that's actually what's intended before submitting.`;
  }

  function renderExpiryPreview() {
    const input = form.expires_on;
    const preview = container.querySelector("#expiry-preview");
    if (!input.value) {
      preview.textContent = "";
      return;
    }
    const days = daysUntil(input.value);
    preview.textContent = days >= 0
      ? `This exception will be active for ${days} day(s), until ${input.value}.`
      : `${input.value} is in the past - pick a future date.`;
  }

  const form = container.querySelector("#exception-form");
  renderSuggestedControls(form.finding_id.value);
  renderApprovalConflictWarning(form.finding_id.value);
  form.finding_id.addEventListener("change", () => {
    renderSuggestedControls(form.finding_id.value);
    renderApprovalConflictWarning(form.finding_id.value);
  });
  form.expires_on.addEventListener("change", renderExpiryPreview);
  container.querySelector(".exception-expiry-picker").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-expires-in]");
    if (!btn) return;
    const d = new Date();
    d.setDate(d.getDate() + Number(btn.dataset.expiresIn));
    form.expires_on.value = d.toISOString().slice(0, 10);
    renderExpiryPreview();
  });
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
    getRows: () => (groupFilter === "all" ? exceptionsAll : exceptionsAll.filter((e) => e.groupLabel === groupFilter)),
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-exceptions",
  });

  renderExceptionRows();
  container.querySelector("#exceptions-f-group").addEventListener("change", (e) => {
    groupFilter = e.target.value;
    page = 1;
    renderExceptionRows();
  });
  wirePagination(container.querySelector("#exceptions-pagination"), (p) => {
    page = p;
    renderExceptionRows();
  });

  // Delegated + stashed-and-removed on the container, same pattern assets.js/
  // remediationApprovals.js use - renderExceptionRows() replaces the tbody on every
  // page/filter change, and a successful revoke calls render(container) again (a full
  // re-fetch), either of which would otherwise leave stale or stacked listeners.
  if (container._exceptionsClickHandler) {
    container.removeEventListener("click", container._exceptionsClickHandler);
  }
  const onExceptionsClick = (e) => {
    const revokeBtn = e.target.closest("[data-revoke]");
    if (!revokeBtn) return;
    api.exceptionRevoke(revokeBtn.dataset.revoke)
      .then(() => {
        flash(`${revokeBtn.dataset.revoke} revoked.`, "success");
        render(container);
      })
      .catch((err) => flash(err.message, "error"));
  };
  container._exceptionsClickHandler = onExceptionsClick;
  container.addEventListener("click", onExceptionsClick);

  if (highlightId) {
    const noteEl = container.querySelector("#highlight-note");
    const row = container.querySelector(`[data-exception-id="${CSS.escape(highlightId)}"]`);
    if (row) {
      row.classList.add("row-highlight");
      row.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (noteEl) {
      noteEl.innerHTML = `<div class="callout callout-warn">Exception <code>${escapeHtml(highlightId)}</code> was not found (it may be on a different page/filter - try "All").</div>`;
    }
  }
}
