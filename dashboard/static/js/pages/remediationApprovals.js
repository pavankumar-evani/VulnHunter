// Remediation Approvals: the real human-in-the-loop approve/reject action this app was
// missing for normal/emergency-change-type findings (see remediation/config/
// remediation_policy_engine.py) - distinct from Exceptions (which accepts risk instead
// of fixing). Requesting an approval schedules against the finding's already-resolved
// policy window; approving/rejecting is admin-gated server-side, and - if the policy
// names an AD approval group and AD is actually configured - the approve action is
// validated against a real, read-only LDAP group-membership lookup.
import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";
import { groupLabelFor } from "../domainGrouping.js";

export const title = "Remediation Approvals";

const PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"];
const STATUS_CLASS = {
  pending: "badge-medium", approved: "badge-auto_approvable", rejected: "badge-critical",
  expired: "badge-manual_only", remediation_triggered: "badge-auto_approvable",
};
const CHANGE_TYPE_CLASS = { emergency: "badge-critical", normal: "badge-medium", standard: "badge-auto_approvable" };

function windowText(w) {
  if (!w || !w.date) return "—";
  return `${w.date} (${w.day_of_week}) ${w.start_time}-${w.end_time} ${w.timezone}`;
}

// Renders `pagedRows` (each already carrying a `groupLabel`) into a tbody's innerHTML,
// with a divider row before every group change - including the very first row on a
// page, so a page that starts mid-group still shows which group it's in. Same pattern
// compensatingControls.js/threatIntel.js already use for their own domain-grouped
// tables. `allFilteredRows` (the full, pre-pagination set) is what each divider's own
// count is computed from, so it stays accurate even when a group spans multiple pages.
function groupedRowsHtml(pagedRows, allFilteredRows, rowHtml, colspan) {
  let lastGroupKey = null;
  const parts = [];
  for (const row of pagedRows) {
    if (row.groupLabel !== lastGroupKey) {
      const groupCount = allFilteredRows.filter((r) => r.groupLabel === row.groupLabel).length;
      parts.push(`<tr class="table-section-row"><td colspan="${colspan}">${escapeHtml(row.groupLabel)} (${groupCount})</td></tr>`);
      lastGroupKey = row.groupLabel;
    }
    parts.push(rowHtml(row));
  }
  return parts.join("");
}

function needsApprovalRow(f) {
  const policy = f.remediation_policy || {};
  return `
    <tr>
      <td>${escapeHtml(f.priority || "")}</td>
      <td>${escapeHtml(f.id)}</td>
      <td>${escapeHtml(f.title || "")}</td>
      <td>${escapeHtml((f.asset && f.asset.name) || "")}</td>
      <td><span class="badge ${CHANGE_TYPE_CLASS[policy.change_type] || ""}">${escapeHtml(policy.change_type || "")}</span></td>
      <td>${windowText(policy.next_window)}</td>
      <td>${policy.requires_approval_group ? escapeHtml(policy.requires_approval_group) : `<span class="muted">—</span>`}</td>
      <td><button type="button" class="link-button" data-request-approval="${escapeHtml(f.id)}">Request approval</button></td>
    </tr>`;
}

function stagingCellHtml(a) {
  if (a.staging_validated_by) {
    return `<span class="badge badge-auto_approvable" data-tooltip="ISO/IEC 27002:2022 §8.32 - tested before production approval">✓ ${escapeHtml(a.staging_validated_by)} on ${escapeHtml(a.staging_validated_at)}</span>`;
  }
  if (a.computed_status === "pending") {
    return `<button type="button" class="link-button" data-mark-staging-validated="${escapeHtml(a.id)}">Mark staging validated</button>`;
  }
  return `<span class="muted">—</span>`;
}

function rollbackPlanCellHtml(a) {
  if (!a.rollback_plan) return `<span class="muted" data-tooltip="No playbook generated for this finding yet">Not yet available</span>`;
  return `<span data-tooltip="${escapeHtml(a.rollback_plan)}">${escapeHtml(a.rollback_plan.split("\n")[0].slice(0, 60))}${a.rollback_plan.length > 60 ? "…" : ""}</span>`;
}

function approvalRow(a) {
  const status = a.computed_status;
  let decisionCell = `<span class="muted">—</span>`;
  if (status === "approved") {
    const validated = a.ad_group_validated;
    const note = validated === true ? "AD-verified" : validated === false ? "AD group NOT verified" : "AD not configured";
    decisionCell = `${escapeHtml(a.approved_by)} on ${escapeHtml(a.approved_at)} <span class="muted">(${note})</span>`;
  } else if (status === "rejected") {
    decisionCell = `${escapeHtml(a.rejected_by)} on ${escapeHtml(a.rejected_at)}${a.rejection_reason ? ` - ${escapeHtml(a.rejection_reason)}` : ""}`;
  } else if (status === "remediation_triggered") {
    decisionCell = `${escapeHtml(a.approved_by)} on ${escapeHtml(a.approved_at)} — remediation triggered by ${escapeHtml(a.triggered_by)} on ${escapeHtml(a.triggered_at)}`;
  }
  return `
    <tr>
      <td>${escapeHtml(a.id)}</td>
      <td>${escapeHtml(a.finding_id)}</td>
      <td>${escapeHtml(a.requested_by)}</td>
      <td>${windowText(a.scheduled_window)}</td>
      <td><span class="badge ${STATUS_CLASS[status] || ""}">${escapeHtml(status)}</span></td>
      <td>${decisionCell}</td>
      <td>${stagingCellHtml(a)}</td>
      <td>${rollbackPlanCellHtml(a)}</td>
      <td>
        <button type="button" class="link-button" data-communication="${escapeHtml(a.id)}">Communication</button>
        ${status === "pending" ? `
        <button type="button" class="link-button" data-approve="${escapeHtml(a.id)}">Approve</button>
        <button type="button" class="link-button" data-reject="${escapeHtml(a.id)}">Reject</button>
        ` : ""}
        ${status === "approved" ? `
        <button type="button" class="link-button" data-trigger-remediation="${escapeHtml(a.id)}" data-finding-id="${escapeHtml(a.finding_id)}">Trigger Remediation</button>
        ` : ""}
      </td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, { approvals }, directoryStatus] = await Promise.all([
    api.queue(), api.remediationApprovalsList(), api.directoryStatus(),
  ]);

  const findingsById = new Map(queue.findings.map((f) => [f.id, f]));
  const approvedFindingIds = new Set(approvals.map((a) => a.finding_id));
  const needsApprovalAll = queue.findings
    .filter((f) => {
      const ct = (f.remediation_policy || {}).change_type;
      return (ct === "normal" || ct === "emergency") && !approvedFindingIds.has(f.id);
    })
    .sort((a, b) => PRIORITY_ORDER.indexOf(a.priority) - PRIORITY_ORDER.indexOf(b.priority))
    .map((f) => ({ ...f, groupLabel: groupLabelFor(f) }));
  // Approval records aren't findings themselves - look up each one's real finding to
  // classify it into the same domain taxonomy every other grouped table in this app
  // uses. An approval whose finding has since disappeared from the live queue (a rare
  // edge case - e.g. a since-superseded sample-data regeneration) still gets a real,
  // honest "Unknown" bucket rather than crashing or silently dropping the row.
  const approvalsAll = approvals.map((a) => {
    const finding = findingsById.get(a.finding_id);
    return { ...a, groupLabel: finding ? groupLabelFor(finding) : "Unknown" };
  });

  const needsApprovalGroupLabels = [...new Set(needsApprovalAll.map((f) => f.groupLabel))].sort();
  const approvalsGroupLabels = [...new Set(approvalsAll.map((a) => a.groupLabel))].sort();
  const NEEDS_APPROVAL_COLSPAN = 8;
  const APPROVALS_COLSPAN = 9;

  let needsApprovalPage = 1;
  let needsApprovalGroupFilter = "all";
  let approvalsPage = 1;
  let approvalsGroupFilter = "all";

  function renderNeedsApprovalRows() {
    const filtered = needsApprovalGroupFilter === "all"
      ? needsApprovalAll : needsApprovalAll.filter((f) => f.groupLabel === needsApprovalGroupFilter);
    const paged = paginate(filtered, needsApprovalPage);
    needsApprovalPage = paged.page;
    const tbody = container.querySelector("#needs-approval-body");
    tbody.innerHTML = paged.rows.length
      ? groupedRowsHtml(paged.rows, filtered, needsApprovalRow, NEEDS_APPROVAL_COLSPAN)
      : `<tr><td colspan="${NEEDS_APPROVAL_COLSPAN}" class="empty-state">Nothing currently needs a new approval request.</td></tr>`;
    const paginationEl = container.querySelector("#needs-approval-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#needs-approval-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${needsApprovalAll.length} finding(s)`;
  }

  function renderApprovalsRows() {
    const filtered = approvalsGroupFilter === "all"
      ? approvalsAll : approvalsAll.filter((a) => a.groupLabel === approvalsGroupFilter);
    const paged = paginate(filtered, approvalsPage);
    approvalsPage = paged.page;
    const tbody = container.querySelector("#approvals-body");
    tbody.innerHTML = paged.rows.length
      ? groupedRowsHtml(paged.rows, filtered, approvalRow, APPROVALS_COLSPAN)
      : `<tr><td colspan="${APPROVALS_COLSPAN}" class="empty-state">No approval requests yet.</td></tr>`;
    const paginationEl = container.querySelector("#approvals-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#approvals-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${approvalsAll.length} approval(s)`;
  }

  container.innerHTML = `
    <p class="subtitle">
      Findings whose resolved <a href="/remediation-policy" data-link>remediation policy</a>
      requires a human approval click (change type normal/emergency) before their
      generated playbook is considered ready - approving here does not run anything
      against real infrastructure, it records who authorized it and when.
    </p>

    <div class="callout ${directoryStatus.configured ? "" : "callout-warn"}">
      ${directoryStatus.configured
        ? "Active Directory is configured - approving a finding whose policy names an approval group runs a real, read-only LDAP group-membership check."
        : "Active Directory is NOT configured on this server - approvals still work, but group membership is honestly reported as \"AD not configured\" rather than silently skipped or fabricated as verified. See the FAQ."}
    </div>

    <h2>Findings awaiting an approval request</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Grouped by security domain, same taxonomy as Compensating Controls/Threat Intel.
      See <a href="/queue" data-link>the full Remediation Queue</a> for every finding,
      including standard/auto-remediate ones with no approval gate.
    </p>
    <div class="filter-bar">
      <label>Domain
        <select id="needs-approval-f-group">
          <option value="all">All (${needsApprovalAll.length})</option>
          ${needsApprovalGroupLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="needs-approval-count"></span>
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Priority</th><th>ID</th><th>Title</th><th>Asset</th><th>Change Type</th>
            <th>Next Window</th><th>Approval Group</th><th></th>
          </tr>
        </thead>
        <tbody id="needs-approval-body"></tbody>
      </table>
    </div>
    <div id="needs-approval-pagination"></div>

    <h2 style="margin-top:28px">Approval requests</h2>
    <div class="filter-bar">
      <label>Domain
        <select id="approvals-f-group">
          <option value="all">All (${approvalsAll.length})</option>
          ${approvalsGroupLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="approvals-count"></span>
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Finding</th><th>Requested By</th><th>Scheduled Window</th>
            <th>Status</th><th>Decision</th><th>Staging Validation</th><th>Rollback Plan</th><th></th>
          </tr>
        </thead>
        <tbody id="approvals-body"></tbody>
      </table>
    </div>
    <div id="approvals-pagination"></div>`;

  renderNeedsApprovalRows();
  container.querySelector("#needs-approval-f-group").addEventListener("change", (e) => {
    needsApprovalGroupFilter = e.target.value;
    needsApprovalPage = 1;
    renderNeedsApprovalRows();
  });
  // Two independent paginated tables on one page - wirePagination() delegates clicks
  // on whatever element it's given, so scoping each call to its OWN pagination div
  // (not the whole page container) keeps the two tables' page state independent.
  wirePagination(container.querySelector("#needs-approval-pagination"), (p) => {
    needsApprovalPage = p;
    renderNeedsApprovalRows();
  });

  renderApprovalsRows();
  container.querySelector("#approvals-f-group").addEventListener("change", (e) => {
    approvalsGroupFilter = e.target.value;
    approvalsPage = 1;
    renderApprovalsRows();
  });
  wirePagination(container.querySelector("#approvals-pagination"), (p) => {
    approvalsPage = p;
    renderApprovalsRows();
  });

  // A single delegated listener (not six separate querySelectorAll().forEach() calls)
  // so every action button keeps working after renderNeedsApprovalRows()/
  // renderApprovalsRows() replace their tbody's innerHTML on a page or filter change -
  // same reasoning as assets.js's data-apply-suggestion/data-edit-owner handlers.
  // Several of these actions call render(container) again on success (a full
  // re-fetch+re-render), which would otherwise stack a duplicate copy of this same
  // listener on the persistent #app node every time - stashing the handler on the
  // container and removing any previous copy first keeps exactly one attached.
  if (container._remediationApprovalsClickHandler) {
    container.removeEventListener("click", container._remediationApprovalsClickHandler);
  }
  const onApprovalsClick = (e) => {
    const requestApprovalBtn = e.target.closest("[data-request-approval]");
    if (requestApprovalBtn) {
      const findingId = requestApprovalBtn.dataset.requestApproval;
      const body = openModal(`
        <h2>Request approval - ${escapeHtml(findingId)}</h2>
        <form class="run-form" id="request-approval-form">
          <label>Requested by
            <input type="text" name="requested_by" placeholder="you@example.com" required>
          </label>
          <button type="submit">Request</button>
        </form>`);
      body.querySelector("#request-approval-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          await api.remediationApprovalCreate(findingId, event.target.requested_by.value);
          closeModal();
          flash(`Approval requested for ${findingId}.`, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
      return;
    }

    const communicationBtn = e.target.closest("[data-communication]");
    if (communicationBtn) {
      const approvalId = communicationBtn.dataset.communication;
      const approval = approvals.find((a) => a.id === approvalId);
      const finding = findingsById.get(approval && approval.finding_id);
      const rendered = ((finding && finding.remediation_policy) || {}).rendered_communication
        || "No communication template configured for this finding's policy domain.";
      const body = openModal(`
        <h2>Downtime Communication - ${escapeHtml(approvalId)}</h2>
        <p class="subtitle">
          Rendered from this finding's resolved <a href="/remediation-policy" data-link>Remediation Policy</a>
          template. Sending uses the real SMTP configuration from
          <a href="/notification-settings" data-link>Notification Settings</a> - if SMTP isn't configured,
          sending will honestly fail rather than pretend to deliver.
        </p>
        <div class="callout" style="white-space:pre-wrap">${escapeHtml(rendered)}</div>
        <form class="run-form" id="send-communication-form">
          <label>Send to (email)
            <input type="email" name="recipient" placeholder="stakeholder@example.com" required>
          </label>
          <button type="submit">Send</button>
        </form>`);
      body.querySelector("#send-communication-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const result = await api.remediationApprovalSendCommunication(approvalId, event.target.recipient.value, true);
          closeModal();
          flash(result.message, "success");
        } catch (err) {
          flash(err.message, "error");
        }
      });
      return;
    }

    const approveBtn = e.target.closest("[data-approve]");
    if (approveBtn) {
      const approvalId = approveBtn.dataset.approve;
      const body = openModal(`
        <h2>Approve ${escapeHtml(approvalId)}</h2>
        <form class="run-form" id="approve-form">
          <label>Your name/email (approver)
            <input type="text" name="decided_by" placeholder="approver@example.com" required>
          </label>
          <button type="submit">Approve</button>
        </form>`);
      body.querySelector("#approve-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const result = await api.remediationApprovalApprove(approvalId, event.target.decided_by.value);
          closeModal();
          flash(result.message, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
      return;
    }

    const triggerBtn = e.target.closest("[data-trigger-remediation]");
    if (triggerBtn) {
      const findingId = triggerBtn.dataset.findingId;
      const body = openModal(`
        <h2>Trigger Remediation - ${escapeHtml(findingId)}</h2>
        <p class="subtitle">
          Generates this one finding's real Ansible playbook on demand (the same real
          <code>/remediate</code> pipeline <a href="/run" data-link>Run Pipeline</a>
          uses, scoped to just this finding) - a reviewable artifact for a human/
          change-management process to run, never applied to real infrastructure by
          this app. Preview first (free) - checking confirm calls the real Claude API
          and spends real usage/credits.
        </p>
        <form class="run-form" id="trigger-form">
          <label class="checkbox-label checkbox-danger">
            <input type="checkbox" name="confirm">
            I understand this spends real API usage/credits — actually generate the
            playbook (leave unchecked for a dry-run preview only)
          </label>
          <button type="submit">Submit</button>
        </form>
        <div id="trigger-result"></div>`);
      body.querySelector("#trigger-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const resultEl = body.querySelector("#trigger-result");
        try {
          const result = await api.runPost({
            pipeline: "remediate",
            fix_or_generate: true,
            finding_id: findingId,
            confirm: event.target.confirm.checked,
          });
          resultEl.innerHTML = `<div class="callout">${escapeHtml(result.message)}</div>`;
          if (!result.dry_run) {
            flash(result.message, result.exit_code === 0 ? "success" : "error");
            if (result.exit_code === 0) render(container);
          }
        } catch (err) {
          resultEl.innerHTML = `<p style="color:var(--danger)">${escapeHtml(err.message)}</p>`;
        }
      });
      return;
    }

    const stagingBtn = e.target.closest("[data-mark-staging-validated]");
    if (stagingBtn) {
      const approvalId = stagingBtn.dataset.markStagingValidated;
      const body = openModal(`
        <h2>Mark staging validated - ${escapeHtml(approvalId)}</h2>
        <p class="subtitle">
          Records that this change was tested in a staging/test environment before
          production approval (ISO/IEC 27002:2022 §8.32) - metadata only (who/when),
          not a live staging-environment integration. See the FAQ.
        </p>
        <form class="run-form" id="staging-validated-form">
          <label>Your name/email
            <input type="text" name="validated_by" placeholder="you@example.com" required>
          </label>
          <button type="submit">Record</button>
        </form>`);
      body.querySelector("#staging-validated-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const result = await api.remediationApprovalMarkStagingValidated(approvalId, event.target.validated_by.value);
          closeModal();
          flash(result.message, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
      return;
    }

    const rejectBtn = e.target.closest("[data-reject]");
    if (rejectBtn) {
      const approvalId = rejectBtn.dataset.reject;
      const body = openModal(`
        <h2>Reject ${escapeHtml(approvalId)}</h2>
        <form class="run-form" id="reject-form">
          <label>Your name/email
            <input type="text" name="decided_by" placeholder="approver@example.com" required>
          </label>
          <label>Reason
            <textarea name="reason" rows="3"></textarea>
          </label>
          <button type="submit">Reject</button>
        </form>`);
      body.querySelector("#reject-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          const result = await api.remediationApprovalReject(approvalId, event.target.decided_by.value, event.target.reason.value);
          closeModal();
          flash(result.message, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
      return;
    }
  };
  container._remediationApprovalsClickHandler = onApprovalsClick;
  container.addEventListener("click", onApprovalsClick);
}
