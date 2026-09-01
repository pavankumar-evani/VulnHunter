// Activity Log: real who/what/when audit trail (remediation/audit/activity_log.py) -
// every asset edit, exception revocation, approval decision, login attempt, bulk
// asset-policy apply, and remediation trigger elsewhere in this app writes here. Plus a
// real, non-ML summary (works at any volume) and a real IsolationForest anomaly layer
// over per-actor behavior once there's enough genuine history to fit on honestly - see
// remediation/enrichment/activity_insights.py's module docstring for why a fresh
// checkout starts with none of that yet, by design.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";

export const title = "Activity Log";

const ACTION_LABELS = {
  "asset.set_owner": "Asset owner changed",
  "asset.set_facing": "Asset facing changed",
  "asset.set_environment": "Asset environment changed",
  "asset.set_remediation_schedule": "Asset remediation schedule changed",
  "exception.create": "Exception created",
  "exception.revoke": "Exception revoked",
  "approval.request": "Remediation approval requested",
  "approval.approve": "Remediation approval approved",
  "approval.reject": "Remediation approval rejected",
  "login.success": "Login succeeded",
  "login.failure": "Login failed",
};

function actionLabel(action) {
  return ACTION_LABELS[action] || action;
}

function detailsText(details) {
  if (!details || !Object.keys(details).length) return "—";
  return Object.entries(details).map(([k, v]) => `${k}: ${v}`).join(", ");
}

function rowHtml(e) {
  return `
    <tr>
      <td>${escapeHtml(e.timestamp)}</td>
      <td>${escapeHtml(e.actor)}</td>
      <td>${escapeHtml(actionLabel(e.action))}</td>
      <td>${escapeHtml(e.target || "—")}</td>
      <td>${escapeHtml(detailsText(e.details))}</td>
    </tr>`;
}

const EXPORT_COLUMNS = [
  { label: "Timestamp", value: (e) => e.timestamp },
  { label: "Actor", value: (e) => e.actor },
  { label: "Action", value: (e) => actionLabel(e.action) },
  { label: "Target", value: (e) => e.target },
  { label: "Details", value: (e) => detailsText(e.details) },
];

function unusualActorRowHtml(r) {
  return `
    <tr>
      <td>${escapeHtml(r.actor)}</td>
      <td>${r.action_count}</td>
      <td>${(r.off_hours_fraction * 100).toFixed(0)}%</td>
      <td>${(r.self_approval_fraction * 100).toFixed(0)}%</td>
      <td><code>${r.anomaly_score}</code></td>
      <td>${r.reasons.length
        ? `<ul style="margin:0; padding-left:18px">${r.reasons.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`
        : `<span class="muted">—</span>`}</td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;

  const [logData, insights] = await Promise.all([
    api.activityLog({ limit: 1000 }),
    api.activityLogInsights(),
  ]);

  const entries = logData.entries;
  const summary = insights.summary;
  const unusualActors = insights.unusual_actors;

  let page = 1;
  let actionFilter = "all";

  function currentSlice() {
    return actionFilter === "all" ? entries : entries.filter((e) => e.action === actionFilter);
  }

  function renderRows() {
    const sliced = currentSlice();
    const paged = paginate(sliced, page);
    page = paged.page;
    const tbody = container.querySelector("#activity-body");
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="5" class="empty-state">No activity recorded yet.</td></tr>`;
    const paginationEl = container.querySelector("#activity-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#activity-count");
    if (countEl) countEl.textContent = `${sliced.length} of ${entries.length} entr${sliced.length === 1 ? "y" : "ies"}`;
  }

  const actionOptions = [...new Set(entries.map((e) => e.action))].sort();

  const unusualActorsSection = unusualActors.length
    ? `
      <h3 style="margin-top:28px">Unusual Activity (real IsolationForest, per-actor)</h3>
      <p class="subtitle">
        Real anomaly detection over per-actor behavior (action volume, action-type
        diversity, off-hours fraction, self-approval fraction) - fit fresh against this
        app's own real activity log once there's enough genuine history. Not predictive
        and never blocks anything; purely advisory.
      </p>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Actor</th><th>Actions</th><th>Off-hours %</th><th>Self-approval %</th><th>Anomaly score</th><th>Why flagged</th></tr></thead>
          <tbody>${unusualActors.filter((r) => r.is_anomaly).map(unusualActorRowHtml).join("") || `<tr><td colspan="6" class="empty-state">Nothing unusual detected.</td></tr>`}</tbody>
        </table>
      </div>`
    : `
      <h3 style="margin-top:28px">Unusual Activity</h3>
      <div class="callout">
        Not enough real activity history yet to fit anomaly detection on honestly (see
        <code>remediation/enrichment/activity_insights.py</code>'s real, enforced
        floor) - this is expected on a freshly-checked-out demo. As real activity
        accumulates (asset edits, approvals, logins), this section activates on its own;
        nothing here is ever backfilled with fabricated history.
      </div>`;

  container.innerHTML = `
    <p class="subtitle">
      Real, unified who/what/when feed (<code>remediation/audit/activity_log.py</code>) -
      every asset edit, exception revocation, remediation-approval decision, login
      attempt, bulk asset-policy apply, and remediation trigger elsewhere in this app
      writes here. Append-only - never edited or backdated.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${summary.total}</div><div class="kpi-label">Total real activity entries</div></div>
      <div class="kpi-card"><div class="kpi-value">${Object.keys(summary.by_actor).length}</div><div class="kpi-label">Distinct actors</div></div>
      <div class="kpi-card"><div class="kpi-value">${Object.keys(summary.by_action).length}</div><div class="kpi-label">Distinct action types</div></div>
      <div class="kpi-card"><div class="kpi-value">${summary.most_recent_timestamp ? escapeHtml(summary.most_recent_timestamp) : "—"}</div><div class="kpi-label">Most recent activity</div></div>
    </div>

    <h3>Activity Feed</h3>
    <div class="filter-bar">
      <label>Action
        <select id="f-action">
          <option value="all">All</option>
          ${actionOptions.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(actionLabel(a))}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="activity-count"></span>
    </div>
    ${exportButtonsHtml("activity-log")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
        <tbody id="activity-body"></tbody>
      </table>
    </div>
    <div id="activity-pagination"></div>

    ${unusualActorsSection}`;

  renderRows();

  container.querySelector("#f-action").addEventListener("change", (e) => {
    actionFilter = e.target.value;
    page = 1;
    renderRows();
  });

  wirePagination(container, (p) => { page = p; renderRows(); });

  wireExportButtons(container, "activity-log", {
    getRows: () => currentSlice(),
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-activity-log",
  });
}
