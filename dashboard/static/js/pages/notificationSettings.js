// Notification Settings: configure scheduled security reports (sub-domain/team-wise,
// weekly through yearly) and critical/zero-day/threat-intel email alerts to specific
// teams. Same YAML-text-editor-plus-admin-gated-save pattern as Priority Rules/Exploit
// Criteria, and the same dry-run-preview-by-default/explicit-confirm-to-spend pattern as
// AI Assist/ServiceNow/Jira for actually sending a test email - real SMTP delivery
// (remediation/notifications/email_sender.py) is env-var-configured and optional; every
// control on this page still works (as preview/config-only) without it configured.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { QUEUE_SCAN_TYPES, SCAN_TYPE_LABELS } from "../scanTypes.js";

export const title = "Notification Settings";

const CADENCES = ["weekly", "monthly", "quarterly", "half-yearly", "yearly"];
const ALERT_TYPES = [
  { value: "critical", label: "Critical Vulnerabilities" },
  { value: "zero_day", label: "Zero-Day Findings (KEV + Exploit Criteria match)" },
  { value: "threat_intel", label: "Threat Intel Matches (MITRE ATT&CK threat-actor group)" },
];

function scopeOptionsHtml(selected) {
  return `<option value="all" ${selected === "all" ? "selected" : ""}>All sub-domains (landscape-wide)</option>` +
    QUEUE_SCAN_TYPES.map((s) => `<option value="${s}" ${s === selected ? "selected" : ""}>${escapeHtml(SCAN_TYPE_LABELS[s])}</option>`).join("");
}

function statusCalloutHtml(status) {
  if (status.smtp_configured) {
    return `<div class="callout">
      ✅ SMTP is configured (sending from <code>${escapeHtml(status.from_address)}</code>).
      Scheduled reports and alerts below will actually deliver once enabled.
    </div>`;
  }
  return `<div class="callout callout-warn">
    ⚠️ SMTP is NOT configured on this server - scheduled reports/alerts below can be
    previewed and edited, but won't actually send until an admin sets
    <code>SMTP_HOST</code>, <code>SMTP_PORT</code>, and <code>SMTP_FROM_ADDRESS</code>
    (plus optionally <code>SMTP_USERNAME</code>/<code>SMTP_PASSWORD</code>/
    <code>SMTP_USE_TLS</code>) as real environment variables on this server and restart
    it. Due subscriptions are honestly skipped (never silently dropped) until then.
  </div>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [status, schedule, alerts, assetsData] = await Promise.all([
    api.notificationStatus(), api.getReportSchedule(), api.getAlertRules(), api.assetsList(),
  ]);
  const teams = [...new Set(assetsData.assets.map((a) => a.team).filter(Boolean))].sort();

  container.innerHTML = `
    <p class="subtitle">
      Scheduled security reports (weekly through yearly, scoped to one sub-domain and/or
      team) and real-time-ish email alerts for critical vulnerabilities, zero-day-style
      findings, and threat-intel-correlated findings - sent to specific sub-domain team
      recipients. Runs on an in-process timer while this server is alive (every
      ${Math.round(status.check_interval_seconds / 60)} min) - for delivery independent
      of server uptime, point a real external cron at "Run checks now" below instead.
    </p>

    ${statusCalloutHtml(status)}

    <h2 style="margin-top:24px">Scheduled reports</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      One subscription per sub-domain/team/cadence combination. Edit the YAML directly -
      see the comments in the file for the exact schema.
    </p>
    <form class="config-form" id="schedule-form">
      <textarea name="rules_text" spellcheck="false" rows="16">${escapeHtml(schedule.rules_text)}</textarea>
      <button type="submit">Save Report Schedule</button>
    </form>

    <h2 style="margin-top:28px">Team alert subscriptions</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      One subscription per alert type/sub-domain/team combination. An alert fires once
      per finding per subscription, not on every check.
    </p>
    <form class="config-form" id="alerts-form">
      <textarea name="rules_text" spellcheck="false" rows="16">${escapeHtml(alerts.rules_text)}</textarea>
      <button type="submit">Save Alert Rules</button>
    </form>

    <h2 style="margin-top:28px">Preview / send a test</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Build a real report or alert email from current live data without needing a saved
      subscription - useful for checking what a subscription would actually send before
      enabling it.
    </p>
    <form class="run-form" id="preview-form">
      <label>Kind
        <select name="kind" id="preview-kind">
          <option value="report">Scheduled report</option>
          <option value="alert">Team alert</option>
        </select>
      </label>
      <label>Sub-domain
        <select name="scope">${scopeOptionsHtml("all")}</select>
      </label>
      <label>Team
        <select name="team">
          <option value="">All teams</option>
          ${teams.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("")}
        </select>
      </label>
      <label id="preview-period-label">Cadence
        <select name="period">${CADENCES.map((c) => `<option value="${c}">${c[0].toUpperCase() + c.slice(1)}</option>`).join("")}</select>
      </label>
      <label id="preview-alert-type-label" hidden>Alert type
        <select name="alert_type">${ALERT_TYPES.map((a) => `<option value="${a.value}">${escapeHtml(a.label)}</option>`).join("")}</select>
      </label>
      <button type="submit">Preview</button>
    </form>

    <div id="preview-output"></div>

    <div style="margin-top:20px">
      <button type="button" class="secondary-button" id="run-checks-now">Run checks now</button>
      <span class="filter-count">Manually triggers the same scheduled-report and alert check the background timer runs - real sends if SMTP is configured.</span>
    </div>
    <div id="run-checks-output"></div>`;

  container.querySelector("#preview-kind").addEventListener("change", (e) => {
    const isAlert = e.target.value === "alert";
    container.querySelector("#preview-period-label").hidden = isAlert;
    container.querySelector("#preview-alert-type-label").hidden = !isAlert;
  });

  container.querySelector("#schedule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.saveReportSchedule(event.target.rules_text.value);
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#alerts-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.saveAlertRules(event.target.rules_text.value);
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  const previewOutput = container.querySelector("#preview-output");
  let lastPreviewBody = null;

  function renderPreview(body, result) {
    lastPreviewBody = body;
    const matchedNote = typeof result.matched_count === "number" ? `<p class="filter-count">${result.matched_count} finding(s) currently match.</p>` : "";
    previewOutput.innerHTML = `
      <h3>Subject</h3>
      <p><strong>${escapeHtml(result.subject)}</strong></p>
      ${matchedNote}
      <h3>Body (plain text)</h3>
      <pre class="code-block">${escapeHtml(result.body_text)}</pre>
      <div class="callout callout-warn" style="margin:14px 0">
        This is preview-only - nothing has been sent. Provide a real recipient and check
        confirm below to actually send this exact email via the configured SMTP relay.
      </div>
      <form class="run-form" id="send-test-form">
        <label>Recipient email
          <input type="email" name="recipient" placeholder="you@example.com" required>
        </label>
        <label class="checkbox-label checkbox-danger">
          <input type="checkbox" name="confirm" id="send-test-confirm">
          I understand this sends a real email via the configured SMTP relay
        </label>
        <button type="submit">Send test email</button>
      </form>
      <div id="send-test-result"></div>`;

    previewOutput.querySelector("#send-test-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.target;
      const resultEl = previewOutput.querySelector("#send-test-result");
      resultEl.innerHTML = `<div class="empty-state">Sending…</div>`;
      try {
        const sendResult = await api.notificationSendTest({
          ...lastPreviewBody, recipient: form.recipient.value, confirm: form.confirm.checked,
        });
        resultEl.innerHTML = "";
        flash(sendResult.message, sendResult.preview_only ? "info" : "success");
      } catch (err) {
        resultEl.innerHTML = "";
        flash(err.message, "error");
      }
    });
  }

  container.querySelector("#preview-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    const body = {
      kind: form.kind.value, scope: form.scope.value, team: form.team.value,
      period: form.period.value, alert_type: form.alert_type.value,
    };
    previewOutput.innerHTML = `<div class="empty-state">Building preview…</div>`;
    try {
      const result = await api.notificationPreview(body);
      renderPreview(body, result);
    } catch (err) {
      previewOutput.innerHTML = "";
      flash(err.message, "error");
    }
  });

  container.querySelector("#run-checks-now").addEventListener("click", async () => {
    const output = container.querySelector("#run-checks-output");
    output.innerHTML = `<div class="empty-state">Running checks…</div>`;
    try {
      const result = await api.notificationRunChecksNow();
      const rows = [...result.report_results, ...result.alert_results];
      output.innerHTML = rows.length
        ? `<div class="table-scroll"><table class="data-table">
            <thead><tr><th>Subscription</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>${rows.map((r) => `
              <tr>
                <td>${escapeHtml(r.id)}</td>
                <td><span class="badge badge-${r.status === "sent" ? "auto_approvable" : r.status === "error" ? "critical" : "medium"}">${escapeHtml(r.status)}</span></td>
                <td>${escapeHtml(r.reason || (r.recipients ? r.recipients.join(", ") : "") || (typeof r.new_count === "number" ? `${r.new_count} new` : ""))}</td>
              </tr>`).join("")}
            </tbody></table></div>`
        : `<p class="empty-state">No enabled subscription is currently due.</p>`;
    } catch (err) {
      output.innerHTML = "";
      flash(err.message, "error");
    }
  });
}
