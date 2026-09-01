// Admin Settings: the one place an admin configures things that affect every user of
// this app - which model every real Claude Code call should use, an optional per-user
// daily token cap (enforced server-side, see dashboard/app.py's _enforce_ai_usage_limit),
// and real per-user AI usage/cost. Deliberately does NOT try to expose SMTP/session-
// secret/storage-limit-style settings as editable here - those are real environment
// variables this running web process can't safely rewrite for itself; they're shown
// read-only (from the same /api/status every page's footer already uses) so an admin
// can see what's configured without a false "edit this from the UI" promise.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { getCurrentUser } from "../auth.js";
import { CONNECTORS } from "../adaptorCatalog.js";

export const title = "Admin Settings";

const MODEL_LABELS = { sonnet: "Sonnet", opus: "Opus", fable: "Fable" };

function usageRowHtml(email, allTime, today) {
  const at = allTime || { call_count: 0, total_tokens: 0, total_cost_usd: 0, unknown_cost_calls: 0 };
  const td = today || { total_tokens: 0 };
  return `
    <tr>
      <td>${escapeHtml(email)}</td>
      <td>${at.call_count}</td>
      <td>${at.total_tokens.toLocaleString()}</td>
      <td>$${at.total_cost_usd.toFixed(4)}</td>
      <td>${td.total_tokens.toLocaleString()}</td>
      <td>${at.unknown_cost_calls ? `<span class="badge badge-medium" data-tooltip="A response came back but this app couldn't find usage figures in it - see ai_usage_log.py">${at.unknown_cost_calls}</span>` : `<span class="muted">0</span>`}</td>
    </tr>`;
}

function overrideRowHtml(email, limit) {
  return `
    <tr data-override-email="${escapeHtml(email)}">
      <td>${escapeHtml(email)}</td>
      <td>${limit === null ? "Unlimited" : limit.toLocaleString()}</td>
      <td><button type="button" class="link-button" data-remove-override="${escapeHtml(email)}">Remove</button></td>
    </tr>`;
}

function formatUptime(seconds) {
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m ${s % 60}s`;
}

function timeAgo(isoString) {
  if (!isoString) return "never";
  const ms = Date.now() - new Date(isoString).getTime();
  const mins = Math.round(ms / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// Real, honest facts only: exists/last-modified/record-count for each gitignored
// runtime data store /api/status actually reads from disk. No fabricated "connected"
// state - a store that has never been written to just says so.
function dataStoreRowHtml(label, fact) {
  if (!fact.exists) {
    return `<tr><td>${escapeHtml(label)}</td><td colspan="2" class="muted">Not created yet (no data written)</td></tr>`;
  }
  return `
    <tr>
      <td>${escapeHtml(label)}</td>
      <td>${fact.record_count === null ? `<span class="badge badge-medium" data-tooltip="${escapeHtml(fact.error || "")}">Unreadable</span>` : `${fact.record_count.toLocaleString()} record(s)`}</td>
      <td>${timeAgo(fact.last_modified)}</td>
    </tr>`;
}

// Connector/adaptor health, reusing adaptorCatalog.js's own live/reference status -
// one definition of "what's actually wired up," not a second copy that could drift.
// "Live" means a real dashboard page with a working preview/send form exists; none of
// them store credentials server-side (each call takes credentials fresh from the
// request), so there is nothing persistent to health-ping from here - the honest
// on-demand test is the "Open ->" link into that connector's own preview form.
function connectorHealthHtml() {
  const live = CONNECTORS.filter((c) => c.status === "live");
  const reference = CONNECTORS.filter((c) => c.status === "reference");
  return `
    <p class="filter-count" style="margin:-4px 0 8px">
      <strong>${live.length}</strong> connector(s) have a real, working preview/send
      form wired into this dashboard; <strong>${reference.length}</strong> more are
      catalogued (real API/auth facts) but not yet wired to a page. None store
      credentials server-side - test a live connector from its own page, where you
      enter credentials fresh each time.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Connector</th><th>Category</th><th>Status</th><th></th></tr></thead>
        <tbody>
          ${live.map((c) => `
            <tr>
              <td>${escapeHtml(c.label)}</td>
              <td>${escapeHtml(c.category)}</td>
              <td><span class="badge badge-low">Wired</span></td>
              <td><a href="/adaptors?connector=${encodeURIComponent(c.key)}" data-link>Open →</a></td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
    <details style="margin-top:10px">
      <summary>${reference.length} reference-only connectors (not yet wired)</summary>
      <div class="table-scroll" style="margin-top:8px">
        <table class="data-table">
          <thead><tr><th>Connector</th><th>Category</th></tr></thead>
          <tbody>
            ${reference.map((c) => `<tr><td>${escapeHtml(c.label)}</td><td>${escapeHtml(c.category)}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    </details>`;
}

function budgetSectionHtml(budget) {
  const row = (label, r) => `
    <tr>
      <td>${label}</td>
      <td>${r.call_count}</td>
      <td>${r.total_tokens.toLocaleString()}</td>
      <td>$${r.total_cost_usd.toFixed(4)}</td>
      <td>${r.unknown_cost_calls ? `<span class="badge badge-medium">${r.unknown_cost_calls}</span>` : `<span class="muted">0</span>`}</td>
    </tr>`;
  return `
    <p class="filter-count" style="margin:-4px 0 8px">
      There is no subscription/invoice system in this app - the only real dollar
      figures are actual Claude API spend, aggregated below from every recorded call,
      and the real per-call spend cap (<code>--max-budget-usd</code>) this app passes
      to every Claude Code invocation.
    </p>
    <div class="kpi-grid" style="margin-bottom:14px">
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.3rem">$${budget.max_cost_usd_per_call.toFixed(2)}</div>
        <div class="kpi-label">Spend cap per AI call</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.3rem">$${budget.today.total_cost_usd.toFixed(4)}</div>
        <div class="kpi-label">Spent today, all users</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.3rem">$${budget.all_time.total_cost_usd.toFixed(4)}</div>
        <div class="kpi-label">Spent all-time, all users</div>
      </div>
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Window</th><th>Calls</th><th>Tokens</th><th>Cost</th><th>Unknown-usage calls</th></tr></thead>
        <tbody>
          ${row("Today", budget.today)}
          ${row("Last 7 days", budget.last_7_days)}
          ${row("Last 30 days", budget.last_30_days)}
          ${row("All-time", budget.all_time)}
        </tbody>
      </table>
    </div>`;
}

export async function render(container) {
  const user = await getCurrentUser(true);
  if (!user) {
    window.history.pushState({}, "", "/login?redirect=/admin");
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }
  if (user.role !== "admin") {
    container.innerHTML = `
      <div class="callout callout-warn">
        Admins only - this page configures AI model policy and token limits that affect
        every user of this app. Signed in as <strong>${escapeHtml(user.email)}</strong>
        (role: ${escapeHtml(user.role)}).
      </div>`;
    return;
  }

  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [governance, usageData, status] = await Promise.all([
    api.getAiGovernance(), api.aiUsage(), api.status(),
  ]);

  let overrides = { ...governance.per_user_overrides };

  function renderOverrides() {
    const body = container.querySelector("#overrides-body");
    const rows = Object.entries(overrides);
    body.innerHTML = rows.length
      ? rows.map(([email, limit]) => overrideRowHtml(email, limit)).join("")
      : `<tr><td colspan="3" class="empty-state">No per-user overrides - everyone uses the default limit above.</td></tr>`;
  }

  function usersUnion() {
    return [...new Set([...Object.keys(usageData.all_time_by_user), ...Object.keys(usageData.today_by_user)])].sort();
  }

  container.innerHTML = `
    <p class="subtitle">
      Admin-only configuration that affects every user - which real Claude Code model
      to use, an optional per-user daily token cap (enforced server-side before a real
      call is made, never trusted from the client), and real recorded usage/cost per
      user.
    </p>

    <h2>AI Model Policy</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Passed as Claude Code's own real <code>--model</code> flag (verified via
      <code>claude --help</code>) to every AI Assist, AI Trend Analysis, Code Scan
      (<code>/vulnhunt</code>), and Remediation (<code>/remediate</code>) call this app
      makes. "No preference" omits the flag entirely - Claude Code picks its own default.
    </p>
    <form class="run-form" id="model-form">
      <label>Model
        <select name="default_model">
          <option value="">No preference (Claude Code's own default)</option>
          ${Object.entries(MODEL_LABELS).map(([value, label]) =>
            `<option value="${value}" ${governance.default_model === value ? "selected" : ""}>${label}</option>`).join("")}
        </select>
      </label>
      <button type="submit">Save model policy</button>
    </form>

    <h2 style="margin-top:28px">Daily Token Limits</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      A real, server-side cap (<code>remediation/audit/ai_usage_log.py</code>'s
      <code>would_exceed_limit()</code>) checked before every real AI call - a user over
      their limit gets a real 429 rejection instead of the call ever being made. Leave
      blank for unlimited (the default - opt-in, not a surprise restriction).
    </p>
    <form class="run-form" id="limit-form">
      <label>Default daily limit per user (tokens)
        <input type="number" name="daily_token_limit_per_user" min="0" step="1000"
               placeholder="Unlimited" value="${governance.daily_token_limit_per_user ?? ""}">
      </label>
      <button type="submit">Save default limit</button>
    </form>

    <h3 style="margin-top:20px">Per-user overrides</h3>
    <p class="filter-count" style="margin:-4px 0 8px">Takes precedence over the default limit above for that one user.</p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>User</th><th>Daily limit (tokens)</th><th></th></tr></thead>
        <tbody id="overrides-body"></tbody>
      </table>
    </div>
    <form class="run-form" id="add-override-form" style="margin-top:12px">
      <label>User email<input type="email" name="email" placeholder="user@example.com" required></label>
      <label>Daily limit (tokens)<input type="number" name="limit" min="0" step="1000" required></label>
      <button type="submit">Add / update override</button>
    </form>

    <h2 style="margin-top:28px">Real AI Usage by User</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Every figure below comes straight from this app's own recorded calls - nothing
      estimated or fabricated. "Unknown-usage calls" are real calls whose response
      didn't include figures this app could find (see the module docstring in
      <code>ai_usage_log.py</code>) - not silently counted as zero cost.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr><th>User</th><th>Calls (all-time)</th><th>Tokens (all-time)</th><th>Cost (all-time)</th><th>Tokens (today)</th><th>Unknown-usage calls</th></tr>
        </thead>
        <tbody>
          ${usersUnion().length
            ? usersUnion().map((email) => usageRowHtml(email, usageData.all_time_by_user[email], usageData.today_by_user[email])).join("")
            : `<tr><td colspan="6" class="empty-state">No real AI calls recorded yet.</td></tr>`}
        </tbody>
      </table>
    </div>

    <h2 style="margin-top:28px">AI Spend vs. Budget</h2>
    ${budgetSectionHtml(usageData.budget)}

    <h2 style="margin-top:28px">System Health</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Real, live-checked facts from <code>/api/status</code> - SMTP and the session
      secret are environment variables this running server can't safely rewrite for
      itself, so they're shown read-only here; see <code>dashboard/README.md</code> to
      configure them.
    </p>
    <div class="kpi-grid">
      <div class="kpi-card ${status.status === "ok" ? "kpi-good" : "kpi-danger"}">
        <div class="kpi-value" style="font-size:1.1rem;text-transform:uppercase">${escapeHtml(status.status)}</div>
        <div class="kpi-label">Overall status</div>
      </div>
      <div class="kpi-card kpi-good">
        <div class="kpi-value" style="font-size:1.1rem">${formatUptime(status.uptime_seconds)}</div>
        <div class="kpi-label">Server uptime (this process)</div>
      </div>
      <div class="kpi-card ${status.notification_scheduler_alive ? "kpi-good" : "kpi-danger"}">
        <div class="kpi-value" style="font-size:1.1rem">${status.notification_scheduler_alive ? "Running" : "Stopped"}</div>
        <div class="kpi-label">Notification scheduler</div>
      </div>
      <div class="kpi-card ${status.smtp_configured ? "kpi-good" : ""}">
        <div class="kpi-value" style="font-size:1.1rem">${status.smtp_configured ? "Configured" : "Not configured"}</div>
        <div class="kpi-label">SMTP (scheduled reports/alerts)</div>
      </div>
      <div class="kpi-card ${status.session_secret_configured ? "kpi-good" : "kpi-warn"}">
        <div class="kpi-value" style="font-size:1.1rem">${status.session_secret_configured ? "Configured" : "Random (per-process)"}</div>
        <div class="kpi-label">Session secret</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.1rem">${status.threat_intel.available ? "Available" : "Unavailable"}</div>
        <div class="kpi-label">Threat intel (CISA KEV/FIRST.org EPSS)</div>
      </div>
    </div>
    ${status.remediation_findings_error ? `<div class="callout callout-danger" style="margin-top:12px">Findings file error: ${escapeHtml(status.remediation_findings_error)}</div>` : ""}

    <h3 style="margin-top:20px">Data store freshness</h3>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Store</th><th>Size</th><th>Last written</th></tr></thead>
        <tbody>
          ${dataStoreRowHtml("Exceptions", status.data_stores.exceptions)}
          ${dataStoreRowHtml("Remediation approvals", status.data_stores.remediation_approvals)}
          ${dataStoreRowHtml("Activity log", status.data_stores.activity_log)}
          ${dataStoreRowHtml("AI usage log", status.data_stores.ai_usage_log)}
        </tbody>
      </table>
    </div>

    <h2 style="margin-top:28px">Connector / Adaptor Health</h2>
    ${connectorHealthHtml()}`;

  renderOverrides();

  container.querySelector("#model-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const saved = await api.saveAiGovernance({
        default_model: event.target.default_model.value || null,
        daily_token_limit_per_user: governance.daily_token_limit_per_user,
        per_user_overrides: overrides,
      });
      governance.default_model = saved.default_model;
      flash("Model policy saved.", "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#limit-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = event.target.daily_token_limit_per_user.value;
    try {
      const saved = await api.saveAiGovernance({
        default_model: governance.default_model,
        daily_token_limit_per_user: raw === "" ? null : Number(raw),
        per_user_overrides: overrides,
      });
      governance.daily_token_limit_per_user = saved.daily_token_limit_per_user;
      flash("Default token limit saved.", "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#add-override-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = event.target.email.value.trim();
    const limit = Number(event.target.limit.value);
    const next = { ...overrides, [email]: limit };
    try {
      await api.saveAiGovernance({
        default_model: governance.default_model,
        daily_token_limit_per_user: governance.daily_token_limit_per_user,
        per_user_overrides: next,
      });
      overrides = next;
      renderOverrides();
      flash(`Override saved for ${email}.`, "success");
      event.target.reset();
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#overrides-body").addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-remove-override]");
    if (!btn) return;
    const email = btn.dataset.removeOverride;
    const next = { ...overrides };
    delete next[email];
    try {
      await api.saveAiGovernance({
        default_model: governance.default_model,
        daily_token_limit_per_user: governance.daily_token_limit_per_user,
        per_user_overrides: next,
      });
      overrides = next;
      renderOverrides();
      flash(`Override removed for ${email}.`, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
