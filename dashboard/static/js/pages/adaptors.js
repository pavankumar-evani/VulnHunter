// Consolidated Adaptors hub: one page, one dropdown/filter selector, instead of six
// separate sidebar entries spread across four different "Adaptors — X" group headings.
// Selecting a connector dynamically renders its existing settings/preview panel below -
// reuses each connector's existing page module as-is (servicenow.js, jira.js, etc.),
// no changes to those modules. New "reference" catalog entries (no live preview yet)
// render a documented-facts panel instead of a form - see adaptorCatalog.js.
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { CATEGORIES, CONNECTORS, connectorByKey } from "../adaptorCatalog.js";

export const title = "Connectors / Adaptors";

function referencePanelHtml(c) {
  return `
    <div class="callout callout-warn">
      ⚠️ <strong>${escapeHtml(c.label)}</strong> is a reference catalog entry, not a
      working preview/send connector yet - the facts below are real (auth model, API
      shape, what data would flow), but there's no code in this repo talking to it yet.
      This is one step earlier than the "live" connectors (ServiceNow, Jira, Splunk,
      CrowdStrike, Infoblox, Axonius), which do have a working, documented-contract
      implementation - see <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>
      for the full catalog in doc form.
    </div>
    <table class="data-table finding-detail-table">
      <tbody>
        <tr><th>Category</th><td>${escapeHtml(c.category)}</td></tr>
        <tr><th>What it does</th><td class="wrap-cell">${escapeHtml(c.blurb)}</td></tr>
        <tr><th>Auth model</th><td>${escapeHtml(c.authMethod)}</td></tr>
        <tr><th>Integration shape</th><td class="wrap-cell">${escapeHtml(c.integrationShape)}</td></tr>
        <tr><th>Data that would flow</th><td class="wrap-cell">${escapeHtml(c.dataFlow)}</td></tr>
      </tbody>
    </table>`;
}

// The real "settings" story for this catalog, stated plainly rather than a form that
// doesn't actually persist anything: live connectors take credentials fresh on every
// request (typed into that connector's own page, never written to disk/DB) - a real,
// deliberate security property (no stored secret to leak), not a missing feature.
// Reference entries have no code wired up yet, so there's nothing to configure at all.
function connectionSettingsHtml(c) {
  if (c.status !== "live") {
    return `
      <div class="callout callout-warn">
        ⚠️ No connection settings to show - <strong>${escapeHtml(c.label)}</strong> has no
        working code in this repo yet (see the Reference panel below for its real,
        researched API facts).
      </div>`;
  }
  const credNote = c.credentialShape === "none"
    ? "No credentials involved."
    : "Entered fresh on every request below - never written to disk or a database. Restarting the server or navigating away clears them; nothing is stored server-side.";
  return `
    <table class="data-table finding-detail-table">
      <tbody>
        <tr><th>Auth model</th><td class="wrap-cell">${escapeHtml(c.authMethod || "—")}</td></tr>
        <tr><th>Credential storage</th><td class="wrap-cell">${escapeHtml(credNote)}</td></tr>
        <tr><th>Direction</th><td>${escapeHtml(c.blurb)}</td></tr>
      </tbody>
    </table>`;
}

function optionsHtml(selectedKey) {
  return CATEGORIES.map((category) => {
    const items = CONNECTORS.filter((c) => c.category === category);
    if (!items.length) return "";
    const opts = items.map((c) =>
      `<option value="${c.key}" ${c.key === selectedKey ? "selected" : ""}>` +
      `${escapeHtml(c.label)} ${c.status === "live" ? "" : "(reference)"}</option>`).join("");
    return `<optgroup label="${escapeHtml(category)}">${opts}</optgroup>`;
  }).join("");
}

export async function render(container) {
  const requestedKey = new URLSearchParams(window.location.search).get("connector");
  const initial = connectorByKey(requestedKey) || CONNECTORS[0];

  container.innerHTML = `
    <p class="subtitle">
      Every external system VulnHunter talks to (or has a documented, real API contract
      researched for), in one place - pick a connector below instead of hunting across
      separate sidebar entries. "Preview available" connectors have a working page
      (form, results, or usage reference); "Reference" entries are real, researched API
      facts with no working preview/send wired up yet.
    </p>

    <div class="adaptor-picker">
      <label for="adaptor-select">Connector</label>
      <select id="adaptor-select">${optionsHtml(initial.key)}</select>
      <span class="adaptor-count">${CONNECTORS.length} connectors cataloged
        (${CONNECTORS.filter((c) => c.status === "live").length} with a live preview)</span>
    </div>

    <div class="adaptor-summary" id="adaptor-summary"></div>

    <h2 style="margin-top:20px">Connection &amp; settings</h2>
    <div id="adaptor-connection-settings"></div>

    <div id="adaptor-panel-heading"></div>
    <div id="adaptor-panel"><div class="empty-state">Loading…</div></div>`;

  const select = container.querySelector("#adaptor-select");
  const summaryEl = container.querySelector("#adaptor-summary");
  const connectionSettingsEl = container.querySelector("#adaptor-connection-settings");
  const panelHeadingEl = container.querySelector("#adaptor-panel-heading");
  const panelEl = container.querySelector("#adaptor-panel");

  async function showConnector(key, { pushState = true } = {}) {
    const c = connectorByKey(key);
    if (!c) return;

    summaryEl.innerHTML = `
      <span class="adaptor-option-icon">${icon(c.iconName, 20)}</span>
      <div>
        <strong>${escapeHtml(c.label)}</strong>
        <span class="adaptor-option-status adaptor-status-${c.status}">${c.status === "live" ? "Preview available" : "Reference"}</span>
        <p class="filter-count" style="margin:2px 0 0">${escapeHtml(c.blurb)}</p>
      </div>`;

    connectionSettingsEl.innerHTML = connectionSettingsHtml(c);

    if (pushState) {
      const url = new URL(window.location.href);
      url.searchParams.set("connector", key);
      window.history.replaceState({}, "", url.pathname + url.search);
    }

    if (c.status === "live") {
      panelHeadingEl.innerHTML = `
        <h2 style="margin-top:28px">Preview / test this connector</h2>
        <p class="filter-count" style="margin:-4px 0 8px">
          Findings-based preview - builds the exact payload real findings would produce,
          without sending anything unless you enter real credentials above and confirm.
        </p>`;
      panelEl.innerHTML = "";
      const mod = await c.module();
      await mod.render(panelEl);
    } else {
      panelHeadingEl.innerHTML = "";
      panelEl.innerHTML = referencePanelHtml(c);
    }
  }

  select.addEventListener("change", (e) => showConnector(e.target.value));
  await showConnector(initial.key, { pushState: false });
}
