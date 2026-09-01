// Connectors/Adaptors hub: a category sidebar + card grid (the same real pattern most
// connector-management pages use - a category list on the left, cards with a status
// badge on the right, click a card for its detail) instead of six separate sidebar
// entries or a single dropdown selector. Clicking a card opens the app's existing
// modal (dom.js) with real connection/settings info, then either the connector's own
// page module - a preview/send form for push connectors (servicenow.js, jira.js,
// splunk.js) or a Test Connection + Fetch form for pull connectors (tenable.js,
// qualys.js, prismacloud.js, cortexXsiam.js, infoblox.js, axonius.js,
// activeDirectory.js) - for "live" entries, or a documented-facts panel for
// "reference" catalog entries with no working code yet - see adaptorCatalog.js.
import { escapeHtml, openModal } from "../dom.js";
import { icon } from "../icons.js";
import { CATEGORIES, CONNECTORS, connectorByKey } from "../adaptorCatalog.js";

export const title = "Connectors / Adaptors";

function referencePanelHtml(c) {
  return `
    <div class="callout callout-warn">
      ⚠️ <strong>${escapeHtml(c.label)}</strong> is a reference catalog entry, not a
      working preview/send connector yet - the facts below are real (auth model, API
      shape, what data would flow), but there's no code in this repo talking to it yet.
      This is one step earlier than this catalog's "live" connectors, which do have a
      working, documented-contract implementation - see
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>
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
        working code in this repo yet (see the facts below for its real, researched API).
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

function categoryListHtml(activeCategory) {
  const withCounts = CATEGORIES
    .map((cat) => ({ cat, count: CONNECTORS.filter((c) => c.category === cat).length }))
    .filter((c) => c.count > 0);
  const item = (value, label, count) => `
    <button type="button" class="adaptor-category-item ${activeCategory === value ? "active" : ""}" data-category="${escapeHtml(value)}">
      <span>${escapeHtml(label)}</span><span class="adaptor-category-count">${count}</span>
    </button>`;
  return item("all", "All Integrations", CONNECTORS.length) +
    withCounts.map(({ cat, count }) => item(cat, cat, count)).join("");
}

function cardHtml(c) {
  return `
    <div class="adaptor-card" data-key="${escapeHtml(c.key)}" tabindex="0" role="button" aria-label="${escapeHtml(c.label)}">
      <div class="adaptor-card-header">
        <span class="adaptor-card-icon">${icon(c.iconName, 22)}</span>
        <div>
          <strong>${escapeHtml(c.label)}</strong><br>
          <span class="adaptor-category-badge">${escapeHtml(c.category)}</span>
        </div>
      </div>
      <p class="adaptor-card-blurb">${escapeHtml(c.blurb)}</p>
      <div class="adaptor-card-footer">
        <span class="adaptor-option-status adaptor-status-${c.status}">${c.status === "live" ? "Configure & connect" : "Reference"}</span>
        <span class="link-button">${c.status === "live" ? "Configure →" : "View facts →"}</span>
      </div>
    </div>`;
}

function cardGridHtml(items) {
  if (!items.length) return `<p class="empty-state">No connectors in this category.</p>`;
  return `<div class="adaptor-card-grid">${items.map(cardHtml).join("")}</div>`;
}

async function openConnectorModal(c) {
  const body = openModal(`
    <div class="adaptor-modal-header">
      <span class="adaptor-card-icon">${icon(c.iconName, 24)}</span>
      <div>
        <h2 style="margin:0 0 2px">${escapeHtml(c.label)}</h2>
        <span class="adaptor-option-status adaptor-status-${c.status}">${c.status === "live" ? "Configure & connect" : "Reference"}</span>
      </div>
    </div>
    <p class="filter-count">${escapeHtml(c.blurb)}</p>
    <h3 style="margin-top:18px">Connection &amp; settings</h3>
    ${connectionSettingsHtml(c)}
    <div id="adaptor-modal-panel-heading"></div>
    <div id="adaptor-modal-panel"><div class="empty-state">Loading…</div></div>`);

  const panelHeadingEl = body.querySelector("#adaptor-modal-panel-heading");
  const panelEl = body.querySelector("#adaptor-modal-panel");

  if (c.status === "live") {
    // Only push connectors (findings out -> a real send) get this specific heading -
    // it describes their "preview the exact payload, confirm to send" shape, which
    // doesn't apply to pull connectors (Test Connection + Fetch) - those modules
    // introduce themselves with their own subtitle/callout instead.
    panelHeadingEl.innerHTML = c.kind === "push" ? `
      <h3 style="margin-top:22px">Preview / test this connector</h3>
      <p class="filter-count" style="margin:-4px 0 8px">
        Findings-based preview - builds the exact payload real findings would produce,
        without sending anything unless you enter real credentials above and confirm.
      </p>` : "";
    const mod = await c.module();
    await mod.render(panelEl);
  } else {
    panelHeadingEl.innerHTML = "";
    panelEl.innerHTML = referencePanelHtml(c);
  }

  const url = new URL(window.location.href);
  url.searchParams.set("connector", c.key);
  window.history.replaceState({}, "", url.pathname + url.search);
}

export async function render(container) {
  let activeCategory = "all";

  container.innerHTML = `
    <p class="subtitle">
      Every external system VulnHunter talks to (or has a documented, real API contract
      researched for) - browse by category, click a card for its real connection
      settings and (for "Configure &amp; connect" connectors) a working preview/send or
      Test Connection + Fetch form.
    </p>
    <div class="adaptor-layout">
      <div class="adaptor-categories" id="adaptor-categories">${categoryListHtml(activeCategory)}</div>
      <div class="adaptor-main">
        <h2 style="margin-top:0">Live connectors</h2>
        <p class="filter-count" style="margin:-4px 0 8px">Have a real, working preview/send page - click a card for its connection settings.</p>
        <div id="adaptor-live-grid"></div>
        <h2 style="margin-top:28px">Reference catalog</h2>
        <p class="filter-count" style="margin:-4px 0 8px">Real, researched API facts - no working preview/send wired up yet.</p>
        <div id="adaptor-reference-grid"></div>
      </div>
    </div>`;

  const categoriesEl = container.querySelector("#adaptor-categories");
  const liveGridEl = container.querySelector("#adaptor-live-grid");
  const referenceGridEl = container.querySelector("#adaptor-reference-grid");

  function renderGrids() {
    const inCategory = (c) => activeCategory === "all" || c.category === activeCategory;
    liveGridEl.innerHTML = cardGridHtml(CONNECTORS.filter((c) => c.status === "live" && inCategory(c)));
    referenceGridEl.innerHTML = cardGridHtml(CONNECTORS.filter((c) => c.status !== "live" && inCategory(c)));
  }

  categoriesEl.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-category]");
    if (!btn) return;
    activeCategory = btn.dataset.category;
    categoriesEl.innerHTML = categoryListHtml(activeCategory);
    renderGrids();
  });

  container.addEventListener("click", (e) => {
    const card = e.target.closest(".adaptor-card");
    if (!card) return;
    const c = connectorByKey(card.dataset.key);
    if (c) openConnectorModal(c);
  });
  container.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const card = e.target.closest(".adaptor-card");
    if (!card) return;
    e.preventDefault();
    const c = connectorByKey(card.dataset.key);
    if (c) openConnectorModal(c);
  });

  renderGrids();

  const requestedKey = new URLSearchParams(window.location.search).get("connector");
  const requested = requestedKey && connectorByKey(requestedKey);
  if (requested) openConnectorModal(requested);
}
