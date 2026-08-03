import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";

export const title = "Asset Inventory";

function assetRow(a) {
  const kev = a.kev_count > 0
    ? `<span class="badge badge-critical">${a.kev_count} KEV</span>`
    : `<span class="muted">—</span>`;
  const severity = a.highest_severity
    ? `<span class="badge badge-${a.highest_severity.toLowerCase()}">${escapeHtml(a.highest_severity)}</span>`
    : `<span class="muted">—</span>`;
  return `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td class="asset-type-cell">${escapeHtml(a.type)}</td>
      <td>${a.finding_count}</td>
      <td>${severity}</td>
      <td>${kev}</td>
      <td>${a.owner ? escapeHtml(a.owner) : `<span class="muted">Unassigned</span>`}</td>
      <td>${a.team ? escapeHtml(a.team) : `<span class="muted">—</span>`}</td>
      <td><button type="button" class="link-button" data-edit-owner="${escapeHtml(a.name)}">Edit</button></td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const { assets } = await api.assetsList();

  container.innerHTML = `
    <p class="subtitle">
      Every asset with at least one finding against it, aggregated from
      <code>remediation/output/normalized-findings.json</code> - not a separate CMDB, a
      real live query over the same data the Queue and Overview pages already read.
    </p>

    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Asset</th><th>Type</th><th>Findings</th><th>Highest Severity</th>
            <th>KEV Exposure</th><th>Owner</th><th>Team</th><th></th>
          </tr>
        </thead>
        <tbody id="assets-body">${assets.map(assetRow).join("")}</tbody>
      </table>
    </div>

    <div class="callout">
      Ownership is stored locally in
      <code>remediation/inventory/asset_ownership.json</code> - a real, editable file
      (same pattern as <code>priority_rules.yaml</code>), not a sync from a real
      CMDB/asset-management system. See the module docstring for what a production
      version would need instead.
    </div>`;

  container.querySelectorAll("[data-edit-owner]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const name = btn.dataset.editOwner;
      const asset = assets.find((a) => a.name === name);
      const body = openModal(`
        <h2>Edit owner - ${escapeHtml(name)}</h2>
        <form class="run-form" id="owner-form">
          <label>Owner
            <input type="text" name="owner" value="${escapeHtml(asset.owner || "")}">
          </label>
          <label>Team
            <input type="text" name="team" value="${escapeHtml(asset.team || "")}">
          </label>
          <button type="submit">Save</button>
        </form>`);
      body.querySelector("#owner-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          await api.assetSetOwner(name, {
            owner: event.target.owner.value,
            team: event.target.team.value,
          });
          closeModal();
          flash(`Updated owner for ${name}.`, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
    });
  });
}
