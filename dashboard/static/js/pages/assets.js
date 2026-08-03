import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";

export const title = "Asset Inventory";

const EXPORT_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Type", value: (a) => a.type },
  { label: "Findings", value: (a) => a.finding_count },
  { label: "Critical Findings", value: (a) => a.critical_count },
  { label: "Highest Severity", value: (a) => a.highest_severity },
  { label: "KEV Exposure", value: (a) => a.kev_count },
  { label: "Facing", value: (a) => a.facing },
  { label: "Owner", value: (a) => a.owner },
  { label: "Team", value: (a) => a.team },
];

// Pattern-matched (NOT machine learning - see pattern_recognition.py's module
// docstring) owner/team suggestion for an unowned asset, based on hostname naming
// convention, IP subnet, and asset-type matches against assets that already have an
// owner. Never applied automatically - a one-click "Use" button on top of the
// existing manual "Edit" flow, same non-authoritative posture as the ATT&CK tags and
// compensating-control suggestions elsewhere in this app.
function ownerCellHtml(a) {
  if (a.owner) return escapeHtml(a.owner);
  if (!a.suggestion) return `<span class="muted">Unassigned</span>`;
  const pct = Math.round(a.suggestion.confidence * 100);
  return `
    <span class="muted">Unassigned</span>
    <div class="asset-suggestion" data-tooltip="${escapeHtml(a.suggestion.reasons.join("; "))}">
      Suggested: ${escapeHtml(a.suggestion.owner)} (${pct}% pattern match)
      <button type="button" class="link-button" data-apply-suggestion="${escapeHtml(a.name)}">Use</button>
    </div>`;
}

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
      <td>${ownerCellHtml(a)}</td>
      <td>${a.team ? escapeHtml(a.team) : `<span class="muted">—</span>`}</td>
      <td><button type="button" class="link-button" data-edit-owner="${escapeHtml(a.name)}">Edit</button></td>
    </tr>`;
}

function columnSelect(fieldName, label, headers, selected) {
  return `
    <label>${label}
      <select name="${fieldName}">
        <option value="">(none)</option>
        ${headers.map((h) => `<option value="${escapeHtml(h)}" ${h === selected ? "selected" : ""}>${escapeHtml(h)}</option>`).join("")}
      </select>
    </label>`;
}

function reconciledRow(entry, groupLabel) {
  return `
    <tr data-reconciled-row>
      <td><span class="badge ${groupLabel === "Matched" ? "badge-auto_approvable" : "badge-manual_only"}">${groupLabel}</span></td>
      <td>${escapeHtml(entry.asset_name)}</td>
      <td><input type="text" class="reconciled-owner" value="${escapeHtml(entry.owner)}"></td>
      <td><input type="text" class="reconciled-team" value="${escapeHtml(entry.team)}"></td>
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

    <details class="cmdb-import">
      <summary>Import owner/team from a CMDB export (CSV)</summary>
      <p class="filter-count" style="margin:8px 0">
        Upload a CSV export of your asset details - column names are guessed (keyword
        heuristic, adjust below if wrong), then reconciled against the real asset list
        above. "Excel" here means CSV, which Excel exports/opens natively - see the FAQ.
      </p>
      <form class="run-form" id="cmdb-upload-form">
        <label>CSV file<input type="file" name="file" accept=".csv,text/csv" required></label>
        <button type="submit">Preview Import</button>
      </form>
      <div id="cmdb-preview"></div>
    </details>

    ${exportButtonsHtml("assets")}

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
      version would need instead. Unassigned assets may show a <strong>pattern-matched
      suggestion</strong> (hostname naming convention, IP subnet, or asset type shared
      with an already-owned asset) - a transparent heuristic, not machine learning
      (the dataset here is far too small to train anything real on), never applied
      automatically. Hover a suggestion to see exactly why it was made.
    </div>`;

  wireExportButtons(container, "assets", {
    getRows: () => assets,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-asset-inventory",
  });

  let lastCsvText = "";

  function renderPreview(data) {
    const previewEl = container.querySelector("#cmdb-preview");
    const rows = [...data.matched, ...data.unmatched];
    previewEl.innerHTML = `
      <form class="run-form" id="cmdb-mapping-form">
        <p><strong>Column mapping</strong> (re-preview after adjusting)</p>
        ${columnSelect("asset_name", "Asset name column", data.headers, data.column_mapping.asset_name)}
        ${columnSelect("owner", "Owner column", data.headers, data.column_mapping.owner)}
        ${columnSelect("team", "Team column", data.headers, data.column_mapping.team)}
        <button type="submit">Re-preview with this mapping</button>
      </form>

      <p class="filter-count" style="margin:10px 0">
        <strong>${data.matched.length}</strong> matched (already have findings - owner/team
        applies immediately), <strong>${data.unmatched.length}</strong> not yet seen
        (owner/team stored, applies once a finding against them exists),
        <strong>${data.invalid.length}</strong> invalid (no asset name found).
      </p>

      ${rows.length ? `
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>Status</th><th>Asset</th><th>Owner</th><th>Team</th></tr></thead>
            <tbody id="cmdb-reconciled-body">
              ${data.matched.map((e) => reconciledRow(e, "Matched")).join("")}
              ${data.unmatched.map((e) => reconciledRow(e, "Not yet seen")).join("")}
            </tbody>
          </table>
        </div>
        <button type="button" class="secondary-button" id="cmdb-apply" style="margin-top:10px">
          Apply Import (${rows.length} asset(s))
        </button>` : ""}`;

    previewEl.querySelector("#cmdb-mapping-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.target;
      const mapping = {
        asset_name: form.asset_name.value || null,
        owner: form.owner.value || null,
        team: form.team.value || null,
      };
      try {
        const result = await api.cmdbImportPreview(lastCsvText, mapping);
        renderPreview(result);
      } catch (err) {
        flash(err.message, "error");
      }
    });

    const applyBtn = previewEl.querySelector("#cmdb-apply");
    if (applyBtn) {
      applyBtn.addEventListener("click", async () => {
        const entries = [...previewEl.querySelectorAll("[data-reconciled-row]")].map((row) => ({
          asset_name: row.children[1].textContent,
          owner: row.querySelector(".reconciled-owner").value,
          team: row.querySelector(".reconciled-team").value,
        }));
        try {
          const result = await api.cmdbImportApply(entries);
          flash(`Applied owner/team for ${result.applied} asset(s).`, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
    }
  }

  container.querySelector("#cmdb-upload-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const fileInput = event.target.file;
    const file = fileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      lastCsvText = reader.result;
      try {
        const result = await api.cmdbImportPreview(lastCsvText);
        renderPreview(result);
      } catch (err) {
        flash(err.message, "error");
      }
    };
    reader.readAsText(file);
  });

  container.querySelectorAll("[data-apply-suggestion]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = btn.dataset.applySuggestion;
      const asset = assets.find((a) => a.name === name);
      if (!asset || !asset.suggestion) return;
      try {
        await api.assetSetOwner(name, {
          owner: asset.suggestion.owner,
          team: asset.suggestion.team,
        });
        flash(`Applied suggested owner for ${name}.`, "success");
        render(container);
      } catch (err) {
        flash(err.message, "error");
      }
    });
  });

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
