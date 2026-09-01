// Infoblox - a PULL connector: fetches DNS host records FROM an Infoblox NIOS grid and
// normalizes them into asset-inventory records, not vulnerability findings. Test
// Connection + Fetch, same shape as tenable.js/qualys.js - but Fetch here reconciles
// real ip/mac ground truth directly into asset_ownership.json (asset_inventory.
// reconcile_pulled_assets()), the same real, bounded action the CMDB CSV import already
// performs, rather than writing a raw export file needing /remediate.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Adaptors — Infoblox";

function reconcileResultHtml(result) {
  return `
    <div class="callout">
      <strong>${result.matched.length}</strong> matched an existing asset (ip/mac updated),
      <strong>${result.unmatched.length}</strong> had no existing findings yet (ip/mac stored,
      will appear on <a href="/assets">Asset Inventory</a> once one does),
      <strong>${result.skipped.length}</strong> skipped.
    </div>
    ${result.skipped.length ? `
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Asset</th><th>Reason skipped</th></tr></thead>
          <tbody>${result.skipped.slice(0, 10).map((s) => `
            <tr><td>${escapeHtml(s.asset_name || "—")}</td><td>${escapeHtml(s.reason)}</td></tr>`).join("")}</tbody>
        </table>
      </div>` : ""}`;
}

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Infoblox NIOS's DNS/IPAM data - fetches host
    records and reconciles real ip/mac ground truth into the asset inventory. Test your
    credentials, then fetch.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Infoblox NIOS grid — no
      credentials were available while building it. It implements the WAPI (Web API)
      documented <code>record:host</code> contract and is unit-tested against mocked
      HTTP responses shaped like that documentation. Verify field names against your
      grid's current WAPI version before trusting live output.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Authenticates via HTTP Basic auth against the grid master</li>
      <li>Fetches DNS host records (<code>GET /wapi/{version}/record:host</code>)</li>
      <li>Reconciles each host's real ip against the asset inventory (<code>asset_inventory.reconcile_pulled_assets()</code>) - the same real, bounded action <a href="/assets">CMDB CSV import</a> already performs</li>
    </ol>

    <div class="callout">
      A DNS host record doesn't carry MAC address or OS/platform data - Infoblox keeps
      those on separate <code>lease</code>/<code>ipv4address</code> objects this
      connector doesn't fetch. So <code>mac</code> is always <code>null</code> on an
      Infoblox-sourced record, and an asset with no existing findings won't appear on
      Asset Inventory until one does - that table is built from findings, not a separate
      asset registry.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="infoblox-form">
      <label>Grid master (hostname)<input type="text" name="grid_master" placeholder="grid.example.com"></label>
      <label>Username<input type="text" name="username" autocomplete="off"></label>
      <label>Password<input type="password" name="password" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch and reconcile live Infoblox host records now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="infoblox-result"></div>`;

  const form = container.querySelector("#infoblox-form");
  const resultEl = container.querySelector("#infoblox-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.infobloxTestConnection({
        grid_master: form.grid_master.value.trim(),
        username: form.username.value.trim(),
        password: form.password.value,
      });
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      grid_master: form.grid_master.value.trim(),
      username: form.username.value.trim(),
      password: form.password.value,
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.infobloxFetch(body);
      flash(result.message, result.preview_only ? "info" : "success");
      resultEl.innerHTML = result.preview_only ? "" : reconcileResultHtml(result);
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
