// Axonius - a PULL connector: fetches aggregated device records FROM Axonius and
// normalizes them into asset-inventory records, not vulnerability findings. Same
// Test Connection + Fetch shape as infoblox.js - Fetch reconciles real ip/mac ground
// truth directly into asset_ownership.json (asset_inventory.reconcile_pulled_assets()).
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Adaptors — Axonius";

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
    <p class="subtitle">A pull connector for Axonius's aggregated cyber-asset inventory -
    fetches device records (already merged across whatever adapters/sources Axonius is
    configured with) and reconciles real ip/mac ground truth into the asset inventory.
    Test your credentials, then fetch.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Axonius tenant — no
      credentials were available while building it. It implements Axonius's documented
      <code>api-key</code>/<code>api-secret</code> header auth and
      <code>POST /api/devices</code> contract, and is unit-tested against mocked HTTP
      responses shaped like that documentation. The exact response envelope key and
      field-flattening have varied across Axonius versions in public docs - verify
      against your own tenant's current API version before trusting live output.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Authenticates via <code>api-key</code>/<code>api-secret</code> request headers</li>
      <li>Fetches a page of device records (<code>POST /api/devices</code> with an offset/limit body)</li>
      <li>Reconciles each device's real ip/mac against the asset inventory (<code>asset_inventory.reconcile_pulled_assets()</code>) - the same real, bounded action <a href="/assets">CMDB CSV import</a> already performs</li>
    </ol>

    <div class="callout">
      Axonius's real query language lets you request specific flattened fields (e.g.
      <code>specific_data.data.hostname</code>) - a raw device record otherwise nests
      almost everything under <code>specific_data.data.*</code>. This connector assumes
      the response has already been shaped with reasonably flattened keys rather than
      replicating that flattening/query-building logic in full - an honest MVP scope
      limit. It also fetches a single page only; a real integration needs an
      offset/limit pagination loop the same way <code>ArmisConnector.search_all_pages()</code> does.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="axonius-form">
      <label>Base URL<input type="text" name="base_url" placeholder="https://axonius.example.com"></label>
      <label>API key<input type="text" name="api_key" autocomplete="off"></label>
      <label>API secret<input type="password" name="api_secret" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch and reconcile live Axonius device records now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="axonius-result"></div>`;

  const form = container.querySelector("#axonius-form");
  const resultEl = container.querySelector("#axonius-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.axoniusTestConnection({
        base_url: form.base_url.value.trim(),
        api_key: form.api_key.value.trim(),
        api_secret: form.api_secret.value,
      });
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      base_url: form.base_url.value.trim(),
      api_key: form.api_key.value.trim(),
      api_secret: form.api_secret.value,
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.axoniusFetch(body);
      flash(result.message, result.preview_only ? "info" : "success");
      resultEl.innerHTML = result.preview_only ? "" : reconcileResultHtml(result);
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
