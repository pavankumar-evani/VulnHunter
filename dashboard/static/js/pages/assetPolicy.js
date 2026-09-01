// Bulk, rule-based asset-metadata policy - editing owner/team/environment/facing/
// remediation-schedule one asset at a time on /assets works, but doesn't scale past a
// handful of assets. This page edits remediation/config/asset_policy_rules.yaml (real
// YAML, validated before saving - same pattern as /priority-rules, /exploit-criteria,
// /remediation-policy) and previews which REAL assets each rule matches before
// anything is written - Apply only ever runs the currently-SAVED rules, never an
// unsaved edit, so what gets applied is exactly what was reviewed and saved first.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Asset Policy";

function previewHtml(rules) {
  if (!rules.length) return `<p class="muted">No rules defined.</p>`;
  return `
    <table class="data-table">
      <thead><tr><th>Rule</th><th>Would set</th><th>Matched assets</th></tr></thead>
      <tbody>
        ${rules.map((r) => `
          <tr>
            <td>${escapeHtml(r.rule_name)}</td>
            <td>${Object.entries(r.set).map(([k, v]) => `<code>${escapeHtml(k)}: ${escapeHtml(JSON.stringify(v))}</code>`).join("<br>") || `<span class="muted">—</span>`}</td>
            <td><strong>${r.matched_assets.length}</strong>${r.matched_assets.length ? ` <span class="muted" data-tooltip="${escapeHtml(r.matched_assets.join(", "))}">(hover to see which)</span>` : ""}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

async function refreshPreview(container, rulesText) {
  const panel = container.querySelector("#policy-preview");
  panel.innerHTML = `<p class="muted">Checking matches against the real current asset inventory…</p>`;
  try {
    const result = await api.previewAssetPolicy(rulesText);
    panel.innerHTML = previewHtml(result.rules);
  } catch (err) {
    panel.innerHTML = `<p style="color:var(--danger)">${escapeHtml(err.message)}</p>`;
  }
}

export async function render(container) {
  const data = await api.getAssetPolicy();

  container.innerHTML = `
    <p class="subtitle">
      Bulk, rule-based asset-metadata editing — match a group of real assets (by
      hostname prefix/regex, real asset type, environment, or facing) and set
      owner/team/environment/facing/remediation-schedule on all of them in one action,
      instead of editing each asset individually on <a href="/assets" data-link>Asset
      Inventory</a>. Asset <strong>type</strong> can never be set by a rule — it always
      reflects what the real finding/scan data actually reports.
    </p>

    <form class="config-form" id="rules-form">
      <textarea name="rules_text" spellcheck="false">${escapeHtml(data.rules_text)}</textarea>
      <div style="display:flex; gap:8px">
        <button type="submit">Save Rules</button>
        <button type="button" class="secondary-button" id="preview-button">Preview matches (without saving)</button>
      </div>
    </form>

    <div class="callout">
      This is plain YAML, validated before saving — an invalid file is rejected with an
      error rather than silently breaking every page that reads it.
    </div>

    <h3>Live match preview</h3>
    <p class="muted">
      Which real, currently-matching assets each rule above would affect — computed
      against the actual asset inventory, writes nothing.
    </p>
    <div id="policy-preview"></div>

    <h3 style="margin-top:24px">Apply</h3>
    <div class="callout callout-warn">
      Applies the <strong>currently-saved</strong> rules (save first if you just edited
      them above) against the real asset inventory right now — real writes, via the
      same setters the single-asset editor on <a href="/assets" data-link>Asset
      Inventory</a> uses, each recorded in the <a href="/activity-log" data-link>Activity
      Log</a>.
    </div>
    <button type="button" id="apply-button">Apply saved rules now</button>
    <div id="apply-result"></div>`;

  const textarea = container.querySelector("textarea[name=rules_text]");

  await refreshPreview(container, textarea.value);

  container.querySelector("#preview-button").addEventListener("click", () => {
    refreshPreview(container, textarea.value);
  });

  const form = container.querySelector("#rules-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.saveAssetPolicy(form.rules_text.value);
      flash(result.message, "success");
      await refreshPreview(container, textarea.value);
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#apply-button").addEventListener("click", async () => {
    const resultEl = container.querySelector("#apply-result");
    resultEl.innerHTML = `<p class="muted">Applying…</p>`;
    try {
      const result = await api.applyAssetPolicy();
      resultEl.innerHTML = `<div class="callout">Applied ${result.rules_applied} rule(s) — ${result.assets_changed} real asset(s) changed. See the <a href="/activity-log" data-link>Activity Log</a> for exactly what changed.</div>`;
      flash(`Applied - ${result.assets_changed} asset(s) changed.`, "success");
    } catch (err) {
      resultEl.innerHTML = `<p style="color:var(--danger)">${escapeHtml(err.message)}</p>`;
    }
  });
}
