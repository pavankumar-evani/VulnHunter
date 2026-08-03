import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Configure Priority Rules";

export async function render(container) {
  const data = await api.getPriorityRules();

  container.innerHTML = `
    <p class="subtitle">
      Edits here take effect immediately on the
      <a href="/queue" data-link>Live Remediation Queue</a> and Overview SLA KPIs —
      no pipeline re-run needed. This does not change <code>REMEDIATION_PLAN.md</code>'s
      static snapshot from remediation-planner's own (separate) priority logic.
    </p>

    <form class="config-form" id="rules-form">
      <textarea name="rules_text" spellcheck="false">${escapeHtml(data.rules_text)}</textarea>
      <button type="submit">Save Rules</button>
    </form>

    <div class="callout">
      This is plain YAML, validated before saving — an invalid file is rejected with an error
      rather than silently breaking every page that reads it. See the comments in the file
      itself for what each section controls (SLA windows per priority tier, the CISA KEV /
      EPSS override rules, asset-criticality keyword weights, and severity weights).
    </div>`;

  const form = container.querySelector("#rules-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.savePriorityRules(form.rules_text.value);
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
