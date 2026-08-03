import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Configure Priority Rules";

// Toggles the enabled: true/false flag under a top-level YAML key, preserving every
// other line (comments, other weights) untouched - a targeted string replacement on the
// live editor text, the same "raw YAML, formatting preserved" philosophy the whole
// rules file already uses (see priority_engine.load_rules()'s docstring), rather than
// parsing/re-serializing the whole document and risking reformatting a user's own edits.
function withOverrideToggled(yamlText, key, enabled) {
  const pattern = new RegExp(`(${key}:\\s*\\n\\s*enabled:)\\s*\\S+`);
  return yamlText.replace(pattern, `$1 ${enabled}`);
}

function applyModelPreset(textarea, model) {
  if (model === "cvss") {
    textarea.value = withOverrideToggled(
      withOverrideToggled(textarea.value, "kev_override", "false"),
      "epss_escalation", "false",
    );
  } else if (model === "vpr") {
    textarea.value = withOverrideToggled(
      withOverrideToggled(textarea.value, "kev_override", "true"),
      "epss_escalation", "true",
    );
  }
}

export async function render(container) {
  const data = await api.getPriorityRules();

  container.innerHTML = `
    <p class="subtitle">
      Edits here take effect immediately on the
      <a href="/queue" data-link>Live Remediation Queue</a> and Overview SLA KPIs —
      no pipeline re-run needed. This does not change <code>REMEDIATION_PLAN.md</code>'s
      static snapshot from remediation-planner's own (separate) priority logic.
    </p>

    <div class="callout">
      <strong>Prioritization model</strong> - this engine already supports three real
      approaches, all through the same weighted-score + override mechanism below, not
      three separate code paths:
      <ul style="margin:8px 0 0; padding-left:20px">
        <li><strong>Pure CVSS/severity</strong> - score from <code>severity_weights</code>
          and asset weights only; <code>kev_override</code> and <code>epss_escalation</code>
          both disabled.</li>
        <li><strong>VPR-style (threat-intel-aware, the shipped default)</strong> - the
          same weighted score, but a CISA KEV-listed or high-EPSS finding is escalated
          regardless of severity alone - conceptually the same idea as Tenable's VPR
          (severity + real-world exploitation signal + asset context), not a
          byte-for-byte reproduction of Tenable's proprietary formula.</li>
        <li><strong>Custom</strong> - edit any weight, keyword, or threshold below
          directly; this is the same YAML either preset button edits, so there's no
          separate "custom mode" to switch into.</li>
      </ul>
      <div style="margin-top:10px; display:flex; gap:8px">
        <button type="button" class="secondary-button" id="preset-cvss">Switch to pure CVSS/severity</button>
        <button type="button" class="secondary-button" id="preset-vpr">Switch to VPR-style (default)</button>
      </div>
    </div>

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

  const textarea = container.querySelector("textarea[name=rules_text]");
  container.querySelector("#preset-cvss").addEventListener("click", () => {
    applyModelPreset(textarea, "cvss");
    flash("Pure CVSS/severity preset applied to the editor below - click Save Rules to activate it.", "info");
  });
  container.querySelector("#preset-vpr").addEventListener("click", () => {
    applyModelPreset(textarea, "vpr");
    flash("VPR-style preset applied to the editor below - click Save Rules to activate it.", "info");
  });

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
