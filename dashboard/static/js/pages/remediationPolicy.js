// Remediation Policy: the real, admin-editable config that decides HOW a finding
// actually gets remediated - cadence, ITIL 4 change type (standard/normal/emergency),
// maintenance window, whether it can skip a per-instance approval click, an AD approval
// group, downtime communication, and which real PAM backend a generated playbook should
// reference. Same YAML-text-editor pattern as Priority Rules/Exploit Criteria - edits
// here take effect on the live Remediation Queue immediately, no pipeline re-run.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Remediation Policy";

// A light client-side YAML reader for the summary table only (never used for
// save/validation - the real parse/validate happens server-side via PyYAML on save,
// same as every other config editor in this app). Handles exactly this file's own
// two-level indentation shape; falls back to showing nothing extra if the admin's edit
// doesn't match it yet (the textarea below is always the source of truth).
function parseSummary(rulesText) {
  const rows = [];
  const lines = rulesText.split("\n");
  let inPolicies = false;
  let current = null;
  for (const line of lines) {
    if (/^policies:\s*$/.test(line)) { inPolicies = true; continue; }
    if (!inPolicies) continue;
    const domainMatch = line.match(/^  (\w[\w-]*):\s*$/);
    if (domainMatch) {
      if (current) rows.push(current);
      current = { domain: domainMatch[1] };
      continue;
    }
    if (!current) continue;
    const fieldMatch = line.match(/^    (change_type|cadence|auto_remediate|downtime_expected|pam_backend):\s*"?([\w.-]*)"?/);
    if (fieldMatch) current[fieldMatch[1]] = fieldMatch[2];
  }
  if (current) rows.push(current);
  return rows;
}

function summaryTableHtml(rows) {
  if (!rows.length) return `<p class="empty-state">No domain policies parsed from the current text.</p>`;
  return `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Domain</th><th>Change Type</th><th>Cadence</th><th>Auto-Remediate</th><th>Downtime Expected</th><th>PAM Backend</th></tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td>${escapeHtml(r.domain)}</td>
              <td><span class="badge badge-outline">${escapeHtml(r.change_type || "?")}</span></td>
              <td>${escapeHtml(r.cadence || "?")}</td>
              <td>${r.auto_remediate === "true" ? "Yes" : "No"}</td>
              <td>${r.downtime_expected === "true" ? "Yes" : "No"}</td>
              <td>${r.pam_backend && r.pam_backend !== "none" ? escapeHtml(r.pam_backend) : `<span class="muted">—</span>`}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

export async function render(container) {
  const data = await api.getRemediationPolicy();

  container.innerHTML = `
    <p class="subtitle">
      The real operational layer on top of finding classification - per domain (server
      OS, EUC endpoints, dev-tagged assets, everything else), this decides patch cadence,
      whether a human approval click is required, the maintenance window, and which real
      PAM backend a generated Ansible playbook should reference. Edits take effect on
      <a href="/queue" data-link>the live Remediation Queue</a> immediately.
    </p>

    <div class="callout callout-warn">
      This never causes VulnHunter itself to connect to, or execute anything against,
      real infrastructure. "Auto-remediate" only means the generated playbook doesn't
      need a per-instance Approve click before it's considered ready - a human or an
      existing enterprise system (SCCM, Ansible Tower/AWX, your own change-management
      pipeline) still has to actually run it. See
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/REMEDIATION_WORKFLOWS.md" target="_blank" rel="noopener">docs/REMEDIATION_WORKFLOWS.md</a>'s
      "Remediation Policy" section for the full model.
    </div>

    <h2 style="margin-top:20px">Current policy summary</h2>
    <div id="policy-summary">${summaryTableHtml(parseSummary(data.rules_text))}</div>

    <h2 style="margin-top:28px">Edit policy YAML</h2>
    <form class="config-form" id="policy-form">
      <textarea name="rules_text" spellcheck="false" rows="34">${escapeHtml(data.rules_text)}</textarea>
      <button type="submit">Save Remediation Policy</button>
    </form>

    <div class="callout">
      A CISA KEV-listed finding always escalates to <code>change_type: emergency</code>
      regardless of its domain's configured default (the <code>kev_emergency_override</code>
      block) - same override convention as Priority Rules' own KEV escalation. Domain
      resolution order: an asset's <code>environment</code> tag (Asset Inventory) if it's
      "dev" and a <code>dev</code> policy exists, then its infrastructure sub-category,
      then its scan type, then <code>default</code>.
    </div>`;

  const textarea = container.querySelector("textarea[name=rules_text]");
  textarea.addEventListener("input", () => {
    container.querySelector("#policy-summary").innerHTML = summaryTableHtml(parseSummary(textarea.value));
  });

  container.querySelector("#policy-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.saveRemediationPolicy(event.target.rules_text.value);
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
