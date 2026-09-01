import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Jira Integration";

// A real send always covers every current finding (that's the actual point of the
// integration) - only the DISPLAY is sampled, so this page doesn't render a table with
// thousands of rows just to show what the payload shape looks like. Capped small (4)
// on purpose: it's illustrating a format, not auditing a full run.
const SAMPLE_SIZE = 4;

function previewRows(previews) {
  return previews.slice(0, SAMPLE_SIZE).map((p) => `
    <tr>
      <td>${escapeHtml(p.finding_id)}</td>
      <td class="wrap-cell">${escapeHtml(p.body.fields.summary)}</td>
      <td>${escapeHtml(p.body.fields.issuetype.name)}</td>
      <td>${(p.body.fields.labels || []).map((l) => `<code>${escapeHtml(l)}</code>`).join(" ")}</td>
    </tr>`).join("");
}

function sampleNoteHtml(total) {
  return total > SAMPLE_SIZE
    ? `<p class="filter-count" style="margin:-4px 0 8px">Showing a sample of ${SAMPLE_SIZE} of ${total} matching finding(s) - a real send covers all ${total}, not just the sample shown here.</p>`
    : "";
}

function resultRows(results) {
  return results.slice(0, SAMPLE_SIZE).map((r) => `
    <tr>
      <td>${escapeHtml(r.finding_id)}</td>
      <td>${escapeHtml(r.status)}</td>
      <td>${escapeHtml(r.issue_key || "—")}</td>
      <td>${escapeHtml(r.error || "—")}</td>
    </tr>`).join("");
}

export async function render(container) {
  const data = await api.jiraPreview();

  container.innerHTML = `
    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Jira Cloud site — no
      credentials were available while building it. It implements Jira Cloud's documented
      REST API v3 contract and is unit-tested against mocked responses shaped like that
      documentation. Verify against a test/non-production site before relying on it.
      Preview below uses a placeholder project key (<code>VULN</code>) until you enter a
      real one. See <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>.
    </div>

    <form class="run-form" id="jira-form">
      <label>Jira site URL<input type="text" name="base_url" placeholder="https://yourcompany.atlassian.net"></label>
      <label>Account email<input type="text" name="email"></label>
      <label>API token<input type="password" name="api_token"></label>
      <label>Project key<input type="text" name="project_key" placeholder="VULN"></label>
      <label>Issue type<input type="text" name="issue_type" value="Bug"></label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to actually create issues for all
        ${data.previews.length} matching finding(s) - not just the sample below (leave
        unchecked for a preview of exactly what would be sent, no network call made)
      </label>
      <button type="submit">Submit</button>
    </form>

    <div id="jira-results"></div>

    <h2>Preview — what would be sent for each finding</h2>
    <div id="jira-sample-note">${sampleNoteHtml(data.previews.length)}</div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Finding</th><th>Summary</th><th>Issue Type</th><th>Labels</th></tr></thead>
        <tbody id="jira-preview-body">${previewRows(data.previews)}</tbody>
      </table>
    </div>`;

  const form = container.querySelector("#jira-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      base_url: form.base_url.value.trim(),
      email: form.email.value.trim(),
      api_token: form.api_token.value,
      project_key: form.project_key.value.trim(),
      issue_type: form.issue_type.value.trim() || "Bug",
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.jiraSend(body);
      flash(result.message, result.preview_only ? "info" : "success");
      container.querySelector("#jira-preview-body").innerHTML = previewRows(result.previews);
      container.querySelector("#jira-sample-note").innerHTML = sampleNoteHtml(result.previews.length);
      if (result.results) {
        container.querySelector("#jira-results").innerHTML = `
          <h2>Results</h2>
          ${sampleNoteHtml(result.results.length)}
          <div class="table-scroll">
            <table class="data-table">
              <thead><tr><th>Finding</th><th>Status</th><th>Issue Key</th><th>Error</th></tr></thead>
              <tbody>${resultRows(result.results)}</tbody>
            </table>
          </div>`;
      }
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
