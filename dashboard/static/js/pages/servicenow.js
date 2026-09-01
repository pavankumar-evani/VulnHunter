import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "ServiceNow Integration";

// A real send always covers every current finding (that's the actual point of the
// integration) - only the DISPLAY is sampled, so this page doesn't render a table with
// thousands of rows just to show what the payload shape looks like. Capped small (4)
// on purpose: it's illustrating a format, not auditing a full run - see resultRows()
// below for the same treatment after a real send.
const SAMPLE_SIZE = 4;

function previewRows(previews) {
  return previews.slice(0, SAMPLE_SIZE).map((p) => `
    <tr>
      <td>${escapeHtml(p.finding_id)}</td>
      <td class="wrap-cell">${escapeHtml(p.body.short_description)}</td>
      <td>${escapeHtml(p.body.urgency)}</td>
      <td>${escapeHtml(p.body.impact)}</td>
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
      <td>${escapeHtml(r.incident_number || "—")}</td>
      <td>${escapeHtml(r.error || "—")}</td>
    </tr>`).join("");
}

export async function render(container) {
  const data = await api.servicenowPreview();

  container.innerHTML = `
    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real ServiceNow instance — no
      credentials were available while building it. It implements ServiceNow's documented
      Table API contract and is unit-tested against mocked responses shaped like that
      documentation. Verify against a test/non-production instance before relying on it.
      See <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>.
    </div>

    <form class="run-form" id="sn-form">
      <label>ServiceNow instance name (the <code>xxx</code> in <code>xxx.service-now.com</code>)
        <input type="text" name="instance" placeholder="mycompany"></label>
      <label>Username<input type="text" name="username"></label>
      <label>Password<input type="password" name="password"></label>
      <label>Table<input type="text" name="table" value="incident"></label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to actually create incidents for all
        ${data.previews.length} matching finding(s) - not just the sample below (leave
        unchecked for a preview of exactly what would be sent, no network call made)
      </label>
      <button type="submit">Submit</button>
    </form>

    <div id="sn-results"></div>

    <h2>Preview — what would be sent for each finding</h2>
    ${sampleNoteHtml(data.previews.length)}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Finding</th><th>short_description</th><th>Urgency</th><th>Impact</th></tr></thead>
        <tbody id="sn-preview-body">${previewRows(data.previews)}</tbody>
      </table>
    </div>`;

  const form = container.querySelector("#sn-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      instance: form.instance.value.trim(),
      username: form.username.value.trim(),
      password: form.password.value,
      table: form.table.value.trim() || "incident",
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.servicenowSend(body);
      flash(result.message, result.preview_only ? "info" : "success");
      if (result.results) {
        container.querySelector("#sn-results").innerHTML = `
          <h2>Results</h2>
          ${sampleNoteHtml(result.results.length)}
          <div class="table-scroll">
            <table class="data-table">
              <thead><tr><th>Finding</th><th>Status</th><th>Incident #</th><th>Error</th></tr></thead>
              <tbody>${resultRows(result.results)}</tbody>
            </table>
          </div>`;
      }
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
