import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Splunk Integration";

// A real send always covers every current finding (that's the actual point of the
// integration) - only the DISPLAY is sampled, so this page doesn't render a table with
// thousands of rows just to show what the payload shape looks like. Capped small (4)
// on purpose: it's illustrating a format, not auditing a full run.
const SAMPLE_SIZE = 4;

function previewRows(previews) {
  return previews.slice(0, SAMPLE_SIZE).map((p) => `
    <tr>
      <td>${escapeHtml(p.finding_id)}</td>
      <td class="wrap-cell">${escapeHtml(p.body.event.title || "")}</td>
      <td>${escapeHtml(p.body.event.severity || "")}</td>
      <td>${escapeHtml(p.body.sourcetype)}</td>
      <td>${escapeHtml(p.body.index || "(HEC default)")}</td>
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
      <td>${escapeHtml(r.error || "—")}</td>
    </tr>`).join("");
}

export async function render(container) {
  const data = await api.splunkPreview();

  container.innerHTML = `
    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Splunk instance — no
      credentials were available while building it. It implements Splunk's documented
      HTTP Event Collector (HEC) contract and is unit-tested against mocked responses
      shaped like that documentation. Verify against a test/non-production index before
      relying on it. This is one-directional push - VulnHunter sends findings to Splunk
      as events, it does not read anything back. Re-sending the same finding on every
      pipeline run is expected (HEC events are an append-only stream, not a ticket
      system - there is deliberately no dedup here). See
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>.
    </div>

    <form class="run-form" id="splunk-form">
      <label>HEC URL<input type="text" name="hec_url" placeholder="https://splunk.example.com:8088/services/collector/event"></label>
      <label>HEC token<input type="password" name="hec_token"></label>
      <label>Sourcetype<input type="text" name="sourcetype" value="vulnhunter:finding"></label>
      <label>Index (optional - leave blank for the HEC token's default)<input type="text" name="index"></label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have a real HEC token and want to actually send events for all
        ${data.previews.length} matching finding(s) - not just the sample below (leave
        unchecked for a preview of exactly what would be sent, no network call made)
      </label>
      <button type="submit">Submit</button>
    </form>

    <div id="splunk-results"></div>

    <h2>Preview — what would be sent for each finding</h2>
    <div id="splunk-sample-note">${sampleNoteHtml(data.previews.length)}</div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Finding</th><th>Title</th><th>Severity</th><th>Sourcetype</th><th>Index</th></tr></thead>
        <tbody id="splunk-preview-body">${previewRows(data.previews)}</tbody>
      </table>
    </div>`;

  const form = container.querySelector("#splunk-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      hec_url: form.hec_url.value.trim(),
      hec_token: form.hec_token.value,
      sourcetype: form.sourcetype.value.trim() || "vulnhunter:finding",
      index: form.index.value.trim(),
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.splunkSend(body);
      flash(result.message, result.preview_only ? "info" : "success");
      container.querySelector("#splunk-preview-body").innerHTML = previewRows(result.previews);
      container.querySelector("#splunk-sample-note").innerHTML = sampleNoteHtml(result.previews.length);
      if (result.results) {
        container.querySelector("#splunk-results").innerHTML = `
          <h2>Results</h2>
          ${sampleNoteHtml(result.results.length)}
          <div class="table-scroll">
            <table class="data-table">
              <thead><tr><th>Finding</th><th>Status</th><th>Error</th></tr></thead>
              <tbody>${resultRows(result.results)}</tbody>
            </table>
          </div>`;
      }
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
