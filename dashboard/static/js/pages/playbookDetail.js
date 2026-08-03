import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export function title(filenameParam) {
  return decodeURIComponent(filenameParam);
}

export async function render(container, filenameParam) {
  const filename = decodeURIComponent(filenameParam);
  let playbook;
  try {
    playbook = await api.playbook(filename);
  } catch (err) {
    if (err.status === 404) {
      container.innerHTML = `<p class="empty-state">Playbook not found: ${escapeHtml(filename)}</p>`;
      return;
    }
    throw err;
  }

  container.innerHTML = `
    <p class="subtitle">
      Finding ${escapeHtml(playbook.finding_id)} &middot;
      ${playbook.needs_approval
        ? `<span class="badge badge-needs_change_approval">Change approval required</span>`
        : `<span class="badge badge-auto_approvable">Auto-approvable</span>`}
    </p>
    <div class="callout callout-warn">
      This is a generated, unreviewed draft. Do not run it against real infrastructure
      without human review and, if flagged above, formal change-management approval.
    </div>
    <pre class="code-block">${escapeHtml(playbook.content)}</pre>
    <p><a href="/remediate" data-link>&larr; Back to remediation queue</a></p>`;
}
