// Infrastructure Vulnerabilities hub: rolls up Infrastructure Vulnerability
// Management findings into the sub-categories a real infra/security team actually
// organizes around - OS-level patching, network hardware, network security
// appliances, OT/IoT devices, and cloud infrastructure - rather than one flat
// "Infrastructure Vulnerabilities" list. Same rollup-view pattern as /appsec: every
// count here comes straight from /api/queue (already tagged with `infra_category` by
// remediation/enrichment/infra_classification.py via dashboard/data.py's
// load_live_queue()), not a separate data source.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { INFRA_CATEGORIES, INFRA_CATEGORY_LABELS } from "../infraTypes.js";

export const title = "Infrastructure Vulnerabilities";

const CATEGORY_ICONS = {
  "os": "infra",
  "network": "sca",
  "network-security": "certmgmt",
  "ot": "container",
  "cloud": "cloud",
};

const CATEGORY_NOTES = {
  "os": "Windows/Unix server and endpoint patching.",
  "network": "Routers, switches, and other core network hardware.",
  "network-security": "Firewalls, IDS/IPS, and other security appliances.",
  "ot": "Operational technology and IoT devices.",
  "cloud": "Cloud asset/posture findings (AWS/Azure/GCP).",
};

function domainCard({ href, iconName, label, count, note }) {
  return `
    <a class="domain-card" href="${href}" data-link>
      <span class="domain-card-icon">${icon(iconName, 22)}</span>
      <span class="domain-card-count">${count}</span>
      <span class="domain-card-label">${escapeHtml(label)}</span>
      <span class="domain-card-note">${escapeHtml(note)}</span>
    </a>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const queue = await api.queue();

  const counts = Object.fromEntries(INFRA_CATEGORIES.map((c) => [c, 0]));
  for (const f of queue.findings) {
    if (f.infra_category && f.infra_category in counts) counts[f.infra_category] += 1;
  }

  container.innerHTML = `
    <p class="subtitle">Infrastructure Vulnerability Management findings, split by the
    asset-type groupings a real infra/security team actually organizes around -
    Tenable/Armis-style asset scanning underneath, not a separate data source.</p>

    <div class="domain-card-grid">
      ${INFRA_CATEGORIES.map((c) => domainCard({
        href: `/queue?category=infra-vm&infraType=${c}`,
        iconName: CATEGORY_ICONS[c],
        label: INFRA_CATEGORY_LABELS[c],
        count: counts[c],
        note: counts[c] ? CATEGORY_NOTES[c] : `${CATEGORY_NOTES[c]} No sample finding yet - see the FAQ.`,
      })).join("")}
    </div>

    <div class="callout">
      This is a rollup view, not a separate data source - every count above comes
      straight from <code>/api/queue</code>'s <code>infra_category</code> field
      (<code>remediation/enrichment/infra_classification.py</code>), the same data the
      Remediation Queue page already shows. Click any card to jump to the
      pre-filtered underlying view.
    </div>`;
}
