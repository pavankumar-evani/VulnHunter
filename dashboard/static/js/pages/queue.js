import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Live Remediation Queue";

const PRIORITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };

function rowHtml(f) {
  const kev = f.kev && f.kev.listed
    ? `<span class="badge badge-critical">KEV</span>`
    : `<span class="muted">—</span>`;
  const epss = f.epss ? `${(f.epss.score * 100).toFixed(1)}%` : "—";

  let slaCell = `<span class="muted">—</span>`;
  if (f.sla && f.sla.due_date) {
    if (f.sla.breached) {
      slaCell = `<span class="sla-breached">${escapeHtml(f.sla.due_date)} (breached)</span>`;
    } else if (f.sla.days_remaining <= 3) {
      slaCell = `<span class="sla-warn">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d)</span>`;
    } else {
      slaCell = `<span class="sla-ok">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d)</span>`;
    }
  }

  const attackTags = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) => `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join("")
    : `<span class="muted">—</span>`;

  return `
    <tr>
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td>${escapeHtml(f.id)}</td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td><code>${escapeHtml(f.cve || "—")}</code></td>
      <td>${kev}</td>
      <td>${epss}</td>
      <td>${slaCell}</td>
      <td>${attackTags}</td>
    </tr>`;
}

function sortFindings(findings, key, dir) {
  const factor = dir === "asc" ? 1 : -1;
  return [...findings].sort((a, b) => {
    let av;
    let bv;
    if (key === "priority") {
      av = PRIORITY_RANK[a.priority] ?? -1;
      bv = PRIORITY_RANK[b.priority] ?? -1;
    } else if (key === "sla") {
      av = a.sla && a.sla.days_remaining !== null && a.sla.days_remaining !== undefined ? a.sla.days_remaining : Infinity;
      bv = b.sla && b.sla.days_remaining !== null && b.sla.days_remaining !== undefined ? b.sla.days_remaining : Infinity;
    } else {
      av = a[key];
      bv = b[key];
    }
    if (av < bv) return -1 * factor;
    if (av > bv) return 1 * factor;
    return 0;
  });
}

export async function render(container) {
  const data = await api.queue();
  const sla = data.sla;
  let sort = { key: "priority", dir: "desc" };

  container.innerHTML = `
    <p class="subtitle">
      Re-scored on every page load from <a href="/priority-rules" data-link>the
      current priority rules</a> — edit the weights there and reload this page to see it change.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${sla.breached}</div><div class="kpi-label">SLA breached</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${sla.at_risk}</div><div class="kpi-label">Due within 3 days</div></div>
      <div class="kpi-card kpi-good"><div class="kpi-value">${sla.on_track}</div><div class="kpi-label">On track</div></div>
    </div>

    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th class="sortable" data-sort="priority">Priority <span class="sort-indicator"></span></th>
            <th>ID</th><th>Asset</th><th>Title</th><th>CVE</th>
            <th>KEV</th><th>EPSS</th>
            <th class="sortable" data-sort="sla">SLA Due <span class="sort-indicator"></span></th>
            <th>ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody id="queue-body"></tbody>
      </table>
    </div>

    <div class="callout">
      Priority reasoning for each finding (why it landed where it did) is in the plan detail
      at <a href="/remediate" data-link>/remediate</a>. MITRE ATT&amp;CK tags are a
      keyword heuristic, not authoritative technique attribution — see
      <code>remediation/enrichment/attack_mapping.py</code>'s docstring.
    </div>`;

  const tbody = container.querySelector("#queue-body");

  function renderRows() {
    const sorted = sortFindings(data.findings, sort.key, sort.dir);
    tbody.innerHTML = sorted.map(rowHtml).join("");
    container.querySelectorAll("th.sortable").forEach((th) => {
      const indicator = th.querySelector(".sort-indicator");
      indicator.textContent = th.dataset.sort === sort.key ? (sort.dir === "asc" ? "▲" : "▼") : "";
    });
  }

  container.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      sort = sort.key === key ? { key, dir: sort.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" };
      renderRows();
    });
  });

  renderRows();
}
