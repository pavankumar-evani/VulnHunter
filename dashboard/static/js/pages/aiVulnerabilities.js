// AI Vulnerabilities: a reference + illustrative MITRE ATLAS cross-reference for
// real, established AI/ML security concepts (prompt injection, model poisoning,
// supply-chain compromise, etc.) - see remediation/enrichment/ai_vuln_taxonomy.py's
// module docstring for the same "illustrative, not authoritative" honesty caveat
// already applied to the Risk Dashboard's MITRE ATT&CK heat map. Every count here
// comes from real /api/ai-vulnerabilities data (findings tagged by keyword against
// this taxonomy) - vulnerable-demo-app/ai_assistant.py plants real AI/ML SAST
// findings, so several categories now show genuine non-zero counts; see the FAQ for
// which categories still honestly have none.
import { escapeHtml } from "../dom.js";
import { api } from "../api.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";

export const title = "AI Vulnerabilities";

const EXPORT_COLUMNS = [
  { label: "Category", value: (v) => v.name },
  { label: "Summary", value: (v) => v.summary },
  { label: "Remediation", value: (v) => v.remediation },
  { label: "ATLAS Tactic", value: (v) => v.atlas_tactic },
  { label: "ATLAS Technique ID", value: (v) => v.atlas_technique_id },
  { label: "ATLAS Technique Name", value: (v) => v.atlas_technique_name },
  { label: "Finding Count", value: (v) => v.count },
];

// Same canonical-ish ordering convenience as risk.js's TACTIC_ORDER, but built from
// whatever tactics this taxonomy actually uses (ATLAS has more tactics than the ten
// entries here touch) rather than hardcoding the full ATLAS tactic list.
const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Collection", "ML Attack Staging", "Exfiltration", "Impact",
];

function heatCellClass(count, maxCount) {
  if (count === 0) return "heat-0";
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio >= 0.75) return "heat-4";
  if (ratio >= 0.5) return "heat-3";
  if (ratio >= 0.25) return "heat-2";
  return "heat-1";
}

function renderHeatmap(heatmap) {
  const maxCount = Math.max(0, ...heatmap.map((r) => r.count));
  const byTactic = new Map();
  for (const row of heatmap) {
    if (!byTactic.has(row.atlas_tactic)) byTactic.set(row.atlas_tactic, []);
    byTactic.get(row.atlas_tactic).push(row);
  }
  const tactics = [
    ...TACTIC_ORDER.filter((t) => byTactic.has(t)),
    ...[...byTactic.keys()].filter((t) => !TACTIC_ORDER.includes(t)),
  ];

  return `
    <div class="heatmap-grid">
      ${tactics.map((tactic) => `
        <div class="heatmap-column">
          <div class="heatmap-tactic">${escapeHtml(tactic)}</div>
          ${byTactic.get(tactic).map((row) => `
            <div class="heatmap-cell ${heatCellClass(row.count, maxCount)}"
                 data-tooltip="${escapeHtml(row.name)}${row.atlas_technique_id ? ` (${escapeHtml(row.atlas_technique_id)})` : ""} - ${row.count} finding(s)">
              <span class="heatmap-technique-id">${row.atlas_technique_id ? escapeHtml(row.atlas_technique_id) : "—"}</span>
              <span class="heatmap-count">${row.count}</span>
            </div>`).join("")}
        </div>`).join("")}
    </div>`;
}

function vulnerabilityCard(v) {
  const atlasRef = v.atlas_technique_id
    ? `<code>${escapeHtml(v.atlas_technique_id)}</code> - ${escapeHtml(v.atlas_technique_name)} (tactic: ${escapeHtml(v.atlas_tactic)})`
    : `${escapeHtml(v.atlas_technique_name)} (tactic: ${escapeHtml(v.atlas_tactic)})`;
  // Same ATLAS reference shown below in the expanded body, surfaced here too as a small
  // inline badge so the TTP is visible on the collapsed row - previously it was only
  // visible after clicking a category open.
  const ttpBadge = v.atlas_technique_id
    ? `<span class="badge badge-outline" data-tooltip="${escapeHtml(v.atlas_tactic)}">${escapeHtml(v.atlas_technique_id)}</span>`
    : `<span class="badge badge-outline muted" data-tooltip="${escapeHtml(v.atlas_tactic)} - no dedicated ATLAS technique">No dedicated technique</span>`;
  return `
    <details class="faq-item">
      <summary>${escapeHtml(v.name)} ${ttpBadge}</summary>
      <p><strong>Summary:</strong> ${escapeHtml(v.summary)}</p>
      <p><strong>Remediation:</strong> ${escapeHtml(v.remediation)}</p>
      <p><strong>MITRE ATLAS cross-reference:</strong> ${atlasRef}</p>
    </details>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const { vulnerabilities, heatmap } = await api.aiVulnerabilities();
  const countById = new Map(heatmap.map((row) => [row.id, row.count]));
  const exportRows = vulnerabilities.map((v) => ({ ...v, count: countById.get(v.id) || 0 }));

  container.innerHTML = `
    <p class="subtitle">Real, established AI/ML security concepts - prompt injection,
    training-data/model poisoning, supply-chain compromise, and more - with a
    summary, remediation guidance, and an illustrative MITRE ATLAS cross-reference for
    each.</p>

    <div class="callout callout-warn">
      ⚠️ ATLAS tactic/technique references below are an illustrative cross-reference
      built from this module's own reading of published ATLAS documentation
      (<a href="https://atlas.mitre.org/" target="_blank" rel="noopener">atlas.mitre.org</a>),
      not a verified or authoritative mapping - same "suggestion to verify, not a fact
      to cite" caveat already applied to the Risk Dashboard's MITRE ATT&CK heat map.
      Confirm any specific ID before citing it formally.
      vulnerable-demo-app/ai_assistant.py plants real AI/ML SAST findings (an insecure
      model-deserialization path, a prompt-injection-shaped concatenation, an
      excessive-agency LLM-to-shell path), so Prompt Injection, AI Supply Chain
      Compromise, and Excessive Agency below show genuine non-zero counts. Every other
      category is honestly zero - not faked to look populated (same treatment DAST and
      API Vulnerabilities get).
    </div>

    <h2>MITRE ATLAS heat map</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Counts of real findings tagged against this taxonomy by keyword heuristic
      (<code>remediation/enrichment/ai_vuln_taxonomy.py</code>). Zero-count cells are
      real known categories this taxonomy supports, just absent from today's findings.
    </p>
    ${renderHeatmap(heatmap)}

    <h2 style="margin-top:28px">AI/ML vulnerability categories</h2>
    <p class="filter-count" style="margin:-4px 0 8px">Click a category for its summary and remediation guidance.</p>
    ${exportButtonsHtml("ai-vuln")}
    <div class="faq-list">
      ${vulnerabilities.map(vulnerabilityCard).join("")}
    </div>`;

  wireExportButtons(container, "ai-vuln", {
    getRows: () => exportRows,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-ai-vulnerabilities",
  });
}
