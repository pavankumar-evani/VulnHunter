import { escapeHtml } from "./dom.js";

// Renders one guidance object from /api/findings/{id}/guidance or /api/guidance as HTML. Shared by the
// finding detail modal and the code-scan page so the two always read the same.
export function guidanceHtml(g) {
  const list = (items, ordered) => (items && items.length
    ? `<${ordered ? "ol" : "ul"} class="guidance-list">${items.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</${ordered ? "ol" : "ul"}>` : "");
  const refs = (g.references || []).map((r) => `<li><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.title)}</a></li>`).join("");
  const auto = g.automation || {};
  const ctl = g.client_controls;
  return `
    <p class="subtitle"><strong>${escapeHtml(g.title)}</strong>${g.curated ? "" : " (general approach)"}
      ${g.effort ? ` &middot; effort: ${escapeHtml(g.effort)}` : ""}</p>
    ${g.matched_by ? `<p class="muted">Matched on ${escapeHtml(g.matched_by)}.</p>` : `<p class="muted">No specific guidance matches this finding yet, so this is the general approach.</p>`}
    <p>${escapeHtml(g.summary || "")} ${g.why_it_matters ? `<em>${escapeHtml(g.why_it_matters)}</em>` : ""}</p>
    ${g.tailored && g.tailored.length ? `<div class="callout"><strong>For this finding</strong>${list(g.tailored)}</div>` : ""}
    <h4>Steps</h4>${list(g.steps, true)}
    <h4>How to confirm it is fixed</h4>${list(g.verify)}
    ${g.vendor_solution && g.vendor_solution.informative ? `<h4>What the scanner recommends</h4><p>${escapeHtml(g.vendor_solution.text)}</p>` : ""}
    <h4>If it cannot be fixed now</h4>${list(g.compensating_controls)}
    ${ctl ? `<div class="callout"><strong>Your existing controls</strong><p>These cover about ${ctl.existing_coverage_pct}% of this exposure (residual risk about ${ctl.residual_risk_pct}%).
      ${ctl.recommended_controls && ctl.recommended_controls.length ? "To close the gap:" : ""}</p>${list(ctl.recommended_controls)}</div>`
      : (g.client_controls_note ? `<p class="muted">${escapeHtml(g.client_controls_note)}</p>` : "")}
    ${assessmentHtml(g.client_assessment, list)}
    <p class="muted"><strong>What Quanta can do:</strong> ${escapeHtml(auto.note || "")}</p>
    ${refs ? `<h4>References</h4><ul class="guidance-list">${refs}</ul>` : ""}`;
}

const STATUS = {
  verified: ["In place (verified)", "badge-auto_approvable"], claimed: ["In place (recorded, not verified)", "badge-outline"],
  absent: ["Not in place", "badge-critical"], unknown: ["Not known for this asset", "badge-outline"],
};

// The compensating controls for this finding's attack techniques (MITRE ATT&CK mitigations), checked against the controls
// recorded for its asset.
function assessmentHtml(a, list) {
  if (!a) return "";
  const techs = (a.techniques || []).map((t) => `${escapeHtml(t.technique_id)}${t.technique_name ? ` ${escapeHtml(t.technique_name)}` : ""}`).join(", ");
  const rows = (a.compensating || []).map((m) => {
    const [label, cls] = STATUS[m.status] || STATUS.unknown;
    return `<tr><td><strong>${escapeHtml(m.name)}</strong><br><span class="muted">${escapeHtml(m.id)} &middot; ${escapeHtml(m.class_label)}${m.nist && m.nist.length ? ` &middot; NIST ${escapeHtml(m.nist.join(", "))}` : ""}</span></td>
      <td>${escapeHtml(m.action)}${m.evidence && m.evidence.length ? `<br><span class="muted">Recorded: ${m.evidence.map((e) => escapeHtml(e.name)).join("; ")}</span>` : ""}</td>
      <td><span class="badge ${cls}">${escapeHtml(label)}</span></td></tr>`;
  }).join("");
  return `<h4>Compensating controls for your environment</h4>
    ${techs ? `<p class="muted">Techniques this flaw enables: ${techs}. Mitigations are the ones MITRE ATT&amp;CK lists for them.</p>` : ""}
    ${a.coverage_pct !== null && a.coverage_pct !== undefined ? `<p>About <strong>${a.coverage_pct}%</strong> of the applicable mitigations are in place on this asset (indicative: verified counts 1, recorded 0.5). ${a.gaps && a.gaps.length ? `Biggest gaps: ${a.gaps.slice(0, 3).map((m) => escapeHtml(m.name)).join(", ")}.` : ""}</p>` : ""}
    ${a.note ? `<p class="muted">${escapeHtml(a.note)}</p>` : ""}
    ${rows ? `<div class="table-scroll"><table class="data-table"><thead><tr><th>Mitigation</th><th>What to put in place</th><th>On this asset</th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
    <p class="muted">${escapeHtml(a.disclaimer || "")}</p>`;
}
