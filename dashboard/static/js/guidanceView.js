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
    <p class="muted"><strong>What Quanta can do:</strong> ${escapeHtml(auto.note || "")}</p>
    ${refs ? `<h4>References</h4><ul class="guidance-list">${refs}</ul>` : ""}`;
}
