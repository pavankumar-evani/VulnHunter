// Shared "AI trend analysis" widget - reused across Overview/Infrastructure/AppSec/
// Risk/Certificate Vulnerabilities so each gets the same real, confirm-gated Claude
// Code call over that page's OWN
// already-computed real stats (severity/team/priority breakdowns, KPI totals, etc.),
// never a fabricated "AI insight" and never an auto-run-on-page-load call (per
// /api/ai-assist's own established pattern: no caching, no budget cap on this route,
// so every analysis is a genuine, explicit spend the admin opts into, same as AI Assist
// on a single finding - this is that same pattern, just over a page-level stats
// snapshot instead of one finding).
import { api } from "./api.js";
import { escapeHtml, flash } from "./dom.js";

// Sized to sit as a chart-block in an existing .chart-row next to whichever real
// chart that page already renders (e.g. overview.js's "By team"/"By priority" row)
// instead of pushing everything else down as its own full-width section. The full
// warning text lives in a hover tooltip on the (i) - still real, still disclosed,
// just not taking up permanent vertical space in a tile-sized slot.
export function aiTrendAnalysisTileHtml(idPrefix, scopeLabel) {
  const tooltip = `Generating a REAL analysis (checking confirm) calls the real Claude API and spends real usage/credits, over the ${scopeLabel} stats already shown - not a live re-query, never fabricated. Preview first, it's free.`;
  return `
    <div class="chart-block ai-trend-tile">
      <h3>✨ AI trend analysis <span class="muted" data-tooltip="${escapeHtml(tooltip)}" style="cursor:help">ⓘ</span></h3>
      <form class="ai-trend-tile-form" id="${idPrefix}-ai-trend-form">
        <label class="checkbox-label checkbox-danger" style="font-size:0.8rem">
          <input type="checkbox" name="confirm" id="${idPrefix}-ai-trend-confirm">
          Actually ask AI (spends credits)
        </label>
        <button type="submit" class="secondary-button">Generate</button>
      </form>
      <div id="${idPrefix}-ai-trend-result" class="ai-trend-tile-result"></div>
    </div>`;
}

// `statsFn` is called fresh at click-time (not captured once at render time) - may be
// async (e.g. re-fetching /api/overview itself rather than relying on a closure
// variable from the page's last render, which matters on pages like Overview that
// auto-refresh and fully replace their own DOM every 20s: keeping this panel's own
// markup outside that regenerated region, and re-fetching stats on demand instead of
// closing over a stale snapshot, is what lets an in-progress/just-received analysis
// survive the next auto-refresh instead of being wiped mid-read.
export function wireAiTrendAnalysis(container, idPrefix, scope, statsFn) {
  const form = container.querySelector(`#${idPrefix}-ai-trend-form`);
  const resultEl = container.querySelector(`#${idPrefix}-ai-trend-result`);
  if (!form || !resultEl) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const confirm = container.querySelector(`#${idPrefix}-ai-trend-confirm`).checked;
    resultEl.innerHTML = `<div class="empty-state">${confirm ? "Asking Claude - this calls the real API and can take a little while…" : "Building preview…"}</div>`;
    try {
      const stats = await statsFn();
      const result = await api.aiTrendAnalysis({ scope, stats, confirm });
      if (result.dry_run) {
        resultEl.innerHTML = `
          <h3>Prompt preview (nothing sent, no cost)</h3>
          <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
        flash(result.message, "info");
      } else {
        resultEl.innerHTML = `
          <h3>AI trend analysis</h3>
          <div class="callout">${escapeHtml(result.response).replaceAll("\n", "<br>")}</div>
          <h3>Prompt sent</h3>
          <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
        flash("AI trend analysis received.", "success");
      }
    } catch (err) {
      resultEl.innerHTML = "";
      flash(err.message, "error");
    }
  });
}
