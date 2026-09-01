// Shared "AI trend analysis" widget - reused across Overview/Infrastructure/AppSec/
// Risk/Certificate Vulnerabilities so each gets the same real, confirm-gated Claude
// Code call over that page's OWN already-computed real stats (severity/team/priority
// breakdowns, KPI totals, etc.), never a fabricated "AI insight" and never an
// auto-run-on-page-load call (per /api/ai-assist's own established pattern: no caching,
// no budget cap on this route, so every analysis is a genuine, explicit spend the admin
// opts into, same as AI Assist on a single finding - this is that same pattern, just
// over a page-level stats snapshot instead of one finding).
//
// A floating action button (copilot-style), not a chart-block sharing a .chart-row -
// a fixed-size tile competing for row space pushed sibling charts onto their own row
// whenever the row got tight, which is exactly the "gaps between graphs" complaint this
// redesign exists to remove. Clicking it opens a small anchored panel with 3 real
// actions (preview the prompt, generate a real analysis, or open the full Ask
// VulnHunter assistant) - selecting one shows its result in that same small panel.
import { api } from "./api.js";
import { escapeHtml, flash } from "./dom.js";

export function aiTrendAnalysisFabHtml(idPrefix) {
  return `
    <div class="ai-trend-fab-wrap" id="${idPrefix}-ai-trend-wrap">
      <div class="ai-trend-panel" id="${idPrefix}-ai-trend-panel" hidden>
        <div class="ai-trend-panel-header">
          <strong>✨ AI trend analysis</strong>
          <button type="button" class="ai-trend-panel-close" id="${idPrefix}-ai-trend-close" aria-label="Close">&times;</button>
        </div>
        <div class="ai-trend-panel-body" id="${idPrefix}-ai-trend-body"></div>
      </div>
      <button type="button" class="ai-trend-fab" id="${idPrefix}-ai-trend-fab" aria-label="AI trend analysis" aria-expanded="false" aria-haspopup="true">✨</button>
    </div>`;
}

function menuViewHtml(scopeLabel) {
  return `
    <p class="ai-trend-scope">Over: ${escapeHtml(scopeLabel)}</p>
    <button type="button" class="ai-trend-menu-option" data-action="preview">
      <span class="ai-trend-menu-option-title">🔍 Preview prompt</span>
      <span class="ai-trend-menu-option-note">Free - shows the exact prompt, no API call</span>
    </button>
    <button type="button" class="ai-trend-menu-option" data-action="generate">
      <span class="ai-trend-menu-option-title">✨ Generate analysis</span>
      <span class="ai-trend-menu-option-note">Calls the real Claude API - spends credits</span>
    </button>
    <a class="ai-trend-menu-option" href="/ask" data-link data-action="ask">
      <span class="ai-trend-menu-option-title">💬 Ask VulnHunter</span>
      <span class="ai-trend-menu-option-note">Open the full search assistant</span>
    </a>`;
}

function confirmGenerateViewHtml(scopeLabel) {
  return `
    <div class="callout callout-warn" style="margin:0 0 10px">
      ⚠️ This calls the real Claude API and spends real usage/credits against your plan,
      over the ${escapeHtml(scopeLabel)} stats already shown - not a live re-query, never
      fabricated.
    </div>
    <div class="ai-trend-panel-actions">
      <button type="button" class="secondary-button" data-action="back">Cancel</button>
      <button type="button" data-action="confirm-generate">Yes, generate</button>
    </div>`;
}

function resultViewHtml(result) {
  const backButton = `<div class="ai-trend-panel-actions"><button type="button" class="secondary-button" data-action="back">← Back</button></div>`;
  if (result.dry_run) {
    return `${backButton}
      <h3>Prompt preview (nothing sent, no cost)</h3>
      <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
  }
  return `${backButton}
    <h3>AI trend analysis</h3>
    <div class="callout">${escapeHtml(result.response).replaceAll("\n", "<br>")}</div>
    <h3>Prompt sent</h3>
    <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
}

// `statsFn` is called fresh at click-time (not captured once at render time) - may be
// async (e.g. re-fetching /api/overview itself rather than relying on a closure
// variable from the page's last render, which matters on pages like Overview that
// auto-refresh and fully replace their own DOM every 20s: keeping this widget's own
// markup outside that regenerated region, and re-fetching stats on demand instead of
// closing over a stale snapshot, is what lets an in-progress/just-received analysis
// survive the next auto-refresh instead of being wiped mid-read.
export function wireAiTrendAnalysis(container, idPrefix, scope, statsFn, scopeLabel) {
  const fab = container.querySelector(`#${idPrefix}-ai-trend-fab`);
  const panel = container.querySelector(`#${idPrefix}-ai-trend-panel`);
  const closeBtn = container.querySelector(`#${idPrefix}-ai-trend-close`);
  const body = container.querySelector(`#${idPrefix}-ai-trend-body`);
  if (!fab || !panel || !body) return;

  function showMenu() {
    body.innerHTML = menuViewHtml(scopeLabel);
    body.querySelectorAll(".ai-trend-menu-option[data-action]").forEach((el) => {
      el.addEventListener("click", () => {
        const action = el.dataset.action;
        if (action === "preview") runAnalysis(false);
        else if (action === "generate") showConfirm();
        else if (action === "ask") closePanel(); // real data-link anchor - let the router navigate
      });
    });
  }

  function showConfirm() {
    body.innerHTML = confirmGenerateViewHtml(scopeLabel);
    body.querySelector('[data-action="back"]').addEventListener("click", showMenu);
    body.querySelector('[data-action="confirm-generate"]').addEventListener("click", () => runAnalysis(true));
  }

  async function runAnalysis(confirm) {
    body.innerHTML = `<div class="empty-state">${confirm ? "Asking Claude - this calls the real API and can take a little while…" : "Building preview…"}</div>`;
    try {
      const stats = await statsFn();
      const result = await api.aiTrendAnalysis({ scope, stats, confirm });
      body.innerHTML = resultViewHtml(result);
      body.querySelector('[data-action="back"]').addEventListener("click", showMenu);
      flash(result.dry_run ? result.message : "AI trend analysis received.", result.dry_run ? "info" : "success");
    } catch (err) {
      showMenu();
      flash(err.message, "error");
    }
  }

  function openPanel() {
    panel.hidden = false;
    fab.setAttribute("aria-expanded", "true");
    showMenu();
  }

  function closePanel() {
    panel.hidden = true;
    fab.setAttribute("aria-expanded", "false");
  }

  fab.addEventListener("click", () => (panel.hidden ? openPanel() : closePanel()));
  closeBtn.addEventListener("click", closePanel);
}
