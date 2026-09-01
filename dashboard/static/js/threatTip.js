// A dismissible, horizontal "threat intel tip" banner shown above the page content on
// every route (wired once from app.js, lives in the shell's #threat-tip-banner - a
// sibling of #app, same "persists across client-side navigation" pattern as
// flash-container/modal-root in index.html). Content is a real, live-computed fact
// pulled from the same CISA KEV + FIRST.org EPSS data already shown on /queue - not a
// canned message, so it can never say something the data doesn't actually support.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { getCurrentUser } from "./auth.js";

const DISMISS_KEY = "vulnhunter-tip-dismissed";

// Plain, precise date - not a relative "Xm ago" (dom.js's timeAgo() only makes sense
// for values that are fresh within minutes; this can honestly be days/weeks old).
function formatFreshnessDate(isoString) {
  const d = new Date(isoString);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short",
  });
}

function buildTipText(queueData, freshness) {
  const findings = queueData.findings || [];
  const kevFindings = findings.filter((f) => f.kev && f.kev.listed);
  const breachedKev = kevFindings.filter((f) => f.sla && f.sla.breached);
  const topEpss = findings
    .filter((f) => f.epss && typeof f.epss.score === "number")
    .sort((a, b) => b.epss.score - a.epss.score)[0];

  const facts = [];
  if (breachedKev.length) {
    facts.push(`<strong>${breachedKev.length}</strong> CISA KEV-listed finding(s) are past SLA - actively exploited, needs immediate attention`);
  } else if (kevFindings.length) {
    facts.push(`<strong>${kevFindings.length}</strong> finding(s) are CISA KEV-listed (actively exploited in the wild)`);
  }
  if (topEpss) {
    facts.push(`highest exploit-probability finding: <code>${escapeHtml(topEpss.id)}</code> — ${escapeHtml(topEpss.title)} (${(topEpss.epss.score * 100).toFixed(1)}% EPSS)`);
  }
  if (!facts.length) return null;
  // Real, from normalized-findings.json's own last-modified time (see
  // dashboard_data.load_threat_intel_freshness()) - honest about how current the
  // KEV/EPSS data behind the facts above actually is, not just the facts themselves.
  if (freshness && freshness.available) {
    facts.push(`threat intel last refreshed ${escapeHtml(formatFreshnessDate(freshness.last_refreshed))} - <a href="/threat-intel" data-link>refresh now</a>`);
  }
  return `Live threat intel (CISA KEV + FIRST.org EPSS): ${facts.join(" &middot; ")}.`;
}

export function initThreatTip() {
  const root = document.getElementById("threat-tip-banner");
  if (!root) return;

  async function render() {
    root.innerHTML = "";
    if (sessionStorage.getItem(DISMISS_KEY)) return;
    if (!(await getCurrentUser())) return; // keep the login page clean

    let queueData;
    try {
      queueData = await api.queue();
    } catch {
      return; // not logged in yet, or the call failed - just show nothing
    }
    // A freshness-fetch hiccup shouldn't hide the (already-fetched, working) KEV/EPSS
    // facts above it - degrade to just those facts instead of the whole banner.
    const freshness = await api.threatIntelFreshness().catch(() => null);
    const text = buildTipText(queueData, freshness);
    if (!text) return;

    root.innerHTML = `
      <div class="threat-tip">
        ${icon("risk", 18)}
        <span class="threat-tip-text">${text} <a href="/queue" data-link>View queue &rarr;</a></span>
        <button type="button" class="threat-tip-close" aria-label="Dismiss">&times;</button>
      </div>`;
    root.querySelector(".threat-tip-close").addEventListener("click", () => {
      root.innerHTML = "";
      sessionStorage.setItem(DISMISS_KEY, "1");
    });
  }

  render();
  // Re-checks after login (so the tip appears without a full reload) and clears it
  // on logout (a stale queue-derived tip has no business surviving past sign-out).
  window.addEventListener("vulnhunter-auth-changed", render);
}
