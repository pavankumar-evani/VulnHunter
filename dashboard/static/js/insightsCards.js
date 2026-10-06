// Home "Insights" cards: the top proactive insights (GET /api/insights) with what happened, why it matters, the evidence, how sure Quanta is and
// the next best action, plus Snooze / Dismiss / Done. Deterministic rules behind it, no model. Kept outside #overview-body so the page's own
// 20s refresh does not wipe a card mid-click. Signed-out visitors simply see nothing (the route needs a login).
import { api } from "./api.js";
import { escapeHtml, flash } from "./dom.js";

const ROLES = ["admin", "analyst", "appsec", "exec"];
let currentRole = null;
try { currentRole = localStorage.getItem("quanta.insightRole"); } catch { /* private mode */ }

function cardHtml(i) {
  const conf = Math.round((i.confidence?.value || 0) * 100);
  const ev = (i.evidence || []).filter((e) => e.page).slice(0, 3)
    .map((e) => `<a href="${escapeHtml(e.page)}" data-link>${escapeHtml(e.label)}</a>`).join(" · ");
  const b = i.breakdown || {};
  const why = `impact ${(b.impact ?? 0).toFixed(2)} × confidence ${(b.confidence ?? 0).toFixed(2)} × urgency ${(b.urgency ?? 0).toFixed(2)} × relevance ${(b.role_relevance ?? 0).toFixed(2)} × learned ${(b.learned_weight ?? 1).toFixed(2)}`;
  return `<div class="callout insight-card" data-insight="${escapeHtml(i.id)}" style="margin-bottom:10px">
    <div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline">
      <strong>${escapeHtml(i.title)}</strong>
      <span class="badge badge-outline" title="${escapeHtml(why)}">${escapeHtml(i.kind)} · score ${i.score}</span>
    </div>
    <p style="margin:6px 0 2px">${escapeHtml(i.what)}</p>
    <p class="filter-count" style="margin:2px 0">${escapeHtml(i.why)}</p>
    <p class="filter-count" style="margin:2px 0" title="${escapeHtml(i.confidence?.reasoning || "")}">Confidence ${conf}% · ${escapeHtml(i.impact?.text || "")}${ev ? " · " + ev : ""}</p>
    <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
      ${i.action?.page ? `<a class="btn" href="${escapeHtml(i.action.page)}" data-link>${escapeHtml(i.action.label || "Open")}</a>` : ""}
      <button type="button" class="link-button" data-act="acted">Done</button>
      <button type="button" class="link-button" data-act="snooze">Snooze</button>
      <button type="button" class="link-button" data-act="dismiss">Dismiss</button>
    </div></div>`;
}

export async function mountInsights(el) {
  async function load() {
    let data;
    try { data = await api.insights(currentRole, 5); } catch { el.innerHTML = ""; return; }
    if (!data.enabled) { el.innerHTML = ""; return; }
    const lens = data.role;
    const roleSel = `<select id="insight-role" aria-label="Role lens">${ROLES.map((r) => `<option value="${r}"${r === lens ? " selected" : ""}>${r}</option>`).join("")}</select>`;
    el.innerHTML = `<section class="insights-cards" style="margin-bottom:16px">
      <div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">Insights for you</h3><label class="filter-count">View as ${roleSel}</label></div>
      ${data.insights.length ? data.insights.map(cardHtml).join("") : `<p class="filter-count">Nothing needs attention right now${data.last_refresh ? "" : " (insights have not been computed yet)"}.</p>`}
    </section>`;
    el.querySelector("#insight-role")?.addEventListener("change", (e) => {
      currentRole = e.target.value;
      try { localStorage.setItem("quanta.insightRole", currentRole); } catch { /* ignore */ }
      load();
    });
    el.querySelectorAll("[data-act]").forEach((btn) => btn.addEventListener("click", async () => {
      const id = btn.closest("[data-insight]").dataset.insight;
      let body = {};
      if (btn.dataset.act === "dismiss") {
        const reason = window.prompt("Why dismiss this insight? (it helps Quanta learn what is useful)");
        if (!reason || !reason.trim()) return;
        body = { reason: reason.trim() };
      }
      try {
        await api.insightAction(id, btn.dataset.act, body);
        await load();
      } catch (err) { flash(err.message, "error"); }
    }));
  }
  await load();
}
