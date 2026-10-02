import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Capabilities";

const PIN_KEY = "quanta.capabilities.area";

function remembered() {
  try { return window.localStorage.getItem(PIN_KEY); } catch { return null; }
}
function remember(id) {
  try { window.localStorage.setItem(PIN_KEY, id); } catch { /* private window: the choice just is not kept */ }
}

export async function render(container) {
  const { areas } = await api.capabilities();
  const asked = new URLSearchParams(window.location.search).get("area");
  let current = areas.find((a) => a.id === asked) || areas.find((a) => a.id === remembered()) || areas[0];

  const draw = () => {
    container.innerHTML = `<p class="subtitle">Pick what you want to do. Each area opens the pages that belong to it, shows what it holds right now, and says what to connect if it is empty. Nothing needs to be switched on first.</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:14px 0">
        ${areas.map((a) => `<button type="button" data-area="${a.id}" style="text-align:left;padding:14px 16px;border-radius:8px;cursor:pointer;color:var(--ink,#eef1fb);background:${a.id === current.id ? "rgba(109,151,247,.16)" : "rgba(255,255,255,.04)"};border:1.5px solid ${a.id === current.id ? "var(--brand-accent)" : "rgba(255,255,255,.14)"}">
          <div class="muted" style="font-size:13px;letter-spacing:.08em">${escapeHtml(a.number)}</div><strong style="font-size:17px">${escapeHtml(a.title)}</strong>
          <div class="muted" style="margin-top:6px;font-size:13px">${a.in_use} of ${a.capabilities} in use</div></button>`).join("")}</div>
      <h2 style="margin-top:22px">${escapeHtml(current.number)}. ${escapeHtml(current.title)}</h2><p>${escapeHtml(current.summary)}</p>
      ${current.groups.map((g) => `<h3>${escapeHtml(g.number)} ${escapeHtml(g.title)}</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px">
        ${g.items.map((i) => `<div style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:12px 16px;display:flex;flex-direction:column;gap:6px">
          <div><strong>${escapeHtml(i.title)}</strong> ${i.state === "active" ? '<span class="badge badge-low">in use</span>' : '<span class="badge badge-outline">ready</span>'}${i.admin ? ' <span class="badge badge-outline">admin</span>' : ""}</div>
          <div class="muted" style="font-size:14px">${escapeHtml(i.summary)}</div>
          ${i.metric ? `<div style="font-size:14px">${escapeHtml(i.metric)}</div>` : (i.needs && i.needs.length ? `<div class="muted" style="font-size:13px">To start: ${i.needs.map(escapeHtml).join("; ")}</div>` : "")}
          <div style="margin-top:auto"><a href="${escapeHtml(i.path)}" data-link style="color:var(--brand-accent);font-weight:600">Open &rarr;</a></div></div>`).join("")}</div>`).join("")}`;
    container.querySelectorAll("[data-area]").forEach((b) => b.addEventListener("click", () => {
      current = areas.find((a) => a.id === b.dataset.area);
      remember(current.id);
      window.history.replaceState({}, "", `/capabilities?area=${encodeURIComponent(current.id)}`);
      draw();
    }));
  };
  draw();
}
