import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "All modules";

const PIN_KEY = "quanta.capabilities.area";

function remembered() {
  try { return window.localStorage.getItem(PIN_KEY); } catch { return null; }
}
function remember(id) {
  try { window.localStorage.setItem(PIN_KEY, id); } catch { /* private window: the choice just is not kept */ }
}

export async function render(container) {
  const { areas, license } = await api.capabilities();
  const asked = new URLSearchParams(window.location.search).get("area");
  let current = areas.find((a) => a.id === asked) || areas.find((a) => a.id === remembered()) || areas[0];

  const draw = () => {
    const banner = license && license.mode !== "off"
      ? `<p class="callout ${["valid", "unrestricted"].includes(license.state) ? "" : "callout-warn"}"><strong>Licence${license.customer ? ": " + escapeHtml(license.customer) : ""}${license.edition ? " (" + escapeHtml(license.edition) + ")" : ""}.</strong> ${escapeHtml(license.message)}${license.expires ? " Ends " + escapeHtml(license.expires) + "." : ""}${license.enforced ? "" : " Checking is in report-only mode."}</p>` : "";
    container.innerHTML = `${banner}<p class="subtitle">Pick a module. Each one opens the pages that belong to it, shows what it holds right now, and says what to connect if it is empty. Nothing needs to be switched on first.</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:14px 0">
        ${areas.map((a) => `<button type="button" data-area="${a.id}" style="text-align:left;padding:14px 16px;border-radius:8px;cursor:pointer;color:var(--ink,#eef1fb);background:${a.id === current.id ? "rgba(109,151,247,.16)" : "rgba(255,255,255,.04)"};border:1.5px solid ${a.id === current.id ? "var(--brand-accent)" : "rgba(255,255,255,.14)"}">
          <div class="muted" style="font-size:13px;letter-spacing:.08em">${escapeHtml(a.number)}</div><strong style="font-size:17px">${escapeHtml(a.title)}</strong>
          <div class="muted" style="margin-top:6px;font-size:13px">${a.licensed === false ? "Not part of your licence" : `${a.in_use} of ${a.capabilities} in use`}</div></button>`).join("")}</div>
      ${current.licensed === false ? `<p class="callout callout-warn"><strong>${escapeHtml(current.title)} is not part of your licence.</strong> Its pages stay closed until your administrator adds it.</p>` : ""}
      <h2 style="margin-top:22px">${escapeHtml(current.number)}. ${escapeHtml(current.title)}</h2><p>${escapeHtml(current.summary)}</p>
      ${current.groups.map((g) => `<h3>${escapeHtml(g.number)} ${escapeHtml(g.title)}</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px">
        ${g.items.map((i) => `<div style="border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:12px 16px;display:flex;flex-direction:column;gap:6px">
          <div><strong>${escapeHtml(i.title)}</strong> ${i.state === "active" ? '<span class="badge badge-low">in use</span>' : '<span class="badge badge-outline">ready</span>'}${i.admin ? ' <span class="badge badge-outline">admin</span>' : ""}</div>
          <div class="muted" style="font-size:14px">${escapeHtml(i.summary)}</div>
          ${i.metric ? `<div style="font-size:14px">${escapeHtml(i.metric)}</div>` : (i.needs && i.needs.length ? `<div class="muted" style="font-size:13px">To start: ${i.needs.map(escapeHtml).join("; ")}</div>` : "")}
          <div style="margin-top:auto"><a href="${escapeHtml(i.path)}" data-link style="color:var(--brand-accent);font-weight:600">Open &rarr;</a></div></div>`).join("")}</div>`).join("")}
      ${(current.connectors || []).length ? `<h3>Connectors for this module</h3><p class="muted">The systems that feed it. Credentials are stored encrypted on the Connections page.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">${current.connectors.map((c) => `<a href="${escapeHtml(c.path)}" data-link style="display:block;border:1px solid rgba(255,255,255,.14);border-radius:8px;padding:10px 14px;text-decoration:none;color:inherit">
          <strong>${escapeHtml(c.title)}</strong><div class="muted" style="font-size:13px;margin-top:4px">${escapeHtml(c.summary)}</div></a>`).join("")}</div>` : ""}`;
    container.querySelectorAll("[data-area]").forEach((b) => b.addEventListener("click", () => {
      current = areas.find((a) => a.id === b.dataset.area);
      remember(current.id);
      window.history.replaceState({}, "", `/capabilities?area=${encodeURIComponent(current.id)}`);
      draw();
    }));
  };
  draw();
}
