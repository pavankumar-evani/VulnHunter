import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { NAV } from "../nav.js";
import { icon } from "../icons.js";
import { chip, dataAgeBadge, mountDataAge, mountCounters, emptyState, debounce, onCleanup } from "../ui.js";

// The module picker, built on the UI kit (ui.js): tiles with an in-use meter and counters, a filter over the capabilities of the
// chosen module, empty states with a next step, and a data-age badge. Behaviour (module choice remembered, ?area= deep link,
// licence banner) is unchanged.
export const title = "All modules";

const PIN_KEY = "quanta.capabilities.area";

function remembered() {
  try { return window.localStorage.getItem(PIN_KEY); } catch { return null; }
}
function remember(id) {
  try { window.localStorage.setItem(PIN_KEY, id); } catch { /* private window: the choice just is not kept */ }
}
const iconFor = (id) => (NAV.find((g) => g.id === id) || {}).icon || "dashboard";

export async function render(container) {
  const { areas, license } = await api.capabilities();
  const fetchedAt = new Date();
  const asked = new URLSearchParams(window.location.search).get("area");
  let current = areas.find((a) => a.id === asked) || areas.find((a) => a.id === remembered()) || areas[0];
  let query = "";

  const tile = (a) => {
    const locked = a.licensed === false;
    const pct = a.capabilities ? Math.round((a.in_use / a.capabilities) * 100) : 0;
    return `<button type="button" class="mod-tile" data-area="${escapeHtml(a.id)}" aria-pressed="${a.id === current.id}"${locked ? ' aria-describedby="lic-note"' : ""}>
      <span class="mod-no"><span class="mod-ico">${icon(iconFor(a.id), 18)}</span>${escapeHtml(a.number)}</span>
      <span class="mod-title">${escapeHtml(a.title)}</span>
      <span class="mod-meta"><span>${locked ? "Not part of your licence" : `<strong data-count="${a.in_use}">${a.in_use}</strong> of ${a.capabilities} in use`}</span>${locked ? chip("locked", { tone: "bad" }) : ""}</span>
      <span class="mod-meter" role="presentation"><i style="width:${locked ? 0 : pct}%"></i></span></button>`;
  };

  const itemCard = (i) => `<div class="mod-item">
    <div><strong>${escapeHtml(i.title)}</strong> ${i.state === "active" ? chip("in use", { tone: "good" }) : chip("ready")}${i.admin ? " " + chip("admin") : ""}</div>
    <div class="ui-muted" style="font-size:.9rem">${escapeHtml(i.summary)}</div>
    ${i.metric ? `<div style="font-size:.9rem">${escapeHtml(i.metric)}</div>` : (i.needs && i.needs.length ? `<div class="ui-muted" style="font-size:.82rem">To start: ${i.needs.map(escapeHtml).join("; ")}</div>` : "")}
    <div style="margin-top:auto"><a href="${escapeHtml(i.path)}" data-link style="color:var(--brand-accent);font-weight:600">Open &rarr;</a></div></div>`;

  const matches = (i) => !query || `${i.title} ${i.summary}`.toLowerCase().includes(query);

  const detail = () => {
    const groups = current.groups.map((g) => ({ ...g, shown: g.items.filter(matches) })).filter((g) => g.shown.length);
    const body = groups.length
      ? groups.map((g) => `<h3>${escapeHtml(g.number)} ${escapeHtml(g.title)}</h3><div class="ui-grid ui-grid-wide">${g.shown.map(itemCard).join("")}</div>`).join("")
      : emptyState({ title: query ? "No capability matches that" : "This module has no capabilities listed", body: query ? "Try a shorter word, or clear the filter." : "", iconName: "search" });
    const connectors = (current.connectors || []).length ? `<h3>Connectors for this module</h3><p class="ui-muted">The systems that feed it. Credentials are stored encrypted on the Connections page.</p>
      <div class="ui-grid ui-grid-wide">${current.connectors.map((c) => `<a href="${escapeHtml(c.path)}" data-link class="mod-item" style="text-decoration:none;color:inherit"><strong>${escapeHtml(c.title)}</strong><span class="ui-muted" style="font-size:.84rem">${escapeHtml(c.summary)}</span></a>`).join("")}</div>` : "";
    return `${current.licensed === false ? `<p class="callout callout-warn" id="lic-note"><strong>${escapeHtml(current.title)} is not part of your licence.</strong> Its pages stay closed until your administrator adds it.</p>` : ""}
      <div class="ui-section-title"><h2>${escapeHtml(current.number)}. ${escapeHtml(current.title)}</h2>
        <label class="ui-table-filter" style="margin-left:auto"><span class="ui-sr">Filter capabilities</span>${icon("search", 14)}<input type="search" id="cap-filter" placeholder="Filter capabilities…" autocomplete="off" value="${escapeHtml(query)}"></label></div>
      <p>${escapeHtml(current.summary)}</p>${body}${connectors}`;
  };

  const draw = () => {
    const banner = license && license.mode !== "off"
      ? `<p class="callout ${["valid", "unrestricted"].includes(license.state) ? "" : "callout-warn"}"><strong>Licence${license.customer ? ": " + escapeHtml(license.customer) : ""}${license.edition ? " (" + escapeHtml(license.edition) + ")" : ""}.</strong> ${escapeHtml(license.message)}${license.expires ? " Ends " + escapeHtml(license.expires) + "." : ""}${license.enforced ? "" : " Checking is in report-only mode."}</p>` : "";
    container.innerHTML = `${banner}<div class="home-top"><p class="subtitle" style="margin:0">Pick a module. Each one opens the pages that belong to it, shows what it holds right now, and says what to connect if it is empty. Nothing needs to be switched on first. Press <kbd>Ctrl</kbd> <kbd>K</kbd> to jump anywhere.</p>${dataAgeBadge(fetchedAt)}</div>
      <div class="mod-grid" role="group" aria-label="Modules">${areas.map(tile).join("")}</div>
      <div id="cap-detail">${detail()}</div>`;
    mountDataAge(container);
    wire();
  };

  // Filtering redraws only the detail, so typing never loses focus and the tiles do not re-animate.
  const redrawDetail = () => {
    const box = container.querySelector("#cap-filter");
    const pos = box ? box.selectionStart : 0;
    container.querySelector("#cap-detail").innerHTML = detail();
    const again = container.querySelector("#cap-filter");
    if (again) { again.focus(); try { again.setSelectionRange(pos, pos); } catch { /* not supported on this input type */ } wireFilter(); }
  };
  const onType = debounce((value) => { query = value.trim().toLowerCase(); redrawDetail(); }, 160);
  onCleanup(() => onType.cancel());
  function wireFilter() {
    const box = container.querySelector("#cap-filter");
    if (box) box.addEventListener("input", () => onType(box.value));
  }
  function wire() {
    container.querySelectorAll("[data-area]").forEach((b) => b.addEventListener("click", () => {
      current = areas.find((a) => a.id === b.dataset.area);
      query = "";
      remember(current.id);
      window.history.replaceState({}, "", `/capabilities?area=${encodeURIComponent(current.id)}`);
      container.querySelectorAll("[data-area]").forEach((t) => t.setAttribute("aria-pressed", String(t.dataset.area === current.id)));
      container.querySelector("#cap-detail").innerHTML = detail();
      wireFilter();
    }));
    wireFilter();
  }
  draw();
  mountCounters(container);
}
