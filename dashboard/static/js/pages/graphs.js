// Relationship graphs: one interactive graph per module (?module=soc|appsec|devsecops|infra|ai|remediation|grc|admin).
// The graph is built on the server from that module's own stored data (remediation/graphs/*), and drawn and analysed in the browser (graphView.js).
// With nothing recorded it says what to connect, instead of drawing an invented picture.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { renderGraphView } from "../graphView.js";

export const title = "Relationship graphs";

const MODULES = [
  ["soc", "Threat Detection & Response"], ["appsec", "Application Security"], ["devsecops", "DevSecOps & Supply Chain"], ["infra", "Infrastructure & Exposure"],
  ["ai", "AI Security"], ["remediation", "Remediation & Workflow"], ["grc", "Risk, Governance & Compliance"], ["admin", "Administration"],
];

export async function render(container) {
  const params = new URLSearchParams(window.location.search);
  const wanted = params.get("module");
  const module = MODULES.some(([id]) => id === wanted) ? wanted : "soc";
  container.innerHTML = `
    <p class="subtitle">How things in a module are connected, drawn from what Quanta has recorded. Clusters, choke points and single points of failure are computed from the links, so the picture shows structure you cannot see in a table. Nothing here is guessed: with no data it tells you what to connect.</p>
    <div class="gv-tabs" role="tablist" aria-label="Module">${MODULES.map(([id, name]) => `<a class="gv-tab${id === module ? " gv-tab-on" : ""}" role="tab" aria-selected="${id === module}" href="/graphs?module=${id}" data-link>${escapeHtml(name)}</a>`).join("")}</div>
    <div id="gv-host"><p class="muted">Loading the graph…</p></div>`;
  const host = container.querySelector("#gv-host");
  try {
    const graph = await api.graph(module);
    host.innerHTML = `<h2 class="gv-title">${escapeHtml(graph.title || "")}</h2><div id="gv-view"></div>`;
    renderGraphView(host.querySelector("#gv-view"), graph, { navigate: (href) => { window.history.pushState({}, "", href); window.dispatchEvent(new PopStateEvent("popstate")); } });
  } catch (err) {
    host.innerHTML = `<p class="gv-empty">${escapeHtml(err && err.message ? err.message : "The graph could not be loaded.")}</p>`;
  }
}
