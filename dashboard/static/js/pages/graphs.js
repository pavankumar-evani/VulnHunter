// Relationship graphs: one interactive graph per module (?module=soc|appsec|devsecops|infra|ai|remediation|grc|admin).
// The graph is built on the server from that module's own stored data (remediation/graphs/*), and drawn and analysed in the browser (graphView.js).
// With nothing recorded it says what to connect, instead of drawing an invented picture.
// Below the graph, an Ontology section (remediation/ontology): a conformance check of the graphs against the ontology and a picker of named multi-hop
// questions whose result paths are lit up on the graph above where they touch this module.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { renderGraphView } from "../graphView.js";

export const title = "Relationship graphs";

const MODULES = [
  ["soc", "Threat Detection & Response"], ["appsec", "Application Security"], ["devsecops", "DevSecOps & Supply Chain"], ["infra", "Infrastructure & Exposure"],
  ["ai", "AI Security"], ["remediation", "Remediation & Workflow"], ["grc", "Risk, Governance & Compliance"], ["admin", "Administration"],
];

let lastResult = null;   // the last question result, kept so it is lit up again when the person switches module

const errText = (err, fallback) => (err && err.message ? err.message : fallback);

export async function render(container) {
  const params = new URLSearchParams(window.location.search);
  const wanted = params.get("module");
  const module = MODULES.some(([id]) => id === wanted) ? wanted : "soc";
  container.innerHTML = `
    <p class="subtitle">How things in a module are connected, drawn from what Quanta has recorded. Clusters, choke points and single points of failure are computed from the links, so the picture shows structure you cannot see in a table. Nothing here is guessed: with no data it tells you what to connect.</p>
    <div class="gv-tabs" role="tablist" aria-label="Module">${MODULES.map(([id, name]) => `<a class="gv-tab${id === module ? " gv-tab-on" : ""}" role="tab" aria-selected="${id === module}" href="/graphs?module=${id}" data-link>${escapeHtml(name)}</a>`).join("")}</div>
    <div id="gv-host"><p class="muted">Loading the graph…</p></div>
    <section id="onto-host" class="gv-onto" aria-label="Ontology"></section>`;
  const host = container.querySelector("#gv-host");
  let view = null;
  renderOntology(container.querySelector("#onto-host"), module, () => view);   // does not wait for the (possibly slow) graph
  try {
    const graph = await api.graph(module);
    host.innerHTML = `<h2 class="gv-title">${escapeHtml(graph.title || "")}</h2><div id="gv-view"></div>`;
    view = renderGraphView(host.querySelector("#gv-view"), graph, { navigate: (href) => { window.history.pushState({}, "", href); window.dispatchEvent(new PopStateEvent("popstate")); } });
    if (lastResult && lastResult.count && view && view.setHighlight) view.setHighlight(highlightPaths(lastResult, module).paths);
  } catch (err) {
    host.innerHTML = `<p class="gv-empty">${escapeHtml(errText(err, "The graph could not be loaded."))}</p>`;
  }
}

// ------------------------------------------------------------------ ontology section
function pathText(p) {
  return p.nodes.map((n) => `${escapeHtml(n.label || n.id)} <span class="muted">(${escapeHtml(n.class)})</span>`).join(" &rarr; ");
}

function factText(e) {
  const f = e.fact;
  if (!f) return "";
  if (!f.known) return `${escapeHtml(e.relation)}: provenance unknown`;
  const bits = [f.source && `source ${f.source}`, f.source_kind, f.observed_at && `seen ${f.observed_at}`, f.confidence].filter(Boolean);
  return `${escapeHtml(e.relation)}: ${escapeHtml(bits.join(", "))}`;
}

// Map a result's estate ids onto this module graph's own ids through each node's origin, so the paths can be lit on the graph above.
export function highlightPaths(result, module) {
  const own = (n) => (n.origin || []).filter((o) => o.module === module).map((o) => o.id);
  const paths = [];
  let inside = 0, total = 0;
  const others = new Set();
  for (const p of result.paths || []) {
    const byId = new Map(p.nodes.map((n) => [n.id, own(n)]));
    const nodes = [], edges = [];
    for (const n of p.nodes) {
      total += 1;
      const ids = byId.get(n.id);
      if (ids.length) { inside += 1; nodes.push(...ids); } else for (const o of n.origin || []) others.add(o.module);
    }
    for (const e of p.edges) for (const s of byId.get(e.source) || []) for (const t of byId.get(e.target) || []) edges.push({ source: s, target: t });
    paths.push({ nodes, edges });
  }
  return { paths, inside, total, others: [...others].sort() };
}

function renderOntology(el, module, getView) {
  el.innerHTML = `
    <h2 class="gv-title">Ontology</h2>
    <p class="muted">The graphs above are checked against a shared vocabulary of classes and typed relations, and joined into one estate graph so a question can follow links across modules. Both tools below are for administrators.</p>
    <div class="gv-bar">
      <button type="button" class="secondary-button" data-onto="validate">Check conformance</button>
      <span data-onto="status" class="muted" aria-live="polite"></span>
    </div>
    <div data-onto="report"></div>
    <div class="gv-bar">
      <label>Question <select data-onto="question" aria-label="Question"><option value="">Loading…</option></select></label>
      <button type="button" class="secondary-button" data-onto="run" disabled>Run question</button>
    </div>
    <p class="muted" data-onto="qtext"></p>
    <div data-onto="result" aria-live="polite"></div>`;
  const q = (n) => el.querySelector(`[data-onto="${n}"]`);
  const select = q("question"), runBtn = q("run");
  let questions = [];

  api.ontologyQuestions().then((d) => {
    questions = d.questions || [];
    select.innerHTML = questions.map((x) => `<option value="${escapeHtml(x.id)}"${x.error ? " disabled" : ""}>${escapeHtml(x.title || x.id)}</option>`).join("") || '<option value="">No questions</option>';
    runBtn.disabled = !questions.length;
    showQuestion();
    if (lastResult && questions.some((x) => x.id === lastResult.question?.id)) { select.value = lastResult.question.id; showQuestion(); showResult(lastResult); }
  }).catch((err) => { select.innerHTML = '<option value="">Unavailable</option>'; q("qtext").textContent = errText(err, "The questions could not be loaded."); });

  function showQuestion() {
    const x = questions.find((y) => y.id === select.value);
    q("qtext").innerHTML = x ? `${escapeHtml(x.question || "")}<br><code>${escapeHtml(x.text || x.error || "")}</code>` : "";
  }
  select.addEventListener("change", showQuestion);

  function showResult(res) {
    const view = getView();
    const lit = highlightPaths(res, module);
    let lead;
    if (res.count) lead = `<p><strong>${res.count}</strong> result${res.count === 1 ? "" : "s"}.${res.note ? " " + escapeHtml(res.note) : ""}</p>`;
    else lead = `<p class="gv-empty">No result. ${escapeHtml(res.reason || "")}</p>`;
    let where = "";
    if (res.count) {
      const n = view && view.setHighlight ? view.setHighlight(lit.paths) : 0;
      where = `<p class="muted">${n ? `${lit.inside} of ${lit.total} steps on these paths are lit on this graph.` : "None of these paths touches this module's graph."}${lit.others.length ? ` Other steps are in: ${escapeHtml(lit.others.join(", "))}.` : ""}</p>`;
    } else if (view && view.setHighlight) view.setHighlight([]);
    const rows = (res.paths || []).slice(0, 25).map((p) => `<li>${pathText(p)}<br><span class="muted">${p.edges.map(factText).join(" &middot; ")}</span></li>`).join("");
    q("result").innerHTML = lead + where + (rows ? `<ol class="gv-paths">${rows}</ol>` : "") + (res.question?.limits ? `<p class="muted">${escapeHtml(res.question.limits)}</p>` : "");
  }

  runBtn.addEventListener("click", async () => {
    if (!select.value) return;
    runBtn.disabled = true;
    q("result").innerHTML = '<p class="muted">Running…</p>';
    try {
      lastResult = await api.ontologyQuery({ question: select.value });
      showResult(lastResult);
    } catch (err) {
      q("result").innerHTML = `<p class="gv-empty">${escapeHtml(errText(err, "The question could not be run."))}</p>`;
    } finally { runBtn.disabled = false; }
  });

  q("validate").addEventListener("click", async () => {
    q("status").textContent = "Checking…";
    try {
      const r = await api.ontologyValidate();
      const counts = (rep) => Object.entries(rep.counts || {}).map(([k, v]) => `${v} ${k}`).join(", ");
      const prov = r.provenance || { facts: 0, with_any: 0 };
      q("status").textContent = r.conforms ? "All graphs conform." : "Some graphs do not conform.";
      const rows = [...Object.entries(r.modules || {}), ["estate", r.estate]].map(([m, rep]) =>
        `<tr><td>${escapeHtml(m)}</td><td>${rep.conforms ? "conforms" : "does not conform"}</td><td>${rep.checked.nodes} / ${rep.checked.edges}</td><td>${escapeHtml(counts(rep))}</td></tr>`).join("");
      const sample = [...Object.entries(r.modules || {}), ["estate", r.estate]].flatMap(([m, rep]) => (rep.violations || []).slice(0, 3).map((v) => `<li><strong>${escapeHtml(m)}</strong> ${escapeHtml(v.rule)}: ${escapeHtml(v.message)} <span class="muted">${escapeHtml(v.node || (v.edge ? v.edge.source + " &rarr; " + v.edge.target : ""))}</span></li>`)).join("");
      q("report").innerHTML = `<table class="data-table"><thead><tr><th>Graph</th><th>Result</th><th>Nodes / edges</th><th>Violations</th></tr></thead><tbody>${rows}</tbody></table>`
        + (sample ? `<ul class="gv-paths">${sample}</ul>` : "")
        + `<p class="muted">Provenance: ${prov.with_any} of ${prov.facts} links in the estate graph say where they came from; the rest are unknown, not guessed.${(r.unavailable || []).length ? " Unavailable: " + escapeHtml(r.unavailable.join(", ")) + "." : ""}</p>`;
    } catch (err) {
      q("status").textContent = errText(err, "The check could not be run (administrators only).");
    }
  });
}
