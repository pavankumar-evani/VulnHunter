// Threat hunting > Library & frameworks (functional first cut; the polished UI builds on docs/HUNT_KNOWLEDGE.md).
// Three views: the out-of-the-box library (scenarios with coverage status, rules, controls, use cases), a framework view for a suggested hypothesis (Diamond, kill chain, PEAK,
// maturity) and a report builder. Nothing here runs a query; promotion creates drafts (a proposed use case, a disabled rule, a planned control).
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { chip, toast } from "./ui.js";

const STATUS_TONE = { enabled: "good", proposed: "info", absent: "warn", "cannot-tell": "neutral" };
const LANG_LABEL = { sigma: "Sigma", "splunk-spl": "Splunk SPL", kql: "KQL", eql: "EQL" };
const e = escapeHtml;

export async function render(body, { isAdmin = false } = {}) {
  let view = "library";
  const paint = async () => {
    body.innerHTML = `<div class="sx-panel"><div class="hx-tabs" role="tablist" aria-label="Library views">${[["library", "Out-of-the-box library"], ["frameworks", "Framework view"], ["report", "Report builder"]]
      .map(([k, l]) => `<button type="button" role="tab" data-v="${k}" aria-selected="${k === view}">${l}</button>`).join("")}</div><div id="hl-body" style="margin-top:12px"></div></div>`;
    body.querySelectorAll("[data-v]").forEach((b) => b.addEventListener("click", () => { view = b.dataset.v; paint(); }));
    const host = body.querySelector("#hl-body");
    host.innerHTML = '<div class="ui-skel ui-skel-table"></div>';
    try {
      if (view === "library") await library(host); else if (view === "frameworks") await frameworks(host); else await reportBuilder(host);
    } catch (err) { host.innerHTML = `<div class="sx-callout warn">${e(err.message || String(err))}</div>`; }
  };

  // ------------------------------------------------------------------ library
  async function library(host) {
    const f = { q: "", category: "", status: "", tactic: "" };
    let lib = await api.huntKnowledgeLibrary("");
    const qs = () => { const p = new URLSearchParams(); Object.entries(f).forEach(([k, v]) => v && p.set(k, v)); const s = p.toString(); return s ? `?${s}` : ""; };
    const opts = (obj, cur) => `<option value="">All</option>${Object.entries(obj || {}).map(([k, n]) => `<option value="${e(k)}"${k === cur ? " selected" : ""}>${e(k)} (${n})</option>`).join("")}`;
    const draw = () => {
      host.innerHTML = `<div class="sx-callout">${e(lib.coverage_note)} ${lib.rules_recorded ? "" : "No detection rules are recorded, so coverage shows as cannot-tell."}</div>
        <div class="sx-row" style="gap:8px;margin:10px 0;flex-wrap:wrap">
          <input id="hl-q" class="ui-input" placeholder="Search title, technique or text" value="${e(f.q)}" aria-label="Search the library">
          <label>Category <select id="hl-cat">${opts(lib.facets.category, f.category)}</select></label>
          <label>Tactic <select id="hl-tac">${opts(lib.facets.tactic, f.tactic)}</select></label>
          <label>Coverage <select id="hl-st">${opts(lib.facets.coverage, f.status)}</select></label>
          <span class="ui-muted">${lib.shown} of ${lib.total}</span></div>
        <div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Scenario</th><th>Category</th><th>Severity</th><th>Techniques</th><th>Data needed</th><th>Coverage</th><th></th></tr></thead><tbody>
        ${lib.items.map((i) => `<tr><td><b>${e(i.title)}</b><div class="ui-muted" style="font-size:.8rem">${e(i.hypothesis).slice(0, 160)}</div></td><td>${e(i.category)}</td><td>${e(i.severity)}</td>
          <td>${i.techniques.slice(0, 4).map((t) => chip(t.id, { title: t.name })).join(" ")}</td><td>${i.data_sources.map((d) => chip(d)).join(" ")}</td>
          <td>${chip(i.coverage_status, { tone: STATUS_TONE[i.coverage_status] || "neutral", title: i.coverage.detail })}</td>
          <td><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-open="${e(i.id)}">Open</button></td></tr>`).join("") || '<tr><td colspan="7">Nothing matches these filters.</td></tr>'}
        </tbody></table></div><div id="hl-detail" style="margin-top:12px"></div>`;
      const reload = async () => { lib = await api.huntKnowledgeLibrary(qs()); draw(); };
      host.querySelector("#hl-q").addEventListener("change", (ev) => { f.q = ev.target.value.trim(); reload(); });
      host.querySelector("#hl-cat").addEventListener("change", (ev) => { f.category = ev.target.value; reload(); });
      host.querySelector("#hl-tac").addEventListener("change", (ev) => { f.tactic = ev.target.value; reload(); });
      host.querySelector("#hl-st").addEventListener("change", (ev) => { f.status = ev.target.value; reload(); });
      host.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => detail(host.querySelector("#hl-detail"), b.dataset.open)));
    };
    draw();
  }

  async function detail(el, id) {
    el.innerHTML = '<div class="ui-skel ui-skel-card"></div>';
    const d = await api.huntKnowledgeScenario(id);
    const s = d.scenario; const c = d.content;
    const lead = (l) => `<details><summary><b>${e(l.name)}</b> ${chip(l.technique)}</summary>${l.notes ? `<p class="ui-muted">${e(l.notes)}</p>` : ""}
      ${Object.entries(l.languages).map(([lang, v]) => `<div><b>${e(LANG_LABEL[lang] || lang)}</b> ${v.status === "provided" ? "" : chip(v.status, { tone: "warn" })}
        ${v.status === "provided" ? `<pre style="white-space:pre-wrap;overflow:auto;max-height:240px">${e(v.query)}</pre>` : `<p class="ui-muted">${e(v.reason || "")}</p>`}</div>`).join("")}</details>`;
    el.innerHTML = `<section class="sx-panel"><h3>${e(s.title)}</h3><p>${e(s.hypothesis_text)}</p>
      <div class="sx-row" style="gap:6px;flex-wrap:wrap">${s.techniques.map((t) => chip(`${t.id} ${t.name}`)).join(" ")} ${chip(`readiness: ${d.readiness.status}`, { tone: d.readiness.status === "ready" ? "good" : "neutral" })}</div>
      <h4>Leads</h4>${d.leads.map(lead).join("")}
      <h4>Malicious looks like</h4><ul>${s.malicious.map((x) => `<li>${e(x)}</li>`).join("")}</ul><h4>Likely benign</h4><ul>${s.benign.map((x) => `<li>${e(x)}</li>`).join("")}</ul>
      <h4>Tuning</h4><ul>${s.tuning.map((x) => `<li>${e(x)}</li>`).join("")}</ul>
      <h4>Recommended response (for a person)</h4><ul>${s.response.map((x) => `<li>${e(x)}</li>`).join("")}</ul>
      <h4>Suggested controls</h4><div class="sx-table-wrap"><table class="sx-table"><tbody>${c.controls.slice(0, 10).map((k) => `<tr><td>${e(k.id)}</td><td>${e(k.name)}</td><td>${e(k.class_label || "not mapped")}</td>
        <td>${e(k.action)}</td><td>${k.status === "planned" ? chip("planned", { tone: "info" }) : isAdmin ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-plan="${e(k.id)}">Add as planned</button>` : ""}</td></tr>`).join("")}</tbody></table></div>
      <p class="ui-muted">Planned controls are a planning list only; nothing is recorded as implemented.</p>
      ${isAdmin ? `<div class="sx-row" style="gap:8px"><button type="button" class="ui-btn" id="hl-uc">Promote to use case (proposed)</button><button type="button" class="ui-btn ui-btn-ghost" id="hl-rep">Build hunt report</button></div>` : ""}
      <div id="hl-out"></div></section>`;
    const out = el.querySelector("#hl-out");
    const act = (sel, fn) => { const b = el.querySelector(sel); if (b) b.addEventListener("click", async () => { try { await fn(); } catch (err) { toast(err.message || String(err), { tone: "bad" }); } }); };
    act("#hl-uc", async () => { const r = await api.huntKnowledgePromote({ kind: "use-case", scenario_id: id }); toast(`Use case ${r.key} is ${r.status}. ${r.note}`, { tone: "good" }); });
    act("#hl-rep", async () => { out.innerHTML = reportLinks(await api.huntKnowledgeReport({ subject: { kind: "scenario", id } })); wireCreate(out); });
    el.querySelectorAll("[data-plan]").forEach((b) => b.addEventListener("click", async () => {
      try { const r = await api.huntKnowledgePromote({ kind: "control", control_id: b.dataset.plan, scenario_id: id }); b.replaceWith(chip(r.status, { tone: "info" })); } catch (err) { toast(err.message || String(err), { tone: "bad" }); }
    }));
  }

  // ------------------------------------------------------------------ framework view for a suggested hypothesis
  async function frameworks(host) {
    const list = await api.huntingSuggestions("");
    if (!list.suggestions.length) { host.innerHTML = '<div class="sx-callout">No hypothesis is suggested yet. Refresh suggestions on the Suggested hunts tab first.</div>'; return; }
    host.innerHTML = `<label>Hypothesis <select id="hl-h">${list.suggestions.map((s) => `<option value="${e(s.id)}">${e(s.title)}</option>`).join("")}</select></label><div id="hl-fw" style="margin-top:12px"></div>`;
    const show = async (id) => {
      const el = host.querySelector("#hl-fw"); el.innerHTML = '<div class="ui-skel ui-skel-card"></div>';
      const v = (await api.huntKnowledgeFrameworks(id)).frameworks;
      const dm = v.diamond;
      el.innerHTML = `<h4>Diamond Model</h4><div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Vertex</th><th>Status</th><th>What is known (and from where)</th><th>Hints</th></tr></thead><tbody>
        ${Object.entries(dm.vertices).map(([k, x]) => `<tr><td><b>${e(k)}</b></td><td>${chip(x.status, { tone: x.status === "unknown" ? "neutral" : "info" })}</td>
          <td>${x.items.slice(0, 6).map((i) => `${e(i.value)} <span class="ui-muted">(${e(i.source)})</span>`).join("<br>") || "unknown"}${(x.candidates || []).length ? `<br><span class="ui-muted">Candidates (overlap, not attribution): ${x.candidates.map((cn) => e(cn.name)).join(", ")}</span>` : ""}</td>
          <td class="ui-muted">${(x.hints || []).slice(0, 2).map(e).join("; ")}</td></tr>`).join("")}</tbody></table></div>
        <p class="ui-muted">${e(dm.note)}</p>
        <h4>Kill chain</h4><div class="sx-row" style="gap:6px;flex-wrap:wrap">${v.kill_chain.phases.map((p) => chip(p.label, { tone: p.covered ? "info" : "neutral", title: p.techniques.join(", ") })).join(" ")}</div><p>${e(v.kill_chain.reading)}</p>
        <h4>PEAK</h4><p>Phase <b>${e(v.peak.current)}</b>. Next: ${e(v.peak.next_action)}</p>
        <h4>Maturity</h4><p><b>${e(v.maturity.label)}</b>: ${e(v.maturity.why)} ${v.maturity.limiting_factor ? `<br><span class="ui-muted">${e(v.maturity.limiting_factor)}</span>` : ""}</p>`;
    };
    host.querySelector("#hl-h").addEventListener("change", (ev) => show(ev.target.value));
    await show(list.suggestions[0].id);
  }

  // ------------------------------------------------------------------ report builder
  async function reportBuilder(host) {
    if (!isAdmin) { host.innerHTML = '<div class="sx-callout">Building a hunt report needs an administrator. The library and framework views are open to everyone signed in.</div>'; return; }
    host.innerHTML = `<div class="sx-row" style="gap:8px;flex-wrap:wrap;align-items:end">
      <label>Subject <select id="hr-k">${["technique", "group", "software", "scenario", "tactic", "atlas-technique"].map((k) => `<option>${k}</option>`).join("")}</select></label>
      <label>Id or name <input id="hr-i" class="ui-input" placeholder="T1558.003, G0016 or APT29, S0154, net-beaconing, credential-access, AML.T0051"></label>
      <label>Look-back (days) <input id="hr-d" class="ui-input" type="number" min="1" max="180" value="30" style="width:80px"></label>
      <button type="button" class="ui-btn" id="hr-go">Build report</button></div><p class="ui-muted">Builds the report from the catalog and what Quanta holds. Nothing is run on any system.</p><div id="hr-out"></div>`;
    host.querySelector("#hr-go").addEventListener("click", async () => {
      const out = host.querySelector("#hr-out");
      try {
        out.innerHTML = '<div class="ui-skel ui-skel-card"></div>';
        const r = await api.huntKnowledgeReport({ subject: { kind: host.querySelector("#hr-k").value, id: host.querySelector("#hr-i").value.trim() }, lookback_days: Number(host.querySelector("#hr-d").value) || 30 });
        out.innerHTML = reportLinks(r); wireCreate(out);
      } catch (err) { out.innerHTML = `<div class="sx-callout warn">${e(err.message || String(err))}</div>`; }
    });
  }

  function reportLinks(r) {
    const rep = r.report;
    return `<section class="sx-panel"><h4>${e(rep.title)} (version ${r.version})</h4><p>${e(rep.hypothesis.statement)}</p>
      <p>${rep.techniques.length} technique(s), ${rep.leads.length} lead(s), data readiness <b>${e(rep.data_readiness.status)}</b>, ${rep.intel.length} relevant intel report(s).</p>
      <p><a href="${e(r.urls.markdown)}" target="_blank" rel="noopener">Markdown</a> | <a href="${e(r.urls.html)}" target="_blank" rel="noopener">HTML</a> | <a href="${e(r.urls.json)}" target="_blank" rel="noopener">JSON</a></p>
      <button type="button" class="ui-btn ui-btn-ghost" data-create="${r.id}">Create hunt from this report</button><p class="ui-muted">Creates a proposed hunt through the normal accept flow; nothing runs.</p></section>`;
  }
  function wireCreate(el) {
    el.querySelectorAll("[data-create]").forEach((b) => b.addEventListener("click", async () => {
      try { const r = await api.huntKnowledgeCreateHunt(b.dataset.create); toast(`Hunt #${r.hunt_id} created (proposed). ${r.note}`, { tone: "good", href: `/hunting?hunt=${r.hunt_id}`, action: "Open" }); } catch (err) { toast(err.message || String(err), { tone: "bad" }); }
    }));
  }

  await paint();
}
