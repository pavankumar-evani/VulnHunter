// The hunt report view: one hunt as an executive summary, a trial-hit table by domain, the queries behind each row, the allow-list and detection recommendations.
// The report is built by the server from stored data (docs/INVESTIGATION_REPORTS.md); this file draws it and records the analyst's own results.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { chip, toast, onCleanup } from "./ui.js";
import { DOMAINS, DOMAIN_LABEL, STATUS_TONE, STATUS_TEXT, verdictText, timingText, groupByDomain, huntProgress, recommendationTone, queryTabs } from "./huntLogic.js";
import { modal, copyText, downloadText, fmtWhen, wireTabs } from "./sxKit.js";

export function queryBlock(q, id) {
  const tabs = queryTabs(q);
  if (!tabs.length) return '<p class="ui-muted">No query for this trial hit: write one for your data model.</p>';
  return `<div class="hx-qtabs" data-q="${id}"><div class="hx-qtabs-bar" role="tablist" aria-label="Query language">${tabs.map((t, i) => `<button type="button" role="tab" data-qt="${t.id}" aria-selected="${i === 0}">${t.label}</button>`).join("")}<button type="button" class="sx-link-btn copy" data-copy-q>${icon("document", 12)} Copy</button></div>
    ${tabs.map((t, i) => `<pre data-qp="${t.id}" ${i ? "hidden" : ""}>${escapeHtml(t.text)}</pre>`).join("")}</div>`;
}
// Wires every query block under root: tab switching and copy.
export function wireQueryBlocks(root) {
  root.querySelectorAll(".hx-qtabs").forEach((b) => {
    if (b.dataset.wired) return;
    b.dataset.wired = "1";
    b.addEventListener("click", (e) => {
      const t = e.target.closest("[data-qt]");
      if (t) { b.querySelectorAll("[data-qt]").forEach((x) => x.setAttribute("aria-selected", String(x === t))); b.querySelectorAll("[data-qp]").forEach((p) => { p.hidden = p.dataset.qp !== t.dataset.qt; }); return; }
      if (e.target.closest("[data-copy-q]")) { const p = [...b.querySelectorAll("[data-qp]")].find((x) => !x.hidden); if (p) copyText(p.textContent, "Query copied"); }
    });
  });
}

export async function renderHuntReport(container, huntId, { back }) {
  let alive = true;
  onCleanup(() => { alive = false; });
  container.innerHTML = `<div class="sx-page"><a class="sx-back" href="${back}" data-link>All hunts</a><div class="ui-skel ui-skel-card"><span class="ui-skel-line tall w50"></span><span class="ui-skel-line w80"></span></div></div>`;
  let R; let H;
  const load = async () => { [R, H] = await Promise.all([api.huntReport(huntId), api.huntingHunt(huntId)]); };
  try { await load(); } catch (e) { container.innerHTML = `<div class="sx-page"><a class="sx-back" href="${back}" data-link>All hunts</a><div class="ui-error" role="alert"><div><h2>Hunt ${huntId} could not be opened</h2><p>${escapeHtml(e.message)}</p></div></div></div>`; return; }

  const statusChip = (s) => chip(STATUS_TEXT[s] || s, { tone: STATUS_TONE[s] || "neutral" });
  const row = (t) => `<tr class="sx-tr" data-th="${t.index}"><td>${t.n}</td><td><b>${escapeHtml(t.name)}</b><div class="ui-muted">${escapeHtml(t.technique || "")} · ${escapeHtml(t.source_tool || "")} · ${escapeHtml(t.window || "")}</div></td><td>${escapeHtml(DOMAIN_LABEL[t.domain] || t.domain || "")}</td><td>${statusChip(t.status)}${t.error ? `<div class="ui-muted">${escapeHtml(t.error)}</div>` : ""}</td>
    <td class="sx-mono">${t.hits ?? "-"}${t.allowlisted_rows ? `<div class="ui-muted">${t.hits_after_allowlist} after allow-list</div>` : ""}</td><td>${(t.entities || []).map((x) => `<span class="sx-ent">${escapeHtml(x)}</span>`).join(" ") || '<span class="ui-muted">none</span>'}</td><td>${escapeHtml(t.assessment || "not assessed")}</td></tr>
    <tr data-th-detail="${t.index}" hidden><td colspan="7"><div class="hx-q">${queryBlock(t.queries, "t" + t.index)}
      <div class="sx-row" style="margin-top:8px"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-record="${t.index}">Record result</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-allow="${t.index}">Add to allow-list</button>${t.notes ? `<span class="ui-muted">${escapeHtml(t.notes)}</span>` : ""}</div></div></td></tr>`;
  const table = (hits) => `<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>#</th><th>Trial hit</th><th>Domain</th><th>Status</th><th>Hits</th><th>Entities</th><th>Assessment</th></tr></thead><tbody>${hits.map(row).join("") || '<tr><td colspan="7" class="ui-muted">No trial hits in this domain.</td></tr>'}</tbody></table></div>`;

  function paint() {
    const v = R.verdict; const prog = huntProgress(R.counts); const groups = groupByDomain(R.trial_hits);
    container.innerHTML = `<div class="sx-page"><a class="sx-back" href="${back}" data-link>&larr; All hunts</a>
      <div class="sx-inc-head"><div class="sx-meta">${chip(R.source, { tone: "neutral" })}${chip(R.status, { tone: "info" })}<span>${escapeHtml(timingText(R.timing))}</span><span>Look-back ${escapeHtml(R.look_back.text || "not set")}</span></div>
        <h2>${escapeHtml(R.topic)}</h2><p class="ui-muted" style="margin:0">${escapeHtml(R.gist || "")}</p>
        <div class="sx-verdict-banner v-${v.label === "confirmed" ? "true-positive" : v.label === "no-ioc-match" ? "false-positive" : v.label === "needs-investigation" ? "action-needed" : ""}"><span class="sx-verdict-big">${escapeHtml(verdictText(v.label))}</span><span>${escapeHtml(v.rationale || "")}</span></div>
        <div class="sx-row"><span class="hx-prog" role="progressbar" aria-valuenow="${prog.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Trial hits run"><i style="width:${prog.pct}%"></i></span><span class="ui-muted">${escapeHtml(prog.label)} · ${R.counts.needs_investigation} need investigation · ${R.counts.no_hit} no hit · ${R.counts.entities} entities</span></div>
        <div class="sx-actions"><button type="button" class="ui-btn sx-btn-sm" data-act="runall">${icon("search", 14)} Run trial hits in the SIEM…</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="md">Download Markdown</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="html">Download HTML</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="copy">Copy Markdown</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="timebox">Time box ${R.timing.time_box_hours} h…</button><a class="ui-btn ui-btn-ghost sx-btn-sm" href="/hunting?tab=hunts" data-link>Full hunt editor</a></div></div>
      <section class="sx-sec"><h3>Executive summary</h3><div class="hx-ex">${(R.executive_summary || []).map((s) => `<p>${escapeHtml(s.text)}${(s.trial_hits || []).length ? ` <span class="ui-muted">(trial hit ${s.trial_hits.join(", ")})</span>` : ""}</p>`).join("")}</div>
        ${(v.correlated_entities || []).length ? `<div class="sx-callout warn" style="margin-top:10px">The same entity appears in more than one trial hit: ${v.correlated_entities.map(escapeHtml).join(", ")}</div>` : ""}</section>
      <section class="sx-sec"><h3>By domain</h3><div class="hx-domains">${DOMAINS.map((d) => { const x = R.per_domain[d] || { trial_hits: 0, run: 0, needs_investigation: 0, hits: 0 }; return `<div class="hx-dom"><span class="ui-muted">${DOMAIN_LABEL[d]}</span><b>${x.trial_hits}</b>${x.run} run · ${x.needs_investigation} to investigate · ${x.hits} hit(s)</div>`; }).join("")}</div></section>
      <section class="sx-sec" id="hx-table"><h3>Trial hits <span class="ui-muted">click a row for its query</span></h3>
        <div class="hx-tabs" role="tablist" aria-label="Domain">${[["all", `All (${R.trial_hits.length})`], ...DOMAINS.map((d) => [d, `${DOMAIN_LABEL[d]} (${groups[d].length})`])].map(([k, l], i) => `<button type="button" role="tab" data-tab="${k}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">${l}</button>`).join("")}</div>
        <div data-panel="all">${table(R.trial_hits)}</div>${DOMAINS.map((d) => `<div data-panel="${d}" hidden>${table(groups[d])}</div>`).join("")}</section>
      <section class="sx-sec"><h3>Allow-list <span class="ui-muted">values an analyst judged benign for a lead</span></h3>${R.allowlist.entries.length ? `<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Lead</th><th>Field</th><th>Value</th><th>Note</th><th></th></tr></thead><tbody>${R.allowlist.entries.map((a) => `<tr><td>${escapeHtml(a.lead_key)}</td><td>${escapeHtml(a.field)}</td><td class="sx-mono">${escapeHtml(a.value)}</td><td>${escapeHtml(a.note)}<div class="ui-muted">${escapeHtml(a.created_by)} ${escapeHtml(fmtWhen(a.created_at))}</div></td><td><button type="button" class="sx-link-btn" data-unallow="${a.id}">Remove</button></td></tr>`).join("")}</tbody></table></div>` : '<p class="ui-muted">Nothing allow-listed. Open a trial hit and use "Add to allow-list" for a known-good value such as a vulnerability scanner.</p>'}
        <p class="ui-muted" style="font-size:.8rem">${escapeHtml(R.allowlist.note || "")}</p></section>
      <section class="sx-sec"><h3>Detection recommendations</h3><ul class="sx-stmts">${(R.detection_recommendations || []).map((d) => `<li>${chip(d.recommendation, { tone: recommendationTone(d.recommendation) })} ${escapeHtml(d.text)} <span class="ui-muted">priority ${escapeHtml(d.priority)}</span>${d.usecase_key ? ` <a class="sx-link-btn" href="/hunting?tab=detections" data-link>Open detection engineering</a>` : ""}</li>`).join("") || '<li class="noev">No recommendations until trial hits have run.</li>'}</ul></section>
      <section class="sx-sec"><h3>Limits</h3><ul class="sx-gaps">${(R.limits || []).map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ul></section></div>`;
    wireTabs(container.querySelector("#hx-table"));
    wireQueryBlocks(container);
  }
  paint();

  async function refresh() { await load(); if (alive) paint(); }
  container.addEventListener("click", async (e) => {
    const tr = e.target.closest("tr[data-th]");
    if (tr && !e.target.closest("button,a")) { const d = tr.parentElement.querySelector(`[data-th-detail="${tr.dataset.th}"]`); if (d) d.hidden = !d.hidden; return; }
    const un = e.target.closest("[data-unallow]");
    if (un) { try { await api.huntAllowlistRemove(huntId, Number(un.dataset.unallow)); toast("Removed from the allow-list.", { tone: "good" }); await refresh(); } catch (er) { toast(er.message, { tone: "bad" }); } return; }
    const rec = e.target.closest("[data-record]");
    if (rec) return record(Number(rec.dataset.record));
    const al = e.target.closest("[data-allow]");
    if (al) return allow(Number(al.dataset.allow));
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const a = b.dataset.act;
    try {
      if (a === "md" || a === "html") downloadText(`hunt-${huntId}-report.${a}`, await api.huntReportText(huntId, a), a === "md" ? "text/markdown" : "text/html");
      else if (a === "copy") copyText(await api.huntReportText(huntId, "md"), "Report copied as Markdown");
      else if (a === "runall") await runAll();
      else if (a === "timebox") {
        const out = await modal({ title: "Time box", confirmLabel: "Set", body: `<label>Hours to report<input type="number" id="m-h" min="1" max="720" value="${R.timing.time_box_hours}"></label>`, collect: (d) => Number(d.querySelector("#m-h").value) });
        if (out) { await api.huntTimeBox(huntId, { hours: out }); await refresh(); toast("Time box set.", { tone: "good" }); }
      }
    } catch (er) { toast(er.message, { tone: "bad", ms: 7000 }); }
  });
  async function runAll() {
    const pre = await api.huntingRunAll(huntId, { earliest: "-30d" });
    const ok = await modal({ title: "Run trial hits in the SIEM?", confirmLabel: "Confirm and run", wide: true, description: pre.message,
      body: `<ul>${pre.leads.map((l) => `<li>${escapeHtml(l.name)} <span class="ui-muted">${escapeHtml(l.technique || "")}</span></li>`).join("") || "<li>Nothing left to run.</li>"}</ul>${pre.not_run_because_of_the_cap ? `<p class="ui-muted">${pre.not_run_because_of_the_cap} more are held back by the per-run cap of ${pre.cap}.</p>` : ""}<p class="ui-muted">Read-only searches in ${escapeHtml(pre.connection)} over ${escapeHtml(pre.earliest)}. A failing search is recorded on its row and the rest still run.</p>`, collect: () => true });
    if (!ok) return;
    const done = await api.huntingRunAll(huntId, { earliest: "-30d", confirm: true });
    toast(`Ran ${done.ran} search(es); ${done.failed} failed.`, { tone: done.failed ? "warn" : "good" });
    await refresh();
  }
  async function record(index) {
    const hunt = H; const q = hunt.queries[index]; if (!q) return;
    const out = await modal({ title: `Record result: ${q.name}`, confirmLabel: "Save", description: "Run the query in your own tool, then record what it returned. An unassessed hit is never treated as benign.",
      body: `<label>Result<select id="m-r">${["", "hits", "no-hits", "not-run", "error"].map((r) => `<option value="${r}" ${(q.result || "") === r ? "selected" : ""}>${r || "(not recorded)"}</option>`).join("")}</select></label>
        <label>Number of hits<input type="number" id="m-c" min="0" value="${q.count ?? ""}"></label>
        <label>My assessment<select id="m-a">${["", "benign", "suspicious", "malicious"].map((r) => `<option value="${r}" ${(q.assessment || "") === r ? "selected" : ""}>${r || "(not assessed)"}</option>`).join("")}</select></label>`,
      collect: (d) => ({ result: d.querySelector("#m-r").value || null, count: d.querySelector("#m-c").value === "" ? null : Number(d.querySelector("#m-c").value), assessment: d.querySelector("#m-a").value || null }) });
    if (!out) return;
    const queries = hunt.queries.map((x, i) => (i === index ? { ...x, ...out } : x));
    try { await api.huntingUpdate(huntId, { queries }); await refresh(); toast("Recorded.", { tone: "good" }); } catch (er) { toast(er.message, { tone: "bad" }); }
  }
  async function allow(index) {
    const out = await modal({ title: "Add to the allow-list", confirmLabel: "Add", description: "Matching rows are set aside from this lead in every later run, in other hunts too. Matching is exact and case-insensitive.",
      body: `<label>Field<select id="m-f">${["host", "user", "src_ip", "dest_ip", "process", "parent_process", "email", "domain"].map((f) => `<option>${f}</option>`).join("")}</select></label><label>Value<input type="text" id="m-v"></label><label>Why it is benign (10+ characters)<input type="text" id="m-n"></label>`,
      validate: (d) => (!d.querySelector("#m-v").value.trim() ? "Give the value." : d.querySelector("#m-n").value.trim().length < 10 ? "Write why it is benign, at least 10 characters." : ""),
      collect: (d) => ({ lead_index: index, field: d.querySelector("#m-f").value, value: d.querySelector("#m-v").value.trim(), note: d.querySelector("#m-n").value.trim() }) });
    if (!out) return;
    try { await api.huntAllowlistAdd(huntId, out); await refresh(); toast("Added to the allow-list.", { tone: "good" }); } catch (er) { toast(er.message, { tone: "bad", ms: 7000 }); }
  }
}
