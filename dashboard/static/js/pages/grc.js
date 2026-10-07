// Risk & Compliance: framework control status from automated tests and people's attestations, the risk register as a likelihood-by-impact grid, and versioned policies.
// Quanta supplies evidence and workflow. It does not certify compliance, and a passing test shows that Quanta observed something, not that an auditor would agree.
// Trend deltas and sparklines come from earlier readings taken in this browser (the server keeps no history); a tile shows only the number until there are two.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, mountCounters, debounce, tipAttr } from "../ui.js";
import { modal, segmented, onSeg } from "../sxKit.js";
import { selectableTable, kpiStrip, tabBar, wireTabBar, stackedBar, pageActions, replaceSearch, readJson, writeJson, skeletonPage } from "../mxKit.js";
import { pushReading, readingSeries, riskGrid, gridLevel, resultCounts, filterByResult, sortControls, frameworkBar, filterRecords } from "../moduleLogic.js";

export const title = "Risk & Compliance";

const TABS = [["overview", "Overview"], ["controls", "Controls"], ["evidence", "Evidence"], ["risks", "Risk register"], ["policies", "Policies"]];
const STATUS = { satisfied: ["good", "Satisfied"], partially: ["warn", "Partly"], "not-satisfied": ["critical", "Not satisfied"], "no-evidence": ["neutral", "No usable evidence"], "not-evidenced": ["neutral", "Not observed by Quanta"] };
const RESULT_TONE = { pass: "good", fail: "critical", warn: "warn", na: "neutral", error: "critical" };
const LEVEL_TONE = { Critical: "critical", High: "warn", Medium: "info", Low: "neutral" };
const HIST_KEY = "quanta.grc.history";
const BAR_COLOR = { good: "var(--sx-good)", warn: "var(--sx-warn)", bad: "var(--sx-bad)", none: "var(--sx-info)", dim: "var(--border)" };

export async function render(container) {
  const $ = (s) => container.querySelector(s);
  let alive = true;
  onCleanup(() => { alive = false; });
  const qs = new URLSearchParams(window.location.search);
  const S = { tab: TABS.some(([k]) => k === qs.get("tab")) ? qs.get("tab") : "overview", framework: qs.get("framework") || null, status: "all", q: "", result: "all", gridCell: null, history: readJson(HIST_KEY, []), table: null, loadedAt: Date.now() };
  const url = () => { const p = new URLSearchParams(); if (S.tab !== "overview") p.set("tab", S.tab); if (S.framework && S.tab === "controls") p.set("framework", S.framework); replaceSearch(p.toString() ? `?${p}` : ""); };

  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Risk &amp; compliance</h2><p>Quanta supplies evidence and workflow. It does not certify compliance, and a passing test shows that Quanta observed something, not that an auditor would agree.</p></div>
    <div class="sx-row"><span id="g-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="g-run">${icon("clock", 14)} Collect evidence now</button></div></div>
    <div id="g-tabs"></div><div id="g-body">${skeletonPage(4)}</div></div>`;
  const body = () => $("#g-body");
  const stamp = () => { const age = $("#g-age"); if (age) { S.loadedAt = Date.now(); age.innerHTML = dataAgeBadge(S.loadedAt, { fresh: 300000, stale: 3600000 }); mountDataAge(age); } };
  const paintTabs = () => { $("#g-tabs").innerHTML = tabBar("Risk and compliance sections", TABS.map(([id, label]) => ({ id, label })), S.tab); };
  const fail = (err) => { if (!alive) return; body().innerHTML = emptyState({ title: err.status === 401 || err.status === 403 ? "This page is for administrators" : "This could not be loaded", body: err.message || "Try again in a moment.", iconName: "risk" }); };

  // ------------------------------------------------------------------ overview
  async function overview() {
    const o = await api.grcOverview();
    if (!alive) return;
    const reading = { pass: o.evidence.pass, fail: o.evidence.fail, warn: o.evidence.warn, openHigh: o.risks.by_level.Critical + o.risks.by_level.High, overdue: o.risks.review_overdue + o.risks.treatment_overdue };
    S.history = pushReading(S.history, reading); writeJson(HIST_KEY, S.history);
    const ser = (k) => readingSeries(S.history, (r) => r[k]);
    const tile = (key, label, value, extra) => ({ key, label, value, filterable: false, previous: ser(key).previous ?? undefined, spark: ser(key).values.length > 1 ? ser(key).values : undefined, ...extra });
    body().innerHTML = `<div id="g-kpis" class="sx-kpis mx-kpis"></div>
      <p class="ui-muted">${o.evidence_collected_at ? `Evidence last collected ${escapeHtml(o.evidence_collected_at)}.` : "No evidence has been collected yet. Use Collect evidence now."}${S.history.length < 2 ? " Trends appear after a second reading in this browser." : ""}</p>
      <h3 class="mx-h3">Frameworks</h3>
      ${o.frameworks.length ? `<div class="mx-grid-cards">${o.frameworks.map((f) => `<button type="button" class="mx-card mx-fwcard" data-fw="${escapeHtml(f.id)}"><div class="mx-card-head"><h4>${escapeHtml(f.name)}</h4><span class="ui-muted mx-sub">${f.total} controls</span></div>
        ${stackedBar(frameworkBar(f.counts).map((p) => ({ label: p.label, value: p.value, color: BAR_COLOR[p.key] })), { label: `${f.name} control status`, height: 10 })}
        <div class="mx-sub">${f.evidenced_pct === null ? "No evidence yet" : `${f.evidenced_pct}% evidenced`} &middot; ${f.counts.satisfied} satisfied &middot; ${f.counts.partially} partly &middot; ${f.counts["not-satisfied"]} not satisfied &middot; ${f.counts["not-evidenced"]} not observed</div><div class="mx-sub">${escapeHtml(f.source)}</div></button>`).join("")}</div>` : emptyState({ title: "No framework is loaded", body: "Import an OSCAL catalog on the Controls tab, or use the built-in subset catalogs.", iconName: "document" })}
      <h3 class="mx-h3">Risk register</h3>
      <p>${o.risks.total} open &middot; ${o.risks.review_overdue} review(s) overdue &middot; ${o.risks.treatment_overdue} treatment(s) overdue &middot; ${o.risks.no_owner} without an owner &middot; ${o.risks.accepted} accepted. <button type="button" class="sx-link-btn" data-go="risks">Open the register</button></p>`;
    kpiStrip($("#g-kpis"), [
      tile("pass", "Control tests passing", o.evidence.pass, { tone: "good", goodWhen: "up", hint: "Automated tests of what Quanta can observe that passed on the last collection." }),
      tile("fail", "Failing", o.evidence.fail, { tone: o.evidence.fail ? "danger" : "good", goodWhen: "down" }), tile("warn", "Warnings", o.evidence.warn, { tone: o.evidence.warn ? "warn" : "good", goodWhen: "down" }),
      tile("openHigh", "Open risks, critical or high", o.risks.by_level.Critical + o.risks.by_level.High, { tone: o.risks.by_level.Critical + o.risks.by_level.High ? "danger" : "good", goodWhen: "down", hint: "Critical and high risks in the register, by residual level when there is one." }),
      tile("overdue", "Overdue reviews and treatments", o.risks.review_overdue + o.risks.treatment_overdue, { tone: o.risks.review_overdue + o.risks.treatment_overdue ? "warn" : "good", goodWhen: "down" }),
    ], () => {});
  }

  // ------------------------------------------------------------------ controls
  async function controls() {
    const { frameworks } = await api.grcFrameworks();
    if (!alive) return;
    if (!frameworks.length) { body().innerHTML = emptyState({ title: "No framework is loaded", body: "Import an OSCAL catalog below, or use the built-in subset catalogs.", iconName: "document" }) + importHtml(); return; }
    if (!S.framework || !frameworks.some((f) => f.id === S.framework)) S.framework = frameworks[0].id;
    const rep = await api.grcReport(S.framework);
    if (!alive) return;
    const all = sortControls(rep.controls);
    const counts = Object.fromEntries(Object.keys(STATUS).map((k) => [k, all.filter((c) => c.status === k).length]));
    body().innerHTML = `<div class="sx-toolbar"><select class="sx-field" id="g-fw" aria-label="Framework">${frameworks.map((f) => `<option value="${escapeHtml(f.id)}" ${f.id === S.framework ? "selected" : ""}>${escapeHtml(f.name)} (${f.control_count})</option>`).join("")}</select>
      <input type="search" class="sx-field" id="g-q" placeholder="Search control id, title, family" value="${escapeHtml(S.q)}" aria-label="Search controls">
      ${segmented("Status", [{ id: "all", label: "All", count: all.length }, ...Object.entries(STATUS).filter(([k]) => counts[k]).map(([k, [, l]]) => ({ id: k, label: l, count: counts[k] }))], S.status)}
      <a class="ui-btn ui-btn-ghost sx-btn-sm" href="/api/grc/frameworks/${encodeURIComponent(S.framework)}/oscal">Download OSCAL results</a></div>
      <p>${rep.evidenced} of ${rep.total} controls have evidence or a current attestation (${rep.evidenced_pct}%). <span class="ui-muted">${escapeHtml(rep.note || "")}</span></p><div id="g-ctable"></div>${importHtml()}`;
    const rows = () => filterRecords(all.filter((c) => S.status === "all" || c.status === S.status), S.q, [(c) => c.control_id, (c) => c.title, (c) => c.family]);
    S.table = selectableTable($("#g-ctable"), { rows: rows(), rowKey: (c) => c.control_id, caption: `${S.framework} controls`, csvName: `quanta-${S.framework}-controls`, storageKey: "grc-controls", rowHeight: 74, maxHeight: 620,
      emptyHtml: emptyState({ title: "No control matches", body: "Change the status filter or the search.", iconName: "search" }),
      columns: [
        { key: "c", label: "Control", width: 340, csv: (c) => `${c.control_id} ${c.title}`, render: (c) => `<strong>${escapeHtml(c.control_id)}</strong> <span class="mx-clip">${escapeHtml(c.title)}</span><div class="mx-sub">${escapeHtml(c.family || "")}</div>` },
        { key: "s", label: "Status", width: 150, csv: (c) => c.status, render: (c) => chip(STATUS[c.status][1], { tone: STATUS[c.status][0] }) },
        { key: "e", label: "Evidence", width: 300, csv: (c) => c.tests.map((t) => `${t.result}: ${t.title}`).join("; "), render: (c) => (c.tests.length ? c.tests.slice(0, 2).map((t) => `${chip(t.result, { tone: RESULT_TONE[t.result] })} <span class="mx-clip">${escapeHtml(t.title)}</span>`).join("<br>") + (c.tests.length > 2 ? `<div class="mx-sub">+${c.tests.length - 2} more</div>` : "") : '<span class="ui-muted">none</span>') },
        { key: "a", label: "Attestation", width: 240, csv: (c) => (c.attestation ? `${c.attestation.result} by ${c.attestation.attested_by}` : ""), render: (c) => `${c.attestation ? `${escapeHtml(c.attestation.result)} by ${escapeHtml(c.attestation.attested_by)}${c.attestation.current ? "" : " (expired)"}<div class="mx-sub" title="${escapeHtml(c.attestation.statement || "")}">${escapeHtml(c.attestation.statement || "")}</div>` : '<span class="ui-muted">none</span>'}` },
        { key: "act", label: "", width: 90, csv: () => "", render: (c) => `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-attest="${escapeHtml(c.control_id)}">Attest</button>` },
      ] });
    onSeg(body(), (id) => { S.status = id; S.table.setRows(rows()); body().querySelectorAll(".sx-seg [data-seg]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.seg === id))); });
    $("#g-fw").addEventListener("change", (e) => { S.framework = e.target.value; S.status = "all"; url(); show(); });
    const typeSearch = debounce((v) => { S.q = v; S.table.setRows(rows()); }, 200);
    $("#g-q").addEventListener("input", (e) => typeSearch(e.target.value));
    $("#imp").addEventListener("submit", async (e) => {
      e.preventDefault(); const f = e.target;
      try { const r = await api.grcImportFramework(f.id.value, f.name.value, f.file.files[0]); toast(`${r.controls} controls imported.`, { tone: "good" }); S.framework = r.id; show(); } catch (err) { toast(err.message, { tone: "bad", ms: 8000 }); }
    });
  }
  const importHtml = () => `<details class="sx-panel mx-details"><summary>Import a full catalog</summary><p class="ui-muted">Upload NIST's official OSCAL JSON (SP 800-53, CSF) to work against every control. For licensed standards, import your licensed copy in OSCAL form.</p>
    <form id="imp" class="sx-toolbar"><input class="sx-field" name="id" required placeholder="nist-800-53-r5" pattern="[a-z0-9][a-z0-9-]{1,59}" aria-label="Framework id"><input class="sx-field" name="name" placeholder="NIST SP 800-53 Rev. 5" aria-label="Name"><input class="sx-field" type="file" name="file" accept=".json" required aria-label="OSCAL catalog (JSON)"><button class="ui-btn sx-btn-sm" type="submit">Import</button></form></details>`;
  async function attest(controlId) {
    const out = await modal({ title: `Attest to ${controlId}`, confirmLabel: "Record attestation", description: "An attestation is a person's statement about a control. It sits beside the automated evidence and never replaces it.",
      body: `<label>Is it effective?<select id="m-res"><option value="effective">Effective</option><option value="partially-effective">Partially effective</option><option value="ineffective">Ineffective</option></select></label><label>What does that rest on? (required)<textarea id="m-stmt" maxlength="2000" placeholder="The review, test or document behind your statement"></textarea></label>`,
      validate: (d) => (d.querySelector("#m-stmt").value.trim().length < 10 ? "Say what the statement rests on (at least 10 characters)." : ""), collect: (d) => ({ result: d.querySelector("#m-res").value, statement: d.querySelector("#m-stmt").value.trim() }) });
    if (!out) return;
    try { await api.grcAttest(S.framework, controlId, out); toast("Attestation recorded.", { tone: "good" }); show(); } catch (e) { toast(e.message, { tone: "bad", ms: 8000 }); }
  }

  // ------------------------------------------------------------------ evidence
  async function evidence() {
    const { tests } = await api.grcEvidence();
    if (!alive) return;
    const c = resultCounts(tests);
    const list = () => filterRecords(filterByResult(tests, S.result), S.q, [(t) => t.title, (t) => t.detail]);
    body().innerHTML = `<div class="sx-toolbar"><input type="search" class="sx-field" id="g-q" placeholder="Search tests" value="${escapeHtml(S.q)}" aria-label="Search tests">${segmented("Result", [{ id: "all", label: "All", count: tests.length }, ...["fail", "warn", "pass", "na", "error"].filter((k) => c[k]).map((k) => ({ id: k, label: k, count: c[k] }))], S.result)}<span class="ui-muted">Collected automatically about once a day.</span></div><div id="g-etable"></div>`;
    S.table = selectableTable($("#g-etable"), { rows: list(), rowKey: (t) => t.test_id || t.title, caption: "Control tests", csvName: "quanta-control-evidence", storageKey: "grc-evidence", rowHeight: 56, maxHeight: 620,
      emptyHtml: emptyState({ title: tests.length ? "No test matches" : "No evidence has been collected yet", body: tests.length ? "Change the filter." : "Collect evidence now runs every automated control test once. Too little data gives n/a, never a pass.", iconName: "document" }),
      columns: [
        { key: "t", label: "Test", width: 300, csv: (t) => t.title, render: (t) => `<span class="mx-title">${escapeHtml(t.title)}</span>` }, { key: "r", label: "Result", width: 90, csv: (t) => t.result, render: (t) => chip(t.result, { tone: RESULT_TONE[t.result] }) },
        { key: "m", label: "Measured", width: 90, align: "right", csv: (t) => t.metric ?? "", render: (t) => (t.metric === null ? "-" : escapeHtml(String(t.metric))) }, { key: "th", label: "Threshold", width: 90, align: "right", csv: (t) => t.threshold ?? "", render: (t) => (t.threshold === null ? "-" : escapeHtml(String(t.threshold))) },
        { key: "d", label: "What was seen", width: 340, csv: (t) => t.detail || "", render: (t) => `<span class="mx-title" title="${escapeHtml(t.detail || "")}">${escapeHtml(t.detail || "")}</span>` }, { key: "w", label: "When", width: 170, csv: (t) => t.collected_at, render: (t) => escapeHtml(t.collected_at) },
      ] });
    onSeg(body(), (id) => { S.result = id; S.table.setRows(list()); body().querySelectorAll(".sx-seg [data-seg]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.seg === id))); });
    $("#g-q").addEventListener("input", debounce((e) => { S.q = e.target.value; S.table.setRows(list()); }, 200));
  }

  // ------------------------------------------------------------------ risk register
  async function risks() {
    const r = await api.grcRisks();
    if (!alive) return;
    const grid = riskGrid(r.risks);
    const cellList = () => (S.gridCell ? r.risks.filter((k) => grid.flat().find((c) => c.likelihood === S.gridCell.likelihood && c.impact === S.gridCell.impact).ids.includes(k.id)) : r.risks);
    body().innerHTML = `<p>${r.summary.total} open &middot; ${r.summary.review_overdue} review(s) overdue &middot; ${r.summary.no_owner} without an owner</p>
      <div class="mx-split"><div><h3 class="mx-h3">Where the risks sit (inherent likelihood by impact)</h3>
        <div class="mx-rgrid" role="grid" aria-label="Risk grid: impact from 5 at the top to 1, likelihood from 1 to 5"><div class="mx-rgrid-axis" aria-hidden="true">Impact</div>${grid.map((row, ri) => `<div class="mx-rgrid-row" role="row"><span class="mx-rgrid-lab" aria-hidden="true">${5 - ri}</span>${row.map((c) => `<button type="button" role="gridcell" class="mx-rcell mx-rcell-${gridLevel(c.likelihood, c.impact).toLowerCase()}${S.gridCell && S.gridCell.likelihood === c.likelihood && S.gridCell.impact === c.impact ? " on" : ""}" data-cell="${c.likelihood}:${c.impact}" aria-label="Likelihood ${c.likelihood}, impact ${c.impact}: ${c.count} risk${c.count === 1 ? "" : "s"}, ${gridLevel(c.likelihood, c.impact)}">${c.count || ""}</button>`).join("")}</div>`).join("")}<div class="mx-rgrid-row"><span class="mx-rgrid-lab"></span>${[1, 2, 3, 4, 5].map((n) => `<span class="mx-rgrid-lab" aria-hidden="true">${n}</span>`).join("")}</div><div class="mx-rgrid-axis" aria-hidden="true">Likelihood</div></div>
        ${S.gridCell ? `<p><button type="button" class="sx-link-btn" id="g-clearcell">Show every risk</button></p>` : ""}</div>
      <div>${r.suggestions.length ? `<div class="mx-callout"><strong>Worth registering</strong> <span class="ui-muted">(drawn from live findings and threat models)</span><ul class="mx-list">${r.suggestions.map((s) => `<li>${escapeHtml(s.title)} <button type="button" class="sx-link-btn" data-sug="${escapeHtml(s.source)}|${escapeHtml(s.source_ref)}">Add to register</button></li>`).join("")}</ul></div>` : '<p class="ui-muted">No suggestions from live findings or threat models right now.</p>'}
        <button type="button" class="ui-btn sx-btn-sm" id="g-addrisk">Add a risk</button></div></div>
      <div id="g-rtable"></div>`;
    S.table = selectableTable($("#g-rtable"), { rows: cellList(), rowKey: (k) => k.id, caption: "Risk register", csvName: "quanta-risk-register", storageKey: "grc-risks", rowHeight: 64, maxHeight: 520,
      emptyHtml: emptyState({ title: "The register is empty", body: "Add a risk, or take one from the suggestions drawn from live findings.", iconName: "risk" }),
      columns: [
        { key: "t", label: "Risk", width: 320, csv: (k) => k.title, render: (k) => `<strong class="mx-title">${escapeHtml(k.title)}</strong><div class="mx-sub">${escapeHtml(k.category || "")} &middot; from ${escapeHtml(k.source)}</div>` },
        { key: "i", label: "Inherent", width: 110, csv: (k) => `${k.inherent_level} ${k.inherent_score}`, render: (k) => `${chip(k.inherent_level, { tone: LEVEL_TONE[k.inherent_level] })} ${k.inherent_score}` },
        { key: "r", label: "Residual", width: 110, csv: (k) => (k.residual_level ? `${k.residual_level} ${k.residual_score}` : ""), render: (k) => (k.residual_level ? `${chip(k.residual_level, { tone: LEVEL_TONE[k.residual_level] })} ${k.residual_score}` : "-") },
        { key: "o", label: "Owner", width: 140, csv: (k) => k.owner || "", render: (k) => (k.owner ? escapeHtml(k.owner) : '<span class="mx-unowned">No owner</span>') },
        { key: "s", label: "Status", width: 170, csv: (k) => k.status, render: (k) => `${escapeHtml(k.status)}${k.treatment ? `<div class="mx-sub">${escapeHtml(k.treatment)}</div>` : ""}` },
        { key: "rv", label: "Review", width: 120, csv: (k) => k.review_date || "", render: (k) => `${escapeHtml(k.review_date || "-")}${k.review_overdue ? ` ${chip("overdue", { tone: "critical" })}` : ""}` },
        { key: "d", label: "", width: 80, csv: () => "", render: (k) => `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-del="${k.id}">Delete</button>` },
      ] });
    body().addEventListener("click", async (e) => {
      const cell = e.target.closest("[data-cell]"); if (cell) { const [likelihood, impact] = cell.dataset.cell.split(":").map(Number); S.gridCell = S.gridCell && S.gridCell.likelihood === likelihood && S.gridCell.impact === impact ? null : { likelihood, impact }; show(); return; }
      if (e.target.closest("#g-clearcell")) { S.gridCell = null; show(); return; }
      const sug = e.target.closest("[data-sug]"); if (sug) { const [source, source_ref] = sug.dataset.sug.split("|"); try { await api.grcRiskFromSuggestion({ source, source_ref }); toast("Added to the register.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad" }); } return; }
      const del = e.target.closest("[data-del]"); if (del) { const ok = await modal({ title: "Delete this risk?", confirmLabel: "Delete", danger: true, description: "It is removed from the register. This is recorded in the activity log.", body: "" }); if (!ok) return; try { await api.grcDeleteRisk(Number(del.dataset.del)); toast("Risk deleted.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad" }); } return; }
      if (e.target.closest("#g-addrisk")) addRisk();
    }, { once: false });
  }
  async function addRisk() {
    const out = await modal({ title: "Add a risk", confirmLabel: "Add", wide: true, description: "Likelihood and impact are 1 to 5. The level follows from their product: 15 or more is Critical, 10 High, 5 Medium.",
      body: `<label>Title<input type="text" id="m-title" maxlength="200"></label><label>Owner<input type="text" id="m-owner" placeholder="name@company.com"></label>
        <div class="sx-row"><label>Likelihood (1-5)<input type="number" id="m-lik" min="1" max="5" value="3"></label><label>Impact (1-5)<input type="number" id="m-imp" min="1" max="5" value="3"></label></div>
        <label>Treatment<select id="m-treat"><option value="">Decide later</option><option>mitigate</option><option>accept</option><option>transfer</option><option>avoid</option></select></label><label>Plan or reason<input type="text" id="m-plan"></label><label>Review by<input type="date" id="m-rev"></label>`,
      validate: (d) => (d.querySelector("#m-title").value.trim() ? "" : "Give the risk a title."),
      collect: (d) => { const b = { title: d.querySelector("#m-title").value.trim(), owner: d.querySelector("#m-owner").value.trim(), inherent_likelihood: Number(d.querySelector("#m-lik").value), inherent_impact: Number(d.querySelector("#m-imp").value), treatment: d.querySelector("#m-treat").value, treatment_plan: d.querySelector("#m-plan").value.trim(), review_date: d.querySelector("#m-rev").value }; return Object.fromEntries(Object.entries(b).filter(([, v]) => v !== "")); } });
    if (!out) return;
    try { await api.grcAddRisk(out); toast("Risk added.", { tone: "good" }); show(); } catch (e) { toast(e.message, { tone: "bad", ms: 8000 }); }
  }

  // ------------------------------------------------------------------ policies
  async function policies() {
    const { policies: ps } = await api.grcPolicies();
    if (!alive) return;
    body().innerHTML = `<p><button type="button" class="ui-btn sx-btn-sm" id="g-addpol">Add a policy</button></p>${ps.length ? `<div class="mx-grid-cards">${ps.map((p) => `<article class="mx-card"><div class="mx-card-head"><h4>${escapeHtml(p.title)}</h4>${chip(p.status, { tone: p.status === "active" ? "good" : "neutral" })}</div>
      <div class="mx-sub">Version ${p.version}${p.owner ? ` &middot; ${escapeHtml(p.owner)}` : ""}${p.review_overdue ? ` &middot; <span class="mx-clock-bad">review overdue</span>` : ""}</div>
      ${p.ack_pct !== undefined ? `<div class="sx-row"><span class="mx-meter ${p.ack_pct !== null && p.ack_pct < 60 ? "warn" : ""}" role="img" aria-label="${p.ack_pct ?? 0}% acknowledged"><i style="width:${p.ack_pct ?? 0}%"></i></span><span class="mx-sub">${p.ack_pct === null ? "no readers yet" : `${p.ack_pct}% acknowledged`}</span></div>` : `<div class="mx-sub">${p.acknowledged_by_me ? "You have acknowledged this version." : "You have not acknowledged this version."}</div>`}
      ${p.status === "active" && p.acknowledged_by_me === false ? `<button type="button" class="ui-btn sx-btn-sm" data-ack="${p.id}">I have read this</button>` : ""}</article>`).join("")}</div>` : emptyState({ title: "No policies yet", body: "A policy has a version, an owner and a review date, and people acknowledge each version.", iconName: "document" })}`;
    body().addEventListener("click", async (e) => {
      const ack = e.target.closest("[data-ack]"); if (ack) { try { await api.grcAckPolicy(Number(ack.dataset.ack)); toast("Acknowledged.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad" }); } return; }
      if (!e.target.closest("#g-addpol")) return;
      const out = await modal({ title: "Add a policy", confirmLabel: "Add", wide: true, body: `<label>Title<input type="text" id="m-title"></label><label>Owner<input type="text" id="m-owner"></label><label>Status<select id="m-status"><option>draft</option><option>active</option></select></label><label>Review by<input type="date" id="m-rev"></label><label>Text<textarea id="m-body" rows="8"></textarea></label>`,
        validate: (d) => (!d.querySelector("#m-title").value.trim() || !d.querySelector("#m-body").value.trim() ? "A policy needs a title and its text." : ""), collect: (d) => ({ title: d.querySelector("#m-title").value.trim(), owner: d.querySelector("#m-owner").value.trim(), status: d.querySelector("#m-status").value, review_date: d.querySelector("#m-rev").value || null, body: d.querySelector("#m-body").value }) });
      if (!out) return;
      try { await api.grcAddPolicy(out); toast("Policy added.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad", ms: 8000 }); }
    });
  }

  // ------------------------------------------------------------------ routing between tabs
  async function show() {
    paintTabs(); url();
    const fresh = body().cloneNode(false); body().replaceWith(fresh); fresh.id = "g-body"; // drops the previous tab's listeners
    fresh.innerHTML = skeletonPage(3);
    try { await { overview, controls, evidence, risks, policies }[S.tab](); stamp(); } catch (err) { fail(err); }
  }
  wireTabBar($("#g-tabs"), (id) => { S.tab = id; S.status = "all"; S.result = "all"; S.q = ""; S.gridCell = null; show(); });
  container.addEventListener("click", async (e) => {
    const a = e.target.closest("[data-attest]"); if (a) { attest(a.dataset.attest); return; }
    const g = e.target.closest("[data-go]"); if (g) { S.tab = g.dataset.go; show(); return; }
    const fw = e.target.closest("[data-fw]"); if (fw && !e.target.closest(".mx-tabs")) { S.tab = "controls"; S.framework = fw.dataset.fw; show(); return; }
    if (e.target.closest("#g-run")) { try { await api.grcRunEvidence(); toast("Evidence collected.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad" }); } }
  });
  pageActions([
    { label: "Compliance: collect evidence now", icon: "risk", run: async () => { try { await api.grcRunEvidence(); toast("Evidence collected.", { tone: "good" }); show(); } catch (er) { toast(er.message, { tone: "bad" }); } } },
    ...TABS.map(([id, label]) => ({ label: `Compliance: ${label}`, icon: "risk", run: () => { S.tab = id; show(); } })),
  ]);
  await show();
  void kpiTile; void mountCounters; void tipAttr;
}
