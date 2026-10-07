// AI Security: where AI is used, what each system can do and how it is defended, checked against the OWASP Top 10 for LLM Applications and agent / MCP hygiene.
// Rebuilt on the UI kit: a scorecard (severity mix per asset, OWASP categories, unanswered questions), the register and findings as tables, a modal confirm before
// publishing. The long asset form is unchanged in behaviour. Quanta does not probe a model; it applies rules to the facts you record.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { chip, severityChip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, mountCounters, tipAttr } from "../ui.js";
import { modal } from "../sxKit.js";
import { selectableTable, kpiStrip, tabBar, wireTabBar, stackedBar, pageActions, replaceSearch, readJson, writeJson, skeletonPage } from "../mxKit.js";
import { pushReading, readingSeries } from "../moduleLogic.js";

export const title = "AI Security";
const SEV_COLOR = { Critical: "var(--sx-crit)", High: "var(--sx-high)", Medium: "var(--sx-med)", Low: "var(--sx-low)" };
const HIST_KEY = "quanta.aisec.history";

const TABS = [["overview", "Overview"], ["register", "Register"], ["findings", "Findings"]];
const SEV = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const NOTE = "Where AI is used, what each system can do and how it is defended, checked against the OWASP Top 10 for LLM Applications and agent / MCP hygiene. Quanta does not probe a model: it applies rules to the facts you record. A question left unanswered is a gap, not a pass.";
const TRI_ORDER = ["untrusted_input", "internet_facing", "auth_required", "can_take_actions", "human_in_loop", "high_stakes_use", "downstream_trusts_output", "input_guardrails", "output_filtering", "rate_limited", "logging",
  "secrets_in_prompt", "plugins_reviewed", "fine_tuned", "training_data_validated", "uses_rag", "rag_access_control"];

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let data = null;
  let draft = null;

  let alive = true;
  onCleanup(() => { alive = false; });
  const shell = (inner) => {
    container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>AI security</h2><p>${NOTE}</p></div><div class="sx-row"><span id="ais-age">${dataAgeBadge(Date.now(), { fresh: 300000, stale: 3600000 })}</span></div></div>
      ${tabBar("AI security sections", TABS.map(([id, label]) => ({ id, label })), tab)}<div id="ais-body">${inner}</div></div>`;
    wireTabBar(container.querySelector(".mx-tabs"), (id) => { tab = id; draft = null; replaceSearch(id === "overview" ? "" : `?tab=${id}`); show(); });
    mountDataAge(container);
  };
  const load = async () => { data = await api.aiSecurityOverview(); return data; };
  pageActions([{ label: "AI security: add an AI asset", icon: "aiVuln", run: () => { tab = "register"; draft = null; show().then(() => { const b = container.querySelector("#new"); if (b) b.click(); }); } }, { label: "AI security: show the findings", icon: "aiVuln", run: () => { tab = "findings"; show(); } }, { label: "AI security: show the overview", icon: "aiVuln", run: () => { tab = "overview"; show(); } }]);

  async function overview() {
    const d = await load(), a = d.assessment;
    if (!alive) return;
    const hist = pushReading(readJson(HIST_KEY, []), { assets: d.assets.length, high: a.by_severity.Critical + a.by_severity.High, all: a.findings.length, unanswered: a.unanswered_total }); writeJson(HIST_KEY, hist);
    const ser = (k) => readingSeries(hist, (r) => r[k]);
    const t = (key, label, value, extra = {}) => ({ key, label, value, filterable: false, previous: ser(key).previous ?? undefined, spark: ser(key).values.length > 1 ? ser(key).values : undefined, goodWhen: "down", ...extra });
    const maxRule = Math.max(1, ...Object.values(a.by_rule));
    shell(`<div id="ais-kpis" class="sx-kpis mx-kpis"></div>
      ${d.assets.length ? "" : emptyState({ title: "No AI assets recorded yet", body: "Add them on the Register tab, or copy in the AI applications Quanta found in your traffic. An unanswered question is a gap, not a pass.", actionLabel: "Open the register", actionHref: "/ai-security?tab=register", iconName: "aiVuln" })}
      <div class="mx-split"><div><h3 class="mx-h3">Assets by risk</h3><div id="ais-assets"></div></div>
        <div><h3 class="mx-h3">By OWASP category</h3>${Object.keys(a.by_rule).length ? `<div class="mx-areas">${Object.entries(a.by_rule).sort((x, y) => y[1] - x[1]).map(([k, v]) => `<div class="mx-area" style="grid-template-columns:minmax(80px,1fr) minmax(60px,1fr) 28px"><span>${escapeHtml(k)}</span><span class="mx-meter" role="img" aria-label="${v} finding${v === 1 ? "" : "s"}"><i style="width:${Math.max(4, (v / maxRule) * 100)}%"></i></span><b>${v}</b></div>`).join("")}</div>` : '<p class="ui-muted">No findings.</p>'}
          <h3 class="mx-h3">Severity mix</h3>${stackedBar(["Critical", "High", "Medium", "Low"].map((s) => ({ label: s, value: a.by_severity[s] || 0, color: SEV_COLOR[s] })), { label: "AI security findings by severity", height: 12 })}</div></div>
      <p class="ui-muted">${escapeHtml(a.note)}${hist.length < 2 ? " Trends appear after a second reading in this browser." : ""}</p>`);
    kpiStrip(container.querySelector("#ais-kpis"), [t("assets", "AI assets recorded", d.assets.length, { goodWhen: "up" }), t("high", "Critical or high findings", a.by_severity.Critical + a.by_severity.High, { tone: a.by_severity.Critical + a.by_severity.High ? "danger" : "good" }),
      t("all", "All findings", a.findings.length), t("unanswered", "Questions still unanswered", a.unanswered_total, { tone: a.unanswered_total ? "warn" : "good", hint: "A question you left unanswered is a gap in the picture, never counted as a pass." })], () => {});
    selectableTable(container.querySelector("#ais-assets"), { rows: a.assets, rowKey: (x) => x.name, caption: "AI assets by risk", csvName: "quanta-ai-assets-by-risk", storageKey: "aisec-assets", rowHeight: 58, maxHeight: 420,
      emptyHtml: emptyState({ title: "None yet", body: "", iconName: "aiVuln" }),
      columns: [{ key: "n", label: "Asset", width: 220, csv: (x) => x.name, render: (x) => `<strong>${escapeHtml(x.name)}</strong><div class="mx-sub">${escapeHtml(x.owner || "no owner")} &middot; ${escapeHtml(x.environment || "environment unknown")}</div>` }, { key: "k", label: "Kind", width: 100, csv: (x) => x.kind, render: (x) => chip(x.kind, { tone: "neutral" }) },
        { key: "w", label: "Worst", width: 100, csv: (x) => x.worst || "", render: (x) => (x.worst ? severityChip(x.worst) : '<span class="ui-muted">none</span>') }, { key: "f", label: "Findings", width: 80, align: "right", csv: (x) => x.findings, render: (x) => x.findings }, { key: "u", label: "Unanswered", width: 100, align: "right", csv: (x) => x.unanswered.length, render: (x) => x.unanswered.length }] });
  }

  async function register() {
    const d = data || await load();
    if (draft) return form(d);
    shell(`<p class="sx-row"><button type="button" class="ui-btn sx-btn-sm" id="new">Add an AI asset</button> <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="imp">Copy in the AI applications found in traffic</button></p><div id="ais-reg"></div>`);
    selectableTable(container.querySelector("#ais-reg"), { rows: d.assets, rowKey: (x) => x.id, caption: "AI asset register", csvName: "quanta-ai-assets", storageKey: "aisec-register", rowHeight: 58, maxHeight: 520,
      emptyHtml: emptyState({ title: "No AI assets recorded yet", body: "Add one, or copy in the AI applications Quanta found in your traffic.", iconName: "aiVuln" }),
      columns: [{ key: "n", label: "Asset", width: 260, csv: (x) => x.name, render: (x) => `<strong>${escapeHtml(x.name)}</strong><div class="mx-sub">${escapeHtml(x.vendor_model || "")}</div>` }, { key: "k", label: "Kind", width: 110, csv: (x) => x.kind, render: (x) => chip(x.kind, { tone: "neutral" }) },
        { key: "o", label: "Owner", width: 170, csv: (x) => x.owner || "", render: (x) => (x.owner ? escapeHtml(x.owner) : '<span class="mx-unowned">no owner</span>') }, { key: "e", label: "Environment", width: 120, csv: (x) => x.environment || "", render: (x) => escapeHtml(x.environment || "-") },
        { key: "r", label: "Last reviewed", width: 130, csv: (x) => x.last_reviewed || "", render: (x) => escapeHtml(x.last_reviewed || "never") },
        { key: "a", label: "", width: 150, csv: () => "", render: (x) => `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-edit="${x.id}">Edit</button> <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-del="${x.id}">Delete</button>` }] });
    container.querySelector("#new").addEventListener("click", () => { draft = { name: "", kind: d.meta.kinds[0], data_classes: [] }; show(); });
    container.querySelector("#imp").addEventListener("click", async () => { try { const r = await api.aiSecurityImport(); toast(`${r.added.length} application(s) copied in.`, { tone: "good" }); data = null; show(); } catch (e) { toast(e.message, { tone: "bad" }); } });
    container.querySelector("#ais-reg").addEventListener("click", async (e) => {
      const ed = e.target.closest("[data-edit]"); if (ed) { draft = JSON.parse(JSON.stringify(d.assets.find((x) => x.id === Number(ed.dataset.edit)))); show(); return; }
      const del = e.target.closest("[data-del]"); if (!del) return;
      const ok = await modal({ title: "Delete this AI asset?", confirmLabel: "Delete", danger: true, description: "It leaves the register, and its findings leave the next published set.", body: "" });
      if (!ok) return;
      try { await api.aiSecurityDelete(Number(del.dataset.del)); toast("Deleted.", { tone: "good" }); data = null; show(); } catch (er) { toast(er.message, { tone: "bad" }); }
    });
  }

  const triOpt = (v) => `<option value="">?</option><option value="true"${v === true ? " selected" : ""}>Yes</option><option value="false"${v === false ? " selected" : ""}>No</option>`;
  const optList = (opts, cur, blank = "(not stated)") => `<option value="">${blank}</option>${opts.map((o) => `<option${cur === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}`;
  const triVal = (el) => (el.value === "" ? null : el.value === "true");

  // The tool and MCP server rows are read back from the page before any add/remove, so typing is never lost.
  function collectAgent(f) {
    const rows = (kind) => [...f.querySelectorAll(`[data-row="${kind}"]`)].map((r) => {
      const o = {};
      r.querySelectorAll("[data-f]").forEach((el) => { o[el.dataset.f] = el.dataset.t === "tri" ? triVal(el) : el.dataset.t === "int" ? (el.value === "" ? null : Number(el.value)) : (el.value.trim() || null); });
      return o;
    }).filter((o) => o.name);
    const list = (name) => f[name].value.split(",").map((v) => v.trim()).filter(Boolean);
    const tri = (n) => triVal(f[n]);
    const block = (prefix, keys) => Object.fromEntries(keys.map((k) => [k, tri(`${prefix}_${k}`)]));
    return {
      provider: f.provider.value.trim() || null, model_ids: list("model_ids"), memory: f.memory.value || null, memory_provenance: tri("memory_provenance"), memory_poisoning_controls: tri("memory_poisoning_controls"),
      max_steps: f.max_steps.value === "" ? null : Number(f.max_steps.value), budget_cap: tri("budget_cap"), prompt_versioning: tri("prompt_versioning"), eval_suite: f.eval_suite.value || null,
      tools: rows("tools").map((t) => ({ ...t, reads: (t.reads || "").split(",").map((v) => v.trim()).filter(Boolean) })), mcp_servers: rows("mcp_servers"),
      data_sources: list("data_sources").map((n) => ({ name: n.replace(/^!/, ""), trusted: n.startsWith("!") ? false : null })),
      release: block("release", ["rollback_path", "canary", "shadow"]), observability: block("obs", ["traces", "cost", "latency", "tool_failures"]), audit_log: block("audit", ["immutable", "redacts_secrets"]),
    };
  }

  function agentSection(m, x) {
    const a = m.agent, rel = x.release || {}, obs = x.observability || {}, aud = x.audit_log || {};
    const q = (name, label, v) => `<label>${escapeHtml(label)} <select name="${name}">${triOpt(v)}</select></label>`;
    const toolRow = (t) => `<div class="run-form" data-row="tools"><input data-f="name" placeholder="tool name" value="${escapeHtml(t.name || "")}" maxlength="80">
      <input data-f="scope" placeholder="scope or permission" value="${escapeHtml(t.scope || "")}"><select data-f="side_effect" title="strongest effect">${optList(a.side_effects, t.side_effect, "effect?")}</select>
      <select data-f="category" title="category">${optList(a.categories, t.category, "category")}</select><select data-f="requires_approval" data-t="tri" title="a person approves each call">${triOpt(t.requires_approval)}</select>
      <input data-f="server" placeholder="MCP server" value="${escapeHtml(t.server || "")}"><input data-f="reads" placeholder="data sources it reads (comma separated)" value="${escapeHtml((t.reads || []).join(", "))}">
      <button type="button" class="link-button danger-link" data-rm="tools">Remove</button></div>`;
    const srvRow = (s) => `<div class="run-form" data-row="mcp_servers"><input data-f="name" placeholder="server name" value="${escapeHtml(s.name || "")}" maxlength="80">
      <select data-f="transport">${optList(a.transports, s.transport, "transport?")}</select><select data-f="auth">${optList(a.auth, s.auth, "auth?")}</select>
      <input data-f="tool_count" data-t="int" type="number" min="0" placeholder="tools exposed" value="${s.tool_count ?? ""}">
      ${a.server_tri.map((k) => `<label>${escapeHtml(a.server_questions[k])} <select data-f="${k}" data-t="tri">${triOpt(s[k])}</select></label>`).join("")}
      <button type="button" class="link-button danger-link" data-rm="mcp_servers">Remove</button></div>`;
    return `<h3>Agent, tools and MCP servers</h3><p class="muted">Tool: name, scope, strongest effect, category, "a person approves each call", the MCP server it comes from, the data sources it reads. A "?" is kept as a gap.</p>
      <label>Provider <input name="provider" value="${escapeHtml(x.provider || "")}"></label><label>Model ids (comma separated) <input name="model_ids" value="${escapeHtml((x.model_ids || []).join(", "))}"></label>
      <label>Data sources it reads (comma separated; start a name with ! if it is untrusted content) <input name="data_sources" value="${escapeHtml((x.data_sources || []).map((d) => (d.trusted === false ? "!" : "") + d.name).join(", "))}"></label>
      <div id="tool-rows">${(x.tools || []).map(toolRow).join("")}</div><p><button type="button" class="secondary-button" id="add-tool">Add a tool</button></p>
      <div id="srv-rows">${(x.mcp_servers || []).map(srvRow).join("")}</div><p><button type="button" class="secondary-button" id="add-srv">Add an MCP server</button></p>
      <label>Memory <select name="memory">${optList(a.memory, x.memory)}</select></label>${q("memory_provenance", a.asset_questions.memory_provenance, x.memory_provenance)}${q("memory_poisoning_controls", a.asset_questions.memory_poisoning_controls, x.memory_poisoning_controls)}
      <label>${escapeHtml(a.asset_questions.max_steps)} <input name="max_steps" type="number" min="0" value="${x.max_steps ?? ""}"></label>${q("budget_cap", a.asset_questions.budget_cap, x.budget_cap)}
      ${q("prompt_versioning", a.asset_questions.prompt_versioning, x.prompt_versioning)}<label>Evaluation suite <select name="eval_suite">${optList(a.eval_suites, x.eval_suite)}</select></label>
      ${a.release.map((k) => q(`release_${k}`, a.asset_questions[`release.${k}`], rel[k])).join("")}${a.observability.map((k) => q(`obs_${k}`, a.asset_questions[`observability.${k}`], obs[k])).join("")}
      ${a.audit_log.map((k) => q(`audit_${k}`, a.asset_questions[`audit_log.${k}`], aud[k])).join("")}`;
  }

  function form(d) {
    const m = d.meta, x = draft;
    const sel = (name, label, opts, blank = true) => `<label>${label} <select name="${name}">${blank ? '<option value="">(not stated)</option>' : ""}${opts.map((o) => `<option${x[name] === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select></label>`;
    const tri = (f) => `<label>${escapeHtml(m.questions[f])} <select name="${f}"><option value="">Don't know</option><option value="true"${x[f] === true ? " selected" : ""}>Yes</option><option value="false"${x[f] === false ? " selected" : ""}>No</option></select></label>`;
    shell(`<form id="af" class="run-form"><label>Name <input name="name" value="${escapeHtml(x.name)}" required maxlength="160"></label>${sel("kind", "Kind", m.kinds, false)}
      <label>Owner <input name="owner" value="${escapeHtml(x.owner || "")}" placeholder="name@company.com"></label>${sel("environment", "Environment", m.environments)}${sel("hosting", "Hosting", m.hosting)}
      <label>Model or vendor <input name="vendor_model" value="${escapeHtml(x.vendor_model || "")}" placeholder="claude-sonnet, gpt-4o, llama-3"></label>
      <label>Last reviewed <input name="last_reviewed" type="date" value="${escapeHtml(x.last_reviewed || "")}"></label>
      <p><strong>Data it handles</strong></p><p>${m.data_classes.map((c) => `<label><input type="checkbox" name="dc" value="${c}"${(x.data_classes || []).includes(c) ? " checked" : ""}> ${c}</label>`).join(" ")}</p>
      ${sel("permissions_scope", "Highest permission its tools hold", m.scopes)}${sel("provenance", "Where the model came from", m.provenance)}${sel("serialization", "Model file format", m.serialization)}
      <p><strong>Questions</strong> <span class="muted">Answer what you know; "don't know" is kept as a gap.</span></p>${TRI_ORDER.map(tri).join("")}
      ${agentSection(m, x)}
      <label>Notes <textarea name="notes" rows="2">${escapeHtml(x.notes || "")}</textarea></label>
      <div><button type="submit">Save</button> <button type="button" class="secondary-button" id="cancel">Cancel</button></div></form>`);
    container.querySelector("#cancel").addEventListener("click", () => { draft = null; show(); });
    const keep = () => { const f = container.querySelector("#af"); draft = { ...draft, ...collectAgent(f), name: f.name.value, kind: f.kind.value }; };
    container.querySelector("#add-tool").addEventListener("click", () => { keep(); draft.tools.push({ name: "" }); show(); });
    container.querySelector("#add-srv").addEventListener("click", () => { keep(); draft.mcp_servers.push({ name: "" }); show(); });
    container.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { b.closest("[data-row]").querySelector("[data-f=name]").value = ""; keep(); show(); }));
    container.querySelector("#af").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target, body = { name: f.name.value, kind: f.kind.value, data_classes: [...f.querySelectorAll("[name=dc]:checked")].map((c) => c.value), notes: f.notes.value, ...collectAgent(f) };
      for (const k of ["owner", "environment", "hosting", "vendor_model", "last_reviewed", "permissions_scope", "provenance", "serialization"]) body[k] = f[k].value || null;
      for (const k of TRI_ORDER) body[k] = f[k].value === "" ? null : f[k].value === "true";
      try { if (x.id) await api.aiSecurityUpdate(x.id, body); else await api.aiSecurityAdd(body); draft = null; data = null; toast("Saved.", { tone: "good" }); show(); } catch (err) { toast(err.message, { tone: "bad", ms: 8000 }); }
    });
  }

  async function findings() {
    const d = await load(), a = d.assessment;
    shell(`<p class="sx-row"><button type="button" class="ui-btn sx-btn-sm" id="pub">Publish to the main queue</button> <span class="ui-muted">Sends this set as source ai-security. It is the complete set, so a finding leaves the queue when the record shows it fixed.</span></p><div id="ais-find"></div>
      ${a.assets.some((x) => x.unanswered.length) ? `<h3 class="mx-h3">Unanswered questions</h3><div class="mx-grid-cards">${a.assets.filter((x) => x.unanswered.length).map((x) => `<article class="mx-card"><h4>${escapeHtml(x.name)}</h4><ul class="mx-list">${x.unanswered.map((u) => `<li>${escapeHtml(u.question)}</li>`).join("")}</ul></article>`).join("")}</div>` : ""}`);
    selectableTable(container.querySelector("#ais-find"), { rows: a.findings, rowKey: (f) => `${f.rule}:${f.asset}:${f.title}`, caption: "AI security findings", csvName: "quanta-ai-security-findings", storageKey: "aisec-findings", rowHeight: 84, maxHeight: 560,
      emptyHtml: emptyState({ title: "No findings", body: "Nothing in the recorded facts breaks a rule. An unanswered question is a gap, not a pass: see below.", iconName: "approved" }),
      columns: [{ key: "s", label: "Severity", width: 110, csv: (f) => f.severity, render: (f) => `${severityChip(f.severity)}<div class="mx-sub">${escapeHtml(f.rule)}</div>` }, { key: "a", label: "Asset", width: 160, csv: (f) => f.asset, render: (f) => `<span class="mx-clip">${escapeHtml(f.asset)}</span>` },
        { key: "f", label: "Finding", width: 380, csv: (f) => f.title, render: (f) => `<strong class="mx-title">${escapeHtml(f.title)}</strong><div class="mx-sub" title="${escapeHtml(f.why)}">${escapeHtml(f.owasp)}${f.atlas ? ` &middot; ATLAS ${escapeHtml(f.atlas)}` : ""}. ${escapeHtml(f.why)}</div>` },
        { key: "x", label: "What to do", width: 320, csv: (f) => f.fix, render: (f) => `<span class="mx-title" title="${escapeHtml(f.fix)}">${escapeHtml(f.fix)}</span>` }] });
    container.querySelector("#pub").addEventListener("click", async () => {
      try {
        const pre = await api.aiSecurityPublish({});
        const ok = await modal({ title: "Publish to the main queue?", confirmLabel: `Publish ${pre.findings}`, description: pre.message, body: `<p>${pre.findings} finding(s) will be in the queue as source ai-security. A finding that no longer applies is removed in the same step.</p>` });
        if (!ok) return;
        const r = await api.aiSecurityPublish({ confirm: true });
        toast(`Published ${r.published}: ${r.added} new, ${r.updated} updated, ${r.removed} removed.`, { tone: "good", ms: 7000 });
      } catch (e) { toast(e.message, { tone: "bad", ms: 8000 }); }
    });
  }

  async function show() {
    try { await { overview, register, findings }[tab](); } catch (err) { shell(emptyState({ title: err.status === 403 || err.status === 401 ? "This page is for administrators" : "This could not be loaded", body: err.message || "Try again in a moment.", iconName: "risk" })); }
  }
  await show();
}
