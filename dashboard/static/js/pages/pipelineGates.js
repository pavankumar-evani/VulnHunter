// Pipeline gates: the release gate a CI job calls before shipping. An on-demand evaluation for any application with a plain verdict banner and rule-by-rule reasons,
// the policy (remediation/config/pipeline_gates.yaml) as a matrix, the step to paste into a pipeline, and the recorded results as a timeline.
// The gate judges what Quanta has been told: findings, the scans that were uploaded and the stored SBOM. A scan that never ran is reported, not assumed clean.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, mountCounters, tipAttr } from "../ui.js";
import { copyText } from "../sxKit.js";
import { pageActions, skeletonPage, tabBar, wireTabBar, replaceSearch, copyButton, wireCopy } from "../mxKit.js";
import { gateStats, groupByDay } from "../moduleLogic.js";

export const title = "Pipeline Gates";

const MODE_TONE = { block: "critical", warn: "warn", off: "neutral" };
const DECISION = { pass: ["good", "Pass", "The release may go ahead."], warn: ["warn", "Warn", "It may go ahead, with the warnings below."], fail: ["critical", "Fail", "The release should not go ahead until the rules below pass."] };
const RULE_STATUS = { pass: ["good", "pass"], warn: ["warn", "warn"], fail: ["critical", "fail"], skipped: ["neutral", "not checked"] };

export async function render(container) {
  const $ = (s) => container.querySelector(s);
  let alive = true;
  onCleanup(() => { alive = false; });
  const S = { app: new URLSearchParams(window.location.search).get("app") || "", snippet: "github-actions", result: null, info: null, panel: "history", loadedAt: 0 };

  function describe(k, r) {
    if (k === "open_severity") return "Limits: " + Object.entries(r.limits || {}).map(([s, n]) => `${s} ${n}`).join(", ");
    if (k === "fixable_overdue") return `${r.severity_at_least} or above, fix available, open more than ${r.older_than_days} days`;
    if (k === "required_scans") return `${r.scan_types.join(", ")} within ${r.max_age_days} days`;
    if (k === "sbom") return `Stored within ${r.max_age_days} days`;
    return "";
  }
  function resultHtml(r) {
    const [tone, label, line] = DECISION[r.decision] || ["neutral", r.decision, ""];
    return `<section class="mx-verdict mx-verdict-${tone}" aria-live="polite"><div><span class="ui-kpi-label">Decision for ${escapeHtml(r.application)} in ${escapeHtml(r.environment)}</span><div class="mx-score">${escapeHtml(label.toUpperCase())}</div><p>${escapeHtml(line)}${r.requested_environment && r.requested_environment !== r.environment ? ` (You asked for ${escapeHtml(r.requested_environment)}, which is not in the policy.)` : ""}${r.application_known ? "" : " This application has no record in Quanta, so its environment and SBOM are unknown."}</p></div>
      <ol class="mx-rules">${r.rules.map((x) => { const [t, l] = RULE_STATUS[x.status]; return `<li class="mx-rule mx-rule-${t}"><span class="mx-rule-dot" aria-hidden="true"></span><div><strong>${escapeHtml(x.title)}</strong> ${chip(l, { tone: t })} ${chip(x.mode, { tone: MODE_TONE[x.mode] })}<div class="mx-sub">${escapeHtml(x.detail)}</div>${x.finding_ids.length ? `<div class="mx-sub">${x.finding_ids.slice(0, 8).map((id) => `<a href="/queue?highlight=${encodeURIComponent(id)}" data-link>${escapeHtml(id)}</a>`).join(", ")}${x.finding_ids.length > 8 ? ", ..." : ""}</div>` : ""}</div></li>`; }).join("")}</ol><p class="ui-muted mx-sub">${escapeHtml(r.note)}</p></section>`;
  }
  function historyHtml(info) {
    const hist = info.history; const st = gateStats(hist);
    if (!hist.length) return emptyState({ title: "No evaluation has been recorded yet", body: "Every call to the gate, from a pipeline or from the form above, is recorded here with its decision.", iconName: "approved" });
    return `<div class="mx-areas">${st.latest.slice(0, 6).map((h) => `<div class="mx-area"><span><a href="/pipeline-gates?app=${encodeURIComponent(h.application)}" data-link>${escapeHtml(h.application)}</a> <span class="ui-muted mx-sub">${escapeHtml(h.environment)}</span></span>${chip(h.decision, { tone: DECISION[h.decision] ? DECISION[h.decision][0] : "neutral" })}<span></span><span class="ui-muted mx-sub">${escapeHtml(String(h.evaluated_at).slice(0, 16).replace("T", " "))}</span></div>`).join("")}</div>
      <h3 class="mx-h3">Timeline</h3>${groupByDay(hist, (h) => h.evaluated_at).map((g) => `<div class="mx-day"><h4>${escapeHtml(g.day)}</h4><ol class="mx-tl">${g.items.map((h) => `<li class="mx-tl-${h.decision === "pass" ? "done" : h.decision === "fail" ? "failed" : "current"}"><span class="mx-tl-dot" aria-hidden="true"></span><span class="mx-tl-body"><strong>${escapeHtml(h.application)}</strong> in ${escapeHtml(h.environment)}: ${chip(h.decision, { tone: DECISION[h.decision] ? DECISION[h.decision][0] : "neutral" })} <span class="ui-muted">${escapeHtml(String(h.evaluated_at).slice(11, 16))}${h.evaluated_by ? `, called by ${escapeHtml(h.evaluated_by)}` : ""}</span></span></li>`).join("")}</ol></div>`).join("")}`;
  }

  async function show() {
    const info = await api.gateInfo(S.app);
    if (!alive) return;
    S.info = info; S.loadedAt = Date.now();
    const envs = Object.keys(info.policy.environments); const rules = info.policy.rules; const st = gateStats(info.history);
    const snip = info.snippets[S.snippet];
    container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Pipeline gates</h2><p>The release gate. A CI job asks Quanta whether an application may ship, and gets <strong>pass</strong>, <strong>warn</strong> or <strong>fail</strong> with the reasons. The gate judges what Quanta has been told: findings, the scans that were uploaded and the stored SBOM. A scan that never ran is reported, not assumed clean. Policy version <code>${escapeHtml(info.version)}</code>.</p></div><div class="sx-row"><span id="pg-age">${dataAgeBadge(S.loadedAt)}</span></div></div>
      <div id="pg-kpis" class="sx-kpis mx-kpis"></div>
      <form id="gf" class="mx-card mx-gateform"><h4>Try it</h4><div class="sx-toolbar"><label class="mx-inline">Application <input class="sx-field" name="app" list="apps" value="${escapeHtml(S.app)}" required placeholder="application name"><datalist id="apps">${info.applications.map((a) => `<option value="${escapeHtml(a)}">`).join("")}</datalist></label>
        <label class="mx-inline">Environment <select class="sx-field" name="env">${envs.map((e) => `<option${e === info.policy.default_environment ? " selected" : ""}>${escapeHtml(e)}</option>`).join("")}</select></label><button type="submit" class="ui-btn sx-btn-sm">Evaluate</button><span class="ui-muted mx-sub">Each evaluation is recorded in the history.</span></div></form>
      <div id="out">${S.result ? resultHtml(S.result) : ""}</div>
      ${tabBar("Pipeline gate sections", [{ id: "history", label: "History", count: info.history.length }, { id: "policy", label: "Policy" }, { id: "pipeline", label: "Add it to a pipeline" }], S.panel)}
      <div id="pg-body"></div></div>`;
    mountDataAge(container);
    const tile = (label, value, extra = {}) => `<div class="sx-kpi-cell">${kpiTile({ label, value, ...extra })}</div>`;
    $("#pg-kpis").innerHTML = [tile("Evaluations recorded", st.n), tile("Pass rate", st.passRate === null ? "n/a" : st.passRate, { suffix: st.passRate === null ? "" : "%", tone: st.passRate === null ? "" : st.passRate >= 80 ? "good" : "warn", hint: "Share of recorded evaluations that passed. Shown once there is at least one." }),
      tile("Failed", st.fail, { tone: st.fail ? "danger" : "good" }), tile("Warned", st.warn, { tone: st.warn ? "warn" : "good" }), tile("Applications gated", st.latest.length, { hint: "Applications with at least one recorded evaluation." })].join("");
    mountCounters($("#pg-kpis"));
    const body = () => $("#pg-body");
    function paintBody() {
      if (S.panel === "policy") {
        body().innerHTML = `<div class="ui-table-wrap"><table class="mx-plain"><caption class="ui-sr">Gate rules by environment</caption><thead><tr><th scope="col">Rule</th>${envs.map((e) => `<th scope="col">${escapeHtml(e)}</th>`).join("")}</tr></thead><tbody>${Object.entries(rules).map(([k, r]) => `<tr><td><strong>${escapeHtml(r.title)}</strong><div class="mx-sub">${escapeHtml(describe(k, r))}</div></td>${envs.map((e) => { const m = info.policy.environments[e][k] || "off"; return `<td>${chip(m, { tone: MODE_TONE[m] })}</td>`; }).join("")}</tr>`).join("")}</tbody></table></div>
          <p class="ui-muted"><code>block</code> fails the job, <code>warn</code> lets it pass with a warning, <code>off</code> is not checked. A finding with an approved exception is not counted. Edit <code>remediation/config/pipeline_gates.yaml</code>; it is read on every evaluation.</p>`;
      } else if (S.panel === "pipeline") {
        body().innerHTML = `<p class="ui-muted">Create an API key with the <code>read:findings</code> scope (Administration, API keys), store it as the secret <code>QUANTA_API_KEY</code>, and add the step. The job fails only on <strong>fail</strong>. Pin any third-party action you add to a commit you have reviewed.</p>
          <div class="mx-tabs" role="tablist" aria-label="Pipeline system">${["github-actions", "gitlab-ci", "shell"].map((k) => `<button type="button" role="tab" data-snip="${k}" aria-selected="${k === S.snippet}">${k === "github-actions" ? "GitHub Actions" : k === "gitlab-ci" ? "GitLab CI" : "Shell"}</button>`).join("")}</div>
          <div class="mx-actions">${copyButton(snip, "Copy this step")}</div><pre class="diff-view mx-code">${escapeHtml(snip)}</pre>`;
      } else {
        body().innerHTML = `${S.app ? `<p>Showing ${escapeHtml(S.app)}. <a href="/pipeline-gates" data-link>Show every application</a></p>` : ""}${historyHtml(info)}`;
      }
    }
    paintBody();
    wireTabBar(container.querySelector(".mx-tabs"), (id) => { S.panel = id; container.querySelectorAll(".mx-tabs")[0].querySelectorAll("[data-tab]").forEach((b) => { b.setAttribute("aria-selected", String(b.dataset.tab === id)); b.tabIndex = b.dataset.tab === id ? 0 : -1; }); paintBody(); });
    $("#gf").addEventListener("submit", async (e) => {
      e.preventDefault();
      S.app = e.target.elements.app.value.trim(); replaceSearch(S.app ? `?app=${encodeURIComponent(S.app)}` : "");
      const btn = e.target.querySelector("button[type=submit]"); btn.disabled = true;
      try { S.result = await api.gateEvaluate({ application: S.app, environment: e.target.elements.env.value }); await show(); } catch (err) { toast(err.message, { tone: "bad", ms: 8000 }); btn.disabled = false; }
    });
    body().addEventListener("click", (e) => { const b = e.target.closest("[data-snip]"); if (b) { S.snippet = b.dataset.snip; paintBody(); } });
    wireCopy(container, copyText);
    void tipAttr;
  }

  container.innerHTML = skeletonPage(5);
  try { await show(); } catch (err) { container.innerHTML = `<div class="sx-page">${emptyState({ title: "The gate could not be loaded", body: err.message || "Try again in a moment.", iconName: "risk" })}</div>`; return; }
  pageActions([{ label: "Pipeline gates: copy the GitHub Actions step", icon: "approved", run: () => S.info && copyText(S.info.snippets["github-actions"], "Step copied") }, { label: "Pipeline gates: show the policy", icon: "approved", run: () => { S.panel = "policy"; show(); } }, { label: "Pipeline gates: show the history", icon: "approved", run: () => { S.panel = "history"; show(); } }]);
}
