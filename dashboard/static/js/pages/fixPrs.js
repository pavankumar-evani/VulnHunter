// Fix pull requests: dependency upgrades and code fixes as reviewable pull requests on the customer's Git host, tracked from proposal to merge to verification as a
// lifecycle board. Quanta writes to a repository in exactly one place, "Open the pull request", after a dry run and an explicit confirmation. It never merges.
// Cards are not draggable on purpose: moving one would mean writing to a repository, which only the preview-then-confirm flow may do.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, touchDataAge, mountCounters, tipAttr, debounce, sparkline } from "../ui.js";
import { modal, liveBadge, avatar, copyText } from "../sxKit.js";
import { selectableTable, autoRefresh, pageActions, skeletonPage, tabBar, wireTabBar, replaceSearch } from "../mxKit.js";
import { PR_LANES, PR_LANE_LABEL, prLane, prGroups, prAttention, prKpis, prActions, filterRecords } from "../moduleLogic.js";

export const title = "Fix Pull Requests";

const VERIFY = { verified: ["good", "Verified: no longer reported"], "still-present": ["critical", "Merged, but still reported"], "awaiting-rescan": ["warn", "Waiting for a rescan"], "not-merged": ["neutral", "Not merged yet"] };
const FLOW = [["created_at", "Proposed"], ["approved_at", "Approved"], ["opened_at", "Pull request opened"], ["merged_at", "Merged"], ["verified_at", "Verified by a scan"]];
const hours = (v) => (v == null ? "no data" : v < 48 ? `${v} h` : `${(v / 24).toFixed(1)} days`);
const STATE_TONE = { approved: "good", changes_requested: "warn", "changes-requested": "warn", failing: "critical", failure: "critical", passing: "good", success: "good", pending: "warn" };

function diffHtml(d) {
  return `<pre class="diff-view mx-code">${String(d || "").split("\n").map((ln) => {
    const cls = ln.startsWith("+") && !ln.startsWith("+++") ? "diff-add" : ln.startsWith("-") && !ln.startsWith("---") ? "diff-del" : ln.startsWith("@@") ? "diff-hunk" : "";
    return `<span class="${cls}">${escapeHtml(ln)}</span>`;
  }).join("\n")}</pre>`;
}

export async function render(container) {
  let admin = false;
  try { admin = ((await api.authMe()).user || {}).role === "admin"; } catch { admin = false; }
  const qs = new URLSearchParams(window.location.search);
  const S = { id: qs.get("id"), q: qs.get("q") || "", app: qs.get("app") || "", panel: "board", data: null, vel: null, pol: null, loadedAt: 0, pending: new Set(), flash: new Set() };
  let alive = true;
  onCleanup(() => { alive = false; });
  const $ = (s) => container.querySelector(s);
  const go = (n) => { S.cur = null; const u = new URL(window.location.href); if (n) u.searchParams.set("id", n); else u.searchParams.delete("id"); window.history.pushState({}, "", u); S.id = n || null; show(); };

  // ------------------------------------------------------------------ the board
  async function loadList() {
    const [pol, d, vel] = await Promise.all([api.gitopsPolicy(), api.gitopsProposals(), api.gitopsVelocity()]);
    if (!alive) return;
    S.pol = pol; S.data = d.proposals; S.vel = vel; S.loadedAt = Date.now();
  }
  const visible = () => filterRecords(S.data.filter((p) => !S.app || p.application === S.app), S.q, [(p) => p.id, (p) => p.title, (p) => p.application, (p) => p.finding_ids.join(" ")]);
  function cardHtml(p) {
    const att = prAttention(p); const acts = prActions(p, admin);
    const v = p.verified_state ? VERIFY[p.verified_state] : null;
    return `<article class="sx-card mx-prcard${S.pending.has(p.id) ? " pending" : ""}${S.flash.has(p.id) ? " flash" : ""}" data-pr="${p.id}" data-sev="${att.length ? "High" : "Informational"}" tabindex="0" role="listitem" aria-label="Proposal ${p.id}, ${escapeHtml(p.title)}, ${escapeHtml(PR_LANE_LABEL[p.lane] || p.status)}">
      <div class="sx-card-top"><span class="sx-row"><span class="sx-card-id">#${p.id}</span>${chip(p.kind === "dependency-upgrade" ? "Dependency" : "Code fix", { tone: "neutral" })}</span>${att.length ? chip("Needs attention", { tone: "critical" }) : ""}</div>
      <h4 class="sx-card-title"><button type="button" class="sx-link-btn mx-cardlink" data-detail="${p.id}">${escapeHtml(p.title)}</button></h4>
      <div class="mx-sub">${escapeHtml(p.application)} &middot; ${p.finding_ids.length} finding${p.finding_ids.length === 1 ? "" : "s"}: ${escapeHtml(p.finding_ids.slice(0, 2).join(", "))}${p.finding_ids.length > 2 ? "..." : ""}</div>
      ${p.review_state || p.checks_state ? `<div class="sx-row">${p.review_state ? chip(`review: ${p.review_state}`, { tone: STATE_TONE[p.review_state] || "neutral" }) : ""}${p.checks_state ? chip(`checks: ${p.checks_state}`, { tone: STATE_TONE[p.checks_state] || "neutral" }) : ""}</div>` : ""}
      ${v ? `<div>${chip(v[1], { tone: v[0] })}</div>` : ""}${att.length ? `<div class="mx-why-not">${att.map(escapeHtml).join(". ")}.</div>` : ""}
      ${acts.length ? `<div class="mx-actions">${acts.includes("approve") ? `<button type="button" class="ui-btn sx-btn-sm" data-act="approve" data-id="${p.id}">Approve</button>` : ""}${acts.includes("preview") ? `<button type="button" class="ui-btn sx-btn-sm" data-act="preview" data-id="${p.id}">Preview and open</button>` : ""}${acts.includes("sync") ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="sync" data-id="${p.id}">Check the host</button>` : ""}${acts.includes("discard") ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="discard" data-id="${p.id}">Discard</button>` : ""}</div>` : ""}</article>`;
  }
  function paintList() {
    if (!alive || !S.data) return;
    const o = S.vel.outcomes; const op = S.vel.open_pull_requests; const st = S.vel.stages;
    const list = visible().map((p) => ({ ...p, lane: prLane(p) }));
    const g = prGroups(list);
    const k = prKpis(S.data);
    const apps = [...new Set(S.data.map((p) => p.application))].sort();
    const mw = S.vel.merged_per_week.map((w) => w.merged);
    container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Fix pull requests</h2><p>Dependency upgrades and code fixes as pull requests on your Git host, with the finding, the CVE, the fixed version and how to verify in the description. Quanta prepares the change, an administrator approves it, a dry run shows exactly what would be sent, and only then does it create a branch of its own and open the pull request. People review, test and merge it the way they do any change.</p></div>
        <div class="sx-row"><span id="f-live"></span><span id="f-age">${dataAgeBadge(S.loadedAt)}</span>${admin ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="f-sync">${icon("clock", 14)} Check the Git host</button>` : ""}</div></div>
      <div id="f-kpis" class="sx-kpis mx-kpis"></div>
      ${tabBar("Fix pull request views", [{ id: "board", label: "Lifecycle board", count: S.data.length }, { id: "timing", label: "How long it takes" }, { id: "process", label: "The process" }], S.panel)}
      <div id="f-body"></div></div>`;
    mountDataAge(container); setLive(S.mode || "idle");
    const tile = (key, label, value, extra = {}) => `<div class="sx-kpi-cell">${kpiTile({ label, value, ...extra })}</div>`;
    $("#f-kpis").innerHTML = [
      tile("p", "Proposals", S.vel.proposals), tile("o", "Open pull requests", op.count, { tone: op.count ? "warn" : "", hint: `${op.waiting_for_review} waiting for review, ${op.failing_checks} failing checks` }),
      tile("v", "Merged and verified", o.verified, { tone: "good", hint: `${o.verified} of ${o.merged} merged proposals were confirmed fixed by a later scan.` }), tile("s", "Merged, still reported", o.still_present, { tone: o.still_present ? "danger" : "good", hint: "Merged, but the next scan still reports the finding." }),
      tile("a", "Need attention", k.attention, { tone: k.attention ? "danger" : "good", hint: "Failed to open, failing checks, changes requested, or merged and still reported." }),
    ].join("");
    mountCounters($("#f-kpis"));
    wireTabBar(container.querySelector(".mx-tabs"), (id) => { S.panel = id; paintBody(); container.querySelectorAll(".mx-tabs [data-tab]").forEach((b) => { b.setAttribute("aria-selected", String(b.dataset.tab === id)); b.tabIndex = b.dataset.tab === id ? 0 : -1; }); });
    const body = () => $("#f-body");
    function paintBody() {
      if (S.panel === "timing") {
        const rows = [["detected_to_pull_request", "First seen to pull request opened"], ["created_to_approved", "Proposed to approved"], ["opened_to_merged", "Opened to merged"], ["merged_to_verified", "Merged to confirmed by a scan"], ["created_to_verified", "Proposed to verified, end to end"]];
        const max = Math.max(1, ...rows.map(([key]) => st[key].p90_hours || 0));
        body().innerHTML = `<div class="mx-split"><div><div class="mx-areas">${rows.map(([key, l]) => `<div class="mx-area"><span>${l}</span><span class="mx-meter" role="img" aria-label="Median ${hours(st[key].median_hours)}"><i style="width:${st[key].median_hours == null ? 0 : Math.max(3, ((st[key].median_hours || 0) / max) * 100)}%"></i></span><b>${hours(st[key].median_hours)}</b><span class="ui-muted mx-sub">slowest 10%: ${hours(st[key].p90_hours)}, n=${st[key].n}</span></div>`).join("")}</div></div>
          <div class="mx-card"><h4>Merged per week</h4>${mw.some((n) => n) ? sparkline(mw, { width: 220, height: 50, label: "Pull requests merged per week, last 12 weeks" }) : '<p class="ui-muted">Nothing merged in the last 12 weeks.</p>'}<div class="mx-sub">Last 12 weeks: ${mw.join(" ")}</div></div></div><p class="ui-muted">${escapeHtml(S.vel.note)}</p>`;
        return;
      }
      if (S.panel === "process") {
        const pol = S.pol;
        body().innerHTML = `<ol class="mx-steps-list">${pol.policy.process.steps.map((s) => `<li>${escapeHtml(s.text)}</li>`).join("")}</ol>
          <p class="ui-muted">Quanta never: ${pol.never.map(escapeHtml).join("; ")}. Branch pattern <code>${escapeHtml(pol.policy.branch.template)}</code>; approval is required before a pull request is opened${pol.policy.approval.require_distinct_approver ? " and a different administrator must approve" : ""}. Edit <code>remediation/config/gitops_policy.yaml</code> to match your process.</p>
          <div class="mx-callout">Following the pull requests: ${pol.automation.scheduled_sync ? "Quanta checks the Git host every hour" : "the hourly check is switched off (QUANTA_GITOPS_SYNC=false)"}; ${pol.automation.webhook_configured ? "webhooks from GitHub or GitLab to <code>/api/inbound/git-webhook</code> update it at once" : "no webhook secret is set (QUANTA_GIT_WEBHOOK_SECRET), so webhooks are refused; the hourly check and the button above still work"}.</div>`;
        return;
      }
      body().innerHTML = `<div class="sx-toolbar" role="search"><input type="search" class="sx-field" id="f-q" placeholder="Search id, change, application, finding" value="${escapeHtml(S.q)}" aria-label="Search proposals"><select class="sx-field" id="f-app" aria-label="Application"><option value="">Every application</option>${apps.map((a) => `<option ${a === S.app ? "selected" : ""}>${escapeHtml(a)}</option>`).join("")}</select><span class="ui-muted mx-count">${list.length} of ${S.data.length}</span></div>
        ${S.data.length ? `<div class="sx-board" role="list" aria-label="Pull request lifecycle" style="grid-template-columns:repeat(6, minmax(228px, 1fr))">${PR_LANES.map((l) => `<section class="sx-col" aria-label="${PR_LANE_LABEL[l]}, ${g[l].length}"><div class="sx-col-head"><h3>${PR_LANE_LABEL[l]}</h3><span class="sx-col-n">${g[l].length}</span></div><div class="sx-col-body">${g[l].map(cardHtml).join("") || '<div class="sx-col-empty">Nothing here</div>'}</div></section>`).join("")}</div>`
          : `<div class="sx-panel">${emptyState({ title: "No proposals yet", body: "Open an application, find an item in its ranked work and choose Propose PR. The change appears here and moves left to right as it is approved, opened, merged and verified by a scan.", actionLabel: "Open applications", actionHref: "/applications", iconName: "dependencies" })}</div>`}`;
    }
    paintBody();
  }
  const setLive = (m) => { S.mode = m; const el = $("#f-live"); if (el) el.innerHTML = liveBadge(m === "live" ? "live" : m === "poll" ? "poll" : "idle"); };

  async function approve(id) {
    S.pending.add(id); const p = S.data.find((x) => x.id === id); const snap = p && { ...p }; if (p) p.status = "approved"; paintList();
    try { await api.gitopsApprove(id); toast(`Proposal #${id} approved.`, { tone: "good" }); S.flash.add(id); await loadList(); }
    catch (e) { if (p && snap) Object.assign(p, snap); toast(`Not approved: ${e.message}`, { tone: "bad", ms: 8000 }); }
    finally { S.pending.delete(id); paintList(); }
  }
  async function discard(id) {
    const out = await modal({ title: `Discard proposal #${id}?`, confirmLabel: "Discard", danger: true, description: "It is closed and stays in the history. Nothing is changed on the Git host.", body: `<label>Why? (optional)<input type="text" id="m-why" maxlength="300"></label>`, collect: (d) => d.querySelector("#m-why").value.trim() });
    if (out === null) return;
    try { await api.gitopsDiscard(id, out); toast(`Proposal #${id} discarded.`, { tone: "good" }); if (S.id) go(null); else { await loadList(); paintList(); } } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function syncNow(manual = true) {
    try { const r = await api.gitopsSync(); if (manual) toast(`Checked ${r.synced.length} open pull request(s); ${r.verification.length} merged proposal(s) re-checked against the latest scan.`, { tone: "good", ms: 6000 }); await (S.id ? show() : (async () => { await loadList(); paintList(); })()); } catch (e) { if (manual) toast(e.message, { tone: "bad" }); }
  }
  async function preview(id) {
    let r;
    try { r = await api.gitopsOpen(id, false); } catch (e) { toast(e.message, { tone: "bad", ms: 9000 }); return; }
    const ok = await modal({ title: `Open pull request for #${id}`, confirmLabel: `Open it on ${r.plan.provider}`, wide: true, description: "This is a dry run: nothing has been sent. Confirming creates a branch of Quanta's own, commits the files to it and opens the pull request. Quanta will not merge it.",
      body: `<dl class="mx-facts"><div class="mx-fact"><dt>Connection</dt><dd>${escapeHtml(r.connection || "none found")}</dd></div><div class="mx-fact"><dt>Repository</dt><dd>${escapeHtml(r.plan.repo)}</dd></div><div class="mx-fact"><dt>New branch</dt><dd><code>${escapeHtml(r.plan.branch)}</code></dd></div><div class="mx-fact"><dt>Into</dt><dd><code>${escapeHtml(r.plan.base_branch || "the default branch")}</code>${r.plan.draft ? " (as a draft)" : ""}</dd></div><div class="mx-fact"><dt>Files</dt><dd>${r.plan.files.length}</dd></div><div class="mx-fact"><dt>Commit message</dt><dd><code>${escapeHtml(r.plan.commit_message.split("\n")[0])}</code></dd></div></dl><p class="ui-muted">${escapeHtml(r.message)}</p>` });
    if (!ok) return;
    S.pending.add(id); paintList();
    try { const out = await api.gitopsOpen(id, true); toast(`Pull request opened: ${out.pr_url}`, { tone: "good", ms: 9000 }); S.flash.add(id); } catch (e) { toast(`Not opened: ${e.message}`, { tone: "bad", ms: 10000 }); }
    finally { S.pending.delete(id); if (S.id) show(); else { await loadList(); paintList(); } }
  }

  // ------------------------------------------------------------------ one proposal
  async function detail() {
    const p = await api.gitopsProposal(S.id);
    if (!alive) return;
    const plan = p.plan; const v = p.verification; const acts = prActions(p, admin);
    const step = (k, l) => `<li class="${p[k] ? "mx-tl-done" : ""}"><span class="mx-tl-dot" aria-hidden="true"></span><span class="mx-tl-body"><strong>${l}</strong>${p[k] ? `<span class="ui-muted"> ${escapeHtml(p[k].slice(0, 16).replace("T", " "))}${k === "created_at" ? " by " + escapeHtml(p.created_by || "") : k === "approved_at" ? " by " + escapeHtml(p.approved_by || "") : k === "opened_at" ? " by " + escapeHtml(p.opened_by || "") : ""}</span>` : '<span class="ui-muted"> not yet</span>'}</span></li>`;
    container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><p><button type="button" class="sx-link-btn" id="back">&larr; All proposals</button></p><h2>#${p.id} ${escapeHtml(p.title)}</h2>
        <p>${chip(p.status, { tone: p.status === "merged" ? "good" : p.status === "failed" ? "critical" : "neutral" })} ${escapeHtml(p.application)} &middot; ${escapeHtml(p.kind)} &middot; ${p.repo ? `${escapeHtml(p.provider)} ${escapeHtml(p.repo)}` : '<span class="mx-clock-warn">no repository set on the application</span>'}${p.pr_url ? ` &middot; <a href="${escapeHtml(p.pr_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(p.pr_url)}</a>` : ""}</p></div>
        <div class="sx-row">${acts.includes("approve") ? '<button type="button" class="ui-btn sx-btn-sm" data-act="approve">Approve</button>' : ""}${acts.includes("preview") ? '<button type="button" class="ui-btn sx-btn-sm" data-act="preview">Preview and open</button>' : ""}${acts.includes("sync") ? '<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="sync">Check the host now</button>' : ""}${p.status === "merged" && v.state !== "verified" && admin ? '<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="rescan">Queue a rescan</button>' : ""}${acts.includes("discard") ? '<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="discard">Discard</button>' : ""}</div></div>
      ${p.kind === "dependency-upgrade" && p.summary.lockfile_note ? `<div class="mx-callout"><strong>Lock file.</strong> ${escapeHtml(p.summary.lockfile_note)}${(p.summary.lockfiles || []).length ? " Because one is present, the pull request opens as a draft: mark it ready once the lock file is refreshed and the checks pass." : ""}</div>` : ""}
      ${p.last_error ? `<div class="mx-callout mx-callout-warn">${escapeHtml(p.last_error)}</div>` : ""}
      <ol class="mx-tl">${FLOW.map(([k, l]) => step(k, l)).join("")}</ol>
      ${p.pr_state ? `<p class="ui-muted">On the host: ${escapeHtml(p.pr_state)}; review ${escapeHtml(p.review_state || "none")}; checks ${escapeHtml(p.checks_state || "none")}; last checked ${escapeHtml((p.last_synced_at || "never").slice(0, 16).replace("T", " "))}.</p>` : ""}
      ${p.status === "merged" || v.state !== "not-merged" ? `<p>${chip((VERIFY[v.state] || ["neutral", v.state])[1], { tone: (VERIFY[v.state] || ["neutral"])[0] })} <span class="ui-muted">${escapeHtml(v.detail)}</span></p>` : ""}
      <h3 class="mx-h3">Changes</h3>${p.files.map((f) => `<p><strong>${escapeHtml(f.path)}</strong> <span class="ui-muted">+${f.stats.added} -${f.stats.removed}</span></p>${f.changes && f.changes.length ? `<ul class="mx-list">${f.changes.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>` : ""}${diffHtml(f.diff)}`).join("")}
      ${(p.summary.notes || []).length ? `<p class="ui-muted">${p.summary.notes.map(escapeHtml).join("; ")}</p>` : ""}
      <h3 class="mx-h3">Pull request description <button type="button" class="mx-copy" data-copy-body>Copy</button></h3><pre class="diff-view mx-code" style="white-space:pre-wrap">${escapeHtml(p.pr_body)}</pre>
      <h3 class="mx-h3">What opening it does</h3><ol class="mx-steps-list">${plan.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      <p class="ui-muted">Branch <code>${escapeHtml(plan.branch)}</code> into <code>${escapeHtml(plan.base_branch || "the default branch")}</code>${plan.draft ? "; opened as a draft" : ""}${plan.labels.length ? "; labels " + plan.labels.map(escapeHtml).join(", ") : ""}${plan.reviewers.length ? "; reviewers " + plan.reviewers.map(escapeHtml).join(", ") : ""}.</p>
      ${admin ? "" : '<p class="ui-muted">An administrator approves and opens proposals.</p>'}</div>`;
    $("#back").addEventListener("click", () => go(null));
    S.cur = p;
  }

  async function show() {
    container.innerHTML = skeletonPage(5);
    try { if (S.id) await detail(); else { await loadList(); paintList(); } } catch (err) { container.innerHTML = `<div class="sx-page">${emptyState({ title: "Proposals could not be loaded", body: err.message || "Try again in a moment.", iconName: "risk" })}</div>`; }
  }

  container.addEventListener("click", (e) => {
    const t = e.target;
    const d = t.closest("[data-detail]"); if (d) { go(d.dataset.detail); return; }
    if (t.closest("#f-sync")) { syncNow(true); return; }
    if (S.cur && t.closest("[data-copy-body]")) { copyText(S.cur.pr_body, "Description copied"); return; }
    const cur = S.cur && t.closest("[data-act]:not([data-id])");
    if (cur) {
      const k = cur.dataset.act; const id = S.cur.id;
      if (k === "approve") api.gitopsApprove(id).then(() => { toast("Approved.", { tone: "good" }); show(); }).catch((er) => toast(er.message, { tone: "bad" }));
      else if (k === "discard") discard(id); else if (k === "preview") preview(id); else if (k === "sync") syncNow(true);
      else if (k === "rescan") api.gitopsRescan(id).then((r) => toast(r.message, { tone: "good" })).catch((er) => toast(er.message, { tone: "bad" }));
      return;
    }
    const a = t.closest("[data-act][data-id]");
    if (a) { const id = a.dataset.id; const k = a.dataset.act; if (k === "approve") approve(id); else if (k === "preview") preview(id); else if (k === "discard") discard(id); else if (k === "sync") syncNow(true); }
  });
  const typeSearch = debounce((v) => { S.q = v; replaceSearch(S.q ? `?q=${encodeURIComponent(S.q)}` : ""); paintList(); const i = $("#f-q"); if (i) { i.focus(); i.setSelectionRange(v.length, v.length); } }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "f-q") typeSearch(e.target.value); });
  container.addEventListener("change", (e) => { if (e.target.id === "f-app") { S.app = e.target.value; paintList(); } });
  const onPop = () => { S.id = new URLSearchParams(window.location.search).get("id"); };
  void onPop;
  await show();
  pageActions([{ label: "Fix PRs: check the Git host for updates", icon: "dependencies", run: () => syncNow(true) }, { label: "Fix PRs: back to all proposals", icon: "dependencies", run: () => go(null) }]);
  autoRefresh(async () => { if (S.id) return; try { await loadList(); paintList(); const age = $("#f-age .ui-age"); if (age) touchDataAge(age, S.loadedAt); } catch { /* the next tick retries */ } }, { every: 30000, onMode: setLive });
  void tipAttr; void avatar; void selectableTable; void PR_LANES;
}
