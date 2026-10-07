// Remediation approvals: the human decision before a generated playbook counts as ready. Each request is a card with its safety lint, rollback plan, staging
// check, timeline and verification outcome; Review opens the evidence pack (finding, playbook, lint, trail) with approve and reject, and a reject needs a reason.
// Approving records who authorised it and when: nothing runs against real infrastructure. The rules in moduleLogic.js mirror the server's refusals and are tested under Node.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { getCurrentUser } from "../auth.js";
import { groupLabelFor } from "../domainGrouping.js";
import { kpiTile, chip, severityChip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, openDrawer, tipAttr, debounce, mountCounters } from "../ui.js";
import { modal, avatar, liveBadge, copyText } from "../sxKit.js";
import { selectableTable, autoRefresh, pageActions, skeletonPage, tabBar, wireTabBar, replaceSearch } from "../mxKit.js";
import { approvalTimeline, approvalBucket, approvalKpis, canApprove, canReject, validateReason, needsApproval, windowDays, filterRecords } from "../moduleLogic.js";
import { openFindingById } from "../findingLookup.js";

export const title = "Remediation Approvals";

const STATUS_TONE = { pending: "warn", approved: "good", rejected: "critical", expired: "neutral", remediation_triggered: "good" };
const STATUS_TEXT = { pending: "Awaiting decision", approved: "Approved", rejected: "Rejected", expired: "Window passed", remediation_triggered: "Remediation triggered" };
const REFRESH_MS = 20000;
const TABS = ["pending", "approved", "closed", "request"];

const windowText = (w) => (!w || !w.date ? "No window" : `${w.date} (${w.day_of_week}) ${w.start_time}-${w.end_time} ${w.timezone}`);

export async function render(container) {
  const me = await getCurrentUser().catch(() => null);
  const isAdmin = !!me && me.role === "admin";
  const qs = new URLSearchParams(window.location.search);
  const S = { approvals: [], findings: new Map(), queue: [], tab: TABS.includes(qs.get("tab")) ? qs.get("tab") : "pending", q: qs.get("q") || "", domain: qs.get("domain") || "all", metrics: null, ad: { configured: false }, loadedAt: 0, pending: new Set(), flash: new Set(), table: null };
  let alive = true;
  onCleanup(() => { alive = false; });
  const $ = (s) => container.querySelector(s);

  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Remediation approvals</h2><p>Findings whose <a href="/remediation-policy" data-link>remediation policy</a> needs a person to approve the change before its generated playbook is considered ready. Approving records who authorised it and when; this app never runs anything against real infrastructure.</p></div>
    <div class="sx-row"><span id="p-live"></span><span id="p-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="p-refresh">${icon("clock", 14)} Refresh</button></div></div>
    <div id="p-skel">${skeletonPage(5)}</div><div id="p-kpis" class="sx-kpis mx-kpis" hidden></div><div id="p-ad"></div><div id="p-tabs" hidden></div><div id="p-toolbar" hidden></div><div id="p-main"></div></div>`;
  const setLive = (m) => { const el = $("#p-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");

  async function load() {
    const [queue, { approvals }, ad, metrics] = await Promise.all([api.queue(), api.remediationApprovalsList(), api.directoryStatus().catch(() => ({ configured: false })), api.remediationMetrics().catch(() => null)]);
    if (!alive) return;
    S.queue = queue.findings; S.findings = new Map(queue.findings.map((f) => [f.id, f]));
    S.approvals = approvals.map((a) => { const f = S.findings.get(a.finding_id); return { ...a, finding: f || null, group: f ? groupLabelFor(f) : "Unknown" }; });
    S.ad = ad; S.metrics = metrics; S.loadedAt = Date.now();
  }
  const inTab = (tab) => (tab === "request" ? [] : S.approvals.filter((a) => approvalBucket(a) === tab));
  const needs = () => needsApproval(S.queue, S.approvals).map((f) => ({ ...f, group: groupLabelFor(f) }));
  const matches = (list, getters) => filterRecords(list.filter((x) => S.domain === "all" || x.group === S.domain), S.q, getters);
  const approvalGetters = [(a) => a.id, (a) => a.finding_id, (a) => a.requested_by, (a) => a.finding && a.finding.title, (a) => a.finding && a.finding.asset && a.finding.asset.name];
  const findingGetters = [(f) => f.id, (f) => f.title, (f) => f.asset && f.asset.name, (f) => f.cve];
  const url = () => { const p = new URLSearchParams(); if (S.tab !== "pending") p.set("tab", S.tab); if (S.q) p.set("q", S.q); if (S.domain !== "all") p.set("domain", S.domain); replaceSearch(p.toString() ? `?${p}` : ""); };

  // ------------------------------------------------------------------ painting
  function paintKpis() {
    const k = approvalKpis(S.approvals, S.metrics);
    const cell = (key, t, label) => `<div class="sx-kpi-cell" data-kpi="${key}" role="button" tabindex="0" aria-pressed="${S.tab === key}" aria-label="${escapeHtml(label)}">${t}</div>`;
    const el = $("#p-kpis"); el.hidden = false; $("#p-skel").hidden = true;
    el.innerHTML = [
      cell("pending", kpiTile({ label: "Awaiting a decision", value: k.pending, tone: k.pending ? "warn" : "good", hint: "Requests with no decision yet, whose window has not passed." }), "Show requests awaiting a decision"),
      cell("approved", kpiTile({ label: "Approved", value: k.approved + k.triggered, hint: "Approved, including those where remediation was already triggered." }), "Show approved requests"),
      `<div class="sx-kpi-cell">${kpiTile({ label: "Lint failed", value: k.lintFailed, tone: k.lintFailed ? "danger" : "good", hint: "Pending requests whose generated playbook failed the safety lint. They cannot be approved until it is regenerated." })}</div>`,
      `<div class="sx-kpi-cell">${kpiTile({ label: "Still present after fix", value: k.stillPresent, tone: k.stillPresent ? "danger" : "good", hint: "Triggered remediations the next scan still reports. Evidence, not proof." })}</div>`,
      `<div class="sx-kpi-cell">${kpiTile({ label: "Days to approval", value: k.avgDaysToApproval === null || k.avgDaysToApproval === undefined ? "n/a" : k.avgDaysToApproval, decimals: 1, hint: "Average days from request to approval. Shown only once something has been approved." })}</div>`,
      `<div class="sx-kpi-cell">${kpiTile({ label: "Fix hold rate", value: k.fixHoldRate === null || k.fixHoldRate === undefined ? "n/a" : Math.round(k.fixHoldRate * 100), suffix: k.fixHoldRate === null || k.fixHoldRate === undefined ? "" : "%", hint: "Of triggered fixes assessed after a rescan, the share that stayed fixed." })}</div>`,
    ].join("");
    mountCounters(el);
    $("#p-ad").innerHTML = `<div class="mx-callout${S.ad.configured ? "" : " mx-callout-warn"}">${S.ad.configured ? "Active Directory is configured: approving a finding whose policy names an approval group runs a real, read-only group-membership check." : "Active Directory is not configured on this server. Approvals still work, but group membership is reported as \"AD not configured\" rather than skipped or shown as verified."}</div>`;
  }
  function paintTabs() {
    const el = $("#p-tabs"); el.hidden = false;
    el.innerHTML = tabBar("Approval views", [{ id: "pending", label: "Awaiting a decision", count: inTab("pending").length }, { id: "approved", label: "Approved and in flight", count: inTab("approved").length }, { id: "closed", label: "Rejected or lapsed", count: inTab("closed").length }, { id: "request", label: "Needs a request", count: needs().length }], S.tab);
  }
  function paintToolbar() {
    const el = $("#p-toolbar"); el.hidden = false;
    const active = document.activeElement; const restore = active && el.contains(active) && active.id ? `#${active.id}` : ""; const caret = active && active.id === "p-q" ? active.selectionStart : null;
    const groups = [...new Set([...S.approvals.map((a) => a.group), ...needs().map((f) => f.group)])].sort();
    el.innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter approvals"><input type="search" class="sx-field" id="p-q" placeholder="Search id, finding, asset, requester" value="${escapeHtml(S.q)}" aria-label="Search approvals">
      <select class="sx-field" id="p-domain" aria-label="Security domain"><option value="all">All domains</option>${groups.map((g) => `<option value="${escapeHtml(g)}" ${g === S.domain ? "selected" : ""}>${escapeHtml(g)}</option>`).join("")}</select></div>`;
    if (restore) { const n = el.querySelector(restore); if (n) { n.focus(); if (caret !== null && n.setSelectionRange) n.setSelectionRange(caret, caret); } }
  }
  function timelineHtml(a, compact) {
    const steps = approvalTimeline(a);
    return `<ol class="mx-tl${compact ? " mx-tl-compact" : ""}" aria-label="Approval timeline">${steps.map((s) => `<li class="mx-tl-${s.state}"><span class="mx-tl-dot" aria-hidden="true"></span><span class="mx-tl-body"><strong>${escapeHtml(s.label)}</strong>${s.state === "pending" || s.state === "skipped" ? `<span class="ui-muted"> ${s.optional ? "(optional)" : s.state === "skipped" ? "(window passed)" : ""}</span>` : ""}${!compact && s.who ? `<span class="ui-muted"> ${escapeHtml(s.who)}${s.when ? `, ${escapeHtml(s.when)}` : ""}</span>` : ""}${!compact && s.note ? `<div class="mx-sub">${escapeHtml(s.note)}</div>` : ""}</span></li>`).join("")}</ol>`;
  }
  function lintChip(a) {
    const l = a.playbook_lint;
    if (!l) return chip("No playbook yet", { tone: "neutral", title: "No playbook has been generated for this finding yet" });
    return l.passed ? chip(`Lint passed${l.warnings ? `, ${l.warnings} warning${l.warnings > 1 ? "s" : ""}` : ""}`, { tone: l.warnings ? "warn" : "good", title: "Passed the deterministic safety lint" }) : chip(`Lint failed, ${l.errors} error${l.errors > 1 ? "s" : ""}`, { tone: "critical", title: "Cannot be approved until the playbook is regenerated" });
  }
  function approvalCard(a) {
    const f = a.finding; const status = a.computed_status; const wd = windowDays(a.scheduled_window);
    const ap = canApprove(a, me); const rj = canReject(a, me);
    const when = status === "pending" && wd !== null ? (wd < 0 ? `window passed ${-wd}d ago` : wd === 0 ? "window is today" : `window in ${wd}d`) : "";
    return `<article class="mx-card${S.pending.has(a.id) ? " pending" : ""}${S.flash.has(a.id) ? " flash" : ""}" data-apr="${escapeHtml(a.id)}" tabindex="0" aria-label="${escapeHtml(a.id)}, ${escapeHtml(f ? f.title : a.finding_id)}, ${escapeHtml(STATUS_TEXT[status] || status)}">
      <div class="mx-card-head"><span class="sx-row">${chip(STATUS_TEXT[status] || status, { tone: STATUS_TONE[status] || "neutral" })}<span class="sx-card-id">${escapeHtml(a.id)}</span></span>${f ? severityChip(f.priority) : ""}</div>
      <h4>${f ? `<button type="button" class="sx-link-btn mx-cardlink" data-open-finding="${escapeHtml(a.finding_id)}">${escapeHtml(f.title)}</button>` : escapeHtml(a.finding_id)}</h4>
      <div class="mx-sub">${escapeHtml(a.finding_id)} &middot; ${escapeHtml((f && f.asset && f.asset.name) || "asset not in the live queue")} &middot; ${escapeHtml(a.group)}</div>
      <div class="sx-row">${lintChip(a)}${f && f.remediation_policy && f.remediation_policy.change_type ? chip(`${f.remediation_policy.change_type} change`, { tone: f.remediation_policy.change_type === "emergency" ? "critical" : f.remediation_policy.change_type === "normal" ? "warn" : "good" }) : ""}${a.staging_validated_by ? chip("Staging validated", { tone: "good", title: `${a.staging_validated_by}, ${a.staging_validated_at}` }) : ""}</div>
      <div class="mx-sub">Window: ${escapeHtml(windowText(a.scheduled_window))}${when ? ` <b>${escapeHtml(when)}</b>` : ""}</div>
      <div class="mx-sub"><span class="sx-who">${avatar(a.requested_by, { size: 18 })}<span class="t">Requested by ${escapeHtml(a.requested_by)}</span></span></div>
      ${timelineHtml(a, true)}
      <div class="mx-actions"><button type="button" class="ui-btn sx-btn-sm" data-review="${escapeHtml(a.id)}">Review evidence</button>
        ${status === "pending" ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-quick-approve="${escapeHtml(a.id)}" ${ap.ok ? "" : `disabled aria-disabled="true" ${tipAttr(ap.reason)}`}>Approve</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-quick-reject="${escapeHtml(a.id)}" ${rj.ok ? "" : `disabled ${tipAttr(rj.reason)}`}>Reject</button>` : ""}
        ${status === "approved" && isAdmin ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-trigger="${escapeHtml(a.id)}">Trigger remediation</button>` : ""}
        ${status === "pending" && isAdmin && !a.staging_validated_by ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-staging="${escapeHtml(a.id)}" ${tipAttr("Records that this change was tested in staging before production approval (ISO/IEC 27002:2022 8.32). Metadata only: who and when.")}>Mark staging validated</button>` : ""}
        <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-comm="${escapeHtml(a.id)}">Communication</button></div>
      ${status === "pending" && !ap.ok && isAdmin ? `<div class="mx-why-not">${escapeHtml(ap.reason)}</div>` : ""}</article>`;
  }
  function paintMain() {
    const host = $("#p-main");
    if (S.tab === "request") { paintRequest(host); return; }
    S.table = null;
    const list = matches(inTab(S.tab), approvalGetters).sort((a, b) => String(b.created_on).localeCompare(String(a.created_on)) || b.id.localeCompare(a.id, undefined, { numeric: true }));
    if (!list.length) {
      const e = !S.approvals.length ? { title: "No approval requests yet", body: "A request starts from a finding whose policy needs a person to approve the change. Open Needs a request to see which findings qualify.", actionLabel: "See findings that need a request", actionHref: "/remediation-approvals?tab=request", iconName: "approved" }
        : S.q || S.domain !== "all" ? { title: "Nothing matches this filter", body: "Clear the search or the domain filter.", iconName: "search" }
        : { title: S.tab === "pending" ? "Nothing is waiting for a decision" : "Nothing here", body: S.tab === "pending" ? "New requests appear here as they are made." : "", iconName: "approved" };
      host.innerHTML = `<div class="sx-panel">${emptyState(e)}</div>`; return;
    }
    host.innerHTML = `<div class="mx-grid-cards" role="list">${list.map((a) => approvalCard(a)).join("")}</div>`;
    setTimeout(() => { S.flash.clear(); container.querySelectorAll(".mx-card.flash").forEach((n) => n.classList.remove("flash")); }, 2400);
  }
  function paintRequest(host) {
    const list = matches(needs(), findingGetters);
    if (!list.length) { host.innerHTML = `<div class="sx-panel">${emptyState({ title: "Nothing needs a new request", body: "Every finding whose policy needs an approval already has one. Standard, auto-remediate findings need none. See the full queue for everything else.", actionLabel: "Open the queue", actionHref: "/queue", iconName: "approved" })}</div>`; return; }
    host.innerHTML = ""; S.table = selectableTable(host, { rows: list, rowKey: (f) => f.id, caption: "Findings that need an approval request", csvName: "quanta-needs-approval", storageKey: "approvals-need", rowHeight: 54, maxHeight: 560, onOpen: (f) => openFindingById(f.id),
      columns: [
        { key: "p", label: "Priority", width: 100, csv: (f) => f.priority, render: (f) => severityChip(f.priority) },
        { key: "id", label: "Finding", width: 340, csv: (f) => `${f.id} ${f.title}`, render: (f) => `<button type="button" class="sx-link-btn mx-id" data-open-finding="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button><div class="mx-sub" title="${escapeHtml(f.title)}">${escapeHtml(f.title)}</div>` },
        { key: "asset", label: "Asset", width: 150, csv: (f) => f.asset && f.asset.name, render: (f) => `<span class="mx-clip">${escapeHtml((f.asset && f.asset.name) || "")}</span><div class="mx-sub">${escapeHtml(f.group)}</div>` },
        { key: "ct", label: "Change type", width: 110, csv: (f) => (f.remediation_policy || {}).change_type, render: (f) => { const c = (f.remediation_policy || {}).change_type; return chip(c || "", { tone: c === "emergency" ? "critical" : "warn" }); } },
        { key: "win", label: "Next window", width: 220, csv: (f) => windowText((f.remediation_policy || {}).next_window), render: (f) => escapeHtml(windowText((f.remediation_policy || {}).next_window)) },
        { key: "grp", label: "Approval group", width: 150, csv: (f) => (f.remediation_policy || {}).requires_approval_group || "", render: (f) => escapeHtml((f.remediation_policy || {}).requires_approval_group || "") || '<span class="ui-muted">none</span>' },
        { key: "act", label: "", width: 130, csv: () => "", render: (f) => `<button type="button" class="ui-btn sx-btn-sm" data-request="${escapeHtml(f.id)}">Request approval</button>` },
      ] });
  }
  function paintAll() { if (!alive) return; paintKpis(); paintTabs(); paintToolbar(); paintMain(); const age = $("#p-age"); if (age) { age.innerHTML = dataAgeBadge(S.loadedAt); mountDataAge(age); } }

  // ------------------------------------------------------------------ actions
  const reload = async (quiet = true) => { try { await load(); paintAll(); } catch (e) { if (!quiet) toast(`Could not refresh: ${e.message}`, { tone: "bad" }); } };
  async function decide(a, kind, reason) {
    const snap = JSON.parse(JSON.stringify(a)); const i = S.approvals.findIndex((x) => x.id === a.id);
    S.approvals[i] = { ...a, computed_status: kind === "approve" ? "approved" : "rejected", status: kind === "approve" ? "approved" : "rejected", ...(kind === "approve" ? { approved_by: me.email } : { rejected_by: me.email, rejection_reason: reason }) };
    S.pending.add(a.id); paintAll();
    try {
      const r = kind === "approve" ? await api.remediationApprovalApprove(a.id) : await api.remediationApprovalReject(a.id, reason);
      toast(r.message || (kind === "approve" ? "Approved." : "Rejected."), { tone: /WARNING/.test(r.message || "") ? "warn" : "good", ms: 6000 }); S.flash.add(a.id);
      await load();
    } catch (e) { S.approvals[i] = snap; toast(`Not ${kind === "approve" ? "approved" : "rejected"}: ${e.message}`, { tone: "bad", ms: 10000 }); }
    finally { S.pending.delete(a.id); paintAll(); }
  }
  async function askReject(a) {
    const out = await modal({ title: `Reject ${a.id}`, confirmLabel: "Reject", danger: true, description: "The requester sees the reason. It is recorded with your name.", body: `<label>Reason (required)<textarea id="m-reason" maxlength="1000" placeholder="What is wrong, and what would make it acceptable"></textarea></label>`,
      validate: (d) => validateReason(d.querySelector("#m-reason").value), collect: (d) => d.querySelector("#m-reason").value.trim() });
    if (out) await decide(a, "reject", out);
  }
  async function askApprove(a) {
    const ap = canApprove(a, me); if (!ap.ok) { toast(ap.reason, { tone: "warn", ms: 7000 }); return; }
    const need = (a.finding && a.finding.remediation_policy && a.finding.remediation_policy.requires_approval_group) || "";
    const ok = await modal({ title: `Approve ${a.id}`, confirmLabel: "Approve", description: `Records that you authorised this change${need ? ` as a member of ${need}` : ""}. Nothing is run against real infrastructure.`,
      body: `<p class="ui-muted">${a.rollback_plan ? "Rollback plan: " + escapeHtml(a.rollback_plan.split("\n")[0].slice(0, 160)) : "No playbook, and so no rollback plan, has been generated for this finding yet."}</p>
        <label class="mx-check"><input type="checkbox" id="m-reviewed"> I reviewed the playbook, its rollback plan and the lint result</label>`,
      validate: (d) => (d.querySelector("#m-reviewed").checked ? "" : "Confirm that you reviewed the evidence first. Review evidence shows the playbook and its lint result."), collect: () => true });
    if (ok) await decide(a, "approve");
  }
  async function review(id) {
    const a = S.approvals.find((x) => x.id === id); if (!a) return;
    const d = openDrawer({ title: `${a.id}: ${a.finding ? a.finding.title : a.finding_id}`, width: 640, html: `<div class="mx-drawer"><div class="mx-drawer-meta">${chip(STATUS_TEXT[a.computed_status] || a.computed_status, { tone: STATUS_TONE[a.computed_status] || "neutral" })} ${lintChip(a)}</div>
      <h3 class="mx-h3">Timeline</h3>${timelineHtml(a, false)}<div id="e-body"><p class="ui-muted">Loading the evidence pack...</p></div><div class="mx-drawer-actions" id="e-actions"></div></div>` });
    const body = d.body;
    const actions = body.querySelector("#e-actions");
    const ap = canApprove(a, me); const rj = canReject(a, me);
    if (a.computed_status === "pending") {
      actions.innerHTML = `<button type="button" class="ui-btn sx-btn-sm" data-d-approve ${ap.ok ? "" : "disabled"}>Approve...</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-d-reject ${rj.ok ? "" : "disabled"}>Reject...</button>${!ap.ok ? `<p class="mx-why-not">${escapeHtml(ap.reason)}</p>` : ""}`;
      actions.addEventListener("click", (e) => { if (e.target.closest("[data-d-approve]")) { d.close(); askApprove(a); } else if (e.target.closest("[data-d-reject]")) { d.close(); askReject(a); } });
    }
    try {
      const ev = await api.remediationApprovalEvidence(a.id);
      if (!body.isConnected) return;
      const lint = ev.playbook && ev.playbook.lint; const v = ev.verification;
      const issue = (x, tone) => `<li>${chip(x.rule || "", { tone })} ${escapeHtml(x.message || "")}</li>`;
      body.querySelector("#e-body").innerHTML = `
        <h3 class="mx-h3">Finding</h3><dl class="mx-facts">${[["Finding", ev.finding && `${ev.finding.id}: ${ev.finding.title}`], ["CVE", ev.finding && ev.finding.cve], ["Severity", ev.finding && ev.finding.severity], ["Asset", ev.finding && ev.finding.asset && ev.finding.asset.name], ["First seen", ev.finding && ev.finding.first_seen], ["Last seen", ev.finding && ev.finding.last_seen]].filter(([, x]) => x).map(([k, x]) => `<div class="mx-fact"><dt>${k}</dt><dd>${escapeHtml(x)}</dd></div>`).join("")}</dl>
        <h3 class="mx-h3">Safety lint</h3>${lint ? `<p>${lint.passed ? chip("Passed", { tone: "good" }) : chip("Failed", { tone: "critical" })} ${lint.errors.length} error${lint.errors.length === 1 ? "" : "s"}, ${lint.warnings.length} warning${lint.warnings.length === 1 ? "" : "s"}</p>${lint.errors.length || lint.warnings.length ? `<ul class="mx-list">${lint.errors.map((x) => issue(x, "critical")).join("")}${lint.warnings.map((x) => issue(x, "warn")).join("")}</ul>` : '<p class="ui-muted">No issues found.</p>'}` : '<p class="ui-muted">No playbook has been generated for this finding yet, so there is nothing to lint.</p>'}
        <h3 class="mx-h3">Rollback plan</h3>${a.rollback_plan ? `<pre class="mx-code">${escapeHtml(a.rollback_plan)}</pre>` : '<p class="ui-muted">No rollback plan is available until a playbook exists.</p>'}
        <h3 class="mx-h3">Outcome</h3><p>${v && v.state !== "not-triggered" ? `${chip(v.state, { tone: v.state === "verified" ? "good" : v.state === "still-present" ? "critical" : "neutral" })} ${escapeHtml(v.detail || "")}` : '<span class="ui-muted">Not triggered yet, so there is nothing to verify.</span>'}</p>
        ${ev.playbook ? `<details class="mx-details"><summary>Playbook (${ev.playbook.content.split("\n").length} lines)</summary><div class="sx-row"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-copy-pb>Copy playbook</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-copy-ev>Copy evidence pack (JSON)</button></div><pre class="mx-code">${escapeHtml(ev.playbook.content)}</pre></details>` : ""}`;
      body.addEventListener("click", (e) => { if (e.target.closest("[data-copy-pb]")) copyText(ev.playbook.content, "Playbook copied"); else if (e.target.closest("[data-copy-ev]")) copyText(JSON.stringify(ev, null, 2), "Evidence pack copied"); });
    } catch (e) { const el = body.querySelector("#e-body"); if (el) el.innerHTML = `<p class="ui-muted">The evidence pack could not be loaded (${escapeHtml(e.message)}). ${isAdmin ? "" : "It is available to administrators."}</p>`; }
  }
  async function requestApproval(fid) {
    const ok = await modal({ title: `Request approval for ${fid}`, confirmLabel: "Request", description: "The request is recorded under your account and scheduled against the finding's next maintenance window.", body: "" });
    if (!ok) return;
    try { await api.remediationApprovalCreate(fid); toast(`Approval requested for ${fid}.`, { tone: "good" }); S.tab = "pending"; url(); await load(); paintAll(); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function trigger(a) {
    const out = await modal({ title: `Trigger remediation for ${a.finding_id}`, confirmLabel: "Preview or generate", description: "Generates this finding's playbook on demand through the same remediation pipeline as Run pipeline: a reviewable artifact, never applied to real infrastructure. Leave the box unticked for a free dry-run preview; ticking it calls the Claude API and spends real usage.",
      body: `<label class="mx-check"><input type="checkbox" id="m-confirm"> I understand this spends real API usage: generate it for real</label>`, collect: (d) => d.querySelector("#m-confirm").checked });
    if (out === null) return;
    try { const r = await api.runPost({ pipeline: "remediate", fix_or_generate: true, finding_id: a.finding_id, confirm: out }); toast(r.message, { tone: r.dry_run || r.exit_code === 0 ? "good" : "bad", ms: 9000 }); if (!r.dry_run) await reload(); } catch (e) { toast(e.message, { tone: "bad", ms: 9000 }); }
  }
  async function markStaging(a) {
    try { const r = await api.remediationApprovalMarkStagingValidated(a.id); toast(r.message, { tone: "good" }); await reload(); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function communication(a) {
    const f = a.finding; const text = ((f && f.remediation_policy) || {}).rendered_communication || "No communication template is configured for this finding's policy domain.";
    const out = await modal({ title: `Downtime communication for ${a.id}`, confirmLabel: "Send", description: "Rendered from the resolved remediation policy template. Sending uses the SMTP settings from Notification settings; without SMTP it fails honestly rather than pretending to deliver.",
      body: `<pre class="mx-code" style="white-space:pre-wrap">${escapeHtml(text)}</pre><label>Send to (email)<input type="email" id="m-to" placeholder="stakeholder@example.com"></label>`, validate: (d) => (/.+@.+\..+/.test(d.querySelector("#m-to").value) ? "" : "Enter an email address."), collect: (d) => d.querySelector("#m-to").value.trim() });
    if (!out) return;
    try { const r = await api.remediationApprovalSendCommunication(a.id, out, true); toast(r.message, { tone: "good" }); } catch (e) { toast(e.message, { tone: "bad", ms: 9000 }); }
  }

  // ------------------------------------------------------------------ events
  const setTab = (t) => { S.tab = t; url(); paintTabs(); paintMain(); paintKpis(); };
  wireTabBar($("#p-tabs"), (id) => setTab(id));
  const typeSearch = debounce((v) => { S.q = v; url(); paintMain(); }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "p-q") typeSearch(e.target.value); });
  container.addEventListener("change", (e) => { if (e.target.id === "p-domain") { S.domain = e.target.value; url(); paintMain(); } });
  container.addEventListener("click", (e) => {
    const t = e.target; const find = (id) => S.approvals.find((x) => x.id === id);
    const kpi = t.closest("[data-kpi]"); if (kpi) { setTab(kpi.dataset.kpi); return; }
    const of = t.closest("[data-open-finding]"); if (of) { openFindingById(of.dataset.openFinding); return; }
    const rv = t.closest("[data-review]"); if (rv) { review(rv.dataset.review); return; }
    const qa = t.closest("[data-quick-approve]"); if (qa) { const a = find(qa.dataset.quickApprove); if (a) askApprove(a); return; }
    const qr = t.closest("[data-quick-reject]"); if (qr) { const a = find(qr.dataset.quickReject); if (a) askReject(a); return; }
    const rq = t.closest("[data-request]"); if (rq) { requestApproval(rq.dataset.request); return; }
    const tg = t.closest("[data-trigger]"); if (tg) { const a = find(tg.dataset.trigger); if (a) trigger(a); return; }
    const sg = t.closest("[data-staging]"); if (sg) { const a = find(sg.dataset.staging); if (a) markStaging(a); return; }
    const cm = t.closest("[data-comm]"); if (cm) { const a = find(cm.dataset.comm); if (a) communication(a); return; }
    if (t.closest("#p-refresh")) { reload(false).then(() => toast("Refreshed.", { tone: "good", ms: 1600 })); }
  });
  container.addEventListener("keydown", (e) => { const k = e.target.closest && e.target.closest("[data-kpi]"); if (k && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); k.click(); } });

  try { await load(); } catch (e) { $("#p-skel").hidden = true; $("#p-main").innerHTML = `<div class="sx-panel">${emptyState({ title: "Approvals could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" })}</div>`; return; }
  if (qs.get("tab") === null && !inTab("pending").length && needs().length && !S.approvals.length) S.tab = "request";
  paintAll();
  pageActions([
    { label: "Approvals: show requests awaiting a decision", icon: "approved", run: () => setTab("pending") }, { label: "Approvals: show findings that need a request", icon: "approved", run: () => setTab("request") },
    { label: "Approvals: show approved and in flight", icon: "approved", run: () => setTab("approved") }, { label: "Approvals: search", icon: "search", run: () => { const i = $("#p-q"); if (i) i.focus(); } },
  ]);
  autoRefresh(() => reload(true), { every: REFRESH_MS, onMode: setLive });
}
