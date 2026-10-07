// Integrity tab of the Activity Log page (admin only): the code baseline, store consistency checks and the safe repairs.
// Read-only until an administrator previews a repair and then confirms it. See docs/INTEGRITY.md.
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { kpiTile, chip, toast, emptyState, mountCounters, onCleanup } from "./ui.js";
import { modal } from "./sxKit.js";
import { segmented, onSeg, copyButton, wireCopy } from "./mxKit.js";
import { copyText } from "./sxKit.js";

const LEVEL = { ok: "badge-low", info: "badge-outline", warn: "badge-high", fail: "badge-critical" };

function fileList(label, items, note = "") {
  if (!items.length) return "";
  return `<p><strong>${escapeHtml(label)}</strong> (${items.length})${note ? ` <span class="muted">${escapeHtml(note)}</span>` : ""}</p>
    <ul style="margin:0 0 8px; padding-left:18px">${items.slice(0, 30).map((f) => `<li><code>${escapeHtml(f)}</code></li>`).join("")}${items.length > 30 ? `<li>... and ${items.length - 30} more</li>` : ""}</ul>`;
}

function manifestHtml(m) {
  const head = {
    "no-baseline": `<div class="callout"><strong>No baseline.</strong> ${escapeHtml(m.message)} Nothing can be said about whether the code is the released code.</div>`,
    ok: `<div class="callout"><strong>Matches the baseline.</strong> ${m.files_checked} tracked files checked against the manifest built ${escapeHtml((m.baseline || {}).generated_at || "")}.</div>`,
    "policy-changed": `<div class="callout"><strong>Policy files changed (expected).</strong> ${escapeHtml(m.message)}</div>`,
    "code-modified": `<div class="callout" style="border-color:#b91c1c"><strong>Application code differs from the baseline.</strong> ${escapeHtml(m.message)}</div>`,
  }[m.state] || "";
  const ed = m.policy.editors || {};
  const policyRows = [...m.policy.modified, ...m.policy.missing, ...m.policy.unexpected];
  return `${head}
    ${fileList("Code files modified", m.code.modified, "must not change")}
    ${fileList("Code files missing", m.code.missing)}
    ${fileList("Code files not in the baseline", m.code.unexpected)}
    ${policyRows.length ? `<p><strong>Policy files changed</strong> (${policyRows.length}) <span class="muted">expected to change; who is shown only where the activity log recorded it</span></p>
      <ul style="margin:0 0 8px; padding-left:18px">${policyRows.slice(0, 30).map((f) => `<li><code>${escapeHtml(f)}</code>${ed[f] ? ` - ${escapeHtml(ed[f].actor)} (${escapeHtml(ed[f].action)}, ${escapeHtml(ed[f].at)})` : ""}</li>`).join("")}</ul>` : ""}`;
}

const TONE = { ok: "good", info: "neutral", warn: "warn", fail: "critical" };

export async function renderIntegrity(container) {
  let alive = true;
  onCleanup(() => { alive = false; });
  container.innerHTML = `<div class="ui-skel ui-skel-table" aria-hidden="true">${'<i class="ui-skel-line"></i>'.repeat(5)}</div><p class="ui-muted" role="status">Checking...</p>`;
  let report;
  try {
    report = await api.integrity();
  } catch (e) {
    if (alive) container.innerHTML = emptyState({ title: "The integrity report is for administrators", body: e.message || "Sign in as an administrator.", iconName: "risk" });
    return;
  }
  if (!alive) return;
  const c = report.counts;
  let level = "all";
  const tile = (label, value, extra = {}) => `<div class="sx-kpi-cell">${kpiTile({ label, value, ...extra })}</div>`;
  const checksHtml = () => {
    const list = report.checks.filter((k) => level === "all" || k.level === level);
    return list.length ? `<div class="mx-grid-cards">${list.map((k) => `<article class="mx-card mx-chk mx-chk-${k.level}"><div class="mx-card-head"><h4>${escapeHtml(k.title)}</h4>${chip(k.level, { tone: TONE[k.level] || "neutral" })}</div>
        <div class="mx-sub">${escapeHtml(k.detail)}</div>${k.manual && (k.level === "warn" || k.level === "fail") ? `<div class="mx-why-not">Manual step: ${escapeHtml(k.manual)}</div>` : ""}${k.fix ? `<div class="mx-actions"><code class="mx-code">${escapeHtml(k.fix)}</code>${copyButton(k.fix, "Copy command")}</div>` : ""}</article>`).join("")}</div>` : emptyState({ title: "No check at this level", body: "Choose another level.", iconName: "approved" });
  };
  container.innerHTML = `<p class="ui-muted">Whether the running code matches the release, whether the stores are consistent, and the few repairs that are safe to make automatically. Nothing here changes anything until you preview a repair and confirm it; every repair is written to the activity log and no customer data is ever deleted.</p>
    <div class="sx-kpis mx-kpis">${tile("Overall", report.status, { tone: report.status === "ok" ? "good" : report.status === "fail" ? "danger" : "warn", hint: `Checked ${report.checked_at}` })}${tile("Failing", c.fail, { tone: c.fail ? "danger" : "good" })}${tile("Warnings", c.warn, { tone: c.warn ? "warn" : "good" })}${tile("Code baseline", report.code_state, { tone: report.code_state === "ok" ? "good" : report.code_state === "code-modified" ? "danger" : "" })}</div>
    <h3 class="mx-h3">Code baseline</h3>${manifestHtml(report.manifest)}
    <h3 class="mx-h3">Store and host checks</h3>
    <div class="sx-toolbar">${segmented("Level", [{ id: "all", label: "All", count: report.checks.length }, ...["fail", "warn", "info", "ok"].filter((l) => report.checks.some((k) => k.level === l)).map((l) => ({ id: l, label: l, count: report.checks.filter((k) => k.level === l).length }))], level)}</div><div id="chk">${checksHtml()}</div>
    <h3 class="mx-h3">Safe repairs</h3>
    <p class="ui-muted">${escapeHtml(Object.values(report.heal_actions).map((a) => a.title).join("; "))}.</p>
    <p class="sx-row"><button type="button" class="ui-btn sx-btn-sm" id="heal-preview">Preview repairs</button><button type="button" id="heal-confirm" class="ui-btn ui-btn-ghost sx-btn-sm" disabled>Apply previewed repairs</button><button type="button" id="integrity-refresh" class="ui-btn ui-btn-ghost sx-btn-sm">Re-check</button></p>
    <div id="heal-result" role="status"></div>`;
  mountCounters(container);
  wireCopy(container, copyText);
  onSeg(container, (id) => { level = id; container.querySelector("#chk").innerHTML = checksHtml(); container.querySelectorAll(".sx-seg [data-seg]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.seg === id))); });
  const out = container.querySelector("#heal-result");
  const applyBtn = container.querySelector("#heal-confirm");
  const show = (r) => {
    out.innerHTML = `<p><strong>${r.preview ? "Preview (nothing changed)" : "Applied"}</strong></p>
      <ul class="mx-list">${r.results.map((x) => `<li><strong>${escapeHtml(x.title)}</strong>: ${escapeHtml(x.status)}${x.planned.length ? `<br><code class="mx-code">${escapeHtml(JSON.stringify(x.planned).slice(0, 400))}</code>` : ""}</li>`).join("")}</ul>
      ${r.manual.length ? `<p><strong>Needs a person</strong></p><ul class="mx-list">${r.manual.map((m) => `<li>${escapeHtml(m.title)}: ${escapeHtml(m.manual)}</li>`).join("")}</ul>` : ""}`;
  };
  container.querySelector("#heal-preview").addEventListener("click", async () => {
    try { const r = await api.integrityHeal(false); show(r); applyBtn.disabled = !r.results.some((x) => x.planned.length); }
    catch (e) { toast(e.message || "Preview failed", { tone: "bad" }); }
  });
  applyBtn.addEventListener("click", async () => {
    const ok = await modal({ title: "Apply the previewed repairs?", confirmLabel: "Apply", description: "Each repair is recorded in the activity log. No customer data is deleted.", body: "" });
    if (!ok) return;
    try { show(await api.integrityHeal(true)); toast("Repairs applied.", { tone: "good" }); applyBtn.disabled = true; }
    catch (e) { toast(e.message || "Repair failed", { tone: "bad" }); }
  });
  container.querySelector("#integrity-refresh").addEventListener("click", () => renderIntegrity(container));
}
