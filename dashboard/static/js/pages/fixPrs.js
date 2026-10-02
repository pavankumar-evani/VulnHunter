// Fix pull requests: dependency upgrades and code fixes as reviewable pull requests on the customer's Git host, tracked from proposal to merge to verification.
// Quanta writes to a repository in exactly one place - "Open the pull request" - after a dry run and an explicit confirmation. It never merges.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Fix Pull Requests";

const STATUS = { draft: "badge-outline", approved: "badge-medium", "pr-opened": "badge-high", "in-review": "badge-high", merged: "badge-low", closed: "badge-outline", failed: "badge-critical", discarded: "badge-outline" };
const FLOW = [["created_at", "Proposed"], ["approved_at", "Approved"], ["opened_at", "Pull request opened"], ["merged_at", "Merged"], ["verified_at", "Verified by a scan"]];
const VERIFY = { verified: ["badge-low", "Verified: no longer reported"], "still-present": ["badge-critical", "Merged, but still reported"], "awaiting-rescan": ["badge-medium", "Waiting for a rescan"], "not-merged": ["badge-outline", "Not merged yet"] };

function diffHtml(d) {
  return `<pre class="diff-view">${String(d || "").split("\n").map((ln) => {
    const cls = ln.startsWith("+") && !ln.startsWith("+++") ? "diff-add" : ln.startsWith("-") && !ln.startsWith("---") ? "diff-del" : ln.startsWith("@@") ? "diff-hunk" : "";
    return `<span class="${cls}">${escapeHtml(ln)}</span>`;
  }).join("\n")}</pre>`;
}
const hours = (v) => (v == null ? "no data" : v < 48 ? `${v} h` : `${(v / 24).toFixed(1)} days`);

export async function render(container) {
  let admin = false;
  try { admin = ((await api.authMe()).user || {}).role === "admin"; } catch { admin = false; }
  let id = new URLSearchParams(window.location.search).get("id");
  const go = (n) => { const u = new URL(window.location.href); n ? u.searchParams.set("id", n) : u.searchParams.delete("id"); window.history.pushState({}, "", u); id = n; show(); };

  async function list() {
    const [pol, d, vel] = await Promise.all([api.gitopsPolicy(), api.gitopsProposals(), api.gitopsVelocity()]);
    const o = vel.outcomes, st = vel.stages, op = vel.open_pull_requests;
    container.innerHTML = `<p class="subtitle">Dependency upgrades and code fixes as pull requests on your Git host, with the finding, the CVE, the fixed version, the risk context and how to verify in the description. Quanta prepares the change, an administrator approves it, a dry run shows exactly what would be sent, and only then does it create a branch of its own and open the pull request. People review, test and merge it the way they do any change.</p>
      <div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">proposals</div><div class="kpi-value">${vel.proposals}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">open pull requests</div><div class="kpi-value">${op.count}</div><div class="muted">${op.waiting_for_review} waiting for review, ${op.failing_checks} failing checks</div></div>
        <div class="kpi-card kpi-good"><div class="kpi-label">merged &rarr; verified</div><div class="kpi-value">${o.verified}<span class="muted"> of ${o.merged}</span></div></div>
        <div class="kpi-card ${o.still_present ? "kpi-danger" : ""}"><div class="kpi-label">merged, still reported</div><div class="kpi-value">${o.still_present}</div></div></div>
      <h3>How long it takes</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Stage</th><th>Median</th><th>Slowest 10%</th><th>Pull requests measured</th></tr></thead><tbody>
      ${[["detected_to_pull_request", "First seen &rarr; pull request opened"], ["created_to_approved", "Proposed &rarr; approved"], ["opened_to_merged", "Opened &rarr; merged"], ["merged_to_verified", "Merged &rarr; confirmed by a scan"], ["created_to_verified", "Proposed &rarr; verified, end to end"]]
        .map(([k, l]) => `<tr><td>${l}</td><td>${hours(st[k].median_hours)}</td><td>${hours(st[k].p90_hours)}</td><td>${st[k].n}</td></tr>`).join("")}</tbody></table></div>
      <p class="muted">${escapeHtml(vel.note)} Merged per week (last 12): ${vel.merged_per_week.map((w) => w.merged).join(" ")}</p>
      <h3>The process</h3><ol class="step-list">${pol.policy.process.steps.map((s) => `<li>${escapeHtml(s.text)}</li>`).join("")}</ol>
      <p class="muted">Quanta never: ${pol.never.map(escapeHtml).join("; ")}. Branch pattern <code>${escapeHtml(pol.policy.branch.template)}</code>; approval is required before a pull request is opened${pol.policy.approval.require_distinct_approver ? " and a different administrator must approve" : ""}. Edit <code>remediation/config/gitops_policy.yaml</code> to match your process (branch names, labels, reviewers, draft pull requests, per-repository overrides).</p>
      ${admin ? '<p class="inline-actions"><button type="button" class="btn-primary" id="sync">Check the Git host for review and merge updates</button></p>' : ""}
      <h3>Proposals</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>#</th><th>Change</th><th>Application</th><th>Status</th><th>Review / checks</th><th>Verification</th></tr></thead><tbody>
      ${d.proposals.length ? d.proposals.map((p) => `<tr><td><button type="button" class="link-button" data-id="${p.id}">${p.id}</button></td><td class="wrap-cell">${escapeHtml(p.title)}<br><span class="muted">${p.finding_ids.map(escapeHtml).join(", ")}</span></td>
        <td>${escapeHtml(p.application)}</td><td><span class="badge ${STATUS[p.status] || ""}">${escapeHtml(p.status)}</span></td><td>${escapeHtml(p.review_state || "-")} / ${escapeHtml(p.checks_state || "-")}</td>
        <td>${p.verified_state ? `<span class="badge ${(VERIFY[p.verified_state] || [""])[0]}">${escapeHtml(p.verified_state)}</span>` : '<span class="muted">-</span>'}</td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No proposals yet. Open an application, find the item in its ranked work and choose "Propose PR".</td></tr>'}</tbody></table></div>`;
    container.querySelectorAll("[data-id]").forEach((b) => b.addEventListener("click", () => go(b.dataset.id)));
    const sync = container.querySelector("#sync");
    if (sync) sync.addEventListener("click", async () => { sync.disabled = true; try { const r = await api.gitopsSync(); flash(`Checked ${r.synced.length} open pull request(s); ${r.verification.length} merged proposal(s) re-checked against the latest scan.`, "success"); show(); } catch (e) { flash(e.message, "error"); sync.disabled = false; } });
  }

  async function detail() {
    const p = await api.gitopsProposal(id);
    const plan = p.plan, v = p.verification;
    container.innerHTML = `<p><button type="button" class="link-button" id="back">&larr; All proposals</button></p>
      <h2 style="margin:4px 0">#${p.id} ${escapeHtml(p.title)}</h2>
      <p><span class="badge ${STATUS[p.status] || ""}">${escapeHtml(p.status)}</span> ${escapeHtml(p.application)} &middot; ${escapeHtml(p.kind)} &middot; ${p.repo ? `${escapeHtml(p.provider)} ${escapeHtml(p.repo)}` : '<span class="callout-warn">no repository set on the application</span>'}
        ${p.pr_url ? ` &middot; <a href="${escapeHtml(p.pr_url)}" target="_blank" rel="noopener">${escapeHtml(p.pr_url)}</a>` : ""}</p>
      ${p.last_error ? `<p class="callout callout-warn">${escapeHtml(p.last_error)}</p>` : ""}
      <ol class="step-list">${FLOW.map(([k, l]) => `<li${p[k] ? "" : ' class="muted"'}>${l}${p[k] ? ` <span class="muted">${escapeHtml(p[k].slice(0, 16).replace("T", " "))}${k === "created_at" ? " by " + escapeHtml(p.created_by || "") : k === "approved_at" ? " by " + escapeHtml(p.approved_by || "") : k === "opened_at" ? " by " + escapeHtml(p.opened_by || "") : ""}</span>` : ""}</li>`).join("")}</ol>
      ${p.pr_state ? `<p class="muted">On the host: ${escapeHtml(p.pr_state)}; review ${escapeHtml(p.review_state || "none")}; checks ${escapeHtml(p.checks_state || "none")}; last checked ${escapeHtml((p.last_synced_at || "never").slice(0, 16).replace("T", " "))}.</p>` : ""}
      ${p.status === "merged" || v.state !== "not-merged" ? `<p><span class="badge ${(VERIFY[v.state] || ["badge-outline"])[0]}">${escapeHtml((VERIFY[v.state] || ["", v.state])[1])}</span> <span class="muted">${escapeHtml(v.detail)}</span></p>` : ""}
      <h3>Changes</h3>${p.files.map((f) => `<p><strong>${escapeHtml(f.path)}</strong> <span class="muted">+${f.stats.added} -${f.stats.removed}</span></p>${f.changes && f.changes.length ? `<ul class="guidance-list">${f.changes.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>` : ""}${diffHtml(f.diff)}`).join("")}
      ${(p.summary.notes || []).length ? `<p class="muted">${p.summary.notes.map(escapeHtml).join("; ")}</p>` : ""}
      <h3>Pull request description</h3><pre class="diff-view" style="white-space:pre-wrap">${escapeHtml(p.pr_body)}</pre>
      <h3>What opening it does</h3><ol class="step-list">${plan.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      <p class="muted">Branch <code>${escapeHtml(plan.branch)}</code> into <code>${escapeHtml(plan.base_branch || "the default branch")}</code>${plan.draft ? "; opened as a draft" : ""}${plan.labels.length ? "; labels " + plan.labels.map(escapeHtml).join(", ") : ""}${plan.reviewers.length ? "; reviewers " + plan.reviewers.map(escapeHtml).join(", ") : ""}.</p>
      <div id="preview"></div>
      ${admin ? `<div class="inline-actions">${p.status === "draft" ? '<button type="button" class="btn-primary" id="approve">Approve</button>' : ""}
        ${["approved", "failed"].includes(p.status) ? '<button type="button" class="btn-primary" id="dry">Preview what would be sent</button>' : ""}
        ${["draft", "approved", "failed"].includes(p.status) ? '<button type="button" class="secondary-button" id="discard">Discard</button>' : ""}
        ${["pr-opened", "in-review"].includes(p.status) ? '<button type="button" class="secondary-button" id="sync1">Check the Git host now</button>' : ""}</div>` : '<p class="muted">An administrator approves and opens proposals.</p>'}`;
    container.querySelector("#back").addEventListener("click", () => go(null));
    const on = (sel, fn) => { const el = container.querySelector(sel); if (el) el.addEventListener("click", fn); };
    on("#approve", async () => { try { await api.gitopsApprove(p.id); flash("Approved.", "success"); show(); } catch (e) { flash(e.message, "error"); } });
    on("#discard", async () => { const why = window.prompt("Why is this being discarded? (optional)"); if (why === null) return; try { await api.gitopsDiscard(p.id, why); show(); } catch (e) { flash(e.message, "error"); } });
    on("#sync1", async () => { try { await api.gitopsSync(); show(); } catch (e) { flash(e.message, "error"); } });
    on("#dry", async () => {
      try {
        const r = await api.gitopsOpen(p.id, false);
        container.querySelector("#preview").innerHTML = `<div class="callout"><strong>Dry run.</strong> ${escapeHtml(r.message)}<br>Connection: <strong>${escapeHtml(r.connection || "none found")}</strong>.
          <br>Commit message: <code>${escapeHtml(r.plan.commit_message.split("\n")[0])}</code></div><p><button type="button" class="btn-primary" id="go">Open the pull request on ${escapeHtml(r.plan.provider)} now</button></p>`;
        container.querySelector("#go").addEventListener("click", async () => {
          if (!window.confirm(`Create the branch ${r.plan.branch} in ${r.plan.repo}, commit ${r.plan.files.length} file(s) to it and open a pull request?\n\nQuanta will not merge it.`)) return;
          try { const out = await api.gitopsOpen(p.id, true); flash(`Pull request opened: ${out.pr_url}`, "success"); show(); } catch (e) { flash(e.message, "error"); show(); }
        });
      } catch (e) { flash(e.message, "error"); }
    });
  }

  async function show() {
    try { id ? await detail() : await list(); } catch (err) { container.innerHTML = `<p class="callout callout-warn">${escapeHtml(err.message)}</p>`; }
  }
  await show();
}
