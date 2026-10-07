// Attack Surface: the part of the estate visible from the internet, built only from the output of discovery tools the customer runs against their own infrastructure
// (subfinder, dnsx, httpx, naabu, nuclei). Quanta never scans and never contacts a target, so it cannot see anything that was not imported. Every view says how old the data is.
// Rebuilt on the UI kit: a data-age banner that turns amber and red, an exposure map, a faceted asset table, and a change feed that refreshes on its own.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { kpiTile, chip, severityChip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, mountCounters, debounce, tipAttr } from "../ui.js";
import { modal, copyText, segmented, onSeg, liveBadge } from "../sxKit.js";
import { selectableTable, kpiStrip, tabBar, wireTabBar, pageActions, replaceSearch, readJson, writeJson, autoRefresh, skeletonPage, stackedBar, copyButton, wireCopy } from "../mxKit.js";
import { pushReading, readingSeries, filterRecords, assetFacets, exposureLevels, changeTone } from "../moduleLogic.js";

export const title = "Attack Surface";

const TABS = [["overview", "Overview"], ["assets", "Assets"], ["changes", "Changes"], ["findings", "Findings"], ["import", "Import and scope"], ["feed", "How to feed it"]];
const KINDS = ["domain", "subdomain", "ip", "service", "url"];
const KIND_LABEL = { domain: "Domains", subdomain: "Subdomains", ip: "Addresses", service: "Services", url: "Web endpoints" };
const NOTE = "The part of your estate that is visible from the internet, built only from the output of discovery tools that you run against your own infrastructure. Quanta never scans and never contacts a target, so it cannot see anything you did not import.";
const HIST_KEY = "quanta.asm.history";

export async function render(container) {
  const $ = (s) => container.querySelector(s);
  let alive = true;
  onCleanup(() => { alive = false; });
  const qs = new URLSearchParams(window.location.search);
  const S = { tab: TABS.some(([k]) => k === qs.get("tab")) ? qs.get("tab") : "overview", kind: qs.get("kind") || "", scope: qs.get("scope") || "in", status: qs.get("status") || "active", q: qs.get("q") || "", owner: qs.get("owner") || "", change: "", table: null, age: null, mode: "idle", lastChangeAt: null, known: new Set() };
  const url = () => { const p = new URLSearchParams(); if (S.tab !== "overview") p.set("tab", S.tab); if (S.tab === "assets") { if (S.kind) p.set("kind", S.kind); if (S.scope !== "in") p.set("scope", S.scope); if (S.status !== "active") p.set("status", S.status); if (S.q) p.set("q", S.q); if (S.owner) p.set("owner", S.owner); } replaceSearch(p.toString() ? `?${p}` : ""); };

  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Attack surface</h2><p>${NOTE}</p></div><div class="sx-row"><span id="as-live"></span></div></div>
    <div id="as-age"></div><div id="as-tabs"></div><div id="as-body">${skeletonPage(4)}</div></div>`;
  const setLive = (m) => { S.mode = m; const el = $("#as-live"); if (el) el.innerHTML = liveBadge(m); };
  const body = () => $("#as-body");
  const paintTabs = () => { $("#as-tabs").innerHTML = tabBar("Attack surface sections", TABS.map(([id, label]) => ({ id, label })), S.tab); };

  // The server says how old the imported data is; show it as a banner that escalates, plus the live "updated" badge.
  function ageBanner(a) {
    S.age = a;
    const el = $("#as-age");
    if (!a) { el.innerHTML = ""; return; }
    const bad = a.stale || a.never_imported;
    el.innerHTML = `<div class="mx-callout${bad ? " mx-callout-warn" : ""}" role="${bad ? "alert" : "status"}"><strong>Data age.</strong> ${escapeHtml(a.message)}${a.last_import_at ? ` Last import: ${escapeHtml(a.last_import_at)}. ${dataAgeBadge(new Date(a.last_import_at).getTime() || Date.now(), { fresh: 6 * 3600000, stale: 48 * 3600000, label: "Imported" })}` : ""}</div>`;
    mountDataAge(el);
  }
  const fail = (e) => { if (!alive) return; body().innerHTML = emptyState({ title: e.status === 403 || e.status === 401 ? "This page is for administrators" : "This could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" }); };

  // ------------------------------------------------------------------ overview
  async function overview() {
    const s = await api.asmSummary(7);
    if (!alive) return;
    ageBanner(s.data_age);
    const k = s.assets.by_kind;
    const reading = { domains: k.domain + k.subdomain, ips: k.ip, services: k.service, urls: k.url, risky: s.exposed_risky_services, shadow: s.shadow_assets };
    const hist = pushReading(readJson(HIST_KEY, []), reading); writeJson(HIST_KEY, hist);
    const ser = (key) => readingSeries(hist, (r) => r[key]);
    const t = (key, label, value, extra = {}) => ({ key, label, value, filterable: false, previous: ser(key).previous ?? undefined, spark: ser(key).values.length > 1 ? ser(key).values : undefined, goodWhen: "down", ...extra });
    const levels = exposureLevels(s);
    body().innerHTML = `${s.scope.declared ? "" : '<div class="mx-callout mx-callout-warn">No scope is declared, so everything imported is treated as yours. Declare your domains and ranges on the Import and scope tab so anything else is flagged instead of included.</div>'}
      <div id="as-kpis" class="sx-kpis mx-kpis"></div>
      <div class="mx-split"><div><h3 class="mx-h3">Exposure map</h3><p class="ui-muted">What is visible from the internet, widest layer first. Each bar is the share of the imported assets of that kind; red marks what needs a decision.</p>
        <div class="mx-map" role="list">${levels.map((l) => `<button type="button" class="mx-maprow" role="listitem" data-kind="${escapeHtml(l.kind)}" aria-label="${escapeHtml(l.label)}: ${l.count}${l.flag ? `, ${l.flag}` : ""}. Open the asset list."><span class="mx-maplabel">${escapeHtml(l.label)}</span><span class="mx-mapbar"><i style="width:${l.width}%"></i>${l.flagWidth ? `<b style="width:${l.flagWidth}%"></b>` : ""}</span><strong>${l.count}</strong><span class="ui-muted mx-sub">${escapeHtml(l.flag || "")}</span></button>`).join("")}</div></div>
        <div><h3 class="mx-h3">Findings by rule</h3>${Object.keys(s.findings.by_rule).length ? `<div class="sx-row">${Object.entries(s.findings.by_rule).map(([r, n]) => chip(`${r}: ${n}`, { tone: "warn" })).join(" ")}</div>` : '<p class="ui-muted">None raised from the data imported so far. That is not the same as clean: see the gaps and the data age.</p>'}
          ${s.gaps.length ? `<h3 class="mx-h3">What this view cannot judge yet</h3><ul class="mx-list">${s.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul>` : ""}</div></div>
      <p class="ui-muted">${escapeHtml(s.note)}${hist.length < 2 ? " Trends appear after a second reading in this browser." : ""}</p>`;
    kpiStrip($("#as-kpis"), [
      t("domains", "Domains", k.domain + k.subdomain, { goodWhen: "up" }), t("ips", "Addresses", k.ip, { goodWhen: "up" }), t("services", "Services", k.service, { goodWhen: "up" }), t("urls", "Web endpoints", k.url, { goodWhen: "up" }),
      t("new", `New, last ${s.period_days} days`, s.changes.new, { tone: s.changes.new ? "warn" : "good", previous: undefined, spark: undefined }), t("gone", "Disappeared", s.changes.disappeared, { previous: undefined, spark: undefined, tone: "" }),
      t("risky", "Risky services exposed", s.exposed_risky_services, { tone: s.exposed_risky_services ? "danger" : "good", hint: "Services such as remote administration or databases reachable from the internet." }),
      t("shadow", "Not in the asset inventory", s.shadow_assets, { tone: s.shadow_assets ? "warn" : "good", hint: "Seen from outside but unknown to the asset inventory: nobody owns them yet." }),
      t("scope", "Outside your scope", s.assets.out_of_scope, { previous: undefined, spark: undefined }), t("stale", "Stale data", s.stale ? "yes" : "no", { tone: s.stale ? "danger" : "good", previous: undefined, spark: undefined }),
    ], () => {});
  }

  // ------------------------------------------------------------------ assets
  async function assets() {
    const params = { limit: 500 };
    if (S.status) params.status = S.status;
    if (S.scope === "in") params.in_scope = "true"; else if (S.scope === "out") params.in_scope = "false";
    const d = await api.asmAssets(params);
    if (!alive) return;
    ageBanner(d.data_age);
    const all = d.assets;
    const facets = assetFacets(all);
    const rows = () => filterRecords(all.filter((a) => (!S.kind || a.kind === S.kind) && (!S.owner || (S.owner === "owned" ? !!(a.owner || a.team) : !(a.owner || a.team)))), S.q, [(a) => a.value, (a) => a.title, (a) => (a.technologies || []).join(" "), (a) => a.owner, (a) => a.team]);
    body().innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter assets"><input type="search" class="sx-field" id="as-q" placeholder="Name, title, technology, owner" value="${escapeHtml(S.q)}" aria-label="Search assets">
      <select class="sx-field" id="as-scope" aria-label="Scope"><option value="in" ${S.scope === "in" ? "selected" : ""}>In scope</option><option value="out" ${S.scope === "out" ? "selected" : ""}>Outside scope</option><option value="all" ${S.scope === "all" ? "selected" : ""}>Both</option></select>
      <select class="sx-field" id="as-status" aria-label="State"><option value="active" ${S.status === "active" ? "selected" : ""}>Active</option><option value="gone" ${S.status === "gone" ? "selected" : ""}>Disappeared</option><option value="" ${S.status === "" ? "selected" : ""}>Both</option></select>
      ${segmented("Ownership", [{ id: "", label: "Any owner", count: all.length }, { id: "owned", label: "Owned", count: facets.owned }, { id: "unowned", label: "Unowned", count: facets.unowned }], S.owner)}</div>
      ${segmented("Kind", [{ id: "", label: "All kinds" }, ...KINDS.map((x) => ({ id: x, label: KIND_LABEL[x], count: facets.kinds[x] || 0 }))], S.kind).replace('class="sx-seg"', 'class="sx-seg mx-kindseg"')}
      <div id="as-table"></div>${d.total > all.length ? `<p class="ui-muted">Showing ${all.length} of ${d.total}. Narrow the filters to see the rest.</p>` : ""}`;
    S.table = selectableTable($("#as-table"), { rows: rows(), rowKey: (a) => `${a.kind}:${a.value}`, caption: "Attack surface assets", csvName: "quanta-attack-surface", storageKey: "asm-assets", rowHeight: 66, maxHeight: 580,
      emptyHtml: emptyState({ title: "No assets match", body: "Import discovery output on the Import and scope tab, or loosen a filter.", actionLabel: "Import discovery output", actionHref: "/attack-surface?tab=import", iconName: "infra" }),
      columns: [
        { key: "a", label: "Asset", width: 300, csv: (a) => a.value, render: (a) => `<strong class="mx-clip" title="${escapeHtml(a.value)}">${escapeHtml(a.value)}</strong>${a.title ? `<div class="mx-sub" title="${escapeHtml(a.title)}">${escapeHtml(a.title)}</div>` : ""}${a.cname.length ? `<div class="mx-sub">CNAME ${escapeHtml(a.cname.join(", "))}</div>` : ""}${a.tls_expires ? `<div class="mx-sub">certificate until ${escapeHtml(a.tls_expires)}</div>` : ""}` },
        { key: "k", label: "Kind", width: 90, csv: (a) => a.kind, render: (a) => chip(a.kind, { tone: "neutral" }) }, { key: "s", label: "Seen by", width: 140, csv: (a) => a.sources.join(", "), render: (a) => escapeHtml(a.sources.join(", ")) },
        { key: "t", label: "Technologies", width: 220, csv: (a) => a.technologies.join(", "), render: (a) => `<span class="mx-clip">${escapeHtml(a.technologies.slice(0, 6).join(", "))}</span>` },
        { key: "l", label: "Last seen", width: 120, csv: (a) => a.last_seen, render: (a) => `${escapeHtml(a.last_seen.slice(0, 10))}<div class="mx-sub">${a.age_days ?? "?"} days ago</div>` },
        { key: "o", label: "Owner", width: 150, csv: (a) => [a.owner, a.team].filter(Boolean).join(" / "), render: (a) => (a.owner || a.team ? escapeHtml([a.owner, a.team].filter(Boolean).join(" / ")) : '<span class="mx-unowned">none</span>') },
        { key: "f", label: "State", width: 190, csv: (a) => `${a.in_scope ? "" : "outside scope "}${a.status === "gone" ? "disappeared" : ""}`, render: (a) => `${a.in_scope ? "" : chip("outside scope", { tone: "neutral" }) + " "}${a.status === "gone" ? chip("disappeared", { tone: "good" }) + " " : ""}${a.vulns ? chip(`${a.vulns} check(s)`, { tone: "warn" }) : ""}` },
      ] });
    const typeSearch = debounce((v) => { S.q = v; S.table.setRows(rows()); url(); }, 200);
    $("#as-q").addEventListener("input", (e) => typeSearch(e.target.value));
    for (const [id, key] of [["as-scope", "scope"], ["as-status", "status"]]) $(`#${id}`).addEventListener("change", (e) => { S[key] = e.target.value; url(); show(); });
    onSeg(body(), (id, group) => { const label = group.getAttribute("aria-label"); if (label === "Kind") S.kind = id; else S.owner = id; group.querySelectorAll("[data-seg]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.seg === id))); S.table.setRows(rows()); url(); });
  }

  // ------------------------------------------------------------------ changes (refreshes on its own)
  async function changes(quiet = false) {
    const d = await api.asmChanges({ limit: 300 });
    if (!alive || S.tab !== "changes") return;
    ageBanner(d.data_age);
    const fresh = new Set(); if (quiet) for (const c of d.changes) if (!S.known.has(`${c.at}|${c.asset_key}|${c.change}`)) fresh.add(`${c.at}|${c.asset_key}|${c.change}`);
    for (const c of d.changes) S.known.add(`${c.at}|${c.asset_key}|${c.change}`);
    const kinds = ["new", "reappeared", "changed", "disappeared"]; const counts = Object.fromEntries(kinds.map((x) => [x, d.changes.filter((c) => c.change === x).length]));
    const list = d.changes.filter((c) => !S.change || c.change === S.change);
    body().innerHTML = `<div class="sx-toolbar">${segmented("Change", [{ id: "", label: "All", count: d.changes.length }, ...kinds.map((x) => ({ id: x, label: x, count: counts[x] }))], S.change)}<span class="ui-muted mx-count" role="status" aria-live="polite">${quiet && fresh.size ? `${fresh.size} new since the last check` : "Refreshes on its own every 30 seconds"}</span></div>
      <ol class="mx-feed" aria-label="Change feed">${list.map((c) => { const key = `${c.at}|${c.asset_key}|${c.change}`; return `<li class="mx-feed-row${fresh.has(key) ? " new" : ""}">${chip(c.change, { tone: changeTone(c.change) })}${c.in_scope ? "" : ` ${chip("outside scope", { tone: "neutral" })}`}<span class="mx-feed-key" title="${escapeHtml(c.asset_key)}">${escapeHtml(c.asset_key)}</span><span class="ui-muted mx-sub">${escapeHtml(c.detail || "")}</span><time class="ui-muted mx-sub" datetime="${escapeHtml(c.at)}">${escapeHtml(c.at.replace("T", " ").replace("Z", ""))}</time></li>`; }).join("") || `<li>${emptyState({ title: "No changes recorded yet", body: "Each import is compared with the last one. What is new, what changed and what disappeared lands here.", iconName: "signal" })}</li>`}</ol>
      <h3 class="mx-h3">Imports</h3>${d.runs.length ? `<div class="ui-table-wrap"><table class="mx-plain"><caption class="ui-sr">Imports</caption><thead><tr><th>When</th><th>Tool</th><th>Records</th><th>New</th><th>Changed</th><th>Gone</th><th>Outside scope</th><th>By</th></tr></thead><tbody>${d.runs.map((r) => `<tr><td>${escapeHtml(r.imported_at.replace("T", " ").replace("Z", ""))}</td><td>${escapeHtml(r.tool)}${r.complete ? ` (complete${r.scope_label ? " for " + escapeHtml(r.scope_label) : ""})` : ""}</td><td>${r.records}${r.skipped ? ` (${r.skipped} skipped)` : ""}</td><td>${r.new_count}</td><td>${r.changed_count}</td><td>${r.gone_count}</td><td>${r.out_of_scope}</td><td>${escapeHtml(r.actor || "")}</td></tr>`).join("")}</tbody></table></div>` : '<p class="ui-muted">No imports yet.</p>'}`;
    onSeg(body(), (id) => { S.change = id; changes(false); });
  }

  // ------------------------------------------------------------------ findings
  async function findings() {
    const d = await api.asmFindings();
    if (!alive) return;
    ageBanner(d.data_age);
    body().innerHTML = `${d.gaps.length ? `<div class="mx-callout mx-callout-warn">${d.gaps.map(escapeHtml).join("<br>")}</div>` : ""}
      <p>${d.findings.length} finding(s) raised by explicit rules from the imported data. ${d.skipped_info ? `${d.skipped_info} informational check result(s) were counted, not raised. ` : ""}<button type="button" class="ui-btn sx-btn-sm" id="publish">Send to the main queue</button></p><div id="as-ftable"></div>`;
    selectableTable($("#as-ftable"), { rows: d.findings.slice(0, 400), rowKey: (x, i) => `${x.rule}:${x.title}:${x.evidence}`.slice(0, 120), caption: "Attack surface findings", csvName: "quanta-attack-surface-findings", storageKey: "asm-findings", rowHeight: 74, maxHeight: 560,
      emptyHtml: emptyState({ title: "No findings from the data imported so far", body: "That is not the same as clean: see the gaps and the data age above.", iconName: "approved" }),
      columns: [{ key: "s", label: "Severity", width: 110, csv: (x) => x.severity, render: (x) => `${severityChip(x.severity)}<div class="mx-sub">${escapeHtml(x.rule)}</div>` }, { key: "t", label: "Finding", width: 280, csv: (x) => x.title, render: (x) => `<strong class="mx-title">${escapeHtml(x.title)}</strong>${x.cve ? `<div class="mx-sub">${escapeHtml(x.cve)}</div>` : ""}` },
        { key: "e", label: "Evidence", width: 280, csv: (x) => x.evidence, render: (x) => `<span class="mx-title" title="${escapeHtml(x.evidence)}">${escapeHtml(x.evidence)}</span><div class="mx-sub">${escapeHtml(x.fresh)}</div>` }, { key: "n", label: "Next step", width: 260, csv: (x) => x.next_step, render: (x) => `<span class="mx-title">${escapeHtml(x.next_step)}</span>` }] });
    $("#publish").addEventListener("click", async () => {
      try {
        const r = await api.asmPublish({ confirm: false });
        const ok = await modal({ title: "Send these findings to the main queue?", confirmLabel: `Publish ${r.findings}`, description: r.message, body: `<p>${r.findings} finding(s) would be published to the remediation queue. Findings that no longer apply are removed in the same step.</p>` });
        if (!ok) return;
        const out = await api.asmPublish({ confirm: true });
        toast(`Published ${out.published} finding(s): ${out.added} new, ${out.updated} updated, ${out.removed} removed.`, { tone: "good", ms: 7000 });
      } catch (e) { toast(e.message, { tone: "bad", ms: 8000 }); }
    });
  }

  // ------------------------------------------------------------------ import and scope
  async function importTab() {
    const [sc, ages] = await Promise.all([api.asmScope(), api.asmAssets({ limit: 1 })]);
    if (!alive) return;
    ageBanner(ages.data_age);
    body().innerHTML = `<div class="mx-split"><section class="mx-card"><h4>Import tool output</h4><p class="ui-muted">Choose the tool and the file it wrote (JSON lines or a JSON array). Tick complete only when the file is the whole answer for the scope you name (a domain or a range): assets the file omits are then marked disappeared. A partial file never removes anything.</p>
      <form id="imp" class="mx-form"><label>Tool<select class="sx-field" name="tool"><option>subfinder</option><option>dnsx</option><option>httpx</option><option>naabu</option><option>nuclei</option><option value="seeds">seeds (declares scope)</option></select></label>
        <label>Scope for a complete import<input class="sx-field" name="scope" placeholder="example.com or 203.0.113.0/24"></label><label class="mx-check"><input type="checkbox" name="complete"> This file is complete for that scope</label><label class="mx-check"><input type="checkbox" name="publish"> Refresh the main-queue findings afterwards</label>
        <label>File<input class="sx-field" type="file" name="file" required></label><div><button type="submit" class="ui-btn sx-btn-sm">Import</button></div></form><div id="imp-result" role="status"></div></section>
      <section class="mx-card"><h4>Scope</h4><p class="ui-muted">What you declare as yours. Anything else that turns up is recorded and flagged, never silently included, and never raises a finding.</p>
      <form id="scope" class="mx-form"><label>Domains (one per line)<textarea class="sx-field" name="domains" rows="4">${escapeHtml(sc.domains.join("\n"))}</textarea></label><label>Address ranges (one per line)<textarea class="sx-field" name="cidrs" rows="4">${escapeHtml(sc.cidrs.join("\n"))}</textarea></label><div><button type="submit" class="ui-btn sx-btn-sm">Save scope</button></div></form>
      <h4>Expected import cadence</h4><p class="ui-muted">If no import arrives within this many hours Quanta raises a "stale attack-surface data" alert, and every view says the data is out of date. Leave empty for no expectation.</p>
      <form id="cad" class="sx-toolbar"><label class="mx-inline">Hours <input class="sx-field" name="hours" type="number" min="1" step="1" value="${sc.expected_cadence_hours ?? ""}"></label><button type="submit" class="ui-btn sx-btn-sm">Save</button></form></section></div>`;
    $("#imp").addEventListener("submit", async (e) => {
      e.preventDefault(); const el = e.target; const btn = el.querySelector("button[type=submit]"); btn.disabled = true;
      try {
        const r = await api.asmImport(el.tool.value, el.scope.value.trim(), el.complete.checked, el.publish.checked, await el.file.files[0].text());
        $("#imp-result").innerHTML = `<div class="mx-callout">Read ${r.records} record(s)${r.skipped ? `, skipped ${r.skipped}` : ""}: ${r.new} new, ${r.changed} changed, ${r.disappeared} disappeared, ${r.out_of_scope} outside scope.${r.notes.length ? "<br>" + r.notes.map(escapeHtml).join("<br>") : ""}</div>`;
        toast("Imported.", { tone: "good" });
      } catch (err) { toast(err.message, { tone: "bad", ms: 8000 }); } finally { btn.disabled = false; }
    });
    $("#scope").addEventListener("submit", async (e) => {
      e.preventDefault(); const lines = (v) => v.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      try { const r = await api.asmSetScope({ domains: lines(e.target.domains.value), cidrs: lines(e.target.cidrs.value) }); toast(`Scope saved; ${r.rescoped} asset(s) moved in or out.`, { tone: "good" }); } catch (err) { toast(err.message, { tone: "bad" }); }
    });
    $("#cad").addEventListener("submit", async (e) => { e.preventDefault(); const v = e.target.hours.value; try { await api.asmSettings({ expected_cadence_hours: v ? Number(v) : null }); toast("Saved.", { tone: "good" }); } catch (err) { toast(err.message, { tone: "bad" }); } });
  }

  async function feed() {
    const d = await api.asmHowToFeed();
    if (!alive) return;
    $("#as-age").innerHTML = "";
    body().innerHTML = `<div class="mx-callout mx-callout-warn">${escapeHtml(d.safety)}</div><p class="ui-muted">Example commands, with placeholders only. Replace example.com and the address range with your own, run them on infrastructure you are authorised to test, then import the file on the Import and scope tab, or post it from your pipeline.</p>
      <div class="mx-grid-cards">${d.examples.map((x) => `<article class="mx-card"><h4>${escapeHtml(x.tool)}</h4><p>${escapeHtml(x.what)}</p><p class="ui-muted mx-sub">${escapeHtml(x.complete)}</p><code class="mx-code">${escapeHtml(x.command)}</code><div class="mx-actions">${copyButton(x.command, "Copy command")}</div></article>`).join("")}</div>
      <h3 class="mx-h3">From a pipeline</h3><code class="mx-code">${escapeHtml(d.post_example)}</code><div class="mx-actions">${copyButton(d.post_example, "Copy")}</div>
      <p class="ui-muted">Limits: built against the tools' public documentation of their JSON output and unit-tested on sample lines; not yet run against live output at scale. Quanta does no active discovery of its own.</p>`;
  }

  async function show() {
    paintTabs(); url();
    const fresh = body().cloneNode(false); body().replaceWith(fresh); fresh.id = "as-body"; fresh.innerHTML = skeletonPage(3);
    try { await ({ overview, assets, changes, findings, import: importTab, feed }[S.tab])(); } catch (e) { fail(e); }
  }
  wireTabBar($("#as-tabs"), (id) => { S.tab = id; show(); });
  wireCopy(container, copyText);
  container.addEventListener("click", (e) => { const m = e.target.closest("[data-kind]"); if (m && S.tab === "overview") { S.tab = "assets"; S.kind = m.dataset.kind === "domain" ? "" : m.dataset.kind; show(); } });
  pageActions([{ label: "Attack surface: import discovery output", icon: "infra", run: () => { S.tab = "import"; show(); } }, { label: "Attack surface: show what changed", icon: "infra", run: () => { S.tab = "changes"; show(); } }, { label: "Attack surface: show unowned assets", icon: "infra", run: () => { S.tab = "assets"; S.owner = "unowned"; show(); } }]);
  await show();
  autoRefresh(async () => { if (S.tab === "changes") await changes(true); else if (S.tab === "overview") { try { await overview(); } catch { /* retried next tick */ } } }, { every: 30000, onMode: setLive });
}
