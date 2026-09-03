// Read-only "finding detail" modal, opened by clicking a finding ID anywhere findings
// are listed (queue.js today; appsec/infrastructure/aiVulnerabilities hub tables can
// reuse it too). Reuses the same openModal/closeModal pattern as assets.js's edit-owner
// modal (see dom.js) - this one just renders, it never submits anything.
import { escapeHtml, openModal, closeModal } from "./dom.js";
import { api } from "./api.js";

function row(label, valueHtml, wrap = false) {
  if (valueHtml === null || valueHtml === undefined || valueHtml === "") return "";
  return `<tr><th>${escapeHtml(label)}</th><td${wrap ? ` class="wrap-cell"` : ""}>${valueHtml}</td></tr>`;
}

export function openFindingDetail(f) {
  const kev = f.kev && f.kev.listed
    ? `<span class="badge badge-critical">KEV-listed</span>` +
      (f.kev.vulnerability_name ? ` — ${escapeHtml(f.kev.vulnerability_name)}` : "") +
      (f.kev.due_date ? `<br><span class="muted">CISA remediation due ${escapeHtml(f.kev.due_date)}</span>` : "")
    : (f.kev ? `<span class="muted">Not KEV-listed</span>` : `<span class="muted">—</span>`);

  const epss = f.epss
    ? `${(f.epss.score * 100).toFixed(1)}% exploit probability (${(f.epss.percentile * 100).toFixed(0)}th percentile)`
    : `<span class="muted">—</span>`;

  let sla = `<span class="muted">—</span>`;
  if (f.sla && f.sla.due_date) {
    sla = f.sla.breached
      ? `<span class="sla-breached">${escapeHtml(f.sla.due_date)} (breached)</span>`
      : `<span class="sla-ok">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d remaining)</span>`;
  }

  const attack = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) =>
        `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join(" ")
    : null;

  const exception = f.exception
    ? `Risk-accepted until <strong>${escapeHtml(f.exception.expires_on)}</strong> — ${escapeHtml(f.exception.reason)}`
    : null;

  const asset = f.asset || {};

  // Real, dated vendor-lifecycle lookup (remediation/enrichment/eol_lookup.py) - only
  // rendered when the asset's OS actually matched a known EOL/EOS entry; "unknown"
  // (no confident match) shows nothing here, same "don't fabricate a claim" rule as
  // everywhere else in this app.
  const eolStatus = f.eol_status;
  let eolCallout = "";
  let eolReasonForException = "";
  if (eolStatus && (eolStatus.status === "eol" || eolStatus.status === "eol-soon")) {
    const verb = eolStatus.status === "eol" ? "has been" : "is approaching";
    eolReasonForException = `Asset running an End-of-Life/End-of-Support OS (${asset.os || "unknown OS"}) ` +
      `- ${eolStatus.vendor} lists this as EOL ${eolStatus.eol_date} (${eolStatus.source}). No vendor patch is ` +
      `expected - remediation likely needs a hardware/software refresh or isolation, not a patch.`;
    eolCallout = `
      <div class="callout callout-warn" style="margin-top:12px">
        <strong>${eolStatus.status === "eol" ? "End-of-Life" : "End-of-Support approaching"}:</strong>
        ${escapeHtml(asset.os || "this asset's OS")} - ${eolStatus.vendor} lifecycle end
        <strong>${escapeHtml(eolStatus.eol_date)}</strong> (${escapeHtml(eolStatus.source)}). A vendor patch is
        unlikely to exist for this finding - recommended action is a hardware/software refresh or network
        isolation, not patching.
        <br>
        <a href="/exceptions?finding_id=${encodeURIComponent(f.id)}&reason=${encodeURIComponent(eolReasonForException)}" data-link>
          Request an exception for this finding →</a>
      </div>`;
  }

  const body = `
    <h2>${escapeHtml(f.title)}</h2>
    <p class="subtitle">
      <span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority || "—")}</span>
      &nbsp;<code>${escapeHtml(f.id)}</code>
      ${f.scan_type_label ? `&nbsp;<span class="category-tag">${escapeHtml(f.scan_type_label)}</span>` : ""}
    </p>

    ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ""}

    <div class="table-scroll">
      <table class="data-table finding-detail-table">
        <tbody>
          ${row("Source", f.source ? `${escapeHtml(f.source)}${f.source_ref ? ` <span class="muted">(${escapeHtml(f.source_ref)})</span>` : ""}` : null)}
          ${row("Severity", f.severity ? escapeHtml(f.severity) : null)}
          ${row("CVE", f.cve ? `<code>${escapeHtml(f.cve)}</code>` : null)}
          ${row("CVSS", f.cvss !== undefined && f.cvss !== null ? escapeHtml(String(f.cvss)) : null)}
          ${row("CISA KEV", kev)}
          ${row("EPSS", epss)}
          ${row("MITRE ATT&CK", attack)}
          ${row("Asset", asset.name ? `${escapeHtml(asset.name)}${asset.ip ? ` <span class="muted">(${escapeHtml(asset.ip)})</span>` : ""}` : null)}
          ${row("Asset type", asset.type ? escapeHtml(asset.type) : null)}
          ${row("OS", asset.os ? escapeHtml(asset.os) : null)}
          ${row("EOL/EOS", eolStatus && eolStatus.status !== "unknown"
            ? `${escapeHtml(eolStatus.status)} (${escapeHtml(eolStatus.eol_date)}, ${escapeHtml(eolStatus.vendor)})` : null)}
          ${row("First seen", f.first_seen ? escapeHtml(f.first_seen) : null)}
          ${row("Last seen", f.last_seen ? escapeHtml(f.last_seen) : null)}
          ${row("SLA due", sla)}
          ${row("Exception", exception, true)}
        </tbody>
      </table>
    </div>
    ${eolCallout}

    ${f.recommended_fix ? `
      <h3>Recommended fix</h3>
      <p>${escapeHtml(f.recommended_fix)}</p>` : ""}

    <h3>Compensating control coverage</h3>
    <div id="control-coverage-body">
      <p class="filter-count">Loading — checking real firewall/EDR coverage data…</p>
    </div>

    <h3>Network reachability</h3>
    <div id="network-path-body">
      <p class="filter-count">Loading — tracing the path to the internet…</p>
    </div>

    <h3>Similar findings</h3>
    <div id="similar-findings-body">
      <p class="filter-count">Loading — real TF-IDF + cosine-similarity text search…</p>
    </div>

    <p class="subtitle" style="margin-top:16px">
      <a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link>Ask AI about this finding</a>
      &nbsp;·&nbsp;
      <a href="/remediate" data-link>See it in the remediation plan</a>
      &nbsp;·&nbsp;
      <a href="/ml-insights" data-link>ML Insights</a>
    </p>`;

  const modalBody = openModal(body);
  // The links above navigate away via app.js's document-level [data-link] handler -
  // close the modal first so it doesn't stay open over the new page.
  modalBody.querySelectorAll("a[data-link]").forEach((a) => {
    a.addEventListener("click", () => closeModal());
  });

  loadSimilarFindings(f.id, modalBody);
  loadControlCoverage(f.id, modalBody);
  loadNetworkPath(asset.name, modalBody);
}

// Real firewall/EDR coverage assessment (remediation/enrichment/control_coverage.py) -
// fetched lazily, same reasoning as loadSimilarFindings() below: cheap per-call, no
// reason to compute it for every finding in a queue that may never open this modal.
async function loadControlCoverage(findingId, modalBody) {
  const el = modalBody.querySelector("#control-coverage-body");
  if (!el) return;
  let coverage;
  try {
    coverage = await api.controlCoverage(findingId);
  } catch (err) {
    el.innerHTML = `<p class="filter-count">Couldn't load control coverage (${escapeHtml(err.message || String(err))}).</p>`;
    return;
  }
  if (!modalBody.querySelector("#control-coverage-body")) return; // modal closed/replaced meanwhile
  if (!coverage.has_data) {
    el.innerHTML = `<p class="filter-count">No firewall/EDR coverage data on file for this asset — add an entry to <code>remediation/config/security_controls.yaml</code> to see a real coverage assessment here.</p>`;
    return;
  }
  const controlsHtml = coverage.recommended_controls.length
    ? `<ul style="margin:4px 0 0; padding-left:18px">${coverage.recommended_controls.map((c) => `<li style="margin-bottom:2px">${escapeHtml(c)}</li>`).join("")}</ul>`
    : `<p class="muted" style="margin:4px 0 0">No further controls recommended — existing coverage already accounts for everything this module checks.</p>`;
  el.innerHTML = `
    <div class="table-scroll">
      <table class="data-table finding-detail-table">
        <tbody>
          ${row("Existing coverage", `${coverage.existing_coverage_pct}%`)}
          ${row("Residual risk", `${coverage.residual_risk_pct}%`)}
          ${row("Incremental coverage if applied", `${coverage.incremental_coverage_pct}%`)}
        </tbody>
      </table>
    </div>
    <p style="margin:10px 0 4px"><strong>Recommended controls:</strong></p>
    ${controlsHtml}`;
}

// Real network-reachability trace (remediation/enrichment/network_reachability.py) -
// same lazy-fetch reasoning as the coverage assessment above.
async function loadNetworkPath(assetName, modalBody) {
  const el = modalBody.querySelector("#network-path-body");
  if (!el || !assetName) {
    if (el) el.innerHTML = `<p class="filter-count">No asset on this finding to trace.</p>`;
    return;
  }
  let path;
  try {
    path = await api.networkPath(assetName);
  } catch (err) {
    el.innerHTML = `<p class="filter-count">Couldn't load the network path (${escapeHtml(err.message || String(err))}).</p>`;
    return;
  }
  if (!modalBody.querySelector("#network-path-body")) return;
  if (path.verdict === "unknown") {
    el.innerHTML = `<p class="filter-count">No network path on file for this asset — add an entry to <code>remediation/config/network_topology.yaml</code> to see a real reachability verdict here.</p>`;
    return;
  }
  const verdictBadge = path.verdict === "denied"
    ? `<span class="badge badge-auto_approvable">Denied — no path to the internet</span>`
    : `<span class="badge badge-critical">Allowed — reachable from the internet</span>`;
  const hopsHtml = path.hops.map((h) =>
    `<li>${escapeHtml(h.hop_type)} <strong>${escapeHtml(h.name)}</strong> — ${escapeHtml(h.default_action)}</li>`).join("");
  el.innerHTML = `
    <p>${verdictBadge}</p>
    <p style="margin:8px 0 4px"><strong>Path to the internet:</strong></p>
    <ol style="margin:0; padding-left:18px">${hopsHtml}</ol>`;
}

// Fetched lazily (not blocking the modal's initial open) - real scikit-learn
// TfidfVectorizer + cosine similarity over title+description
// (remediation/enrichment/ml_insights.py's find_similar_findings()), same "unsupervised,
// advisory, real - not a heuristic" posture as the rest of /ml-insights.
async function loadSimilarFindings(findingId, modalBody) {
  let similar;
  try {
    ({ similar } = await api.mlSimilarFindings(findingId));
  } catch (err) {
    const el = modalBody.querySelector("#similar-findings-body");
    if (el) el.innerHTML = `<p class="filter-count">Couldn't load similar findings (${escapeHtml(err.message || String(err))}).</p>`;
    return;
  }
  // The modal may have already been closed (or replaced by a different finding) by the
  // time this async fetch resolves - querying modalBody (not document) means a stale
  // response can't accidentally write into whatever's open now.
  const el = modalBody.querySelector("#similar-findings-body");
  if (!el) return;
  if (!similar.length) {
    el.innerHTML = `<p class="filter-count">No similar findings found.</p>`;
    return;
  }
  el.innerHTML = `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Asset</th><th>Severity</th><th>Title</th><th>Similarity</th></tr></thead>
        <tbody>
          ${similar.map((s) => `
            <tr>
              <td><button type="button" class="link-button similar-finding-link" data-finding-id="${escapeHtml(s.id)}">${escapeHtml(s.id)}</button></td>
              <td>${escapeHtml(s.asset && s.asset.name)}</td>
              <td>${escapeHtml(s.severity)}</td>
              <td class="wrap-cell">${escapeHtml(s.title)}</td>
              <td>${(s.similarity * 100).toFixed(0)}%</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
  el.querySelectorAll(".similar-finding-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      const match = similar.find((s) => s.id === btn.dataset.findingId);
      if (match) openFindingDetail(match);
    });
  });
}
