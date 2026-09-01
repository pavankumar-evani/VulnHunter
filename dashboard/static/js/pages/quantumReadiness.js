// Quantum Readiness: real findings whose title names classical asymmetric crypto
// (RSA/ECDSA/Diffie-Hellman - the genuinely quantum-relevant case, since Shor's
// algorithm breaks exactly these) or a legacy TLS/cipher weakness, classified by
// remediation/enrichment/quantum_readiness.py's disclosed keyword heuristic (same
// honesty tier as attack_mapping.py's ATT&CK tagging - this app's normalized finding
// schema carries no CWE field to join against). NOT a "quantum vulnerability scanner" -
// no such product category exists to honestly claim; this is real-CVE classification
// against a real, cited NIST migration standard. Structurally mirrors
// aiVulnerabilities.js's shape (disclosure callout + real counts + a real finding list).
import { escapeHtml } from "../dom.js";
import { api } from "../api.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";
import { openFindingDetail } from "../findingDetail.js";

export const title = "Quantum Readiness";

const CATEGORY_LABELS = {
  "asymmetric-crypto": "Asymmetric crypto (RSA/ECDSA/DH)",
  "legacy-protocol": "Legacy TLS/cipher",
};
const CATEGORY_BADGE_CLASS = {
  "asymmetric-crypto": "badge-critical",
  "legacy-protocol": "badge-medium",
};

const EXPORT_COLUMNS = [
  { label: "ID", value: (f) => f.id },
  { label: "CVE", value: (f) => f.cve },
  { label: "Title", value: (f) => f.title },
  { label: "Asset", value: (f) => f.asset && f.asset.name },
  { label: "Category", value: (f) => CATEGORY_LABELS[f.quantum_readiness.category] || f.quantum_readiness.category },
  { label: "Migration Guidance", value: (f) => f.quantum_readiness.migration_guidance },
  { label: "Priority", value: (f) => f.priority },
];

function rowHtml(f) {
  const qr = f.quantum_readiness;
  return `
    <tr>
      <td><button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td><code>${escapeHtml(f.cve || "—")}</code></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml((f.asset && f.asset.name) || "—")}</td>
      <td><span class="badge ${CATEGORY_BADGE_CLASS[qr.category] || ""}">${escapeHtml(CATEGORY_LABELS[qr.category] || qr.category)}</span></td>
      <td>${escapeHtml(qr.migration_guidance)}</td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const { findings, summary, nist_ir_8547: ir8547 } = await api.quantumReadiness();

  let page = 1;
  let categoryFilter = "all";

  function renderRows() {
    const filtered = categoryFilter === "all" ? findings : findings.filter((f) => f.quantum_readiness.category === categoryFilter);
    const paged = paginate(filtered, page);
    page = paged.page;
    const tbody = container.querySelector("#qr-body");
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="6" class="empty-state">No findings match the current filter.</td></tr>`;
    const paginationEl = container.querySelector("#qr-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#qr-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${findings.length} finding(s)`;
  }

  container.innerHTML = `
    <p class="subtitle">
      Real findings whose title names classical asymmetric cryptography (RSA/ECDSA/
      Diffie-Hellman) or a legacy TLS/cipher weakness - an inventory of what a real
      post-quantum migration effort would need to review, not a live quantum-attack
      detector.
    </p>

    <div class="callout callout-warn">
      ⚠️ This is <strong>not a "quantum vulnerability scanner"</strong> - no such
      product category exists to honestly claim, since a quantum computer capable of
      breaking real-world RSA/ECDSA doesn't exist yet. Categories below are a
      disclosed keyword classification against each finding's own real title (same
      "keyword-matched, not authoritative" honesty tier as the Risk Dashboard's MITRE
      ATT&amp;CK heat map) - see
      <code>remediation/enrichment/quantum_readiness.py</code>'s module docstring for
      the full method and its limitations.
    </div>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${summary.total}</div><div class="kpi-label">Quantum-relevant findings</div></div>
      <div class="kpi-card kpi-danger"><div class="kpi-value">${summary.asymmetric_crypto}</div><div class="kpi-label">Asymmetric crypto (RSA/ECDSA/DH)</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${summary.legacy_protocol}</div><div class="kpi-label">Legacy TLS/cipher</div></div>
    </div>

    <details class="faq-item">
      <summary>What's the real migration standard behind this? (and what isn't quantum yet)</summary>
      <p>NIST finalized three real post-quantum cryptography standards in August 2024:
      <strong>FIPS 203 (ML-KEM)</strong> for key exchange - the Diffie-Hellman/RSA
      replacement; <strong>FIPS 204 (ML-DSA)</strong> for digital signatures - the
      RSA/ECDSA replacement; and <strong>FIPS 205 (SLH-DSA)</strong>, a structurally
      different hash-based signature scheme kept as a backup algorithm. See
      <a href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank" rel="noopener">csrc.nist.gov/pubs/fips/203</a>
      (and /204, /205).</p>
      <p><strong>Asymmetric crypto</strong> findings (RSA/ECDSA/Diffie-Hellman usage)
      are the genuinely quantum-relevant case - a sufficiently large quantum computer
      running Shor's algorithm breaks exactly these. <strong>NIST IR 8547</strong>
      (Initial Public Draft, November 2024 - not yet finalized) targets deprecation
      after <strong>${ir8547.deprecated_by}</strong> and disallowal after
      <strong>${ir8547.disallowed_by}</strong> for the weaker, 112-bit-strength
      classical-parameter tier (e.g. RSA-2048, ECDSA P-256) - stronger parameters skip
      the earlier milestone. NSA's CNSA 2.0 is a separate, National-Security-Systems-
      specific framework with its own different category-by-category schedule
      (2025-2033), not the same dates as IR 8547's - the two are easy to conflate but
      apply to different audiences with different timelines.</p>
      <p><strong>Legacy TLS/cipher</strong> findings (SSLv2/SSLv3, 3DES, RC4,
      export-grade ciphers, MD5/SHA-1 certificate signatures) are classically broken
      already - nothing to do with quantum computers specifically - included because a
      legacy TLS stack exhibiting these is real, practical evidence worth auditing for
      accompanying asymmetric-crypto usage as part of the same modernization effort,
      not because they're quantum-vulnerable themselves.</p>
      <p class="filter-count" style="margin-top:8px">
        See <a href="/faq" data-link>the FAQ</a> and
        <code>docs/COMPLIANCE_MAPPING.md</code> for the full disclosure.
      </p>
    </details>

    <h2 style="margin-top:28px">Findings</h2>
    <div class="filter-bar">
      <label>Category
        <select id="qr-f-category">
          <option value="all">All (${findings.length})</option>
          <option value="asymmetric-crypto">${escapeHtml(CATEGORY_LABELS["asymmetric-crypto"])} (${summary.asymmetric_crypto})</option>
          <option value="legacy-protocol">${escapeHtml(CATEGORY_LABELS["legacy-protocol"])} (${summary.legacy_protocol})</option>
        </select>
      </label>
      <span class="filter-count" id="qr-count"></span>
    </div>
    ${exportButtonsHtml("quantum-readiness")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>CVE</th><th>Title</th><th>Asset</th><th>Category</th><th>Migration Guidance</th></tr></thead>
        <tbody id="qr-body"></tbody>
      </table>
    </div>
    <div id="qr-pagination"></div>`;

  renderRows();
  container.querySelector("#qr-f-category").addEventListener("change", (e) => {
    categoryFilter = e.target.value;
    page = 1;
    renderRows();
  });
  wirePagination(container, (p) => { page = p; renderRows(); });
  wireExportButtons(container, "quantum-readiness", {
    getRows: () => (categoryFilter === "all" ? findings : findings.filter((f) => f.quantum_readiness.category === categoryFilter)),
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-quantum-readiness",
  });
  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const finding = findings.find((f) => f.id === btn.dataset.findingId);
    if (finding) openFindingDetail(finding);
  });
}
