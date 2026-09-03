// Dependencies: SBOM-aware blast radius for every open-source package with a real
// finding attached (remediation/enrichment/sbom.py + the `dependency` field on a
// finding - see remediation/schema/normalized-finding-schema.md). Empty by default -
// `dependency` is only populated after a /remediate run that supplied a CycloneDX SBOM
// alongside the scanner exports (see vuln-ingest-normalizer.md's "Populating
// dependency" section) - this page says so honestly rather than hiding behind a blank
// screen.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { openFindingDetail } from "../findingDetail.js";

export const title = "Dependencies";

function findingChipsHtml(findings) {
  return findings.map((f) => `
    <button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">
      ${escapeHtml(f.id)} — ${escapeHtml(f.title)}
    </button>`).join("<br>");
}

function packageCardHtml(entry) {
  const dep = entry.dependency;
  const fixed = dep.fixed_version
    ? `<span class="badge badge-auto_approvable">fix: ${escapeHtml(dep.fixed_version)}</span>`
    : `<span class="badge badge-medium">fixed version unknown</span>`;
  const radiusHtml = entry.blast_radius.length
    ? `<ul style="margin:4px 0 0; padding-left:18px">${entry.blast_radius.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>`
    : `<span class="muted">No other component in the SBOM depends on this one.</span>`;

  return `
    <div class="card" style="margin-bottom:14px">
      <h4 style="margin:0 0 4px">${escapeHtml(dep.package)} <span class="muted">(${escapeHtml(dep.ecosystem || "ecosystem unknown")})</span></h4>
      <p class="muted" style="margin:0 0 10px">
        Current version <code>${escapeHtml(dep.version || "?")}</code>
        ${dep.direct === false ? " — transitive dependency" : dep.direct === true ? " — direct dependency" : ""}
        &nbsp;${fixed}
      </p>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th style="width:50%">Findings referencing this package</th><th style="width:50%">Blast radius — other components affected if unfixed</th></tr></thead>
          <tbody>
            <tr>
              <td class="wrap-cell">${findingChipsHtml(entry.findings)}</td>
              <td class="wrap-cell">${radiusHtml}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ packages }, queue] = await Promise.all([api.dependencies(), api.queue()]);
  // /api/dependencies' own per-finding rows are a minimal {id, title, asset} subset -
  // look up the full finding (severity, CVE, KEV/EPSS, description, ...) from the live
  // queue so the detail modal renders exactly as it does everywhere else, same pattern
  // as attackPaths.js.
  const findingById = new Map(queue.findings.map((f) => [f.id, f]));

  container.innerHTML = `
    <p class="subtitle">
      Real, SBOM-derived dependency data - which findings trace back to a specific open-source
      package, its confirmed fixed version (when known), and how many other components in the
      SBOM would still be exposed until it's upgraded. Populated only for SCA findings whose
      package was matched against a CycloneDX SBOM during ingestion - see
      <code>remediation/enrichment/sbom.py</code> and the Finding schema's <code>dependency</code>
      field.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${packages.length}</div><div class="kpi-label">Packages with dependency data</div></div>
    </div>

    <div id="dependencies-body">
      ${packages.length
        ? packages.map(packageCardHtml).join("")
        : `<div class="empty-state">No findings currently carry SBOM-matched dependency data. This populates after a <code>/remediate</code> run that supplied a CycloneDX SBOM file (e.g. <code>remediation/sample-data/sbom.json</code>) alongside the scanner exports.</div>`}
    </div>`;

  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const f = findingById.get(btn.dataset.findingId);
    if (f) openFindingDetail(f);
  });
}
