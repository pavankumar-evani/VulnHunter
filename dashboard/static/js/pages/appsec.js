// Application Security hub: a single landing page that rolls up the AppSec-specific
// finding categories (SAST, DAST, SCA, Secrets-in-code, Container, API) into one view
// with a count and a deep link into each's real, pre-filtered page - rather than making
// a user hunt across /vulnhunt and /queue to answer "what does our application security
// posture look like."
// Infrastructure Vulnerability Management and Certificate/TLS findings are deliberately
// NOT rolled up here - those are asset/network-facing categories, not application security
// ones, and each already has its own top-level Security Domains nav entry.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { categoryFor } from "./vulnhunt.js";
import { findingsTableHtml, wireFindingsTable } from "../findingsTable.js";

export const title = "Application Vulnerabilities";

function domainCard({ href, iconName, label, count, note }) {
  return `
    <a class="domain-card" href="${href}" data-link>
      <span class="domain-card-icon">${icon(iconName, 22)}</span>
      <span class="domain-card-count">${count}</span>
      <span class="domain-card-label">${escapeHtml(label)}</span>
      <span class="domain-card-note">${escapeHtml(note)}</span>
    </a>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [vh, queue] = await Promise.all([api.vulnhunt(), api.queue()]);

  const sastFindings = vh.available ? vh.findings : [];
  const sastTotal = sastFindings.length;
  const secretsTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Secrets").length;
  const containerTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Container").length;
  const apiTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "API").length;
  const scaDastFindings = queue.findings.filter((f) => f.scan_type === "sca" || f.scan_type === "dast");
  const scaTotal = scaDastFindings.filter((f) => f.scan_type === "sca").length;
  const dastTotal = scaDastFindings.filter((f) => f.scan_type === "dast").length;

  container.innerHTML = `
    <p class="subtitle">Application-layer findings only - source code (SAST), bundled/
    third-party libraries (SCA), hardcoded secrets, dynamic/runtime testing (DAST),
    container/base-image issues, and API-security findings.
    Infrastructure and certificate findings live under their own Security Domains entries.</p>

    <div class="domain-card-grid">
      ${domainCard({
        href: "/vulnhunt", iconName: "scan", label: "SAST — Code Scan", count: sastTotal,
        note: vh.available ? "Source-code findings from the last /vulnhunt run." : "No scan results yet.",
      })}
      ${domainCard({
        href: "/queue?category=dast", iconName: "dast", label: "DAST — Dynamic Testing", count: dastTotal,
        note: dastTotal ? "Findings from a runtime/dynamic scan." : "No sample DAST data yet - see the FAQ.",
      })}
      ${domainCard({
        href: "/queue?category=sca", iconName: "sca", label: "SCA — Software Composition", count: scaTotal,
        note: "Vulnerable third-party / bundled library findings.",
      })}
      ${domainCard({
        href: "/vulnhunt?category=Secrets", iconName: "secrets", label: "Secrets Management", count: secretsTotal,
        note: "Hardcoded credentials/keys found in source (CWE-798).",
      })}
      ${domainCard({
        href: "/vulnhunt?category=Container", iconName: "container", label: "Container Vulnerabilities", count: containerTotal,
        note: "Base-image and Dockerfile issues - root user, baked-in secrets, unpinned tags.",
      })}
      ${domainCard({
        href: "/vulnhunt?category=API", iconName: "api", label: "API Vulnerabilities", count: apiTotal,
        note: apiTotal ? "Missing auth, permissive CORS, or mass-assignment findings." : "No sample API-security finding yet - see the FAQ.",
      })}
    </div>

    <div class="callout">
      This is a rollup view, not a separate data source - every count above comes straight
      from <code>/api/vulnhunt</code> and <code>/api/queue</code>, the same data the Code
      Scan and Remediation Queue pages already show. Click any card to jump to the
      pre-filtered underlying view.
    </div>

    <h2>SCA and DAST findings (SLA-tracked)</h2>
    <p class="subtitle">
      SAST, Secrets, Container, and API findings come from source-code scanning
      (<a href="/vulnhunt" data-link>Code Scan Results</a>) and aren't SLA-tracked queue
      items by design - see the callout there. SCA and DAST findings are, so they get
      the same live findings table as the Remediation Queue.
    </p>
    ${findingsTableHtml("appsec-hub")}`;

  wireFindingsTable(container, scaDastFindings, {
    exportGroupId: "appsec-hub",
    filenameBase: "vulnhunter-appsec-sca-dast",
  });
}
