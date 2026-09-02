import { escapeHtml } from "./dom.js";

// Shared term definitions for the right-hand Insights panel (insightsPanel.js) - one
// place defining what each term means in THIS app specifically, since several (Priority,
// Risk Score, Remediation Mechanism/Domain, Facing) mean something narrower or
// differently-scoped here than the term suggests generically. Pages reference a subset
// of these keys rather than repeating the definition text inline.
export const GLOSSARY = {
  priority: {
    label: "Priority",
    text: "A weighted score (severity + asset criticality + asset type), with KEV/EPSS overrides - tiered Critical/High/Medium/Low. Distinct from raw Severity. Live-configurable on the Priority Rules page.",
  },
  severity: {
    label: "Severity",
    text: "The raw CVSS-based tier (Critical/High/Medium/Low) for a finding, independent of which asset it's on.",
  },
  sla: {
    label: "SLA",
    text: "The remediation window (in days) a finding gets based on its Priority tier - breached/at-risk/on-track, tracked per finding.",
  },
  kev: {
    label: "KEV",
    text: "CISA's Known Exploited Vulnerabilities catalog - a CVE listed here is confirmed to have been exploited in the real world, not just theoretically vulnerable.",
  },
  epss: {
    label: "EPSS",
    text: "FIRST.org's Exploit Prediction Scoring System - a live-fetched probability (0-100%) that a CVE will be exploited in the next 30 days.",
  },
  riskScore: {
    label: "Risk Score",
    text: "Impact × Likelihood (0-100) per asset - a NIST SP 800-30-inspired, disclosed simplification, not a certified RMF/800-30 assessment.",
  },
  impactScore: {
    label: "Impact Score",
    text: "The severity + asset-criticality component of Risk Score - how bad it would be if this asset were compromised.",
  },
  likelihoodScore: {
    label: "Likelihood Score",
    text: "The KEV + EPSS + exploit-criteria + EOL/EOS component of Risk Score - how likely this asset is to actually be targeted.",
  },
  riskTier: {
    label: "Risk Tier",
    text: "Critical/High/Medium/Low bucket derived from an asset's Risk Score, using the same tier convention as Severity/Priority elsewhere.",
  },
  eol: {
    label: "EOL / EOL-soon",
    text: "End of Life / End of Support - the vendor no longer ships security patches for this OS/software version (or will stop soon). 'Unknown' is a real, honest absence of data, not a downgraded risk.",
  },
  facing: {
    label: "Facing (Internal/External)",
    text: "A manually-set classification of whether an asset is reachable from the public internet - never auto-detected from a network scan in this app.",
  },
  exploitCriteria: {
    label: "Exploit Criteria",
    text: "Admin-configurable rules (e.g. \"KEV-listed AND Critical severity\") that flag a finding as an urgent zero-day-style watch item - live-editable on the Exploit Criteria page.",
  },
  compensatingControl: {
    label: "Compensating Control",
    text: "A documented mitigation (e.g. WAF rule, network segmentation) covering a finding that can't yet be patched - a suggestion to verify, not a confirmed control.",
  },
  exception: {
    label: "Exception / Waiver",
    text: "A time-boxed, approved acceptance of a finding's risk instead of remediating it - has its own approval/expiry/revocation workflow.",
  },
  remediationMechanism: {
    label: "Remediation Mechanism",
    text: "The real-world tool that would normally patch this asset class (e.g. SCCM, MDM/Intune, vendor firmware update) - purely informational, not a working integration from this app.",
  },
  remediationDomain: {
    label: "Remediation Domain",
    text: "Which of this app's own fixers can actually handle a finding - windows-server/unix-server get a generated Ansible playbook, iot-ot-device gets a compensating-control recommendation instead; every other asset type is manual-only today.",
  },
  threatIntel: {
    label: "Threat Intel tagging",
    text: "Which real feed(s) (CISA KEV / NVD / FIRST.org EPSS) and/or matched threat-actor group correlate to a finding - shown as a column on most finding tables.",
  },
  attack: {
    label: "MITRE ATT&CK",
    text: "The real, industry-standard adversary tactic/technique taxonomy. Findings are tagged via keyword heuristic in this app, not authoritative attribution.",
  },
  scanType: {
    label: "Scan Type",
    text: "Which pipeline produced a finding - SAST, DAST, SCA, Secret Scanning, IaC, Runtime, Certificate Management, Infrastructure-VM, or AI/ML.",
  },
  assetCriticality: {
    label: "Asset Criticality",
    text: "Name-keyword (e.g. \"PROD\", \"DB\") and asset-type weighting used in both Priority and Risk scoring - editable in Priority Rules.",
  },
  owner: {
    label: "Owner / Team",
    text: "Who's responsible for an asset - set manually or via CMDB CSV import on Asset Inventory; not auto-detected. Most assets in this demo dataset have neither set.",
  },
};

// `keys`: array of GLOSSARY keys to render, in the given order.
export function glossaryHtml(keys) {
  const entries = keys.map((k) => GLOSSARY[k]).filter(Boolean);
  if (!entries.length) return "";
  return `
    <dl class="insight-glossary">
      ${entries.map((e) => `<dt>${escapeHtml(e.label)}</dt><dd>${escapeHtml(e.text)}</dd>`).join("")}
    </dl>`;
}
