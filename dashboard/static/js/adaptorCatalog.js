// Central catalog for the consolidated Adaptors hub (/adaptors) - one dropdown/filter
// instead of six separate sidebar entries under four different group headings. Two
// tiers, both honestly labeled:
//
// - "live" connectors have a real, working dashboard page (existing ServiceNow/Jira/
//   Splunk/CrowdStrike/Infoblox/Axonius modules, unchanged) - a preview/send form or a
//   documented-usage reference page, same as before this consolidation.
// - "reference" connectors are new catalog entries: real, accurate facts about a real
//   product's API (auth model, real endpoint shape, what data it would carry) with NO
//   working preview/send wired up yet - the honest next step above "not in this repo at
//   all," same "built against docs, not yet exercised against a live instance" spirit as
//   the live connectors, just one stage earlier. See docs/INTEGRATIONS.md for the same
//   catalog in doc form.
import { icon } from "./icons.js";

export const CATEGORIES = [
  "Ticketing / SOAR",
  "SIEM / SOAR",
  "Vulnerability Scanners",
  "Cloud Security (CNAPP)",
  "XDR / EDR",
  "Asset Discovery / IPAM",
  "Communication / On-Call",
];

export const CONNECTORS = [
  // --- Live (existing, unchanged dashboard pages) ---
  { key: "servicenow", label: "ServiceNow", category: "Ticketing / SOAR", iconName: "servicenow", status: "live",
    module: () => import("./pages/servicenow.js"),
    blurb: "Creates an Incident per finding via the Table API, idempotently." },
  { key: "jira", label: "Jira Cloud", category: "Ticketing / SOAR", iconName: "jira", status: "live",
    module: () => import("./pages/jira.js"),
    blurb: "Creates an Issue per finding via the REST API v3, idempotently (label-keyed)." },
  { key: "splunk", label: "Splunk", category: "SIEM / SOAR", iconName: "splunk", status: "live",
    module: () => import("./pages/splunk.js"),
    blurb: "Pushes each finding to Splunk as an HTTP Event Collector event." },
  { key: "xdr", label: "CrowdStrike Falcon", category: "XDR / EDR", iconName: "xdr", status: "live",
    module: () => import("./pages/xdr.js"),
    blurb: "Pulls EDR/XDR alerts via OAuth2 client-credentials + query/fetch-entities." },
  { key: "infoblox", label: "Infoblox", category: "Asset Discovery / IPAM", iconName: "infoblox", status: "live",
    module: () => import("./pages/infoblox.js"),
    blurb: "Pulls DNS host records via WAPI, normalizes into asset-inventory entries." },
  { key: "axonius", label: "Axonius", category: "Asset Discovery / IPAM", iconName: "axonius", status: "live",
    module: () => import("./pages/axonius.js"),
    blurb: "Pulls aggregated device records via the devices API, normalizes into asset-inventory entries." },

  // --- Reference catalog (real product/API facts, no working preview/send yet) ---
  { key: "qualys", label: "Qualys VMDR", category: "Vulnerability Scanners", iconName: "scan", status: "reference",
    blurb: "Enterprise vulnerability management - the other major player alongside Tenable.",
    authMethod: "API key + Basic Auth (username/password) per Qualys Cloud Platform pod",
    integrationShape: "Pull: query the VM/PC API for host-based findings, normalize into the same schema as the Tenable connector (both are asset-vulnerability-scan sources).",
    dataFlow: "Findings only (CVE-scoped host vulnerabilities) - would route into vuln-ingest-normalizer.md alongside Tenable/Armis." },
  { key: "rapid7", label: "Rapid7 InsightVM", category: "Vulnerability Scanners", iconName: "scan", status: "reference",
    blurb: "Cloud or on-prem vulnerability management with a documented REST API.",
    authMethod: "API key (X-Api-Key header) against the InsightVM/Insight Platform REST API",
    integrationShape: "Pull: query assets/vulnerabilities endpoints, normalize into the same schema as Tenable/Qualys.",
    dataFlow: "Findings only (CVE-scoped host vulnerabilities)." },
  { key: "wiz", label: "Wiz", category: "Cloud Security (CNAPP)", iconName: "cloud", status: "reference",
    blurb: "Agentless cloud security posture + vulnerability scanning across AWS/Azure/GCP.",
    authMethod: "OAuth2 client-credentials against Wiz's GraphQL API",
    integrationShape: "Pull: query issues/vulnerabilities via GraphQL, normalize cloud-resource findings into asset.type=cloud-infrastructure - the category this repo's own demo data currently has none of.",
    dataFlow: "Findings (cloud misconfig + vulnerable workload CVEs) and cloud asset inventory." },
  { key: "prismacloud", label: "Prisma Cloud", category: "Cloud Security (CNAPP)", iconName: "cloud", status: "reference",
    blurb: "Palo Alto Networks' CNAPP - posture management, workload protection, and IaC scanning.",
    authMethod: "API key + secret, token exchanged via the Prisma Cloud login endpoint",
    integrationShape: "Pull: query the alerts/compliance API, normalize into cloud-infrastructure findings.",
    dataFlow: "Findings (cloud posture/compliance violations) and cloud asset inventory." },
  { key: "aws-security-hub", label: "AWS Security Hub", category: "Cloud Security (CNAPP)", iconName: "cloud", status: "reference",
    blurb: "AWS's native aggregation point for findings from GuardDuty, Inspector, IAM Access Analyzer, and partner tools.",
    authMethod: "AWS IAM credentials (SigV4-signed requests) via the AWS SDK",
    integrationShape: "Pull: GetFindings API call (AWS Security Finding Format, a real published JSON schema), normalize ASFF findings into this repo's schema.",
    dataFlow: "Findings already in a standardized format (ASFF) - one of the more mechanical mappings in this catalog." },
  { key: "defender-cloud", label: "Microsoft Defender for Cloud", category: "Cloud Security (CNAPP)", iconName: "cloud", status: "reference",
    blurb: "Azure's native CNAPP - posture management and workload protection across Azure/AWS/GCP.",
    authMethod: "Azure AD (Entra ID) OAuth2 service principal against the Azure Resource Manager API",
    integrationShape: "Pull: query the Microsoft.Security/assessments and alerts APIs, normalize into cloud-infrastructure findings.",
    dataFlow: "Findings (posture assessments + security alerts) and cloud asset inventory." },
  { key: "qradar", label: "IBM QRadar", category: "SIEM / SOAR", iconName: "risk", status: "reference",
    blurb: "Long-established enterprise SIEM with a documented REST API.",
    authMethod: "SEC token (API key) via the QRadar REST API's Authorization header",
    integrationShape: "Push: send findings as QRadar offenses/events via the ariel search or events API - similar shape to the Splunk HEC connector.",
    dataFlow: "Push only, same direction as Splunk - findings out, not alerts in." },
  { key: "sentinel", label: "Microsoft Sentinel", category: "SIEM / SOAR", iconName: "risk", status: "reference",
    blurb: "Azure-native cloud SIEM/SOAR built on Log Analytics.",
    authMethod: "Azure AD (Entra ID) OAuth2 service principal, ingested via the Log Analytics Data Collector API or Microsoft Sentinel's incidents API",
    integrationShape: "Push (findings as custom log events) or pull (query Sentinel incidents as a source) - could support either direction.",
    dataFlow: "Bidirectional-capable, same real distinction the CrowdStrike/ServiceNow connectors already draw for push vs. pull." },
  { key: "cortex-xsoar", label: "Palo Alto Cortex XSOAR", category: "SIEM / SOAR", iconName: "risk", status: "reference",
    blurb: "SOAR platform for automated incident response playbooks.",
    authMethod: "API key against the Cortex XSOAR REST API",
    integrationShape: "Push: create an Incident per finding via the incident creation API, triggering the org's own XSOAR playbooks - same idea as the ServiceNow/Jira ticketing connectors, but incident-response-oriented rather than ITSM-oriented.",
    dataFlow: "Push only - findings become XSOAR incidents." },
  { key: "sentinelone", label: "SentinelOne", category: "XDR / EDR", iconName: "xdr", status: "reference",
    blurb: "Autonomous EDR/XDR platform, a direct alternative to CrowdStrike Falcon.",
    authMethod: "API token against the SentinelOne Management Console REST API",
    integrationShape: "Pull: query the threats API, normalize behavioral detections into findings - same architecture as the existing CrowdStrike connector (cve/cvss/kev/epss stay null, since these are behavioral detections, not CVE-scoped).",
    dataFlow: "Findings only (behavioral EDR detections, not CVE-scoped)." },
  { key: "defender-endpoint", label: "Microsoft Defender for Endpoint", category: "XDR / EDR", iconName: "xdr", status: "reference",
    blurb: "Microsoft's EDR/XDR platform, tightly integrated with Azure AD and Intune.",
    authMethod: "Azure AD (Entra ID) OAuth2 app registration against the Microsoft Graph Security API",
    integrationShape: "Pull: query the Graph Security API's alerts endpoint, normalize into findings - same architecture as CrowdStrike/SentinelOne.",
    dataFlow: "Findings only (behavioral EDR detections, not CVE-scoped)." },
  { key: "slack", label: "Slack", category: "Communication / On-Call", iconName: "bell", status: "reference",
    blurb: "Real-time notifications for new KEV-listed findings, SLA breaches, or exceptions expiring.",
    authMethod: "Bot token (OAuth2) via the Slack Web API's chat.postMessage method, or an Incoming Webhook URL",
    integrationShape: "Push only: post a formatted message to a channel when a notification-worthy event fires (mirrors dashboard/static/js/notifications.js's own in-app notification triggers).",
    dataFlow: "Push only - a thin fan-out of the same events already shown in the in-app notification bell, to a channel instead of (or alongside) the UI." },
  { key: "teams", label: "Microsoft Teams", category: "Communication / On-Call", iconName: "bell", status: "reference",
    blurb: "Same real-time notification use case as Slack, for Teams-based organizations.",
    authMethod: "Incoming Webhook URL, or Microsoft Graph API (OAuth2) for richer adaptive-card messages",
    integrationShape: "Push only: post a message/adaptive card to a channel on the same notification-worthy events as the Slack connector.",
    dataFlow: "Push only, same shape as the Slack entry above." },
  { key: "pagerduty", label: "PagerDuty", category: "Communication / On-Call", iconName: "bell", status: "reference",
    blurb: "On-call paging for the subset of findings urgent enough to wake someone up (confirmed KEV-listed, SLA-breached Critical).",
    authMethod: "Events API v2 routing key (a per-service integration key, not a full API token)",
    integrationShape: "Push only: trigger/resolve/acknowledge an incident via the Events API v2 - deliberately narrower than a general notification fan-out, reserved for genuinely page-worthy findings.",
    dataFlow: "Push only, and only for the highest-urgency subset - unlike Slack/Teams, this isn't meant to carry every notification." },
];

export function connectorByKey(key) {
  return CONNECTORS.find((c) => c.key === key);
}

export function connectorCardHtml(c) {
  return `
    <span class="adaptor-option-icon">${icon(c.iconName, 16)}</span>
    <span>${c.label}</span>
    <span class="adaptor-option-status adaptor-status-${c.status}">${c.status === "live" ? "Preview available" : "Reference"}</span>`;
}
