// Reference list of the real vendor/government/vulnerability-database/security-news
// sources a zero-day-tracking workflow actually pulls from, matching the same
// "real, citable source, honestly marked live-vs-reference" pattern as
// threatActorGroups.js/adaptorCatalog.js. `integrated: true` entries are genuinely
// already wired into this pipeline (remediation/enrichment/kev_epss.py fetches real
// CISA KEV + FIRST.org EPSS data; generate_bulk_findings.py's collect_real_cves()
// sources CVE records from NVD's own public API) - every other entry is a real,
// verified URL with no working scraper/poller behind it yet (same reference-tier
// honesty as the Adaptors catalog).
//
// `refreshCadence` is the illustrative TARGET cadence a real deployment would poll
// these on, not a claim that this demo actually runs a scheduled job today - see
// dashboard/static/js/pages/threatIntel.js's own disclosure for what's real now.
export const THREAT_INTEL_FEEDS = [
  { id: "cisa-kev", name: "CISA Known Exploited Vulnerabilities (KEV) Catalog", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", category: "Government / CERT", integrated: true, refreshCadence: "Every 12 hours" },
  { id: "nvd", name: "NVD (National Vulnerability Database)", url: "https://nvd.nist.gov/vuln/search", category: "Vulnerability Database", integrated: true, refreshCadence: "Every 12 hours" },
  { id: "first-epss", name: "FIRST.org EPSS", url: "https://www.first.org/epss/", category: "Vulnerability Database", integrated: true, refreshCadence: "Every 12 hours" },
  { id: "msrc", name: "Microsoft Security Response Center", url: "https://msrc.microsoft.com/update-guide/", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "cisco-psirt", name: "Cisco Security Advisories", url: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "apple-security", name: "Apple Security Updates", url: "https://support.apple.com/en-us/100100", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "oracle-csa", name: "Oracle Critical Patch Updates / Security Alerts", url: "https://www.oracle.com/security-alerts/", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "qualys-advisories", name: "Qualys Security Advisories", url: "https://www.qualys.com/security-advisories/", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "tenable-security", name: "Tenable Security Advisories", url: "https://www.tenable.com/security", category: "Vendor Advisory", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "crowdstrike-intel", name: "CrowdStrike Threat Intel & Research", url: "https://www.crowdstrike.com/en-us/blog/", category: "Security News / Research", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "krebs", name: "Krebs on Security", url: "https://krebsonsecurity.com/", category: "Security News / Research", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "thehackernews", name: "The Hacker News", url: "https://thehackernews.com/", category: "Security News / Research", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "bleepingcomputer", name: "Bleeping Computer Security", url: "https://www.bleepingcomputer.com/news/security/", category: "Security News / Research", integrated: false, refreshCadence: "Every 12 hours" },
  { id: "sg-csa", name: "Singapore CSA Alerts & Advisories", url: "https://www.csa.gov.sg/alerts-and-advisories/", category: "Government / CERT", integrated: false, refreshCadence: "Every 12 hours" },

  // Dark web / identity-exposure feeds - same reference-tier honesty as every entry
  // above; researched and verified 2026-08-05 (see the Dark Web & Identity Exposure
  // Monitoring section on /threat-intel for the full disclosure on what this app does
  // and doesn't have today). `note` records the specific free-vs-paid nuance verified
  // for each, rather than a blanket "free" claim that wouldn't survive scrutiny.
  { id: "hibp", name: "Have I Been Pwned", url: "https://haveibeenpwned.com/", category: "Dark Web / Identity Exposure", integrated: false, refreshCadence: "Every 12 hours",
    note: "Pwned Passwords (password-hash lookup) is genuinely free, no API key - breach search by email/domain now requires a paid subscription key (verified against HIBP's own API docs)." },
  { id: "misp", name: "MISP (Malware Information Sharing Platform)", url: "https://www.misp-project.org/", category: "Dark Web / Identity Exposure", integrated: false, refreshCadence: "Every 12 hours",
    note: "Free, open-source, self-hosted threat-intel platform - a real deployment would feed dark-web/leak-site indicators into its own MISP instance, not subscribe to a hosted feed." },
  { id: "socradar-labs", name: "SOCRadar Labs (free tools)", url: "https://socradar.io/labs/", category: "Dark Web / Identity Exposure", integrated: false, refreshCadence: "Every 12 hours",
    note: "Vendor's no-cost tier for external attack-surface and leaked-credential lookup - a smaller, free complement to its own paid dark-web-monitoring platform." },
];
