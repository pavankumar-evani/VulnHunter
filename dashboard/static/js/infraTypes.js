// Mirrors remediation/enrichment/infra_classification.py's INFRA_CATEGORIES/
// INFRA_CATEGORY_LABELS on the client side - same "small hardcoded label map in JS"
// pattern already used by scanTypes.js for the broader scan-type taxonomy. Listed in
// full (including "cloud", which has no sample data yet) so a deep link or filter
// dropdown shows every real known sub-category, not just today's findings.
export const INFRA_CATEGORIES = ["os", "endpoint", "network", "network-security", "ot", "virtualization", "cloud", "apps", "printer", "iac", "runtime"];

export const INFRA_CATEGORY_LABELS = {
  "os": "Server Vulnerabilities (Windows, Linux/Unix)",
  "endpoint": "End-User Devices (SCCM/MDM-managed)",
  "network": "Network",
  "network-security": "Network Security",
  "ot": "OT / IoT",
  "virtualization": "Virtualization (Hypervisor/VM Platform)",
  "cloud": "Cloud Infrastructure",
  "apps": "OS Applications",
  "printer": "Printers",
  "iac": "Infrastructure-as-Code",
  "runtime": "Container/Host Runtime Security",
};
