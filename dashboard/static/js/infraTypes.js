// Mirrors remediation/enrichment/infra_classification.py's INFRA_CATEGORIES/
// INFRA_CATEGORY_LABELS on the client side - same "small hardcoded label map in JS"
// pattern already used by scanTypes.js for the broader scan-type taxonomy. Listed in
// full (including "cloud", which has no sample data yet) so a deep link or filter
// dropdown shows every real known sub-category, not just today's findings.
export const INFRA_CATEGORIES = ["os", "network", "network-security", "ot", "cloud"];

export const INFRA_CATEGORY_LABELS = {
  "os": "OS Vulnerabilities",
  "network": "Network",
  "network-security": "Network Security",
  "ot": "OT / IoT",
  "cloud": "Cloud Infrastructure",
};
