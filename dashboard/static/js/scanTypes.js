// Mirrors remediation/enrichment/scan_type_mapping.py's SCAN_TYPES/SCAN_TYPE_LABELS on the
// client side, so nav deep-links and filter dropdowns can list every category consistently -
// including ones with no current sample data (e.g. DAST) - instead of only listing whatever
// happens to be present in today's findings. Same "small hardcoded label map in JS" pattern
// already used by vulnhunt.js's CWE_CATEGORY.
export const SCAN_TYPE_LABELS = {
  "infra-vm": "Infrastructure Vulnerability Management",
  "sca": "Software Composition Analysis (SCA)",
  "cert-mgmt": "Certificate & TLS Lifecycle Management",
  "dast": "Dynamic Application Security Testing (DAST)",
};

// "sast" is deliberately excluded here: /remediate findings (what /queue and /assets show)
// are never tagged scan_type "sast" - SAST findings live entirely in the separate /vulnhunt
// data path (see scan_type_mapping.py's module docstring). Listing it in the queue's filter
// would only ever show zero rows, so the Code Scan page is where "SAST" actually lives.
export const QUEUE_SCAN_TYPES = ["infra-vm", "sca", "cert-mgmt", "dast"];
