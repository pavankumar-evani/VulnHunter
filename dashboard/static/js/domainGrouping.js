// Groups a live-queue finding into its security-domain bucket: infra_category label
// (OS/Network/.../Runtime) when the finding is infra-vm, else its scan_type_label
// (Certificate & TLS Lifecycle Management, SCA, DAST, Repository Secret Scanning,
// AI/ML Security) - so every finding lands in exactly one meaningful, already-real
// bucket. Extracted out of compensatingControls.js (its original, single caller) so
// threatIntel.js's own domain grouping reuses the identical definition instead of a
// second, potentially drifting copy - same "exactly one place defines this" rule
// risk_scoring.py's asset_criticality_score() reuse already applies on the Python side.
import { INFRA_CATEGORY_LABELS } from "./infraTypes.js";
import { SCAN_TYPE_LABELS } from "./scanTypes.js";

export function groupLabelFor(f) {
  if (f.infra_category) return INFRA_CATEGORY_LABELS[f.infra_category] || f.infra_category;
  return f.scan_type_label || SCAN_TYPE_LABELS[f.scan_type] || "Other";
}
