// Thin fetch() wrapper over the FastAPI JSON API in dashboard/app.py. Every page
// module goes through this - no page ever calls fetch() directly.

async function request(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail = (data && data.detail) || res.statusText || `HTTP ${res.status}`;
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  overview: () => request("GET", "/api/overview"),
  threatIntelFreshness: () => request("GET", "/api/threat-intel/freshness"),
  threatIntelRefreshNow: (confirm) => request("POST", "/api/threat-intel/refresh-now", { confirm }),
  vulnhunt: () => request("GET", "/api/vulnhunt"),
  remediate: () => request("GET", "/api/remediate"),
  playbook: (filename) => request("GET", `/api/playbooks/${encodeURIComponent(filename)}`),
  queue: () => request("GET", "/api/queue"),
  attackPaths: () => request("GET", "/api/attack-paths"),
  dependencies: () => request("GET", "/api/dependencies"),
  getPriorityRules: () => request("GET", "/api/priority-rules"),
  savePriorityRules: (rulesText) => request("POST", "/api/priority-rules", { rules_text: rulesText }),
  getExploitCriteria: () => request("GET", "/api/exploit-criteria"),
  saveExploitCriteria: (rulesText) => request("POST", "/api/exploit-criteria", { rules_text: rulesText }),
  previewExploitCriteria: (rulesText) => request("POST", "/api/exploit-criteria/preview", { rules_text: rulesText }),
  servicenowPreview: () => request("GET", "/api/servicenow/preview"),
  servicenowSend: (body) => request("POST", "/api/servicenow/send", body),
  jiraPreview: () => request("GET", "/api/jira/preview"),
  jiraSend: (body) => request("POST", "/api/jira/send", body),
  splunkPreview: () => request("GET", "/api/splunk/preview"),
  splunkSend: (body) => request("POST", "/api/splunk/send", body),
  runGet: () => request("GET", "/api/run"),
  runPost: (body) => request("POST", "/api/run", body),
  status: () => request("GET", "/api/status"),
  aiAssist: (body) => request("POST", "/api/ai-assist", body),
  aiTrendAnalysis: (body) => request("POST", "/api/ai-trend-analysis", body),
  reportGenerate: (period) => request("GET", `/api/reports/generate?period=${encodeURIComponent(period)}`),
  getReportSchedule: () => request("GET", "/api/report-schedule"),
  saveReportSchedule: (rulesText) => request("POST", "/api/report-schedule", { rules_text: rulesText }),
  getAlertRules: () => request("GET", "/api/alert-rules"),
  saveAlertRules: (rulesText) => request("POST", "/api/alert-rules", { rules_text: rulesText }),
  notificationStatus: () => request("GET", "/api/notification-settings/status"),
  notificationPreview: (body) => request("POST", "/api/notification-settings/preview", body),
  notificationSendTest: (body) => request("POST", "/api/notification-settings/send-test", body),
  notificationRunChecksNow: () => request("POST", "/api/notification-settings/run-checks-now"),
  getRemediationPolicy: () => request("GET", "/api/remediation-policy"),
  saveRemediationPolicy: (rulesText) => request("POST", "/api/remediation-policy", { rules_text: rulesText }),
  directoryStatus: () => request("GET", "/api/directory/status"),
  remediationApprovalsList: () => request("GET", "/api/remediation-approvals"),
  remediationApprovalCreate: (findingId, requestedBy) => request("POST", "/api/remediation-approvals", { finding_id: findingId, requested_by: requestedBy }),
  remediationApprovalApprove: (id, decidedBy) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/approve`, { decided_by: decidedBy }),
  remediationApprovalReject: (id, decidedBy, reason) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/reject`, { decided_by: decidedBy, reason }),
  remediationApprovalSendCommunication: (id, recipient, confirm) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/send-communication`, { recipient, confirm }),
  remediationApprovalMarkStagingValidated: (id, validatedBy) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/staging-validated`, { validated_by: validatedBy }),
  exceptionsList: () => request("GET", "/api/exceptions"),
  exceptionCreate: (body) => request("POST", "/api/exceptions", body),
  exceptionRevoke: (id) => request("POST", `/api/exceptions/${encodeURIComponent(id)}/revoke`),
  assetsList: () => request("GET", "/api/assets"),
  assetSetOwner: (name, body) => request("POST", `/api/assets/${encodeURIComponent(name)}/owner`, body),
  assetSetFacing: (name, facing) => request("POST", `/api/assets/${encodeURIComponent(name)}/facing`, { facing }),
  assetSetEnvironment: (name, environment) => request("POST", `/api/assets/${encodeURIComponent(name)}/environment`, { environment }),
  assetSetNetworkInfo: (name, body) => request("POST", `/api/assets/${encodeURIComponent(name)}/network-info`, body),
  searchAsk: (query) => request("POST", "/api/search/ask", { query }),
  cmdbImportPreview: (csvText, columnMapping) => request("POST", "/api/assets/cmdb-import/preview", { csv_text: csvText, column_mapping: columnMapping || null }),
  cmdbImportApply: (entries) => request("POST", "/api/assets/cmdb-import/apply", { entries }),
  notifications: () => request("GET", "/api/notifications"),
  attackHeatmap: () => request("GET", "/api/risk/attack-heatmap"),
  blastRadius: () => request("GET", "/api/risk/blast-radius"),
  aiVulnerabilities: () => request("GET", "/api/ai-vulnerabilities"),
  quantumReadiness: () => request("GET", "/api/quantum-readiness"),
  authMe: () => request("GET", "/api/auth/me"),
  authLogin: (email, password) => request("POST", "/api/auth/login", { email, password }),
  authLogout: () => request("POST", "/api/auth/logout"),
  authChangePassword: (newPassword) => request("POST", "/api/auth/change-password", { new_password: newPassword }),
  getAiGovernance: () => request("GET", "/api/admin/ai-governance"),
  saveAiGovernance: (body) => request("POST", "/api/admin/ai-governance", body),
  listUsers: () => request("GET", "/api/admin/users"),
  createUser: (body) => request("POST", "/api/admin/users", body),
  setUserTeam: (email, team) => request("POST", `/api/admin/users/${encodeURIComponent(email)}/team`, { team }),
  setUserRole: (email, role) => request("POST", `/api/admin/users/${encodeURIComponent(email)}/role`, { role }),
  aiUsage: () => request("GET", "/api/admin/ai-usage"),
  authOidcConfig: () => request("GET", "/api/auth/oidc/config"),
  mlAssetAnomalies: () => request("GET", "/api/ml-insights/anomalies"),
  mlFindingClusters: () => request("GET", "/api/ml-insights/clusters"),
  mlFindingClusterMembers: (clusterId) => request("GET", `/api/ml-insights/clusters/${encodeURIComponent(clusterId)}/members`),
  mlSimilarFindings: (findingId) => request("GET", `/api/ml-insights/similar/${encodeURIComponent(findingId)}`),
  controlCoverage: (findingId) => request("GET", `/api/findings/${encodeURIComponent(findingId)}/control-coverage`),
  networkPath: (assetName) => request("GET", `/api/assets/${encodeURIComponent(assetName)}/network-path`),
  activityLog: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request("GET", `/api/activity-log${qs ? `?${qs}` : ""}`);
  },
  activityLogInsights: () => request("GET", "/api/activity-log/insights"),
  getAssetPolicy: () => request("GET", "/api/asset-policy"),
  saveAssetPolicy: (rulesText) => request("POST", "/api/asset-policy", { rules_text: rulesText }),
  previewAssetPolicy: (rulesText) => request("POST", "/api/asset-policy/preview", { rules_text: rulesText }),
  applyAssetPolicy: () => request("POST", "/api/asset-policy/apply", {}),
  setAssetRemediationSchedule: (name, cadence, maintenanceWindow) =>
    request("POST", `/api/assets/${encodeURIComponent(name)}/remediation-schedule`, { cadence, maintenance_window: maintenanceWindow }),
  tenableTestConnection: (body) => request("POST", "/api/tenable/test-connection", body),
  tenableFetch: (body) => request("POST", "/api/tenable/fetch", body),
  qualysTestConnection: (body) => request("POST", "/api/qualys/test-connection", body),
  qualysFetch: (body) => request("POST", "/api/qualys/fetch", body),
  prismacloudTestConnection: (body) => request("POST", "/api/prismacloud/test-connection", body),
  prismacloudFetch: (body) => request("POST", "/api/prismacloud/fetch", body),
  cortexXsiamTestConnection: (body) => request("POST", "/api/cortex-xsiam/test-connection", body),
  cortexXsiamFetch: (body) => request("POST", "/api/cortex-xsiam/fetch", body),
  infobloxTestConnection: (body) => request("POST", "/api/infoblox/test-connection", body),
  infobloxFetch: (body) => request("POST", "/api/infoblox/fetch", body),
  axoniusTestConnection: (body) => request("POST", "/api/axonius/test-connection", body),
  axoniusFetch: (body) => request("POST", "/api/axonius/fetch", body),
  activeDirectoryTestConnection: (body) => request("POST", "/api/active-directory/test-connection", body),
  activeDirectoryFetch: (body) => request("POST", "/api/active-directory/fetch", body),
  openvasTestConnection: (body) => request("POST", "/api/openvas/test-connection", body),
  openvasScanStart: (body) => request("POST", "/api/openvas/scan/start", body),
  openvasScanStatus: (body) => request("POST", "/api/openvas/scan/status", body),
  openvasScanImport: (body) => request("POST", "/api/openvas/scan/import", body),
};
