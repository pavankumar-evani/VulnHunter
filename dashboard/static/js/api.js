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
  quanta_scan: () => request("GET", "/api/quanta-scan"),
  remediate: () => request("GET", "/api/remediate"),
  playbook: (filename) => request("GET", `/api/playbooks/${encodeURIComponent(filename)}`),
  queue: () => request("GET", "/api/queue"),
  teams: () => request("GET", "/api/teams"),
  createTeam: (body) => request("POST", "/api/admin/teams", body),
  updateTeam: (name, body) => request("PUT", `/api/admin/teams/${encodeURIComponent(name)}`, body),
  deleteTeam: (name) => request("DELETE", `/api/admin/teams/${encodeURIComponent(name)}`),
  assignableUsers: () => request("GET", "/api/assignable-users"),
  assignments: (params) => request("GET", `/api/assignments?${new URLSearchParams(params)}`),
  findingAssignment: (id) => request("GET", `/api/findings/${encodeURIComponent(id)}/assignment`),
  assignFinding: (id, body) => request("POST", `/api/findings/${encodeURIComponent(id)}/assign`, body),
  setAssignmentStatus: (id, body) => request("POST", `/api/findings/${encodeURIComponent(id)}/assignment/status`, body),
  unassignFinding: (id) => request("DELETE", `/api/findings/${encodeURIComponent(id)}/assignment`),
  bulkAssign: (body) => request("POST", "/api/assignments/bulk", body),
  autoAssign: (confirm) => request("POST", "/api/assignments/auto-assign", { confirm }),
  ownershipAnalytics: () => request("GET", "/api/analytics/ownership"),

  attackPaths: () => request("GET", "/api/attack-paths"),
  posture: () => request("GET", "/api/posture"),
  graph: (module) => request("GET", `/api/graphs/${encodeURIComponent(module)}`),
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
  remediationApprovalCreate: (findingId) => request("POST", "/api/remediation-approvals", { finding_id: findingId }),
  remediationApprovalApprove: (id) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/approve`, {}),
  remediationApprovalReject: (id, reason) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/reject`, { reason }),
  remediationApprovalSendCommunication: (id, recipient, confirm) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/send-communication`, { recipient, confirm }),
  remediationApprovalMarkStagingValidated: (id) => request("POST", `/api/remediation-approvals/${encodeURIComponent(id)}/staging-validated`, {}),
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
  supportTickets: (params) => request("GET", `/api/support/tickets?${new URLSearchParams(params || {})}`),
  supportTicket: (ref) => request("GET", `/api/support/tickets/${encodeURIComponent(ref)}`),
  createSupportTicket: (body) => request("POST", "/api/support/tickets", body),
  commentSupportTicket: (ref, body) => request("POST", `/api/support/tickets/${encodeURIComponent(ref)}/comments`, body),
  updateSupportTicket: (ref, body) => request("POST", `/api/support/tickets/${encodeURIComponent(ref)}/update`, body),
  escalateSupportTicket: (ref, confirm) => request("POST", `/api/support/tickets/${encodeURIComponent(ref)}/escalate`, { confirm }),
  rateSupportTicket: (ref, body) => request("POST", `/api/support/tickets/${encodeURIComponent(ref)}/csat`, body),
  runSlaEscalations: (confirm) => request("POST", "/api/support/escalations/run", { confirm }),
  connections: () => request("GET", "/api/connections"),
  createConnection: (body) => request("POST", "/api/connections", body),
  updateConnection: (id, body) => request("PUT", `/api/connections/${id}`, body),
  deleteConnection: (id) => request("DELETE", `/api/connections/${id}`),
  testConnectionValues: (body) => request("POST", "/api/connections/test", body),
  syncConnection: (id) => request("POST", `/api/connections/${id}/sync`, {}),
  simulationStatus: () => request("GET", "/api/simulation/status"),
  simulationLoad: (body) => request("POST", "/api/simulation/load", body),
  simulationRemove: () => request("DELETE", "/api/simulation"),
  apiKeys: () => request("GET", "/api/api-keys"),
  createApiKey: (body) => request("POST", "/api/api-keys", body),
  revokeApiKey: (id) => request("DELETE", `/api/api-keys/${id}`),
  connectionSchema: () => request("GET", "/api/connections/schema"),
  findingGuidance: (id) => request("GET", `/api/findings/${encodeURIComponent(id)}/guidance`),
  guidanceLookup: (params) => request("GET", `/api/guidance?${new URLSearchParams(params)}`),
  controls: (asset) => request("GET", `/api/controls${asset ? `?asset=${encodeURIComponent(asset)}` : ""}`),
  addControl: (body) => request("POST", "/api/controls", body),
  deleteControl: (id) => request("DELETE", `/api/controls/${id}`),
  importControls: async (file) => {
    const res = await fetch("/api/controls/import", { method: "POST", body: file });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  aiUsageSummary: (days) => request("GET", `/api/ai-usage/summary?days=${days || 30}`),
  aiApps: () => request("GET", "/api/ai-usage/apps"),
  aiSetApp: (id, body) => request("PUT", `/api/ai-usage/apps/${id}`, body),
  aiAddApp: (body) => request("POST", "/api/ai-usage/apps", body),
  aiAddBudget: (body) => request("POST", "/api/ai-usage/budgets", body),
  aiDeleteBudget: (id) => request("DELETE", `/api/ai-usage/budgets/${id}`),
  aiDiscovery: async (file, source) => {
    const res = await fetch(`/api/ai-usage/discovery?source=${encodeURIComponent(source || "proxy-log")}`, { method: "POST", body: file });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  threatModels: () => request("GET", "/api/threat-models"),
  threatModel: (id) => request("GET", `/api/threat-models/${id}`),
  createThreatModel: (body) => request("POST", "/api/threat-models", body),
  updateThreatModel: (id, body) => request("PUT", `/api/threat-models/${id}`, body),
  deleteThreatModel: (id) => request("DELETE", `/api/threat-models/${id}`),
  seedThreatModel: (id, patterns) => request("POST", `/api/threat-models/${id}/seed`, { patterns }),
  reviewThreat: (id, body) => request("POST", `/api/threat-models/${id}/review`, body),
  threatRules: () => request("GET", "/api/threat-models/rules"),
  grcOverview: () => request("GET", "/api/grc/overview"),
  grcFrameworks: () => request("GET", "/api/grc/frameworks"),
  grcReport: (id) => request("GET", `/api/grc/frameworks/${encodeURIComponent(id)}/report`),
  grcAttest: (fw, control, body) => request("POST", `/api/grc/frameworks/${encodeURIComponent(fw)}/controls/${encodeURIComponent(control)}/attest`, body),
  grcDeleteFramework: (id) => request("DELETE", `/api/grc/frameworks/${encodeURIComponent(id)}`),
  grcImportFramework: async (id, name, file) => {
    const res = await fetch(`/api/grc/frameworks/import?id=${encodeURIComponent(id)}&name=${encodeURIComponent(name || "")}`, { method: "POST", body: file });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  grcEvidence: () => request("GET", "/api/grc/evidence"),
  grcRunEvidence: () => request("POST", "/api/grc/evidence/run", {}),
  grcRisks: () => request("GET", "/api/grc/risks"),
  grcAddRisk: (body) => request("POST", "/api/grc/risks", body),
  grcRiskFromSuggestion: (body) => request("POST", "/api/grc/risks/from-suggestion", body),
  grcUpdateRisk: (id, body) => request("PUT", `/api/grc/risks/${id}`, body),
  grcDeleteRisk: (id) => request("DELETE", `/api/grc/risks/${id}`),
  grcPolicies: () => request("GET", "/api/grc/policies"),
  grcAddPolicy: (body) => request("POST", "/api/grc/policies", body),
  grcUpdatePolicy: (id, body) => request("PUT", `/api/grc/policies/${id}`, body),
  grcAckPolicy: (id) => request("POST", `/api/grc/policies/${id}/acknowledge`, {}),
  huntingOverview: () => request("GET", "/api/hunting/overview"),
  huntingProposals: () => request("GET", "/api/hunting/proposals"),
  huntingAccept: (body) => request("POST", "/api/hunting/proposals/accept", body),
  huntingSuggestions: (qs = "") => request("GET", `/api/hunting/suggestions${qs}`),
  huntingSuggestionRefresh: () => request("POST", "/api/hunting/suggestions/refresh", {}),
  huntingSuggestionAccept: (id) => request("POST", `/api/hunting/suggestions/${id}/accept`, {}),
  huntingSuggestionDismiss: (id, body) => request("POST", `/api/hunting/suggestions/${id}/dismiss`, body),
  huntingSuggestionConclude: (id, body) => request("POST", `/api/hunting/suggestions/${id}/conclude`, body),
  huntingSuggestionPromote: (id) => request("POST", `/api/hunting/suggestions/${id}/promote`, {}),
  huntingList: () => request("GET", "/api/hunting/hunts"),
  huntingCreate: (body) => request("POST", "/api/hunting/hunts", body),
  huntingUpdate: (id, body) => request("PUT", `/api/hunting/hunts/${id}`, body),
  darkwebOverview: () => request("GET", "/api/darkweb/overview"),
  darkwebTerms: (body) => request("PUT", "/api/darkweb/watch-terms", body),
  darkwebEnable: (id, body) => request("POST", `/api/darkweb/sources/${id}/enable`, body),
  darkwebRun: (id, body) => request("POST", `/api/darkweb/sources/${id}/run`, body),
  darkwebImport: (body) => request("POST", "/api/darkweb/import", body),
  darkwebHitStatus: (id, body) => request("POST", `/api/darkweb/hits/${id}/status`, body),
  socAlerts: () => request("GET", "/api/soc/alerts"),
  decisionCalibration: () => request("GET", "/api/decisions/calibration"),
  decisionPolicy: () => request("GET", "/api/decisions/policy"),
  socCases: (q = {}) => request("GET", "/api/soc/cases" + (Object.keys(q).length ? "?" + new URLSearchParams(q) : "")),
  socCase: (id) => request("GET", `/api/soc/cases/${id}`),
  socCaseOpen: (body) => request("POST", "/api/soc/cases", body),
  socCaseAct: (id, action, body) => request("POST", `/api/soc/cases/${id}/${action}`, body),
  socCaseLogs: (id, body) => request("POST", `/api/soc/cases/${id}/analyse-logs`, body),
  socAnalyseLogs: (body) => request("POST", "/api/soc/analyse-logs", body),
  socTtp: (body) => request("POST", "/api/soc/ttp", body),
  socMetrics: (days = 30) => request("GET", `/api/soc/metrics?days=${days}`),
  socAnalysts: () => request("GET", "/api/soc/analysts"),
  socAnalystAdd: (body) => request("POST", "/api/soc/analysts", body),
  socAnalystRemove: (email) => request("DELETE", `/api/soc/analysts/${encodeURIComponent(email)}`),
  socAlert: (id) => request("GET", `/api/soc/alerts/${id}`),
  socUpdateAlert: (id, body) => request("PUT", `/api/soc/alerts/${id}`, body),
  huntingIntelList: () => request("GET", "/api/hunting/intel"),
  huntingIntelAdd: (body) => request("POST", "/api/hunting/intel", body),
  huntingIntelHunt: (id) => request("POST", `/api/hunting/intel/${id}/hunt`, {}),
  huntingRunQuery: (hunt, index, body) => request("POST", `/api/hunting/hunts/${hunt}/queries/${index}/run`, body),
  socInvestigate: (id, body) => request("POST", `/api/soc/alerts/${id}/investigate`, body),
  socFollowUp: (id, body) => request("POST", `/api/soc/alerts/${id}/follow-up`, body),
  socRecommendPlaybook: (id) => request("GET", `/api/soc/alerts/${id}/recommend-playbook`),
  huntingRunAll: (hunt, body) => request("POST", `/api/hunting/hunts/${hunt}/run-all`, body),
  socInvestigation: (id) => request("GET", `/api/soc/alerts/${id}/investigation`),
  soarPlaybooks: () => request("GET", "/api/soar/playbooks"),
  soarAdd: (body) => request("POST", "/api/soar/playbooks", body),
  soarUpdate: (id, body) => request("PUT", `/api/soar/playbooks/${id}`, body),
  soarDelete: (id) => request("DELETE", `/api/soar/playbooks/${id}`),
  soarRun: (id, body) => request("POST", `/api/soar/playbooks/${id}/run`, body),
  soarRuns: () => request("GET", "/api/soar/runs"),
  soarApprove: (id) => request("POST", `/api/soar/runs/${id}/approve`, {}),
  soarReject: (id, body) => request("POST", `/api/soar/runs/${id}/reject`, body),
  soarCancel: (id) => request("POST", `/api/soar/runs/${id}/cancel`, {}),
  cyberRiskOverview: () => request("GET", "/api/cyber-risk/overview"),
  cyberRiskScenarios: () => request("GET", "/api/cyber-risk/scenarios"),
  cyberRiskAdd: (body) => request("POST", "/api/cyber-risk/scenarios", body),
  cyberRiskUpdate: (id, body) => request("PUT", `/api/cyber-risk/scenarios/${id}`, body),
  cyberRiskDelete: (id) => request("DELETE", `/api/cyber-risk/scenarios/${id}`),
  cyberRiskAnalysis: (id) => request("GET", `/api/cyber-risk/scenarios/${id}/analysis`),
  cyberRiskSimulate: (body) => request("POST", "/api/cyber-risk/simulate", body),
  devsecopsOverview: () => request("GET", "/api/devsecops/overview"),
  devsecopsRepo: (asset) => request("GET", `/api/devsecops/repos?asset=${encodeURIComponent(asset)}`),
  devsecopsSetState: (body) => request("POST", "/api/devsecops/state", body),
  devsecopsPolicy: (text) => request("POST", "/api/devsecops/policy-check", { text }),
  devsecopsFactory: () => request("GET", "/api/devsecops/factory"),
  devsecopsQueue: (body) => request("POST", "/api/devsecops/factory/queue", body),
  devsecopsUpdateItem: (id, body) => request("PUT", `/api/devsecops/factory/${encodeURIComponent(id)}`, body),
  cvdAdvisories: () => request("GET", "/api/cvd/advisories"),
  cvdTest: () => request("POST", "/api/cvd/test-connection", {}),
  cvdFetch: (body) => request("POST", "/api/cvd/fetch", body),
  zeroDayWatch: (days) => request("GET", `/api/zero-day-watch?days=${days}`),
  firewallOverview: () => request("GET", "/api/firewall/overview"),
  firewallDeleteDevice: (d) => request("DELETE", `/api/firewall/devices/${encodeURIComponent(d)}`),
  firewallCertify: (body) => request("POST", "/api/firewall/certify", body),
  firewallRequests: () => request("GET", "/api/firewall/requests"),
  firewallRequest: (body) => request("POST", "/api/firewall/requests", body),
  firewallDecide: (id, body) => request("POST", `/api/firewall/requests/${id}/decide`, body),
  firewallImport: async (device, format, text) => {
    const res = await fetch(`/api/firewall/import?device=${encodeURIComponent(device)}&format=${encodeURIComponent(format || "")}`, { method: "POST", body: text });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  aiSecurityOverview: () => request("GET", "/api/ai-security/overview"),
  aiSecurityAdd: (body) => request("POST", "/api/ai-security/assets", body),
  aiSecurityUpdate: (id, body) => request("PUT", `/api/ai-security/assets/${id}`, body),
  aiSecurityDelete: (id) => request("DELETE", `/api/ai-security/assets/${id}`),
  aiSecurityImport: () => request("POST", "/api/ai-security/import-discovered", {}),
  aiSecurityPublish: (body) => request("POST", "/api/ai-security/publish", body),
  license: () => request("GET", "/api/license"),
  features: () => request("GET", "/api/features"),
  apiSecOverview: () => request("GET", "/api/api-security/overview"),
  apiSecEndpoints: (params) => request("GET", `/api/api-security/endpoints?${new URLSearchParams(params || {})}`),
  apiSecEndpoint: (id) => request("GET", `/api/api-security/endpoints/${id}`),
  apiSecEndpointUpdate: (id, body) => request("PATCH", `/api/api-security/endpoints/${id}`, body),
  apiSecSpecs: () => request("GET", "/api/api-security/specs"),
  apiSecSpecUpload: (body) => request("POST", "/api/api-security/specs", body),
  apiSecSpecFetch: (body) => request("POST", "/api/api-security/specs/fetch", body),
  apiSecSpecDelete: (service) => request("DELETE", `/api/api-security/specs/${encodeURIComponent(service)}`),
  apiSecDrift: (service) => request("GET", `/api/api-security/drift?service=${encodeURIComponent(service)}`),
  apiSecGeneratedSpec: (service) => request("GET", `/api/api-security/generated-spec?service=${encodeURIComponent(service)}`),
  apiSecImportLogs: async (service, format, text) => {
    const res = await fetch(`/api/api-security/import-logs?${new URLSearchParams({ service: service || "", format: format || "" })}`, { method: "POST", body: text });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  apiSecFindings: () => request("GET", "/api/api-security/findings"),
  apiSecPublish: (body) => request("POST", "/api/api-security/publish", body),
  apiSecCallers: (days) => request("GET", `/api/api-security/callers?days=${days || 30}`),
  apiSecCaller: (actor) => request("GET", `/api/api-security/callers/detail?${new URLSearchParams({ actor })}`),
  apiSecClassification: () => request("GET", "/api/api-security/classification"),
  apiSecClassificationImport: (body) => request("POST", "/api/api-security/classification", body),
  apiSecClassificationClear: () => request("DELETE", "/api/api-security/classification"),
  apiSecMetrics: (days, service) => request("GET", `/api/api-security/metrics?${new URLSearchParams({ days: days || 30, service: service || "" })}`),
  apiSecPolicies: () => request("GET", "/api/api-security/policies"),
  apiSecPolicyAdd: (body) => request("POST", "/api/api-security/policies", body),
  apiSecPolicyUpdate: (id, body) => request("PUT", `/api/api-security/policies/${id}`, body),
  apiSecPolicyDelete: (id) => request("DELETE", `/api/api-security/policies/${id}`),
  apiSecPolicyApprove: (id) => request("POST", `/api/api-security/policies/${id}/approve`, {}),
  apiSecPolicyArtifact: (id, target) => request("GET", `/api/api-security/policies/${id}/artifact?target=${encodeURIComponent(target)}`),
  apiSecPolicyPush: (id, body) => request("POST", `/api/api-security/policies/${id}/push`, body),
  apiSecPolicyHistory: (id) => request("GET", `/api/api-security/policies/${id}/history`),
  apiSecRollout: (track) => request("GET", `/api/api-security/rollout?track=${encodeURIComponent(track || "")}`),
  apiSecRolloutSet: (id, body) => request("POST", `/api/api-security/rollout/${encodeURIComponent(id)}`, body),
  apiSecCiTemplates: () => request("GET", "/api/api-security/ci-templates"),
  iamOverview: () => request("GET", "/api/iam/overview"),
  iamPrecheck: (body) => request("POST", "/api/iam/precheck", body),
  iamCampaigns: () => request("GET", "/api/iam/campaigns"),
  iamCampaign: (id) => request("GET", `/api/iam/campaigns/${id}`),
  iamCampaignAdd: (body) => request("POST", "/api/iam/campaigns", body),
  iamClose: (id) => request("POST", `/api/iam/campaigns/${id}/close`, {}),
  iamRevocations: (id) => request("GET", `/api/iam/campaigns/${id}/revocations`),
  iamMyReviews: () => request("GET", "/api/iam/my-reviews"),
  iamDecide: (id, body) => request("POST", `/api/iam/items/${id}/decide`, body),
  iamReassign: (id, body) => request("POST", `/api/iam/items/${id}/reassign`, body),
  iamClear: () => request("DELETE", "/api/iam/data"),
  iamImport: async (source, text) => {
    const res = await fetch(`/api/iam/import?source=${encodeURIComponent(source)}`, { method: "POST", body: text });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  iamRoster: async (text) => {
    const res = await fetch("/api/iam/roster", { method: "POST", body: text });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  capabilities: () => request("GET", "/api/capabilities"),
  detectionsOverview: () => request("GET", "/api/detections/overview"),
  detectionsAssess: () => request("POST", "/api/detections/assess", {}),
  detectionsAddRule: (body) => request("POST", "/api/detections/rules", body),
  detectionsToggle: (id, enabled) => request("PUT", `/api/detections/rules/${id}`, { enabled }),
  detectionsDelete: (id) => request("DELETE", `/api/detections/rules/${id}`),
  detectionsImport: async (text) => {
    const res = await fetch("/api/detections/rules/import", { method: "POST", body: text });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  findingLinks: (id) => request("GET", `/api/findings/${encodeURIComponent(id)}/links`),
  importScannerFile: async (source, reconcile, file) => {
    const res = await fetch(`/api/connections/import-file?source=${encodeURIComponent(source)}&reconcile=${reconcile ? "true" : "false"}`, { method: "POST", body: file });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && data.detail) || res.statusText);
    return data;
  },
  supportAnalytics: () => request("GET", "/api/support/analytics"),
  findingTickets: (id) => request("GET", `/api/findings/${encodeURIComponent(id)}/tickets`),
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
  integrity: () => request("GET", "/api/integrity"),
  integrityHeal: (confirm, actions) => request("POST", "/api/integrity/heal", { confirm, actions: actions || null }),
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
  // applications, SBOMs and the dependency graph
  applications: () => request("GET", "/api/applications"),
  applicationSave: (name, body) => request("PUT", `/api/applications/${encodeURIComponent(name)}/context`, body),
  applicationDelete: (name) => request("DELETE", `/api/applications/${encodeURIComponent(name)}/context`),
  applicationAnalysis: (name, view) => request("GET", `/api/applications/${encodeURIComponent(name)}/analysis?view=${view || "focus"}`),
  applicationSbomGenerate: (name, body) => request("POST", `/api/applications/${encodeURIComponent(name)}/sbom/generate`, body),
  applicationSbomUpload: async (name, text) => {
    const res = await fetch(`/api/applications/${encodeURIComponent(name)}/sbom?source=upload`, { method: "POST", body: text });
    const data = await res.json().catch(() => null);
    if (!res.ok) { const err = new Error((data && data.detail) || res.statusText); err.status = res.status; throw err; }
    return data;
  },
  applicationOsvCheck: (name, confirm) => request("POST", `/api/applications/${encodeURIComponent(name)}/osv-check`, { confirm }),
  // fix pull requests
  gitopsPolicy: () => request("GET", "/api/gitops/policy"),
  gitopsProposals: (application) => request("GET", `/api/gitops/proposals${application ? `?application=${encodeURIComponent(application)}` : ""}`),
  gitopsProposal: (id) => request("GET", `/api/gitops/proposals/${id}`),
  gitopsProposeDependency: (body) => request("POST", "/api/gitops/proposals/dependency", body),
  gitopsProposeCode: (body) => request("POST", "/api/gitops/proposals/code", body),
  gitopsApprove: (id) => request("POST", `/api/gitops/proposals/${id}/approve`),
  gitopsDiscard: (id, reason) => request("POST", `/api/gitops/proposals/${id}/discard`, { reason }),
  gitopsOpen: (id, confirm) => request("POST", `/api/gitops/proposals/${id}/open`, { confirm }),
  gitopsRescan: (id) => request("POST", `/api/gitops/proposals/${id}/rescan`),
  gitopsSync: () => request("POST", "/api/gitops/sync"),
  gitopsVelocity: () => request("GET", "/api/gitops/velocity"),
  // release gate, secure design, own controls
  gateInfo: (application) => request("GET", `/api/pipeline-gates${application ? `?application=${encodeURIComponent(application)}` : ""}`),
  gateEvaluate: (body) => request("POST", "/api/pipeline-gates/evaluate", body),
  designQuestions: () => request("GET", "/api/secure-design/questions"),
  designAssess: (body) => request("POST", "/api/secure-design/assess", body),
  customControlSave: (id, body) => request("PUT", `/api/devsecops/custom-controls/${encodeURIComponent(id)}`, body),
  customControlDelete: (id) => request("DELETE", `/api/devsecops/custom-controls/${encodeURIComponent(id)}`),
};
