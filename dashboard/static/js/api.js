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
  vulnhunt: () => request("GET", "/api/vulnhunt"),
  remediate: () => request("GET", "/api/remediate"),
  playbook: (filename) => request("GET", `/api/playbooks/${encodeURIComponent(filename)}`),
  queue: () => request("GET", "/api/queue"),
  getPriorityRules: () => request("GET", "/api/priority-rules"),
  savePriorityRules: (rulesText) => request("POST", "/api/priority-rules", { rules_text: rulesText }),
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
  reportGenerate: (period) => request("GET", `/api/reports/generate?period=${encodeURIComponent(period)}`),
  exceptionsList: () => request("GET", "/api/exceptions"),
  exceptionCreate: (body) => request("POST", "/api/exceptions", body),
  exceptionRevoke: (id) => request("POST", `/api/exceptions/${encodeURIComponent(id)}/revoke`),
  assetsList: () => request("GET", "/api/assets"),
  assetSetOwner: (name, body) => request("POST", `/api/assets/${encodeURIComponent(name)}/owner`, body),
  assetSetFacing: (name, facing) => request("POST", `/api/assets/${encodeURIComponent(name)}/facing`, { facing }),
  cmdbImportPreview: (csvText, columnMapping) => request("POST", "/api/assets/cmdb-import/preview", { csv_text: csvText, column_mapping: columnMapping || null }),
  cmdbImportApply: (entries) => request("POST", "/api/assets/cmdb-import/apply", { entries }),
  notifications: () => request("GET", "/api/notifications"),
  attackHeatmap: () => request("GET", "/api/risk/attack-heatmap"),
  aiVulnerabilities: () => request("GET", "/api/ai-vulnerabilities"),
  authMe: () => request("GET", "/api/auth/me"),
  authLogin: (email, password) => request("POST", "/api/auth/login", { email, password }),
  authLogout: () => request("POST", "/api/auth/logout"),
  authChangePassword: (newPassword) => request("POST", "/api/auth/change-password", { new_password: newPassword }),
  authOidcConfig: () => request("GET", "/api/auth/oidc/config"),
};
