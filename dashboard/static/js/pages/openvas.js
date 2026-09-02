// OpenVAS / Greenbone (GVM) - the one scan ENGINE in this catalog, not a pull
// connector onto a scanner you already run. A real scan is a 3-step lifecycle
// (start -> poll -> import), not a single Fetch, so this page keeps the connection
// fields around across all three calls instead of the single-button shape
// tenable.js/qualys.js use - see docs/VULNERABILITY_ENGINE_ARCHITECTURE.md for why.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "OpenVAS / Greenbone (GVM)";

export async function render(container) {
  let currentTaskId = null;

  container.innerHTML = `
    <p class="subtitle">The free, open-source vulnerability scan engine behind this
    catalog's only "bring your own scanner" story - Tenable/Qualys above pull data out
    of a scanner you already bought; this launches a real authenticated scan itself.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real GVM instance — none was
      available while building it. It implements the documented GMP protocol (via
      Greenbone's own <code>python-gvm</code> library) and is unit-tested against a
      mocked GMP client shaped like that documentation. Verify result field names
      against your instance's actual GMP version before trusting live output at scale -
      see
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/VULNERABILITY_ENGINE_ARCHITECTURE.md" target="_blank" rel="noopener">docs/VULNERABILITY_ENGINE_ARCHITECTURE.md</a>.
    </div>

    <div class="callout">
      Only scan networks and hosts you own or are explicitly authorized to test.
      Scanning is a real, potentially disruptive action against real infrastructure -
      it is not a read-only preview.
    </div>

    <h2>1. Connect</h2>
    <form class="run-form" id="openvas-connect-form">
      <label>GVM hostname (for a TLS connection - leave blank if using a local socket path below)
        <input type="text" name="hostname" placeholder="gvm.example.com"></label>
      <label>GMP port<input type="number" name="port" value="9390"></label>
      <label>Local Unix socket path (advanced - alternative to hostname, e.g. when GVM runs as a sidecar)
        <input type="text" name="socket_path" placeholder="/run/gvmd/gvmd.sock"></label>
      <label>Username<input type="text" name="username" autocomplete="off"></label>
      <label>Password<input type="password" name="password" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
    </form>

    <h2>2. Launch a scan</h2>
    <form class="run-form" id="openvas-scan-form">
      <label>Target name<input type="text" name="target_name" placeholder="Corp LAN"></label>
      <label>Target host(s) - one per line, or comma-separated (IP, hostname, or CIDR range)
        <textarea name="hosts" rows="3" placeholder="10.20.30.0/24&#10;scanme.example.com"></textarea></label>
      <label>Scan config ID (advanced - defaults to Greenbone's stock "Full and fast")
        <input type="text" name="scan_config_id" placeholder="daba56c8-73ec-11df-a475-002264764cea"></label>
      <label>Scanner ID (advanced - defaults to the stock "OpenVAS Default" scanner)
        <input type="text" name="scanner_id" placeholder="08b69003-5fc2-4037-a479-93b440211c73"></label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I own or am explicitly authorized to scan the target(s) above, and want to start a real scan now
      </label>
      <button type="submit">Start Scan</button>
    </form>
    <div id="openvas-scan-result"></div>

    <h2>3. Poll status, then import</h2>
    <form class="run-form" id="openvas-status-form">
      <label>GVM task ID<input type="text" name="task_id" placeholder="filled in automatically after Start Scan"></label>
      <button type="button" class="secondary-button" id="status-btn">Check Status</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="import_confirm">
        I want to pull this task's real results into a live export now
      </label>
      <button type="button" id="import-btn">Import Results</button>
    </form>
    <div id="openvas-status-result"></div>`;

  const connectForm = container.querySelector("#openvas-connect-form");
  const scanForm = container.querySelector("#openvas-scan-form");
  const statusForm = container.querySelector("#openvas-status-form");
  const scanResultEl = container.querySelector("#openvas-scan-result");
  const statusResultEl = container.querySelector("#openvas-status-result");

  function connectionFields() {
    return {
      hostname: connectForm.hostname.value.trim(),
      port: Number(connectForm.port.value) || 9390,
      socket_path: connectForm.socket_path.value.trim(),
      username: connectForm.username.value.trim(),
      password: connectForm.password.value,
    };
  }

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.openvasTestConnection(connectionFields());
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      ...connectionFields(),
      target_name: scanForm.target_name.value.trim(),
      hosts: scanForm.hosts.value,
      scan_config_id: scanForm.scan_config_id.value.trim(),
      scanner_id: scanForm.scanner_id.value.trim(),
      confirm: scanForm.confirm.checked,
    };
    try {
      const result = await api.openvasScanStart(body);
      flash(result.message, result.preview_only ? "info" : "success");
      if (!result.preview_only && result.task_id) {
        currentTaskId = result.task_id;
        statusForm.task_id.value = result.task_id;
        scanResultEl.innerHTML = `<div class="callout">Task ID: <code>${escapeHtml(result.task_id)}</code></div>`;
      }
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#status-btn").addEventListener("click", async () => {
    const taskId = statusForm.task_id.value.trim() || currentTaskId;
    if (!taskId) {
      flash("Start a scan first, or paste in an existing GVM task ID.", "error");
      return;
    }
    try {
      const result = await api.openvasScanStatus({ ...connectionFields(), task_id: taskId });
      statusResultEl.innerHTML = `
        <div class="callout">
          Status: <strong>${escapeHtml(result.status)}</strong>
          (${escapeHtml(String(result.progress))}% complete)
        </div>`;
    } catch (err) {
      flash(err.message, "error");
    }
  });

  container.querySelector("#import-btn").addEventListener("click", async () => {
    const taskId = statusForm.task_id.value.trim() || currentTaskId;
    const body = {
      ...connectionFields(),
      task_id: taskId,
      confirm: statusForm.import_confirm.checked,
    };
    if (!taskId) {
      flash("Start a scan first, or paste in an existing GVM task ID.", "error");
      return;
    }
    try {
      const result = await api.openvasScanImport(body);
      flash(result.message, result.preview_only ? "info" : "success");
      if (!result.preview_only) {
        statusResultEl.innerHTML = `
          <div class="callout">
            Wrote <strong>${result.count}</strong> row(s) to <code>${escapeHtml(result.written_to)}</code>.
          </div>`;
      }
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
