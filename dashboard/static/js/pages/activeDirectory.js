// Active Directory - a PULL connector: fetches computer objects FROM an on-prem AD
// domain controller via LDAP and normalizes them into asset-inventory records, not
// vulnerability findings. Same Test Connection + Fetch shape as infoblox.js/axonius.js.
// A distinct concern from the AD group-membership check the Remediation Approvals
// workflow already uses (dashboard/auth/ad_directory.py) - that one only checks whether
// a named user is in one AD group; this pulls the domain's computer inventory.
import { api } from "../api.js";
import { flash } from "../dom.js";

export const title = "Adaptors — Active Directory";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for on-prem Active Directory's computer
    inventory via LDAP - fetches computer objects and reconciles what real network
    ground truth they carry into the asset inventory. Test your credentials, then
    fetch. A different feature from the AD group-membership check the
    <a href="/remediation-approvals">Remediation Approvals</a> workflow already uses.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Active Directory domain
      controller — no credentials were available while building it. It implements a
      standard LDAP (RFC 4511) simple bind + computer-object search against Microsoft's
      documented AD schema, and is unit-tested against a hand-rolled fake LDAP connection
      (not a real network socket). Verify attribute names against your own domain's
      schema before trusting live output - a computer object's populated attributes can
      vary by AD schema version and domain functional level.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Binds via LDAP (simple bind with a bind DN + password, or anonymous)</li>
      <li>Searches for computer objects (<code>(objectClass=computer)</code>) and reads
        <code>cn</code>, <code>dNSHostName</code>, <code>operatingSystem</code>,
        <code>userAccountControl</code>, and related attributes</li>
    </ol>

    <div class="callout">
      AD computer objects carry no ip or mac address (that's DHCP/DNS's job, not AD's) -
      a real, deliberate property of this source, not a mapping gap. That means Fetch
      below has nothing to reconcile into the asset inventory's ip/mac fields from this
      source alone (see <a href="/tenable">Tenable</a>/<a href="/qualys">Qualys</a>/
      <a href="/infoblox">Infoblox</a>/<a href="/axonius">Axonius</a> for that real
      ip/mac ground truth) - Fetch here mainly proves connectivity and shows what the
      domain's computer inventory actually looks like (name, OS, enabled/disabled).
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="ad-form">
      <label>Server (hostname, or ldap://.../ldaps://... URL)<input type="text" name="server" placeholder="dc01.corp.local"></label>
      <label>Base DN<input type="text" name="base_dn" placeholder="DC=corp,DC=local"></label>
      <label>Bind DN (optional - leave blank for an anonymous bind)<input type="text" name="bind_dn" autocomplete="off" placeholder="CN=svc-vulnhunter,OU=Service Accounts,DC=corp,DC=local"></label>
      <label>Bind password<input type="password" name="bind_password" autocomplete="off"></label>
      <label class="checkbox-label">
        <input type="checkbox" name="use_ssl">
        Use LDAPS (port 636)
      </label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have a real server/base DN and want to fetch live AD computer objects now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="ad-result"></div>`;

  const form = container.querySelector("#ad-form");
  const resultEl = container.querySelector("#ad-result");

  const readForm = () => ({
    server: form.server.value.trim(),
    base_dn: form.base_dn.value.trim(),
    bind_dn: form.bind_dn.value.trim(),
    bind_password: form.bind_password.value,
    use_ssl: form.use_ssl.checked,
  });

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.activeDirectoryTestConnection(readForm());
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = { ...readForm(), confirm: form.confirm.checked };
    try {
      const result = await api.activeDirectoryFetch(body);
      flash(result.message, result.preview_only ? "info" : "success");
      resultEl.innerHTML = result.preview_only ? "" : `
        <div class="callout">
          <strong>${result.matched.length}</strong> matched an existing asset,
          <strong>${result.unmatched.length}</strong> had no existing findings yet,
          <strong>${result.skipped.length}</strong> skipped (see the callout above for why
          that's the common case for this source).
        </div>`;
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
