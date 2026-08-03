# Remediation Plan — 11 findings (Tenable: 6, Armis: 3, Threat Intel: 2)

**Automated remediation available today:** 7 findings (windows-server + unix-server)
**Manual-only (no fixer for this asset class yet):** 4 findings (network-routing-switching, iot-ot-device)

**Risk tier split:** 2 auto-approvable · 5 needs-change-approval · 4 manual-only

## Remediation queue (priority order)

| ID | Asset | Title | CVE | Severity | Action Type | Automation Target | Risk Tier |
|----|-------|-------|-----|----------|-------------|--------------------|-----------|
| FIND-6 | CSW-CORE01 | Cisco IOS XE Web UI Privilege Escalation | CVE-2023-20198 | Critical | config-change | manual-only | manual-only |
| FIND-1 | WIN-DC01 | PrintNightmare RCE | CVE-2021-34527 | Critical | patch | ansible-windows | needs-change-approval |
| FIND-8 | HVAC-CTRL-B2 | Unauthenticated Mgmt Interface | CVE-2019-7592 | Critical | config-change | manual-only | manual-only |
| FIND-11 | LNX-AUTH01 | OpenSSH Auth Bypass Regression | CVE-2024-6387 | Critical | patch | ansible-unix | needs-change-approval |
| FIND-2 | WIN-FS02 | EternalBlue (SMBv1 RCE) | CVE-2017-0144 | Critical | service-disable | ansible-windows | needs-change-approval |
| FIND-4 | LNX-DB03 | Sudo Heap Overflow (Baron Samedit) | CVE-2021-3156 | Critical | patch | ansible-unix | auto-approvable |
| FIND-10 | WIN-BASTION02 | Internet-facing RDP | — | High | network-restriction | ansible-windows | needs-change-approval |
| FIND-3 | WIN-APP07 | MSHTML Security Feature Bypass | CVE-2024-30040 | High | patch | ansible-windows | auto-approvable |
| FIND-5 | LNX-WEB05 | OpenSSL Infinite Loop DoS | CVE-2022-0778 | High | patch | ansible-unix | needs-change-approval |
| FIND-7 | AXIS-CAM-LOBBY-03 | Telnet Service Exposed | — | High | config-change | manual-only | manual-only |
| FIND-9 | MDM-IPHONE-J-SMITH | Outdated iOS Version | — | Medium | manual-investigation | manual-only | manual-only |

## Per-finding detail

### FIND-6 — Cisco IOS XE Web UI Privilege Escalation — Critical (CVE-2023-20198)
**Rationale:** No network-device fixer exists yet, and this is core switching infrastructure
— even once automation exists here, a config push to `CSW-CORE01` warrants manual/change-
managed execution regardless. **Rollback:** re-enable the HTTP/HTTPS server feature if the
fix breaks a dependent management workflow (verify none exist first).

### FIND-1 — PrintNightmare RCE — Critical (CVE-2021-34527)
**Rationale:** Mechanical fix (patch or disable Print Spooler) is well understood, but
`WIN-DC01` is a domain controller — any change there needs change-management sign-off
regardless of how routine the fix looks. **Rollback:** restore from pre-patch VM/config
snapshot, or re-enable the Print Spooler service if disabling it breaks a dependent print
workflow.

### FIND-8 — Unauthenticated Management Interface — Critical (CVE-2019-7592)
**Rationale:** No OT/IoT fixer exists yet; this is a building-automation controller, where
an automated config push carries physical-safety-adjacent risk (HVAC) that needs a human
in the loop regardless of automation maturity. **Rollback:** revert to prior device config
backup if authentication enablement disrupts a dependent integration.

### FIND-11 — OpenSSH Auth Bypass Regression — Critical (CVE-2024-6387)
**Rationale:** Mechanical fix (package upgrade) exists, but `LNX-AUTH01` handles internal
authentication traffic — an SSH-related change on an auth-critical host needs approval
even though the fix itself is narrow. **Rollback:** downgrade `openssh-server` to the
previous version via the distro package cache/repo if the upgrade causes issues.

### FIND-2 — EternalBlue (SMBv1 RCE) — Critical (CVE-2017-0144)
**Rationale:** Disabling SMBv1 is the standard fix, but `WIN-FS02` is a file server —
legacy clients/scripts may still depend on SMBv1, so this needs a change window to confirm
before disabling. **Rollback:** re-enable the SMB1Protocol Windows feature via
`Enable-WindowsOptionalFeature` if legacy clients break.

### FIND-4 — Sudo Heap Overflow (Baron Samedit) — Critical (CVE-2021-3156)
**Rationale:** A single-package upgrade (`sudo`) with no service restart required and a
widely-deployed, well-tested vendor fix — low blast radius even on a database host.
**Rollback:** downgrade the `sudo` package via the distro's package cache if unexpected
issues arise (extremely unlikely for this fix).

### FIND-10 — Internet-facing RDP on Bastion Host — High
**Rationale:** The fix (restrict RDP source range) is mechanical, but `WIN-BASTION02` is a
critical remote-access entry point — a misconfigured rule risks locking out legitimate
admin access, so this needs a human to confirm the approved source range before applying.
**Rollback:** revert the firewall rule to its prior scope if legitimate access is blocked.

### FIND-3 — MSHTML Security Feature Bypass — High (CVE-2024-30040)
**Rationale:** Standard monthly-cycle Windows Update on a non-DC application server —
routine enough to auto-approve within a normal patch window. **Rollback:** uninstall the
applicable update via `wusa /uninstall` if it causes an application regression.

### FIND-5 — OpenSSL Infinite Loop DoS — High (CVE-2022-0778)
**Rationale:** Package upgrade is mechanical, but `LNX-WEB05` is a live web server and the
OpenSSL upgrade likely requires restarting the web service — brief downtime risk means a
maintenance window should be scheduled. **Rollback:** downgrade the OpenSSL package and
restart the web service if the new version causes compatibility issues.

### FIND-7 — Telnet Service Exposed — High
**Rationale:** No IoT/OT device fixer exists yet; disabling Telnet on this camera requires
its vendor-specific management interface, which isn't automated in this pipeline today.
**Rollback:** re-enable Telnet temporarily if the encrypted management alternative isn't
reachable (then re-investigate connectivity before re-disabling).

### FIND-9 — Outdated iOS Version — Medium
**Rationale:** No fixer for mobile/MDM-managed endpoints; this is an MDM compliance-policy
action (nudge/enforce update), not a scriptable infra change. **Rollback:** not applicable
— this is a user-facing update prompt, not a system change.

## Findings with no automated remediation path today

- **FIND-6** (network-routing-switching) and **FIND-7, FIND-8, FIND-9** (iot-ot-device)
  have no working `remediation-fixer-*` subagent. Supporting them would need:
  - `remediation-fixer-network`: generates vendor CLI config diffs (Cisco IOS/IOS
    XE/JunOS) for routing/switching devices, likely via Ansible's network collections
    (`cisco.ios`, `junipernetworks.junos`) or vendor Terraform providers.
  - `remediation-fixer-iot`: given how fragmented IoT/OT vendor management APIs are
    (Axis, Johnson Controls, and everything else), this is realistically a per-vendor
    integration effort, not one generic fixer — start with the highest-volume device
    types in the fleet.
  - Mobile/MDM-managed endpoints (like FIND-9) route through the existing MDM platform's
    compliance policies, not through infra automation at all — that's a different
    integration entirely (Intune/Jamf API), not a gap in this pipeline's design.
