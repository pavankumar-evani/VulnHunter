# Remediation Plan — 15 findings (Tenable: 10, Armis: 3, Threat Intel: 2)

**Automated remediation available today:** 7 findings (windows-server + unix-server)
**Manual-only (no fixer for this asset class yet):** 8 findings (network-routing-switching,
network-security-device, iot-ot-device, application, certificate)

**Risk tier split:** 2 auto-approvable · 5 needs-change-approval · 8 manual-only

**Threat intel:** 10 of 15 findings have a CVE and were checked against CISA KEV + EPSS
data (FIND-8's CVE has a KEV check but no EPSS score available). **7 are KEV-listed**
(confirmed actively exploited in the wild) and **8 have an EPSS score ≥ 50%** (near-term
exploitation probability) — 2 findings clear the EPSS bar without being KEV-listed
(FIND-5 at 70.6%, FIND-11 at 99.5%), which is exactly why both signals matter: EPSS
catches near-term risk KEV hasn't (yet) confirmed.

**New this run: FIND-15** (CVE-2024-3400, Palo Alto PAN-OS GlobalProtect command
injection, `network-security-device`, KEV-listed since 2024-04-12, EPSS ~100.0%) — ranked
#1 in the queue.

**Why some "simple" fixes are still `manual-only` risk tier:** `needs-change-approval` and
`auto-approvable` both presuppose there's an auto-generated artifact (an Ansible playbook)
for a human to review or run. For the 8 findings whose `automation_target` is
`manual-only` — no `remediation-fixer-*` subagent exists yet for their domain — there is no
artifact to approve or auto-run, so the conservative, honest `risk_tier` is `manual-only`
even when the underlying fix (e.g., disabling Telnet on one camera) is intrinsically
low-risk. Only the 7 findings on `windows-server`/`unix-server` get the finer-grained
`auto-approvable` vs. `needs-change-approval` split, based on asset criticality and
whether the fix needs a reboot/service restart.

## Remediation queue (priority order)

| ID | Asset | Title | CVE | Severity | Action Type | Automation Target | Risk Tier | KEV | EPSS |
|----|-------|-------|-----|----------|-------------|--------------------|-----------|-----|------|
| FIND-15 | FW-EDGE01 | PAN-OS GlobalProtect Command Injection | CVE-2024-3400 | Critical | firmware-update | manual-only | manual-only | Yes | 100.0% |
| FIND-6 | CSW-CORE01 | Cisco IOS XE Web UI Privilege Escalation | CVE-2023-20198 | Critical | config-change | manual-only | manual-only | Yes | 99.6% |
| FIND-12 | APP-ORDERS01 | Apache Log4j2 RCE (Log4Shell) | CVE-2021-44228 | Critical | patch | manual-only | manual-only | Yes | 100.0% |
| FIND-1 | WIN-DC01 | PrintNightmare RCE | CVE-2021-34527 | Critical | patch | ansible-windows | needs-change-approval | Yes | 99.8% |
| FIND-2 | WIN-FS02 | EternalBlue (SMBv1 RCE) | CVE-2017-0144 | Critical | service-disable | ansible-windows | needs-change-approval | Yes | 99.2% |
| FIND-4 | LNX-DB03 | Sudo Heap Overflow (Baron Samedit) | CVE-2021-3156 | Critical | patch | ansible-unix | auto-approvable | Yes | 99.3% |
| FIND-11 | LNX-AUTH01 | OpenSSH Auth Bypass Regression | CVE-2024-6387 | Critical | patch | ansible-unix | needs-change-approval | No | 99.5% |
| FIND-8 | HVAC-CTRL-B2 | Unauthenticated Mgmt Interface | CVE-2019-7592 | Critical | config-change | manual-only | manual-only | No | — |
| FIND-5 | LNX-WEB05 | OpenSSL Infinite Loop DoS | CVE-2022-0778 | High | patch | ansible-unix | needs-change-approval | No | 70.6% |
| FIND-3 | WIN-APP07 | MSHTML Security Feature Bypass | CVE-2024-30040 | High | patch | ansible-windows | auto-approvable | Yes | 3.9% |
| FIND-10 | WIN-BASTION02 | Internet-facing RDP | — | High | network-restriction | ansible-windows | needs-change-approval | — | — |
| FIND-7 | AXIS-CAM-LOBBY-03 | Telnet Service Exposed | — | High | config-change | manual-only | manual-only | — | — |
| FIND-13 | WEB-PORTAL01 | SSL Certificate Expiry | — | Medium | config-change | manual-only | manual-only | — | — |
| FIND-14 | WEB-PORTAL01 | Deprecated TLSv1.0/1.1 Protocol | — | Medium | config-change | manual-only | manual-only | — | — |
| FIND-9 | MDM-IPHONE-J-SMITH | Outdated iOS Version | — | Medium | manual-investigation | manual-only | manual-only | — | — |

## Per-finding detail

### FIND-15 — PAN-OS GlobalProtect Command Injection — **CRITICAL** (CVE-2024-3400)
**Priority: High — escalated by CISA KEV** (listed 2024-04-12, known ransomware campaign
use) **and EPSS 100.0%** (99.999th+ percentile) — an unauthenticated, root-level RCE on an
internet/perimeter-facing firewall, about as urgent as findings get. **Rationale for risk
tier:** no fixer exists for `network-security-device` findings yet, and this is the
network perimeter regardless — every remediation step here must be a human-run, reviewed
change on the firewall. **Rollback:** roll back to the previous PAN-OS version via the
firewall's saved config/software rollback feature, or re-enable GlobalProtect telemetry
and restore the prior firewall config from backup if it was disabled as an interim
mitigation.

### FIND-6 — Cisco IOS XE Web UI Privilege Escalation — **CRITICAL** (CVE-2023-20198)
**Priority: High — escalated by CISA KEV**, EPSS 99.6%, CVSS 10.0 (maximum). **Rationale
for risk tier:** no network-device fixer exists yet, and this is core switching
infrastructure regardless — disabling the web UI or applying the vendor fix must be done
and verified by a human. **Rollback:** re-enable the HTTP/HTTPS server feature (or restore
the prior IOS XE image/config) from the device's saved configuration backup if the fix
breaks a dependent management workflow (verify none exist first).

### FIND-12 — Apache Log4j2 RCE (Log4Shell) — **CRITICAL** (CVE-2021-44228)
**Priority: High — escalated by CISA KEV** (listed 2021-12-10, known ransomware campaign
use) **and EPSS 100.0%** (99.9998th percentile) — this is about as close to "certain to be
targeted" as a CVE gets. **Rationale for risk tier:** no fixer exists for `application`
findings yet — a library upgrade needs to go through the app's own build/release process,
not a generic Ansible playbook, and a human must validate the upgrade doesn't break
logging behavior. **Rollback:** roll back the application deployment to the previous
build/artifact (pre-upgrade Log4j2 version) via the CI/CD release history if the upgrade
breaks the app.

### FIND-1 — PrintNightmare RCE — **CRITICAL** (CVE-2021-34527)
**Priority: High — escalated by CISA KEV** (listed 2021-11-03, known ransomware campaign
use), EPSS 99.8%. **Rationale for risk tier:** `WIN-DC01` is a domain controller — change
approval required regardless of how routine the fix looks. **Rollback:** restore from
pre-patch VM/system-state snapshot, or re-enable the Print Spooler service if disabling it
breaks a dependent print workflow.

### FIND-2 — EternalBlue (SMBv1 RCE) — **CRITICAL** (CVE-2017-0144)
**Priority: High — escalated by CISA KEV** (known ransomware campaign use — this is the
CVE WannaCry and NotPetya used), EPSS 99.2%. **Rationale for risk tier:** `WIN-FS02` is a
file server — legacy clients/scripts may still depend on SMBv1, so this needs a change
window to confirm before disabling. **Rollback:** re-enable the SMB1Protocol Windows
feature via `Enable-WindowsOptionalFeature` (and/or uninstall the MS17-010 patch from the
system-state snapshot) if legacy clients break.

### FIND-4 — Sudo Heap Overflow (Baron Samedit) — **CRITICAL** (CVE-2021-3156)
**Priority: High — escalated by CISA KEV**, EPSS 99.3%. **Rationale for risk tier:**
single-package upgrade, no service restart required, widely-deployed and well-tested
vendor fix — low blast radius even on a database host. **Rollback:** downgrade the `sudo`
package via the distro's package cache if unexpected issues arise (extremely unlikely).

### FIND-11 — OpenSSH Auth Bypass Regression — **CRITICAL** (CVE-2024-6387)
**Priority: High — escalated by EPSS 99.5%** despite not (yet) being KEV-listed — exactly
the case EPSS exists for: very high near-term exploitation probability ahead of confirmed
in-the-wild use. **Rationale for risk tier:** `LNX-AUTH01` handles internal authentication
traffic — needs approval even though the fix itself is narrow. **Rollback:** downgrade
`openssh-server` to the previous version via the distro package cache/repo if the upgrade
causes issues.

### FIND-8 — Unauthenticated Management Interface — **CRITICAL** (CVE-2019-7592)
**Priority: High — not KEV-listed, no EPSS score available, escalated by asset
criticality**: building-automation controller, where a misconfiguration carries
physical-safety-adjacent risk (HVAC) regardless of exploitation-likelihood signals.
**Rationale for risk tier:** no OT/IoT fixer exists yet, and this specific vendor's fix
(enable auth + restrict to an OT VLAN) needs a human to implement and verify against the
device's own management console. **Rollback:** revert to the prior device config backup if
enabling authentication (or the VLAN restriction) disrupts a dependent integration.

### FIND-5 — OpenSSL Infinite Loop DoS — **HIGH** (CVE-2022-0778)
**Priority: High — escalated by EPSS 70.6%** despite not being KEV-listed. **Rationale
for risk tier:** the package upgrade itself is mechanical, but `LNX-WEB05` is a live web
server and the OpenSSL upgrade likely requires restarting the web service — brief downtime
risk means a maintenance window should be scheduled. **Rollback:** downgrade the OpenSSL
package and restart the web service if the new version causes compatibility issues.

### FIND-3 — MSHTML Security Feature Bypass — **HIGH** (CVE-2024-30040)
**Priority: High — KEV-listed** (2024-05-14) despite a low EPSS score (3.9%) — a good
example of the two signals disagreeing: KEV confirms this has been used in a real attack
chain, even though EPSS's predictive model doesn't rate broad near-term reuse as highly.
When they disagree, KEV (confirmed fact) takes precedence over EPSS (prediction).
**Rationale for risk tier:** routine monthly-cycle Windows Update on a non-DC application
server — auto-approvable within a normal patch window. **Rollback:** uninstall the
applicable update via Windows Update history if it causes a regression.

### FIND-10 — Internet-facing RDP on Bastion Host — **HIGH**
**Priority: High — no CVE/KEV/EPSS signal (this is a threat-intel/config finding, not a
CVE), escalated by asset criticality**: `WIN-BASTION02` is a critical remote-access entry
point and RDP exposure is a top ransomware initial-access vector. **Rationale for risk
tier:** the fix is mechanical, but a misconfigured rule risks locking out legitimate admin
access — needs a human to confirm the approved source range. **Rollback:** revert the
firewall/NSG rule to its prior scope if legitimate access is blocked.

### FIND-7 — Telnet Service Exposed — **MEDIUM (priority)** / High severity
**Priority: Medium** — no CVE/KEV/EPSS signal; falls back to severity + asset criticality,
and this is a single non-critical lobby camera, not core infrastructure, so it's tempered
down from the High severity label. **Rationale for risk tier:** no IoT/OT device fixer
exists yet; disabling Telnet on this camera requires its vendor-specific management
interface, so a human must apply and verify the change even though the change itself
(switch to SSH/HTTPS, no known dependents on Telnet) is low-risk. **Rollback:** re-enable
Telnet temporarily if the encrypted management alternative isn't reachable, then
re-investigate connectivity before re-disabling.

### FIND-13 — SSL Certificate Expiry — **MEDIUM**
**Priority: Medium** — no CVE, so no KEV/EPSS signal applies; falls back to the Medium
severity label. This is time-sensitive to schedule promptly (expires within 30 days) even
though it isn't classified as urgent by the KEV/EPSS heuristics. **Rationale for risk
tier:** no fixer exists yet — renewal needs integration with the org's CA/ACME tooling, not
a generic config change, so a human must run the renewal today. **Rollback:** re-install
the previous (still-valid) certificate and key from backup if the new certificate causes
TLS handshake failures.

### FIND-14 — Deprecated TLSv1.0/1.1 Protocol — **MEDIUM**
**Priority: Medium** — no CVE, no KEV/EPSS signal; falls back to the Medium severity
label. **Rationale for risk tier:** no TLS-config fixer exists yet, and disabling old TLS
versions carries a small compatibility risk (very old clients that only support TLS
1.0/1.1 would break), so it needs a human to check the client population and apply the
change. **Rollback:** re-enable the deprecated protocol versions in the web server's TLS
configuration from the pre-change config backup if a legacy client breaks.

### FIND-9 — Outdated iOS Version — **LOW**
**Priority: Low** — no CVE, no KEV/EPSS signal, lowest-criticality asset (a single user's
phone). **Rationale for risk/action:** this is the textbook "vague outdated OS version"
alert with no specific CVE or patch identified — a human needs to determine the correct
iOS update and enforce it via MDM policy; there's no fixer for mobile/MDM-managed
endpoints either way. **Rollback:** not applicable until a specific update path is chosen;
relax the MDM compliance policy back to its prior state via the MDM console if enforcement
causes issues.

## Findings with no automated remediation path today

- **FIND-6** (network-routing-switching) and **FIND-15** (network-security-device) need a
  `remediation-fixer-network` subagent generating vendor CLI/API config diffs — e.g. Cisco
  IOS/IOS XE CLI (via Ansible's `cisco.ios` collection) for switches/routers, and PAN-OS
  CLI/XML API for Palo Alto firewalls. These are different enough (routing/switching vs.
  security-appliance policy) that this realistically needs multiple vendor templates
  rather than one shared mechanism.
- **FIND-7, FIND-8, FIND-9** (iot-ot-device) need a `remediation-fixer-iot-ot` subagent —
  given how fragmented IoT/OT vendor management APIs are (Axis cameras, Johnson Controls
  building-management systems, and MDM platforms), this is realistically a per-vendor
  integration effort rather than one generic fixer. FIND-9 specifically routes through an
  MDM platform's compliance policies (Intune/Jamf API), a different integration entirely
  from infra automation.
- **FIND-12** (application) needs a `remediation-fixer-application` subagent: a
  library/dependency upgrade goes through the application's own build and release pipeline
  (Maven/Gradle for a JVM app, npm for Node, pip for Python, etc.) — a fundamentally
  different mechanism per language/package manager, unlike the OS-level fixers' shared
  Ansible approach.
- **FIND-13, FIND-14** (certificate) need integration with the org's CA/ACME tooling for
  renewal (FIND-13) and a TLS-config fixer for protocol/cipher hardening (FIND-14) —
  mechanically simple individually, but organization-specific enough (which CA, which ACME
  client, which web server config format) that no generic fixer exists yet.
