# Module licensing

Quanta is organised into eight modules (see the sidebar and the **All modules** page). The module is also the unit of licence. This page describes how that works; **prices and tiers live in
[PRICING.md](PRICING.md)** and are not decided here.

## What is licensed

| # | Module (id) | Routes it covers |
|---|---|---|
| 1 | Threat Detection & Response (`soc`) | SOC operations, hunting, detection engineering, threat intelligence, dark web watch, SOAR, XSIAM, alert / intel ingest |
| 2 | Application Security (`appsec`) | API security, threat models, code scan, API traffic / spec / test-result ingest |
| 3 | DevSecOps & Supply Chain (`devsecops`) | Control library, applications and SBOMs, fix pull requests, pipeline gates, secure design, SBOM ingest, Git webhooks |
| 4 | Infrastructure & Exposure (`infra`) | Scanner and asset-source connectors, assets, firewall rules, controls, zero-day watch, attack paths, quantum readiness |
| 5 | AI Security (`ai`) | AI vulnerabilities, AI security posture, AI usage and its ingest |
| 6 | Remediation & Workflow (`remediation`) | Plans, approvals, remediation policy, assignments, exceptions, run, ServiceNow / Jira |
| 7 | Risk, Governance & Compliance (`grc`) | Risk and compliance, cyber risk, ML insights, access governance, reports, activity log |
| 8 | Administration (`admin`) | Always included |

**Always included (core):** signing in, the platform shell, the findings store every module writes into (`/api/queue`, `/api/findings`, scanner / SARIF / CSV ingest), search, notifications, support,
teams, connections and API keys, and administration, so a licence can always be applied and a customer is never locked out of their own data. A few connectors serve two modules and need either: Prisma Cloud
(`infra` or `appsec`), Splunk (`soc` or `remediation`), the risk dashboard (`infra` or `grc`). The full route-to-module map is `remediation/config/licensing.yaml`; a test fails if any API route is missing from it.

## The licence

A licence is a small signed document:

```json
{"v": 1, "id": "k3F9...", "customer": "Acme Ltd", "edition": "secops", "modules": ["infra", "remediation", "soc"], "issued": "2026-10-05", "expires": "2027-10-04", "grace_days": 14}
```

It is signed with the vendor's **Ed25519 private key** and verified by the deployment with the vendor **public key**, entirely offline. Nothing is sent anywhere, so it works in an air-gapped network.
The token is `base64url(claims).base64url(signature)`.

```bash
python cli/quanta_license.py keygen --out-dir keys                       # once, by the vendor; keep vendor_private.pem secret
python cli/quanta_license.py issue --private-key keys/vendor_private.pem --customer "Acme Ltd" --edition secops --expires 2027-10-04 --out acme.licence
python cli/quanta_license.py issue --private-key keys/vendor_private.pem --customer "Acme Ltd" --modules soc,appsec --expires 2027-10-04
python cli/quanta_license.py verify --public-key keys/vendor_public.pem --license acme.licence
```

`--edition` is a shortcut for a bundle listed in `licensing.yaml` (`secops`, `appsec`, `platform`, `enterprise`); the licence always lists its modules explicitly, so a bundle can change later without
affecting licences already issued. Bundles are examples, not commercial packages.

## Installing it

| Setting | Meaning |
|---|---|
| `QUANTA_LICENSE` or `QUANTA_LICENSE_FILE` | The licence token, or the file holding it |
| `QUANTA_LICENSE_PUBLIC_KEY_FILE` | The vendor public key (or ship it as `remediation/licensing/vendor_public_key.pem`) |
| `QUANTA_LICENSE_MODE` | `off` (default: nothing is checked), `warn` (read and reported, never blocks), `enforce` |

Start with `warn`: **All modules** and `GET /api/license` show what the licence covers and what would be blocked, without blocking anything.

## What the customer sees

* **Picker and sidebar:** a module the licence does not cover is shown locked ("not licensed") and never opens; the command palette does not offer its pages. The sidebar shows one module at a time, so a
  customer with two modules sees a short, focused app.
* **Pages:** opening a locked module's page by URL shows "not part of your licence" instead of a page full of refused calls.
* **API:** in `enforce` mode a route of an unlicensed module answers `403 {"detail": ..., "modules": [...], "license_state": ...}`; core routes never do.
* **States:** `valid`; `expiring` (30 days before the end); `grace` (past the end date, still working for `grace_days`, default 14); `expired` (only core remains); `missing` and `invalid` (no licence, no
  verification key, bad signature: only core remains in `enforce` mode).

## Honest limits

* Quanta is self-hosted. A technical guardrail cannot stop someone who can edit the code from removing it; the licence terms are what bind. This is a clear, auditable, offline contract with a guardrail, not copy protection.
* There is no seat, asset-count or usage metering, and no telemetry; those would need either a phone-home (not offered) or counting rules agreed in the commercial terms.
* Module boundaries are API route prefixes. Data a module has already written into the shared findings store remains readable through core routes after a module is removed.
* The mechanism is unit-tested with generated keys. It has never been used with a real issued licence or a real vendor key.

## Adding a feature

Add the new route prefix to `remediation/config/licensing.yaml` (core, one module, or `shared`) and the page to the module in `dashboard/static/js/nav.js` and `remediation/config/capabilities.yaml`.
`tests/test_licensing.py` fails if a route has no entry or if the three module lists drift apart.
