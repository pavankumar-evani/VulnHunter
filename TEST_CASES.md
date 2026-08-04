# VulnHunter — Test Cases & Results

Formal test case log for all twenty-six test files: `tests/test_pipeline_artifacts.py` (both
pipelines' real output artifacts), `tests/test_cli.py` (the headless CLI),
`tests/test_dashboard.py` (the web dashboard's FastAPI JSON API and SPA shell routes,
including the live queue, priority-rules editor, ServiceNow/Jira/Splunk preview, the
local-auth/RBAC gating on every sensitive mutation route, the notification feed, the
Risk dashboard's ATT&CK heat map, AI-assist, on-demand reports, the
exceptions/risk-acceptance workflow, the asset inventory, and generic-connector
ingestion), `tests/test_ai_assist.py` (pure prompt-construction logic for the
dashboard's AI-assist feature), `tests/test_reports.py` (the dashboard's on-demand
report-generation logic, both stub-data and real-artifact),
`tests/test_multilang_scanner_patterns.py` (static consistency checks between the
scanner's per-language detection guidance and the Java/JS/Go/PHP/Perl fixture files),
`tests/test_connectors.py` (live Tenable/Armis connectors), `tests/test_enrichment.py`
(live CISA KEV + EPSS enrichment), `tests/test_priority_engine.py` (the configurable
priority/SLA engine), `tests/test_attack_mapping.py` (MITRE ATT&CK keyword tagging,
including the `/risk` heat-map builder), `tests/test_servicenow_connector.py` (the
ServiceNow adapter), `tests/test_exceptions_store.py` (the vulnerability exception /
risk-acceptance workflow), `tests/test_asset_inventory.py` (the per-asset inventory
view, editable ownership store, and internal/external-facing classification),
`tests/test_generic_connector.py` (the vendor-agnostic "bring your own XDR/EDR/SIEM"
webhook ingestion adapter), `tests/test_scan_type_mapping.py` (the finding-category
taxonomy derived from asset type), `tests/test_auth.py` (local password hashing,
session cookies, the user store, and the OIDC client), `tests/test_compensating_controls.py`
(keyword-heuristic compensating-control suggestions), `tests/test_jira_connector.py`,
`tests/test_splunk_connector.py`, `tests/test_crowdstrike_connector.py` (the
Jira/Splunk/CrowdStrike Falcon connectors), `tests/test_cmdb_import.py` (bulk
CMDB-export CSV import for the asset inventory's owner/team fields), and
`tests/test_infoblox_connector.py`, `tests/test_axonius_connector.py` (the Infoblox
NIOS and Axonius asset-inventory pull connectors — unlike every connector before them,
these normalize into asset records, not vulnerability findings), and
`tests/test_pattern_recognition.py` (the pattern-matched, explicitly-not-machine-learning
owner/team/type suggestion heuristic for the asset inventory), and
`tests/test_ai_vuln_taxonomy.py` (the AI/ML vulnerability taxonomy and its
illustrative MITRE ATLAS cross-reference, same keyword-heuristic honesty pattern as
`test_attack_mapping.py`), and `tests/test_infra_classification.py` (the OS/Network/
Network Security/OT-IoT/Cloud sub-classification behind the Infrastructure
Vulnerabilities hub). Every row below
maps 1:1 to one `test_*` method in one of those files — there is no test case here
without a corresponding, runnable assertion, and no assertion in any suite that isn't
documented here.

**How to reproduce these results yourself:**
```bash
pip install -r dashboard/requirements.txt
pip install -r remediation/connectors/requirements.txt
pip install -r remediation/enrichment/requirements.txt
pip install -r remediation/config/requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
```

**Last run:** 562 / 562 passed, 0 failures, 0 errors. Raw output captured in
[`tests/test_results.txt`](tests/test_results.txt).

**What these tests do NOT do:** they don't invoke the Claude Code subagents directly
(subagents only run inside an interactive Claude Code session — see
[KNOWLEDGE_TRANSFER.md §12](KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)),
and — with one deliberate exception — they never call a real external API. The
exception: `test_enrichment.py`'s `LiveSmokeTest` calls the real, free, public CISA KEV
feed and FIRST.org EPSS API (safe: no auth, no cost, and it skips itself rather than
failing if the network is unavailable). Everything else validates the real artifacts
those agents/scripts produced — git history for `/vulnhunt`, generated files for
`/remediate` — which is what makes this both real regression coverage and honest test
evidence rather than a mocked demo.

---

## Summary by suite

| Suite | Test class | Test cases | Result |
|---|---|---|---|
| `/vulnhunt` scan | `VulnHuntScannerFindsRealVulnerabilities` | TC-SCAN-01 – 07 | 7/7 PASS |
| `/vulnhunt` fix | `VulnHuntFixerAppliesOnlyApprovedFixes` | TC-FIX-01 – 08 | 8/8 PASS |
| `/vulnhunt` report | `VulnHuntReportIsAccurate` | TC-RPT-01 – 03 | 3/3 PASS |
| `/remediate` normalize | `RemediationNormalizedFindingsAreWellFormed` | TC-NORM-01 – 09 | 9/9 PASS |
| `/remediate` plan | `RemediationPlanIsConsistentWithFindings` | TC-PLAN-01 – 02 | 2/2 PASS |
| `/remediate` playbooks | `RemediationPlaybooksMatchThePlan` | TC-PB-01 – 05 | 5/5 PASS |
| Cross-cutting safety | `NoRealSecretsLeakedAnywhere` | TC-SEC-01 | 1/1 PASS |
| CLI prompt/command construction | `PromptConstruction`, `CommandConstruction` | TC-CLI-01 – 10 | 10/10 PASS |
| CLI binary discovery | `ClaudeBinaryDiscovery` | TC-CLI-11 | 1/1 PASS |
| CLI end-to-end dry-run | `DryRunEndToEnd` | TC-CLI-12 – 13 | 2/2 PASS |
| Dashboard data layer | `DataLayerReadsRealArtifacts` | TC-DASH-01 – 08 | 8/8 PASS |
| Dashboard `/api/overview` | `ApiOverview` | TC-DASH-09 | 1/1 PASS |
| Dashboard `/api/vulnhunt` | `ApiVulnhunt` | TC-DASH-10 | 1/1 PASS |
| Dashboard `/api/remediate` | `ApiRemediate` | TC-DASH-11 | 1/1 PASS |
| Dashboard `/api/playbooks/{filename}` | `ApiPlaybookDetail` | TC-DASH-12 – 13 | 2/2 PASS |
| Dashboard `/api/run` | `ApiRunPipeline` | TC-DASH-14 – 16 | 3/3 PASS |
| Dashboard `/api/status` | `ApiStatus` | TC-DASH-17 | 1/1 PASS |
| Dashboard `/api/queue` (live queue) | `ApiLiveQueue` | TC-DASH-18 – 19, 106 | 3/3 PASS |
| Dashboard `/api/priority-rules` editor | `ApiPriorityRules` | TC-DASH-20 – 22 | 3/3 PASS |
| Dashboard `/api/servicenow/*` | `ApiServiceNow` | TC-DASH-23 – 25 | 3/3 PASS |
| Dashboard SPA shell routes | `HtmlShellRoutesServeTheSpaShell` | TC-DASH-26 – 31 | 6/6 PASS |
| Dashboard `/api/ai-assist` | `ApiAiAssist` | TC-DASH-32 – 38 | 7/7 PASS |
| Dashboard `/api/reports/*` | `ApiReports` | TC-DASH-39 – 42 | 4/4 PASS |
| Dashboard `/api/exceptions` (risk-acceptance workflow) | `ApiExceptions` | TC-DASH-43 – 49 | 7/7 PASS |
| Dashboard `/api/assets` (asset inventory + ownership) | `ApiAssets` | TC-DASH-50 – 51 | 2/2 PASS |
| Dashboard `/api/ingest/generic` (generic webhook ingestion) | `ApiIngestGeneric` | TC-DASH-52 – 56 | 5/5 PASS |
| Dashboard authentication (login/logout/me/change-password/OIDC) | `ApiAuth` | TC-DASH-57 – 66 | 10/10 PASS |
| Dashboard auth-gating on existing mutation routes | `ApiRunPipeline`, `ApiPriorityRules`, `ApiServiceNow`, `ApiAiAssist`, `ApiExceptions`, `ApiAssets` (additional cases) | TC-DASH-67 – 81 | 15/15 PASS |
| Dashboard notification feed | `ApiNotifications` | TC-DASH-82 – 87 | 6/6 PASS |
| Dashboard `/api/risk/attack-heatmap` | `ApiRiskAttackHeatmap` | TC-DASH-88 – 89 | 2/2 PASS |
| Dashboard `/api/ai-vulnerabilities` | `ApiAiVulnerabilities` | TC-DASH-104 – 105 | 2/2 PASS |
| Dashboard `/api/jira/*` | `ApiJira` | TC-DASH-90 – 93 | 4/4 PASS |
| Dashboard `/api/splunk/*` | `ApiSplunk` | TC-DASH-94 – 97 | 4/4 PASS |
| Dashboard `/api/assets/cmdb-import/*` | `ApiAssets` (additional cases) | TC-DASH-98 – 100 | 3/3 PASS |
| Dashboard `/api/assets` pattern-suggestion field | `ApiAssets` (additional cases) | TC-DASH-101 – 103 | 3/3 PASS |
| Dashboard AI-assist prompt construction | `PromptConstruction` | TC-AI-01 – 12 | 12/12 PASS |
| Dashboard report data generation | `GenerateReportData` | TC-REPORTGEN-01 – 07 | 7/7 PASS |
| Dashboard report HTML rendering | `RenderReportHtml` | TC-REPORTGEN-08 – 12 | 5/5 PASS |
| Dashboard report generation against real artifacts | `RealArtifactIntegration` | TC-REPORTGEN-13 – 14 | 2/2 PASS |
| Vulnerability exception lifecycle (request/approve/expire/revoke) | `ExceptionLifecycle` | TC-EXC-01 – 14 | 14/14 PASS |
| Vulnerability exception real seed-file validation | `RealSeedFileIsValid` | TC-EXC-15 | 1/1 PASS |
| Asset inventory aggregation | `BuildAssetInventory` | TC-INV-01 – 07 | 7/7 PASS |
| Asset ownership store | `OwnershipStore` | TC-INV-08 – 11 | 4/4 PASS |
| Asset ownership real seed-file validation | `RealSeedFileIsValid` | TC-INV-12 | 1/1 PASS |
| Asset inventory facing classification + critical count | `BuildAssetInventory`, `OwnershipStore` (additional cases) | TC-INV-13 – 19 | 7/7 PASS |
| Generic connector payload validation | `ValidateGenericPayload` | TC-GENC-01 – 08 | 8/8 PASS |
| Generic connector finding normalization | `NormalizeGenericFinding` | TC-GENC-09 – 17 | 9/9 PASS |
| Scan-type classification | `ClassifyFinding` | TC-CAT-01 – 07 | 7/7 PASS |
| Scan-type batch tagging | `TagScanTypes` | TC-CAT-08 – 09 | 2/2 PASS |
| Scan-type taxonomy completeness | `Taxonomy` | TC-CAT-10 – 11 | 2/2 PASS |
| Multi-language fixture directory sanity | `FixtureDirectoryIsSeparateFromDemoApp` | TC-LANG-01 – 03 | 3/3 PASS |
| Multi-language Java fixture | `JavaFixture` | TC-LANG-04 – 07 | 4/4 PASS |
| Multi-language JavaScript fixture | `JavaScriptFixture` | TC-LANG-08 – 11 | 4/4 PASS |
| Multi-language Go fixture | `GoFixture` | TC-LANG-12 – 15 | 4/4 PASS |
| Multi-language PHP fixture | `PhpFixture` | TC-LANG-16 – 19 | 4/4 PASS |
| Multi-language Perl fixture | `PerlFixture` | TC-LANG-20 – 23 | 4/4 PASS |
| Multi-language scanner doc consistency | `ScannerDocumentationCoversEachLanguage` | TC-LANG-24 – 31 | 8/8 PASS |
| Tenable connector | `TenableAuthAndExportRequest`, `TenablePollAndDownload`, `TenableRecordMapping`, `TenableWritesSampleCompatibleCsv` | TC-CONN-01 – 11 | 11/11 PASS |
| Armis connector | `ArmisAuthentication`, `ArmisPagination`, `ArmisDeviceAndAlertAssembly` | TC-CONN-12 – 18 | 7/7 PASS |
| KEV/EPSS fetching | `KevFetching`, `EpssFetching` | TC-ENR-01 – 05 | 5/5 PASS |
| KEV/EPSS enrichment assembly | `EnrichmentAssembly`, `EnrichFileIO` | TC-ENR-06 – 12 | 7/7 PASS |
| KEV/EPSS live smoke test | `LiveSmokeTest` | TC-ENR-13 | 1/1 PASS |
| Priority scoring | `PriorityScoring` | TC-PRIO-01 – 07 | 7/7 PASS |
| SLA computation | `SlaComputation` | TC-PRIO-08 – 10 | 3/3 PASS |
| Batch scoring + real rules file validation | `ScoreFindingsBatch`, `RealRulesFileIsValid` | TC-PRIO-11 – 14 | 4/4 PASS |
| ATT&CK keyword matching | `KeywordMatching` | TC-ATTACK-01 – 09 | 9/9 PASS |
| ATT&CK batch tagging | `TagFindingsBatch` | TC-ATTACK-10 – 11 | 2/2 PASS |
| ATT&CK heat map (feeds the `/risk` dashboard) | `AttackHeatmap` | TC-ATTACK-12 – 14 | 3/3 PASS |
| ServiceNow construction + auth | `AuthAndConstruction`, `BuildIncidentBodyPureFunction` | TC-SNOW-01 – 06 | 6/6 PASS |
| ServiceNow incident creation | `FindExistingIncident`, `CreateIncident` | TC-SNOW-07 – 14 | 8/8 PASS |
| ServiceNow batch handling | `CreateIncidentsForFindingsBatch` | TC-SNOW-15 – 16 | 2/2 PASS |
| Local auth MVP (passwords/sessions/users/OIDC) | `PasswordHashing`, `SessionCookies`, `UserStore`, `RealSeedFileIsValid`, `OidcConfiguration`, `OidcFlow` | TC-AUTH-01 – 32 | 32/32 PASS |
| Compensating-control suggestions | `SuggestCompensatingControls`, `TagCompensatingControlsBatch` | TC-COMP-01 – 08 | 8/8 PASS |
| Jira construction + issue body | `AuthAndConstruction`, `BuildIssueBodyPureFunction` | TC-JIRA-01 – 10 | 10/10 PASS |
| Jira issue creation + batch | `FindExistingIssue`, `CreateIssue`, `CreateIssuesForFindingsBatch` | TC-JIRA-11 – 19 | 9/9 PASS |
| Splunk construction + auth | `AuthAndConstruction`, `BuildHecEventPureFunction` | TC-SPLUNK-01 – 10 | 10/10 PASS |
| Splunk event sending | `SendEvent` | TC-SPLUNK-11 – 15 | 5/5 PASS |
| Splunk batch handling (deliberately no dedup) | `SendEventsForFindingsBatch` | TC-SPLUNK-16 – 19 | 4/4 PASS |
| CrowdStrike Falcon connector: auth + alert fetch | `AuthFlow`, `FetchAlertIds`, `FetchAlertDetails` | TC-CS-01 – 10 | 10/10 PASS |
| CrowdStrike Falcon connector: normalization + orchestration | `NormalizeAlert`, `FetchAndNormalizeAlerts` | TC-CS-11 – 24 | 14/14 PASS |
| CMDB bulk import (CSV parsing, column mapping, reconciliation, apply) | `ParseCsvText`, `SuggestColumnMapping`, `ReconcileRows`, `ApplyImport` | TC-CMDB-01 – 14 | 14/14 PASS |
| Infoblox NIOS connector: construction + host-record fetch | `InfobloxConstruction`, `InfobloxFetchHostRecords` | TC-IBLOX-01 – 09 | 9/9 PASS |
| Infoblox NIOS connector: normalization + orchestration | `InfobloxNormalizeHostRecord`, `InfobloxFetchAndNormalizeHosts` | TC-IBLOX-10 – 16 | 7/7 PASS |
| Axonius connector: construction + device fetch | `AxoniusConstruction`, `AxoniusFetchDevices` | TC-AXON-01 – 08 | 8/8 PASS |
| Axonius connector: normalization + orchestration | `AxoniusNormalizeDevice`, `AxoniusFetchAndNormalizeDevices` | TC-AXON-09 – 17 | 9/9 PASS |
| Pattern-recognition helpers (hostname prefix, IP subnet, MAC OUI) | `HostnamePrefix`, `IpSubnet`, `MacOui` | TC-PATTERN-01 – 10 | 10/10 PASS |
| Pattern-recognition owner/team suggestion | `SuggestOwnerTeam` | TC-PATTERN-11 – 18 | 8/8 PASS |
| Pattern-recognition type suggestion | `SuggestType` | TC-PATTERN-19 – 23 | 5/5 PASS |
| Pattern-recognition batch annotation | `AnnotateUnownedAssets` | TC-PATTERN-24 – 28 | 5/5 PASS |
| AI vulnerability taxonomy structure | `Taxonomy` | TC-AIVULN-01 – 04 | 4/4 PASS |
| AI vulnerability keyword matching (incl. honest-scope check) | `KeywordMatching` | TC-AIVULN-05 – 14 | 10/10 PASS |
| AI vulnerability batch tagging | `TagFindingsBatch` | TC-AIVULN-15 – 17 | 3/3 PASS |
| AI vulnerability / MITRE ATLAS heat map | `AiAtlasHeatmap` | TC-AIVULN-18 – 21 | 4/4 PASS |
| Infra sub-category classification | `ClassifyFinding` | TC-INFRA-01 – 10 | 10/10 PASS |
| Infra sub-category tagging | `TagInfraCategories` | TC-INFRA-11 – 13 | 3/3 PASS |
| Infra sub-category counts | `InfraCategoryCounts` | TC-INFRA-14 – 16 | 3/3 PASS |
| **Total** | | **562** | **562/562 PASS** |

---

## Suite 1: `/vulnhunt` scanner finds real vulnerabilities

**Purpose:** prove the vulnerable baseline (`master` branch) genuinely contains the flaws
the demo claims, so later "9 findings" claims aren't testing a strawman.
**Preconditions (all TC-SCAN):** repo cloned with full history; `master` branch exists.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-SCAN-01 | Hardcoded secret is present in the baseline | Read `vulnerable-demo-app/app.py` at `master`; regex for `STRIPE_API_KEY = "sk_live_...` | Pattern found | Pattern found | PASS |
| TC-SCAN-02 | SQL injection via string concatenation is present | Read `app.py` at `master`; check for the exact concatenated query string | String found verbatim | Found | PASS |
| TC-SCAN-03 | Command injection (`shell=True`) is present | Read `app.py` at `master`; check for `shell=True` | Found | Found | PASS |
| TC-SCAN-04 | `eval()` on user input is present | Read `app.py` at `master`; regex for `eval(expression)` | Found | Found | PASS |
| TC-SCAN-05 | Debug mode is hardcoded on | Read `app.py` at `master`; check for `debug=True` | Found | Found | PASS |
| TC-SCAN-06 | Dockerfile has no non-root `USER` directive | Read `Dockerfile` at `master`; regex for a line starting `USER <name>` | NOT found (negative test) | Not found | PASS |
| TC-SCAN-07 | Dockerfile bakes the secret into an image layer | Read `Dockerfile` at `master`; regex for `ENV STRIPE_API_KEY="sk_live_...` | Found | Found | PASS |

---

## Suite 2: `/vulnhunt` fixer applies only approved fixes

**Purpose:** prove the fix branch fixed exactly the 6 findings marked `auto_fixable: true`,
touched nothing else, and didn't break the file.
**Preconditions (all TC-FIX):** a `vulnhunter/auto-fixes-*` branch exists (created by a
`/vulnhunt --fix` run).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-FIX-01 | Secret now reads from environment | Read `app.py` at the fix branch; check for `os.environ["STRIPE_API_KEY"]` present AND the old hardcoded pattern absent | Both conditions hold | Both hold | PASS |
| TC-FIX-02 | SQL injection now parameterized | Check for the exact parameterized `cursor.execute(...)` call AND absence of `+ user_id` | Both conditions hold | Both hold | PASS |
| TC-FIX-03 | Command injection now uses an arg list | Check for `subprocess.check_output(["ping", "-c", "1", host])` AND absence of `shell=True` | Both conditions hold | Both hold | PASS |
| TC-FIX-04 | Debug mode now gated by an env var | Check for `os.environ.get("FLASK_DEBUG"` AND absence of `debug=True` | Both conditions hold | Both hold | PASS |
| TC-FIX-05 | Dockerfile now has a non-root `USER` | Regex for a line starting `USER <name>` | Found | Found | PASS |
| TC-FIX-06 | Dockerfile secret removed as an `ENV` assignment | Regex for `ENV STRIPE_API_KEY=` (a *comment* mentioning the var name at runtime is fine) | NOT found (negative test) | Not found | PASS |
| TC-FIX-07 | Manual-review findings left untouched | Check `eval(expression)` still present AND the plaintext-password `INSERT` still present, unmodified | Both still present (fixer did not touch them) | Both present | PASS |
| TC-FIX-08 | Fixed file is still valid Python | `compile(app_py_source, "app.py", "exec")` | No `SyntaxError` raised | No error | PASS |

---

## Suite 3: `/vulnhunt` report is accurate

**Purpose:** prove `SECURITY_REPORT.md`'s headline numbers match what was actually found/fixed —
a report that overstates or understates its own results is worse than no report.
**Preconditions:** `SECURITY_REPORT.md` exists on the fix branch.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-RPT-01 | Report states 9 total findings | Read `SECURITY_REPORT.md`; check for the string `"9 findings"` | Found | Found | PASS |
| TC-RPT-02 | Report states 6 auto-fixed | Check for the string `"Auto-fixing now (6)"` | Found | Found | PASS |
| TC-RPT-03 | All 9 finding IDs (VULN-1..9) are documented | Loop `VULN-1` through `VULN-9`; each must appear in the report | All 9 present | All 9 present | PASS |

---

## Suite 4: `/remediate` normalized findings are well-formed

**Purpose:** prove the ingestion/normalization stage correctly parsed all 3 source formats
(Tenable CSV, Armis JSON, threat-intel JSON) into one consistent, correctly-classified schema.
**Preconditions:** `remediation/output/normalized-findings.json` exists (from an ingestion run).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-NORM-01 | Exactly 14 findings total | Parse the JSON array; count elements | 14 | 14 | PASS |
| TC-NORM-02 | Every finding has required fields | For each finding, check `id/source/source_ref/asset/title/severity/remediation_domain` present, and `asset.name/ip/type` present | All findings compliant | All compliant | PASS |
| TC-NORM-03 | All 3 sources represented | Collect distinct `source` values | `{tenable, armis, threat-intel}` | Matches exactly | PASS |
| TC-NORM-04 | Asset-type classification spot checks | Check known assets: `WIN-DC01`→windows-server, `LNX-DB03`→unix-server, `CSW-CORE01`→network-routing-switching, Axis camera→iot-ot-device, Log4Shell finding→application, both cert findings→certificate | All 7 spot checks correct | All correct | PASS |
| TC-NORM-05 | `remediation_domain` only set for supported domains | For each finding: if `asset.type` is windows-server/unix-server, `remediation_domain` must equal it; otherwise must be `null` (now including `application`/`certificate`) | Rule holds for all 14 | Holds | PASS |
| TC-NORM-06 | Exactly 7 findings eligible for automation | Count findings with non-null `remediation_domain` | 7 | 7 | PASS |
| TC-NORM-07 | No fabricated CVE IDs | For each non-null `cve`, regex-match `CVE-\d{4}-\d{4,}` | All CVEs well-formed (catches agent hallucination of a plausible-but-fake ID) | All well-formed | PASS |
| TC-NORM-08 | `kev`/`epss` fields present and null-consistent | For each finding, check both keys exist; if `cve` is null both must be null, else `kev` must be a dict with a `listed` key | Rule holds for all 14 | Holds | PASS |
| TC-NORM-09 | Known KEV-listed findings match the real CISA catalog | Spot-check: PrintNightmare and Log4Shell are KEV-listed; OpenSSL DoS is not | All 3 spot checks correct against live-verified data | All correct | PASS |

---

## Suite 5: `/remediate` plan is consistent with findings

**Purpose:** prove the planner didn't drop or forget any finding, and honestly documents the gap for asset classes with no fixer.
**Preconditions:** `REMEDIATION_PLAN.md` and `normalized-findings.json` both exist.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-PLAN-01 | Every finding ID is referenced in the plan | For each of the 11 finding IDs, check it appears in `REMEDIATION_PLAN.md` | All 11 referenced | All referenced | PASS |
| TC-PLAN-02 | Manual-only domains are explicitly called out | Check the plan's lowercased text for `"no automated remediation path today"` | Present | Present | PASS |

---

## Suite 6: `/remediate` playbooks match the plan exactly

**Purpose:** the highest-value safety test in the suite — prove the generated playbooks are
*exactly* the automatable findings, no more (nothing generated for manual-only findings)
and no fewer (nothing silently skipped), and that each carries the right warning label.
**Preconditions:** `remediation/output/*.yml` playbooks exist (from a `/remediate --generate` run).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-PB-01 | Exactly 7 playbooks generated | Glob `remediation/output/FIND-*.yml`; count | 7 | 7 | PASS |
| TC-PB-02 | Every playbook maps to an automatable finding | Derive each playbook's finding ID from its filename; check it's in the set of findings with non-null `remediation_domain` | All playbook IDs are a subset of automatable IDs | Subset holds | PASS |
| TC-PB-03 | No playbook exists for manual-only findings | Check playbook IDs against `{FIND-6, FIND-7, FIND-8, FIND-9}` | Empty intersection (negative test) | Empty | PASS |
| TC-PB-04 | Every playbook has its finding ID, a rollback note, and a `hosts:` line | For each playbook file, check its own finding ID appears in its content, `"Rollback:"` appears, and a `hosts:` line exists | All 7 playbooks compliant | All compliant | PASS |
| TC-PB-05 | Change-approval marker matches the risk tier | For each playbook: if its finding is `needs-change-approval` (FIND-1,2,5,10,11), `"CHANGE APPROVAL REQUIRED"` must be present; if `auto-approvable` (FIND-3,4), it must be absent | All 7 correctly labeled | All correct | PASS |

---

## Suite 7: Cross-cutting safety net

**Purpose:** a repo-wide sanity check independent of either pipeline — catches a real
secret slipping into demo data or generated output, regardless of which stage produced it.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-SEC-01 | No real-looking secrets anywhere in tracked files | List all git-tracked files (`git ls-tree -r --name-only HEAD`); for each readable text file, check against 3 patterns: PEM private key headers, a Stripe-shaped key NOT tagged FAKE/DEMO, an AWS access-key-ID shape | No matches in any tracked file | No matches | PASS |

---

## Suite 8: Headless CLI (`cli/vulnhunter.py`)

**Purpose:** prove the CLI wrapper constructs the right `claude -p` invocation and never
silently defaults to something riskier (a permission bypass) or costlier than intended,
without ever calling the real Claude API in a test.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CLI-01 | `scan_prompt` without `--fix` | Call `scan_prompt("vulnerable-demo-app")` | Returns `"/vulnhunt vulnerable-demo-app"` | Matches | PASS |
| TC-CLI-02 | `scan_prompt` with `--fix` | Call with `fix=True` | Returns the prompt with `--fix` appended | Matches | PASS |
| TC-CLI-03 | `remediate_prompt` without `--generate` | Call `remediate_prompt()` | Returns `"/remediate"` | Matches | PASS |
| TC-CLI-04 | `remediate_prompt` with `--generate` | Call with `generate=True` | Returns the prompt with `--generate` appended | Matches | PASS |
| TC-CLI-05 | Command includes `-p` and the prompt | `build_command("/vulnhunt foo", claude_bin="claude")` | `-p` and the prompt string both present | Present | PASS |
| TC-CLI-06 | Defaults to JSON output format | Same as above | `--output-format json` present | Present | PASS |
| TC-CLI-07 | Includes the permission mode | Pass `permission_mode="acceptEdits"` | `--permission-mode acceptEdits` present | Present | PASS |
| TC-CLI-08 | Includes the max-budget cap | Pass `max_budget_usd="5.00"` | `--max-budget-usd 5.00` present | Present | PASS |
| TC-CLI-09 | Falsy args are omitted, not passed empty | Pass `permission_mode=None, allowed_tools=None, max_budget_usd=None` | None of those 3 flags appear at all | All 3 absent | PASS |
| TC-CLI-10 | Never defaults to a full permission bypass | Build a command with default args | `dangerously-skip-permissions` never appears | Absent | PASS |
| TC-CLI-11 | `CLAUDE_BIN` env var takes priority | Set `CLAUDE_BIN`, call `find_claude_binary()` | Returns the env var's value, not a PATH-discovered binary | Matches | PASS |
| TC-CLI-12 | Dry-run `scan` subprocess call | Run `python cli/vulnhunter.py --dry-run scan vulnerable-demo-app` as a real subprocess | Exit 0; stdout contains `"Would run:"` and the prompt; no API call made | Matches | PASS |
| TC-CLI-13 | Dry-run `remediate --generate` subprocess call | Run `python cli/vulnhunter.py --dry-run remediate --generate` | Exit 0; stdout contains `"/remediate --generate"` | Matches | PASS |

## Suite 9: Web Dashboard (`dashboard/`)

**Purpose:** prove the dashboard's JSON API (FastAPI, `dashboard/app.py`) agrees with the
pipeline test suite about what the artifacts say (no silent drift between the two), every
JSON endpoint returns the correct shape and status code, the single-page frontend shell
(`dashboard/static/index.html` + `static/js/app.js`) is served identically for every page
route while `/api/*` and `/static/*` still 404 correctly, and the three routes that could
have a real-world side effect or spend real API usage (`/api/run`,
`/api/servicenow/send`, and `/api/ai-assist`) never trigger it in a test unless the
underlying `subprocess.run`/binary-discovery call is explicitly mocked. A fourth route
with a real (but safe) side effect, `/api/ingest/generic`, is exercised directly rather
than mocked, since writing its accepted findings to the real, gitignored
`remediation/live-data/generic-ingested.json` is exactly the behavior under test; those
test cases clean the file up afterward. This suite's coverage also grew to include the
exceptions/risk-acceptance workflow (`/api/exceptions`) and the asset inventory
(`/api/assets`), each backed by a small editable JSON store the same way
`/api/priority-rules` already was. As of this
suite's rewrite, the dashboard backend migrated from Flask + Jinja2
server-rendered HTML to a FastAPI JSON API with a vanilla-JS single-page frontend — these
tests validate the JSON contract and the served SPA shell rather than grepping rendered
HTML for substrings; the actual client-side rendering (sidebar nav, tables, KPI cards,
client-side sort, forms) was verified live in a browser during development (see
KNOWLEDGE_TRANSFER.md), not by this Python suite, which cannot execute JavaScript.
**Preconditions (all TC-DASH):** `dashboard/app.py`'s FastAPI app and `dashboard/data.py`
importable; the real pipeline artifacts (vulnhunt findings, remediation findings/plan,
playbooks) present on disk; `remediation/config/priority_rules.yaml` present. All
requests go through FastAPI's `TestClient` (Starlette's in-process ASGI test client) — no
real HTTP server, no network, no Claude API or ServiceNow calls. TC-DASH-20–22
additionally patch `priority_engine.DEFAULT_RULES_PATH` to a temp copy so the suite never
mutates the real, shipped rules file. TC-DASH-37 and TC-DASH-38 additionally patch
`app.subprocess.run` and `app.cli.find_claude_binary` so the two `/api/ai-assist`
test cases that exercise the `confirm=True` path never spawn a real process or spend
real API usage/credits. TC-DASH-43–49 (`ApiExceptions`) additionally patch
`exceptions_store.DEFAULT_STORE_PATH` to a temp file so the suite never mutates the
real, shipped `remediation/exceptions/exceptions.json` — this patch only works because
`store.py`'s functions resolve a `path=None` parameter to `DEFAULT_STORE_PATH` inside the
function body rather than as a bound default (see Suite 12's Preconditions note for the
bug this fixes). TC-DASH-50–51 (`ApiAssets`) likewise patch
`asset_inventory.DEFAULT_OWNERSHIP_PATH` to a temp file for the same reason (see Suite
13's note). TC-DASH-52–56 (`ApiIngestGeneric`) write to, and each clean up afterward, the
real, gitignored `remediation/live-data/generic-ingested.json` path — the same path the
live Tenable/Armis connectors write to — rather than a temp file, since exercising that
real write is the point of TC-DASH-56.

This wave adds a fourth kind of gating to verify: authentication and role-based access
control. TC-DASH-57–66 (`ApiAuth`) cover the login/logout/me/change-password/OIDC-config
endpoints themselves. A module-scoped `setUpModule`/`tearDownModule` pair creates a
temporary user store (patching `auth_users.DEFAULT_USERS_PATH` to a temp directory)
seeded with one known admin and one known regular user, so the real, shipped
`dashboard/auth/users.json` is never read or mutated by the suite. Two small
module-level helpers, `_login(email, password)` (POSTs to `/api/auth/login` and asserts
success) and `_logout()` (clears the shared `TestClient`'s cookies), are called around
every test that needs a specific login state, rather than each test reimplementing the
login POST. From TC-DASH-67 onward, the suite also verifies that every route with a
real-world or administrative side effect enforces this login/role gating *before* doing
anything sensitive: `/api/run` and `/api/ai-assist` (`confirm=true`), `/api/priority-rules`
(POST, admin-only), `/api/servicenow/send` (`confirm=true`), `/api/exceptions` (create
requires login, revoke requires admin), and `/api/assets/*/owner` + `/facing` (login
required) each get an explicit 401-when-logged-out (and, where relevant, 403-when-non-admin)
test case. TC-DASH-90–97 (`ApiJira`/`ApiSplunk`) are new connector preview/send endpoints
that mirror `ApiServiceNow`'s exact dry-run/confirm/credentials/login-gating pattern
test-for-test.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-DASH-01 | `/vulnhunt` data matches known totals | Call `load_vulnhunt_data()` | `total == 9`, `auto_fixable == 6` | Matches | PASS |
| TC-DASH-02 | Remediation findings count matches | Call `load_remediation_findings()` | `len(findings) == 14` | Matches | PASS |
| TC-DASH-03 | Remediation plan queue count matches | Call `load_remediation_plan()` | `len(queue) == 14` | Matches | PASS |
| TC-DASH-04 | Risk tier counts match the known split | Same as above | 2 auto-approvable, 5 needs-change-approval, 7 manual-only | Matches | PASS |
| TC-DASH-05 | Playbook count matches | Call `load_playbooks()` | `len(playbooks) == 7` | Matches | PASS |
| TC-DASH-06 | KEV-listed / high-EPSS counts match live-verified data | Call `count_kev_listed()` / `count_high_epss()` | 6 KEV-listed, 7 with EPSS ≥ 50% | Matches | PASS |
| TC-DASH-07 | Asset-type breakdown covers all 6 categories | Call `asset_type_breakdown()` | Counts sum to 14; all 6 asset types present (including `application`, `certificate`) | Matches | PASS |
| TC-DASH-08 | No mojibake in parsed text (regression guard) | Check `vh["title"]` and `plan["title"]` for the mojibake pattern `â€"` | Pattern absent from both | Absent | PASS |
| TC-DASH-09 | `/api/overview` returns combined dashboard shape and known counts | `GET /api/overview` | HTTP 200; `vulnhunt.total==9`, `vulnhunt.auto_fixable==6`, `remediation.total==14`, `playbook_count==7`, `kev_count==6`, `high_epss_count==7`; `sla` has `breached`/`at_risk`/`on_track`; `asset_type_breakdown` includes `windows-server`/`unix-server`/`application`/`certificate` | Matches | PASS |
| TC-DASH-10 | `/api/vulnhunt` lists all 9 findings | `GET /api/vulnhunt` | HTTP 200; `available` true; finding IDs equal exactly `VULN-1`...`VULN-9` | Matches | PASS |
| TC-DASH-11 | `/api/remediate` lists all 14 findings, the full plan queue, and playbook links | `GET /api/remediate` | HTTP 200; `findings` has 14 entries; plan queue IDs equal exactly `FIND-1`...`FIND-14`; `playbooks_by_finding` has 7 entries | Matches | PASS |
| TC-DASH-12 | `/api/playbooks/{filename}` matches the real playbook file's contents | `GET /api/playbooks/FIND-4-sudo-baron-samedit-patch.yml`; independently read the same file from disk and check for `"CHANGE APPROVAL REQUIRED"` | HTTP 200; `finding_id=="FIND-4"`; `needs_approval` equals whatever the raw file actually contains | Matches | PASS |
| TC-DASH-13 | Unknown playbook returns 404 | `GET /api/playbooks/does-not-exist.yml` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-14 | `GET /api/run` returns default budget and audit-log shape | `GET /api/run` | HTTP 200; response includes `default_budget`; `audit_log` is a list | Matches | PASS |
| TC-DASH-15 | Dry-run POST never calls the real API (critical safety test) | `POST /api/run` with `pipeline=scan`, `path=vulnerable-demo-app`, `max_budget_usd=2.00`, `confirm` omitted | HTTP 200; `dry_run` true; `message` contains `"Dry run only"` | Matches | PASS |
| TC-DASH-16 | Unknown pipeline name is rejected | `POST /api/run` with `pipeline="not-a-real-pipeline"` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-17 | `/api/status` returns correct counts | `GET /api/status` | JSON with `status: ok`, `vulnhunt_findings: 9`, `remediation_findings: 14` | Matches | PASS |
| TC-DASH-18 | Live queue lists all 14 findings sorted by priority | `GET /api/queue` | HTTP 200; finding IDs equal exactly `FIND-1`...`FIND-14`; priorities sorted highest-first (Critical > High > Medium > Low) | Matches | PASS |
| TC-DASH-19 | Live queue shows SLA breach status and ATT&CK tags | `GET /api/queue` | At least one finding has `sla.breached` true; `T1210` (PrintNightmare/Log4Shell-style RCE) appears among the findings' `attack_techniques` | Matches | PASS |
| TC-DASH-106 | Live queue findings carry the infra sub-category | `GET /api/queue` | `FIND-1` (WIN-DC01, windows-server) has `infra_category == "os"`; every application/certificate finding has `infra_category is None` | Matches | PASS |
| TC-DASH-20 | `GET /api/priority-rules` returns the current rules YAML text | `GET /api/priority-rules` (against a temp copy of the real rules file, so the shipped file is never mutated) | HTTP 200; `rules_text` contains `sla_days` | Matches | PASS |
| TC-DASH-21 | Valid YAML POST saves the new rules | `POST /api/priority-rules` with `rules_text` edited to change `Medium: 30` to `Medium: 5` | HTTP 200; response message contains `"saved"`; the (temp) rules file on disk now contains `Medium: 5` | Matches | PASS |
| TC-DASH-22 | Invalid YAML POST is rejected and the file is left unchanged | `POST /api/priority-rules` with `rules_text="not: valid: yaml: ["` | HTTP 400; `detail` contains `"invalid YAML"`; rules file content identical to before the request | Matches | PASS |
| TC-DASH-23 | ServiceNow preview lists every finding without needing credentials | `GET /api/servicenow/preview` | HTTP 200; preview `finding_id`s equal exactly `FIND-1`...`FIND-14` | Matches | PASS |
| TC-DASH-24 | Sending without confirm never touches the network (critical safety test) | `POST /api/servicenow/send` with real-looking `instance`/`username`/`password`/`table` but `confirm` omitted | HTTP 200; `preview_only` true; `results` is `null` | Matches | PASS |
| TC-DASH-25 | Sending with confirm but missing credentials is rejected | `POST /api/servicenow/send` with empty `instance`/`username`/`password`, `table="incident"`, `confirm=true` | HTTP 400; `detail` contains `"required"` | Matches | PASS |
| TC-DASH-26 | Every known page route serves the identical SPA shell | `GET` each of `/`, `/vulnhunt`, `/remediate`, `/run`, `/queue`, `/priority-rules`, `/servicenow`, `/ai-assist`, `/reports`, `/support`, `/faq`, `/exceptions`, `/assets` (`SHELL_ROUTES`; the last two added alongside this round's new `/api/exceptions` and `/api/assets` pages) | All return HTTP 200 with `text/html`, each containing `<script type="module" src="/static/js/app.js">`; all 13 responses are byte-identical | Matches | PASS |
| TC-DASH-27 | Playbook detail route also serves the SPA shell | `GET /playbooks/FIND-4-sudo-baron-samedit-patch.yml` | HTTP 200; body contains `id="app"` | Matches | PASS |
| TC-DASH-28 | Unknown page route still serves the shell (client-side-routing fallback) | `GET /this-route-does-not-exist` | HTTP 200; body still contains `<script type="module" src="/static/js/app.js">` so `app.js`'s router can render a styled "not found" page | Matches | PASS |
| TC-DASH-29 | Unknown `/api/*` route returns a real 404 (not the SPA shell) | `GET /api/this-does-not-exist` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-30 | Unknown `/static/*` asset returns a real 404 | `GET /static/this-does-not-exist.js` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-31 | Static assets (CSS/JS) are actually served | `GET /static/style.css` and `GET /static/js/app.js` | Both HTTP 200; `app.js` response contains `renderRoute` | Matches | PASS |
| TC-DASH-32 | `/api/ai-assist` preview builds a real prompt with no confirm | `POST /api/ai-assist` with `finding_id="FIND-12"`, `action="explain"`, `confirm` omitted | HTTP 200; `dry_run` true; `prompt` contains `"FIND-12"` and `"Log4Shell"` | Matches | PASS |
| TC-DASH-33 | Preview never calls the real Claude binary (critical safety test) | `POST /api/ai-assist` with `finding_id="FIND-1"`, `action="remediate"`, `confirm` omitted, with `app.subprocess.run` mocked | HTTP 200; `dry_run` true; mocked `subprocess.run` never called | Matches | PASS |
| TC-DASH-34 | Works for a code-scan (`VULN-`) finding too, not just infra findings | `POST /api/ai-assist` with `finding_id="VULN-2"`, `action="summarize"` | HTTP 200; `prompt` contains `"VULN-2"` | Matches | PASS |
| TC-DASH-35 | Unknown finding ID returns 404 | `POST /api/ai-assist` with `finding_id="FIND-999"` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-36 | Unknown action returns 400 | `POST /api/ai-assist` with `finding_id="FIND-1"`, `action="delete_everything"` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-37 | `confirm=true` calls the real binary exactly once | `POST /api/ai-assist` with `confirm=true`, with `app.cli.find_claude_binary` and `app.subprocess.run` mocked to return a successful result | HTTP 200; `dry_run` false; `response` equals the mocked stdout; mocked `subprocess.run` called exactly once | Matches | PASS |
| TC-DASH-38 | `confirm=true` surfaces a failed call as 502 | Same as above but the mocked `subprocess.run` result has `returncode=1` | HTTP 502 | 502 | PASS |
| TC-DASH-39 | `/api/reports/generate` returns real computed KPIs | `GET /api/reports/generate?period=weekly` | HTTP 200; `period=="weekly"`, `remediation_total==14`, `vulnhunt_total==9` | Matches | PASS |
| TC-DASH-40 | Invalid report period is rejected | `GET /api/reports/generate?period=fortnightly` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-41 | HTML report is served inline by default | `GET /api/reports/generate.html?period=daily` | HTTP 200; `content-type` contains `text/html`; no `content-disposition` header; body contains `"Daily Security Report"` | Matches | PASS |
| TC-DASH-42 | HTML report download sets `Content-Disposition` | `GET /api/reports/generate.html?period=monthly&download=true` | `content-disposition` contains `"attachment"` and `"vulnhunter-monthly-report.html"` | Matches | PASS |
| TC-DASH-43 | Listing exceptions against an empty store returns an empty list | `GET /api/exceptions` (against a temp exceptions store) | HTTP 200; `exceptions == []` | Matches | PASS |
| TC-DASH-44 | Creating then listing shows the new exception with its computed status | `POST /api/exceptions` with `finding_id="FIND-7"`, a reason, `requested_by`/`approved_by`, `expires_on="2099-01-01"`; then `GET /api/exceptions` | Create returns HTTP 200 with `finding_id=="FIND-7"`; list has exactly 1 entry with `computed_status=="active"` | Matches | PASS |
| TC-DASH-45 | Creating with a past expiry date is rejected | `POST /api/exceptions` with `expires_on="2020-01-01"` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-46 | Creating with a blank reason is rejected | `POST /api/exceptions` with `reason="   "` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-47 | Revoking an existing exception | Create an exception, then `POST /api/exceptions/{id}/revoke` | HTTP 200; `status=="revoked"` | Matches | PASS |
| TC-DASH-48 | Revoking an unknown ID returns 404 | `POST /api/exceptions/EXC-999/revoke` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-49 | The live queue reflects an active exception on its finding | Create an exception (reason `"Isolated OT VLAN"`) against `FIND-7`; `GET /api/queue` | `FIND-7`'s `exception` is not `null` and its `reason` equals `"Isolated OT VLAN"`; `FIND-1` (no exception requested) shows `exception: null`, not an error | Matches | PASS |
| TC-DASH-50 | `/api/assets` aggregates the real findings | `GET /api/assets` (against a temp ownership file) | HTTP 200; `WEB-PORTAL01` row has `finding_count==2` (its 2 real findings, FIND-13/FIND-14) and `owner` is `null` | Matches | PASS |
| TC-DASH-51 | Setting an owner then listing shows the new owner | `POST /api/assets/WEB-PORTAL01/owner` with `owner="Web Ops"`, `team="Platform"`; then `GET /api/assets` | Set returns HTTP 200; list shows `WEB-PORTAL01`'s `owner=="Web Ops"`, `team=="Platform"` | Matches | PASS |
| TC-DASH-52 | A valid generic-ingest payload is accepted and normalized | `POST /api/ingest/generic` with one valid finding (`asset_type="application"`) | HTTP 200; `accepted==1`, `rejected==[]`; the returned finding's `source=="generic"` | Matches | PASS |
| TC-DASH-53 | An ingested ID never collides with a real finding ID | Ingest one valid finding | Its assigned `id` is not among the real pipeline's `FIND-1`..`FIND-14` IDs (from `load_remediation_findings()`) | Matches | PASS |
| TC-DASH-54 | An invalid payload is rejected with specific per-item errors | `POST /api/ingest/generic` with one finding that has only `title` set | HTTP 200 (batch endpoint — per-item errors, not a 4xx); `accepted==0`; exactly 1 rejected entry with `index==0` | Matches | PASS |
| TC-DASH-55 | A mixed batch accepts valid and rejects invalid entries independently | Batch of one valid finding plus one with `severity="Nonsense"` | `accepted==1`; exactly 1 rejected entry | Matches | PASS |
| TC-DASH-56 | Accepted findings are written to `remediation/live-data/generic-ingested.json` | Ingest one valid finding | The live-data file now exists on disk (removed again in the test's `tearDown`) | Matches | PASS |
| TC-DASH-57 | Login with correct credentials sets a session and returns the user | `POST /api/auth/login` with the test admin's email/password | HTTP 200; `user.email` equals the admin email, `user.role=="admin"`, `user` has no `password_hash` key; the session cookie is set in the response | Matches | PASS |
| TC-DASH-58 | Login with unknown email is rejected | `POST /api/auth/login` with `email="nobody@test.local"`, `password="anything"` | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-59 | Login with wrong password is rejected | `POST /api/auth/login` with the admin email but a wrong password | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-60 | `/api/auth/me` after login returns the logged-in user | `_login()` as the regular test user; `GET /api/auth/me` | `user.email` equals the regular test user's email | Matches | PASS |
| TC-DASH-61 | `/api/auth/me` without login returns a null user | `GET /api/auth/me` with no session cookie | HTTP 200; `user` is `null` | Matches | PASS |
| TC-DASH-62 | Logout clears the session | `_login()`; `POST /api/auth/logout`; `GET /api/auth/me` | Logout returns HTTP 200; subsequent `/api/auth/me` returns `user: null` | Matches | PASS |
| TC-DASH-63 | Change-password requires login | `POST /api/auth/change-password` with a new password, no session | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-64 | Changing password invalidates the old password | Create a temp user, log in, `POST /api/auth/change-password` with a new password; log out; try logging in with the old and then the new password | Change returns HTTP 200; login with the old password returns 401; login with the new password returns 200 | Matches | PASS |
| TC-DASH-65 | OIDC config reports disabled when no env vars are set | `GET /api/auth/oidc/config` | HTTP 200; `enabled` is `false`; `provider_name` is `null` | Matches | PASS |
| TC-DASH-66 | OIDC login is unavailable when not configured | `GET /api/auth/oidc/login` with `follow_redirects=False` | HTTP 503 | 503 | PASS |
| TC-DASH-67 | `/api/run` with `confirm=true` but not logged in is rejected before ever running anything | `POST /api/run` with `pipeline="scan"`, `path="vulnerable-demo-app"`, `confirm=True`, no session | HTTP 401 (negative test) — login is enforced before `cli.run()` is ever called, i.e. before any subprocess/API spend could happen | 401 | PASS |
| TC-DASH-68 | `/api/priority-rules` POST without login is rejected | `_logout()`; `POST /api/priority-rules` with a valid `rules_text` | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-69 | `/api/priority-rules` POST as a non-admin is rejected | `_login()` as the regular test user; `POST /api/priority-rules` with a valid `rules_text` | HTTP 403 (negative test) — edits require the `admin` role specifically, not just any logged-in user | 403 | PASS |
| TC-DASH-70 | `/api/servicenow/send` with confirm but not logged in is rejected | `POST /api/servicenow/send` with real-looking credentials, `confirm=True`, no session | HTTP 401 (negative test) — the real-send path requires login even before credential validation | 401 | PASS |
| TC-DASH-71 | `/api/ai-assist` with confirm but not logged in is rejected | `POST /api/ai-assist` with `finding_id="FIND-1"`, `action="explain"`, `confirm=True`, no session | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-72 | Creating an exception without login is rejected | `_logout()`; `POST /api/exceptions` with a full valid body | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-73 | Creating an exception as a regular logged-in user is allowed | `_login()` as the regular test user; `POST /api/exceptions` with a full valid body | HTTP 200 — create only requires login, not admin | Matches | PASS |
| TC-DASH-74 | Revoking an exception without login is rejected | Create an exception (as admin), `_logout()`; `POST /api/exceptions/{id}/revoke` | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-75 | Revoking an exception as a regular user is forbidden | Create an exception (as admin), `_login()` as the regular test user; `POST /api/exceptions/{id}/revoke` | HTTP 403 (negative test) — revoke requires admin specifically, unlike create | 403 | PASS |
| TC-DASH-76 | Setting an asset owner without login is rejected | `_logout()`; `POST /api/assets/WEB-PORTAL01/owner` with `owner="Web Ops"`, `team="Platform"` | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-77 | Setting an asset's facing classification without login is rejected | `_logout()`; `POST /api/assets/WEB-PORTAL01/facing` with `facing="external"` | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-78 | A new asset has `unknown` facing by default | `GET /api/assets` (against a temp, empty ownership file) | `WEB-PORTAL01` row's `facing=="unknown"` | Matches | PASS |
| TC-DASH-79 | Setting facing then listing shows the new classification | `POST /api/assets/WEB-PORTAL01/facing` with `facing="external"`; then `GET /api/assets` | Set returns HTTP 200; list shows `WEB-PORTAL01`'s `facing=="external"` | Matches | PASS |
| TC-DASH-80 | Setting facing with an invalid value is rejected | `POST /api/assets/WEB-PORTAL01/facing` with `facing="space-station"` | HTTP 400 (negative test) | 400 | PASS |
| TC-DASH-81 | Setting facing does not clobber an existing owner | Set an owner on `WEB-PORTAL01`; then set its facing; then `GET /api/assets` | `WEB-PORTAL01`'s `owner` is still set AND `facing` is now `"external"` — the two fields persist independently | Matches | PASS |
| TC-DASH-82 | SLA-breached findings produce danger notifications | `GET /api/notifications` | HTTP 200; exactly 6 notifications have `category=="SLA"` (matches the known queue KPI of 6 breached findings) | Matches | PASS |
| TC-DASH-83 | An exception expiring soon produces a warn notification | Create an exception on `FIND-7` expiring 5 days from today; `GET /api/notifications` | Exactly 1 notification has `category=="Exception"`; its `severity=="warn"` | Matches | PASS |
| TC-DASH-84 | An exception far from expiry produces no notification | Create an exception on `FIND-7` expiring 365 days from today; `GET /api/notifications` | No notifications with `category=="Exception"` | Matches | PASS |
| TC-DASH-85 | Pending generic-ingested findings produce an info notification | Write one pending finding to the temp generic-ingested path; `GET /api/notifications` | Exactly 1 notification has `category=="Ingestion"`; its `message` mentions the pending count | Matches | PASS |
| TC-DASH-86 | No generic-ingested file produces no ingestion notification | `GET /api/notifications` with no generic-ingested file present | No notifications with `category=="Ingestion"` | Matches | PASS |
| TC-DASH-87 | Danger notifications sort before warn and info | `GET /api/notifications` | Sorting by severity (danger/warn/info) yields an already non-decreasing sequence (danger-first ordering) | Matches | PASS |
| TC-DASH-88 | ATT&CK heat map covers the full known taxonomy | `GET /api/risk/attack-heatmap` | HTTP 200; `heatmap` includes every known tactic/technique pair, including zero-count ones; every row has both a `tactic` and a `count` key | Matches | PASS |
| TC-DASH-89 | PrintNightmare finding shows up under its technique on the heat map | `GET /api/risk/attack-heatmap` | The row keyed `T1210` has `count > 0` (FIND-1/PrintNightmare-style RCE) | Matches | PASS |
| TC-DASH-104 | AI Vulnerabilities returns the full taxonomy and a matching heat map | `GET /api/ai-vulnerabilities` | HTTP 200; `vulnerabilities` has ≥8 entries each with `summary`/`remediation`; `heatmap` has one row per vulnerability | Matches | PASS |
| TC-DASH-105 | AI Vulnerabilities heat map is honestly all-zero against real demo data | `GET /api/ai-vulnerabilities` | Every `heatmap` row has `count == 0` - this repo's demo app has no AI/ML component | Matches | PASS |
| TC-DASH-90 | Jira preview lists every finding with no credentials needed | `GET /api/jira/preview` | HTTP 200; preview `finding_id`s equal exactly `FIND-1`...`FIND-14` | Matches | PASS |
| TC-DASH-91 | Jira send without confirm never touches the network | `POST /api/jira/send` with real-looking `base_url`/`email`/`api_token`/`project_key`, `confirm` omitted | HTTP 200; `preview_only` true; `results` is `null` | Matches | PASS |
| TC-DASH-92 | Jira send with confirm but missing credentials is rejected | Log in as admin; `POST /api/jira/send` with blank credentials, `confirm=true` | HTTP 400; `detail` contains `"required"` | Matches | PASS |
| TC-DASH-93 | Jira send with confirm but not logged in is rejected | `POST /api/jira/send` with real-looking credentials, `confirm=true`, no session | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-94 | Splunk preview lists every finding with no credentials needed | `GET /api/splunk/preview` | HTTP 200; preview `finding_id`s equal exactly `FIND-1`...`FIND-14` | Matches | PASS |
| TC-DASH-95 | Splunk send without confirm never touches the network | `POST /api/splunk/send` with real-looking `hec_url`/`hec_token`, `confirm` omitted | HTTP 200; `preview_only` true; `results` is `null` | Matches | PASS |
| TC-DASH-96 | Splunk send with confirm but missing credentials is rejected | Log in as admin; `POST /api/splunk/send` with blank credentials, `confirm=true` | HTTP 400; `detail` contains `"required"` | Matches | PASS |
| TC-DASH-97 | Splunk send with confirm but not logged in is rejected | `POST /api/splunk/send` with real-looking credentials, `confirm=true`, no session | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-98 | CMDB import preview requires no login and reconciles against real assets | `_logout()`; `POST /api/assets/cmdb-import/preview` with a 3-row CSV (`WEB-PORTAL01` real, `NEW-SERVER-01` not real) | HTTP 200; guessed `column_mapping.asset_name == "Hostname"`; exactly 1 matched entry (`asset_name=="WEB-PORTAL01"`); exactly 1 unmatched entry | Matches | PASS |
| TC-DASH-99 | CMDB import apply requires login | `_logout()`; `POST /api/assets/cmdb-import/apply` with one valid entry | HTTP 401 (negative test) | 401 | PASS |
| TC-DASH-100 | CMDB import apply then the asset shows its new owner | `POST /api/assets/cmdb-import/apply` with `{asset_name: "WEB-PORTAL01", owner: "Web Ops", team: "Platform"}`; then `GET /api/assets` | Apply returns `applied==1`; `WEB-PORTAL01`'s `owner=="Web Ops"` in the list | Matches | PASS |
| TC-DASH-101 | Unowned assets carry a `suggestion` key, `None` when nothing matches | `GET /api/assets` against the temp (empty) ownership file | Every asset has a `suggestion` key; every unowned one is `None` (nothing owned yet to pattern-match against) | Matches | PASS |
| TC-DASH-102 | An owned asset produces a pattern suggestion for a same-type asset | `POST /api/assets/WIN-DC01/owner` (`Priya Nair`/`Identity`); then `GET /api/assets` | `WIN-FS02`'s (same type, `windows-server`) `suggestion.owner == "Priya Nair"` | Matches | PASS |
| TC-DASH-103 | An already-owned asset never gets a suggestion for itself | `POST /api/assets/WIN-DC01/owner`; then `GET /api/assets` | `WIN-DC01`'s own `suggestion` is `None` | Matches | PASS |

---

## Suite 10: Dashboard AI-assist prompt construction (`dashboard/ai_assist.py`)

**Purpose:** prove the dashboard's AI-assist feature builds a correct, deterministic
prompt from a finding's real fields before it's ever handed to the `claude` CLI — this
module is deliberately pure (no subprocess, no network, no API spend), so every
assertion here is a direct check on prompt text rather than a mock of an external call;
the actual invocation of the real binary is instead covered (dry-run by default) in
Suite 9's `ApiAiAssist` tests.
**Preconditions (all TC-AI):** `dashboard/ai_assist.py` importable; no network, no
subprocess, no fixture files on disk required — every test constructs its own in-memory
finding dict.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-AI-01 | `explain` action asks for a plain-English explanation | `build_ai_assist_prompt(finding, "explain")` | Prompt contains `"Explain, in plain English"` | Matches | PASS |
| TC-AI-02 | `remediate` action asks for remediation steps | `build_ai_assist_prompt(finding, "remediate")` | Prompt contains `"remediation steps"` | Matches | PASS |
| TC-AI-03 | `summarize` action asks for an executive summary | `build_ai_assist_prompt(finding, "summarize")` | Prompt contains `"executive summary"` | Matches | PASS |
| TC-AI-04 | Prompt includes the finding's ID and title | Build with the sample Log4Shell finding (`id="FIND-12"`, title contains "Log4Shell") | Prompt contains `"FIND-12"` and `"Log4Shell"` | Matches | PASS |
| TC-AI-05 | Prompt includes the asset's name and type | Same finding (`asset={"name": "APP-ORDERS01", "type": "application"}`) | Prompt contains `"APP-ORDERS01"` and `"application"` | Matches | PASS |
| TC-AI-06 | Prompt includes the CVE and severity | Same finding (`cve="CVE-2021-44228"`, `severity="Critical"`) | Prompt contains `"CVE-2021-44228"` and `"Critical"` | Matches | PASS |
| TC-AI-07 | Prompt includes the description when present | Same finding (`description` mentions "order-processing application") | Prompt contains `"order-processing application"` | Matches | PASS |
| TC-AI-08 | Missing CVE renders as `N/A`, not `None` or blank | Build with `cve=None` | Prompt contains `"CVE: N/A"` | Matches | PASS |
| TC-AI-09 | Missing description is omitted without error | Build with the `description` key deleted entirely | Prompt does NOT contain `"Description:"`, no `KeyError` | Absent, no error | PASS |
| TC-AI-10 | Unknown action raises `ValueError` | Call with `action="delete_everything"` | `ValueError` raised | Raised | PASS |
| TC-AI-11 | Same inputs always produce the same prompt (pure function) | Call twice with identical finding + action | Both prompts are equal (no hidden state or timestamp) | Equal | PASS |
| TC-AI-12 | Prompt requests a plain-text, concise response | Build with `action="explain"` | Prompt contains `"plain text only"` and `"under 150 words"` | Matches | PASS |

---

## Suite 11: Dashboard on-demand report generation (`dashboard/reports.py`)

**Purpose:** prove the `/reports` page's data layer computes real KPI/SLA numbers (no
fabricated figures) for every documented reporting period, renders them into a
self-contained, correctly-escaped HTML document, and that both still hold up against the
real repo artifacts (not just a stub). Honest limitation carried over from the module's
own docstring: because the dashboard has no persistence/history layer yet, every period
(`daily` through `yearly`) currently summarizes the same real, current-moment snapshot
rather than actual historical data for that window — `RenderReportHtml`'s caveat test
confirms the report is honest about this rather than inventing trend numbers.
**Preconditions (all TC-REPORTGEN):** `dashboard/reports.py` importable. `GenerateReportData`
and `RenderReportHtml` inject a `_StubDataModule` stand-in for `dashboard/data.py` so
those 12 cases are deterministic and touch no real artifacts. `RealArtifactIntegration`'s
2 cases instead import the real `dashboard/data.py` (as `dashboard_data`) and run against
the actual pipeline artifacts on disk, the same real-artifact rule the rest of this suite
follows.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-REPORTGEN-01 | Invalid period is rejected | `generate_report_data("fortnightly", stub)` | `ValueError` raised | Raised | PASS |
| TC-REPORTGEN-02 | Every documented period is accepted | Loop over `reports.VALID_PERIODS` (`daily`/`weekly`/`monthly`/`quarterly`/`half-yearly`/`yearly`), generating data for each | Each result's `data["period"]` equals the period passed in | Matches | PASS |
| TC-REPORTGEN-03 | SLA summary is pulled from the data module | `generate_report_data("weekly", stub)` where the stub's `sla_summary` returns `{"breached": 1, "at_risk": 0, "on_track": 1}` | `data["sla"]` equals that exact dict | Matches | PASS |
| TC-REPORTGEN-04 | KEV and EPSS counts are pulled from the data module | Same stub call | `data["kev_count"] == 1`, `data["high_epss_count"] == 1` | Matches | PASS |
| TC-REPORTGEN-05 | VulnHunt and remediation totals are pulled correctly | Same stub call | `data["vulnhunt_total"] == 9`, `data["vulnhunt_auto_fixable"] == 6`, `data["remediation_total"] == 2`, `data["playbook_count"] == 1` | Matches | PASS |
| TC-REPORTGEN-06 | Top-priority findings are capped at 5 | Stub `load_live_queue()` returns 20 findings | `len(data["top_priority_findings"]) == 5` | Matches | PASS |
| TC-REPORTGEN-07 | `generated_at` is present and looks like an ISO timestamp | `generate_report_data("weekly", stub)` | `data["generated_at"]` matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}` | Matches | PASS |
| TC-REPORTGEN-08 | Renders a valid-looking HTML document | `render_report_html(data)` for a `"monthly"` report | Output starts with `"<!doctype html>"` and contains `"</html>"` | Matches | PASS |
| TC-REPORTGEN-09 | Period is included in the title | Same monthly report | Output contains `"Monthly Security Report"` | Matches | PASS |
| TC-REPORTGEN-10 | No-persistence caveat is included | Same monthly report | Output contains `"no persistence layer"` | Matches | PASS |
| TC-REPORTGEN-11 | KPI numbers are included | Same monthly report (stub's breached/kev_count/high_epss all `1`) | Output contains `">1<"` | Matches | PASS |
| TC-REPORTGEN-12 | HTML in a finding title is escaped, not injected (XSS guard) | Render with `top_priority_findings` containing a title of `"<script>alert(1)</script>"` | Output does NOT contain the raw `<script>alert(1)</script>`; contains the escaped `"&lt;script&gt;"` | Matches | PASS |
| TC-REPORTGEN-13 | `generate_report_data` against the real dashboard data module | `generate_report_data("weekly", dashboard_data)` against the real, imported `dashboard/data.py` | `remediation_total == 14`, `vulnhunt_total == 9`, `len(top_priority_findings) <= 5` | Matches | PASS |
| TC-REPORTGEN-14 | `render_report_html` against real artifacts | `render_report_html(generate_report_data("yearly", dashboard_data))` | Output contains `"Yearly Security Report"` | Matches | PASS |

---

## Suite 12: Vulnerability exception / risk-acceptance workflow (`remediation/exceptions/store.py`)

**Purpose:** prove the exception (risk-acceptance/waiver) lifecycle — request, validate,
auto-expire-on-read, revoke — is correct against a temporary store file, and that the
real, shipped seed file is well-formed.
**Preconditions (all TC-EXC):** `remediation/exceptions/store.py` importable.
TC-EXC-01–14 (`ExceptionLifecycle`) each use a fresh temporary store file passed
explicitly via `path=...`, never the real, shipped `exceptions.json`. A real bug was
caught and fixed while writing these tests: every function in this module originally
took a bound default parameter (e.g. `def load_exceptions(path=DEFAULT_STORE_PATH):`),
which meant `unittest.mock.patch.object(store, "DEFAULT_STORE_PATH", tmp_path)` silently
failed to redirect any caller that omitted `path` — Python binds a default parameter
value once at function-definition time, so patching the module attribute afterward has
no effect on it. Fixed by changing every such function to `path=None`, resolved inside
the function body (`path = Path(path) if path is not None else DEFAULT_STORE_PATH`)
instead. TC-EXC-15 (`RealSeedFileIsValid`) instead calls `load_exceptions()` with no
`path` override, against the real, shipped `remediation/exceptions/exceptions.json`.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-EXC-01 | Loading from a missing store file returns an empty list | `store.load_exceptions(path)` where `path` doesn't exist yet | `[]` | Matches | PASS |
| TC-EXC-02 | Creating an exception persists it and returns a full record | `store.create_exception("FIND-7", "Compensating control in place", "eng@example.com", "secops@example.com", "2026-12-01", path=path, as_of=2026-08-01)` | `id=="EXC-1"`, `finding_id=="FIND-7"`, `status=="active"`, `created_on=="2026-08-01"`; `load_exceptions(path)` returns exactly `[record]` | Matches | PASS |
| TC-EXC-03 | IDs increment across multiple exceptions | Create two exceptions in sequence against the same store | Second record's `id=="EXC-2"` | Matches | PASS |
| TC-EXC-04 | Missing `finding_id` is rejected | Call `create_exception("", ...)` | `ValueError` raised | Raised | PASS |
| TC-EXC-05 | Blank reason is rejected | Call with `reason="   "` | `ValueError` raised | Raised | PASS |
| TC-EXC-06 | Missing requester or approver is rejected | Call with `requested_by=""`, then separately with `approved_by=""` | `ValueError` raised both times | Raised | PASS |
| TC-EXC-07 | Malformed expiry date is rejected | Call with `expires_on="not-a-date"` | `ValueError` raised | Raised | PASS |
| TC-EXC-08 | Expiry date in the past is rejected | Call with `expires_on="2026-01-01"`, `as_of=2026-08-01` | `ValueError` raised | Raised | PASS |
| TC-EXC-09 | `compute_status` returns "active" before expiry | Create an exception expiring `2026-12-01`; check status with `as_of=2026-08-15` | `"active"` | Matches | PASS |
| TC-EXC-10 | `compute_status` returns "expired" after expiry with no action taken | Create an exception expiring `2026-08-10`; check status with `as_of=2026-09-01` | `"expired"` (status is derived on read, never stored) | Matches | PASS |
| TC-EXC-11 | Revoking marks an exception revoked, and it stays revoked even before its expiry | `revoke_exception(record["id"], path=path)`; reload and recheck `compute_status` | Stored `status=="revoked"`; `compute_status(...)` also returns `"revoked"` even with `as_of` before `expires_on` | Matches | PASS |
| TC-EXC-12 | Revoking an unknown ID raises `KeyError` | `revoke_exception("EXC-999", path=path)` | `KeyError` raised | Raised | PASS |
| TC-EXC-13 | `list_exceptions_with_status` attaches computed status without mutating the file | Create an exception that's since expired; call `list_exceptions_with_status(path=path, as_of=2026-09-01)` | Returned item's `computed_status=="expired"`; the file on disk (`load_exceptions`) still says `status=="active"` | Matches | PASS |
| TC-EXC-14 | `active_exceptions_by_finding` excludes expired and revoked exceptions | Create one active, one expired, and one (explicitly) revoked exception across 3 findings | Result keys equal exactly `{"FIND-1"}`; `FIND-2` (expired) and `FIND-3` (revoked) are both absent | Matches | PASS |
| TC-EXC-15 | Real, shipped `exceptions.json` is well-formed | `store.load_exceptions()` (no `path` override) | Returns a list; every record has `id`/`finding_id`/`reason`/`requested_by`/`approved_by`/`created_on`/`expires_on`/`status`; `expires_on` parses as an ISO date | Matches | PASS |

---

## Suite 13: Asset inventory + ownership (`remediation/inventory/asset_inventory.py`)

**Purpose:** prove the per-asset inventory view correctly aggregates findings (count,
highest severity, critical-finding count, KEV exposure) grouped by asset name, that
ownership and the internal/external-facing classification can both be
set/persisted/read back (independently of each other) via a small editable store, and
that the real shipped ownership file is well-formed.
**Preconditions (all TC-INV):** `remediation/inventory/asset_inventory.py` importable.
TC-INV-08–11, 16–19 (`OwnershipStore`) each use a fresh temporary ownership file passed
explicitly via `path=...`, never the real, shipped `asset_ownership.json` — this module
had the exact same bound-default-parameter bug (and the same fix) as
`remediation/exceptions/store.py`, documented in Suite 12's Preconditions note.
TC-INV-01–07, 13–15 (`BuildAssetInventory`) pass an in-memory `ownership` dict directly
and touch no file at all. TC-INV-12 (`RealSeedFileIsValid`) calls `load_ownership()`
with no `path` override, against the real, shipped `asset_ownership.json`. TC-INV-13–19
were added alongside the Risk Management dashboard's editable internal/external-facing
column (`/risk`, `remediation/inventory/asset_inventory.py`'s `set_facing()`) and prove
it's manually set only (never auto-detected from a network scan), defaults to
`"unknown"`, and coexists with — rather than overwrites — the owner/team fields already
covered by TC-INV-06/09/10.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-INV-01 | Findings are grouped by `asset.name` | Two findings against `WEB-PORTAL01`, one against `WIN-DC01` | `WEB-PORTAL01` row has `finding_count==2`; `WIN-DC01` row has `finding_count==1` | Matches | PASS |
| TC-INV-02 | Highest severity picks the max across an asset's findings | One asset with Medium, Critical, and Low findings | Row's `highest_severity=="Critical"` | Matches | PASS |
| TC-INV-03 | KEV count only counts actually-listed findings | One asset with `kev.listed=True`, `kev.listed=False`, and `kev=None` findings | Row's `kev_count==1` | Matches | PASS |
| TC-INV-04 | Findings with no asset name are skipped, not crashed on | A finding with `asset: {}` | Returns `[]`, no `KeyError` | Matches | PASS |
| TC-INV-05 | Rows are sorted by finding count descending, then name | Assets `A-HOST` (1 finding) and `B-HOST` (2 findings) | Row order is `["B-HOST", "A-HOST"]` | Matches | PASS |
| TC-INV-06 | Owner and team are attached from the ownership map | `ownership={"WIN-DC01": {"owner": "Priya Nair", "team": "Identity"}}` | Row's `owner=="Priya Nair"`, `team=="Identity"` | Matches | PASS |
| TC-INV-07 | An unowned asset has `owner`/`team` both `None` | No matching entry in `ownership` | `owner is None`, `team is None` | Matches | PASS |
| TC-INV-08 | Loading ownership from a missing file returns an empty dict | `load_ownership(path)` where `path` doesn't exist | `{}` | Matches | PASS |
| TC-INV-09 | `set_owner` persists and is readable back | `set_owner("WIN-DC01", "Priya Nair", "Identity", path=path)`; reload | `loaded["WIN-DC01"] == {"owner": "Priya Nair", "team": "Identity"}` | Matches | PASS |
| TC-INV-10 | `set_owner` overwrites a previous entry for the same asset | Set once, then set again with different values | Reloaded entry reflects only the second call's values | Matches | PASS |
| TC-INV-11 | `set_owner` requires an asset name | Call with `asset_name=""` | `ValueError` raised | Raised | PASS |
| TC-INV-12 | Real, shipped `asset_ownership.json` is well-formed | `load_ownership()` (no `path` override) | Returns a dict; every key is a string; every value has `owner`/`team` keys | Matches | PASS |
| TC-INV-13 | Critical count only counts Critical-severity findings | One asset with two Critical findings and one High finding | Row's `critical_count==2` (High excluded) | Matches | PASS |
| TC-INV-14 | Facing defaults to `unknown` when not set | One finding against an unclassified asset, empty `ownership={}` | Row's `facing=="unknown"` | Matches | PASS |
| TC-INV-15 | Facing is attached from the ownership map | One finding against `WEB-PORTAL01`; `ownership={"WEB-PORTAL01": {"facing": "external"}}` | Row's `facing=="external"` | Matches | PASS |
| TC-INV-16 | `set_facing` does not clobber an existing owner/team | `set_owner("WIN-DC01", "Priya Nair", "Identity", path=path)`; then `set_facing("WIN-DC01", "internal", path=path)`; reload | Reloaded entry's `owner=="Priya Nair"` AND `facing=="internal"` (both persist together) | Matches | PASS |
| TC-INV-17 | `set_facing` rejects an invalid value | `set_facing("WIN-DC01", "space-station", path=path)` | `ValueError` raised | Raised | PASS |
| TC-INV-18 | `set_facing` requires an asset name | `set_facing("", "external", path=path)` | `ValueError` raised | Raised | PASS |
| TC-INV-19 | `set_owner` does not clobber an existing facing classification | `set_facing("WIN-DC01", "external", path=path)`; then `set_owner("WIN-DC01", "Priya Nair", "Identity", path=path)`; reload | Reloaded entry's `facing=="external"` AND `owner=="Priya Nair"` (setting owner preserves the previously-set facing) | Matches | PASS |

---

## Suite 14: Generic "bring your own" connector (`remediation/connectors/generic_connector.py`)

**Purpose:** prove the vendor-agnostic ingestion adapter — for any XDR/EDR/SIEM that can
send a custom outbound webhook, rather than one bespoke connector per named product —
correctly validates an inbound JSON payload against its documented minimal shape, and
normalizes an accepted payload into VulnHunter's normalized Finding schema with a
collision-safe ID.
**Preconditions (all TC-GENC):** `remediation/connectors/generic_connector.py`
importable; pure functions only — no network, no file I/O (the actual write to
`remediation/live-data/` is dashboard/app.py's concern, covered separately by Suite 9's
`ApiIngestGeneric`).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-GENC-01 | A valid minimal payload has no errors | `validate_generic_payload({"title": "Reflected XSS", "severity": "High", "asset_name": "APP-ORDERS01", "asset_type": "application"})` | `[]` | Matches | PASS |
| TC-GENC-02 | A non-dict payload is rejected | Call with a list, then separately with `None` | Both return a non-empty (truthy) error list | Matches | PASS |
| TC-GENC-03 | Missing required fields are each reported | `validate_generic_payload({})` | Exactly 4 errors (`title`/`severity`/`asset_name`/`asset_type`) | Matches | PASS |
| TC-GENC-04 | Invalid severity is rejected | `severity="Extreme"` | An error mentioning `"severity"` | Matches | PASS |
| TC-GENC-05 | Invalid asset_type is rejected | `asset_type="toaster"` | An error mentioning `"asset_type"` | Matches | PASS |
| TC-GENC-06 | Malformed CVE is rejected | `cve="not-a-cve"` | An error mentioning `"cve"` | Matches | PASS |
| TC-GENC-07 | Well-formed CVE passes | `cve="CVE-2021-44228"` | `[]` | Matches | PASS |
| TC-GENC-08 | A null CVE is allowed | `cve=None` | `[]` (CVE is optional) | Matches | PASS |
| TC-GENC-09 | Required fields map into the normalized schema | `normalize_generic_finding(payload, [], as_of=2026-08-04)` | `title`/`severity` copied through unchanged; `asset == {"name": "APP-ORDERS01", "ip": None, "type": "application", "os": None}` | Matches | PASS |
| TC-GENC-10 | Source defaults to `"generic"` | Normalize with no `source_name` passed | `finding["source"] == "generic"` | Matches | PASS |
| TC-GENC-11 | A `source_name` override is respected | `source_name="splunk-es"` | `finding["source"] == "splunk-es"` | Matches | PASS |
| TC-GENC-12 | KEV/EPSS are always `null` for generic findings | Normalize any valid payload | `finding["kev"] is None`, `finding["epss"] is None` (enrichment is a separate pipeline stage that never ran here) | Matches | PASS |
| TC-GENC-13 | `first_seen` defaults to `as_of` when not provided | `as_of=2026-08-04`, no `first_seen` in payload | `finding["first_seen"] == "2026-08-04"` | Matches | PASS |
| TC-GENC-14 | An explicit `first_seen` is respected | `first_seen="2026-01-15"` in payload | `finding["first_seen"] == "2026-01-15"` | Matches | PASS |
| TC-GENC-15 | Assigns the next sequential ID after existing findings | `existing=[{"id": "FIND-1"}, {"id": "FIND-14"}, {"id": "FIND-7"}]` | `finding["id"] == "FIND-15"` | Matches | PASS |
| TC-GENC-16 | Starts at `FIND-1` with no existing findings | `existing=[]` | `finding["id"] == "FIND-1"` | Matches | PASS |
| TC-GENC-17 | Ignores non-`FIND-`-prefixed IDs when computing the next ID | `existing=[{"id": "EXC-99"}, {"id": "FIND-3"}]` | `finding["id"] == "FIND-4"` | Matches | PASS |

---

## Suite 15: Finding-category (scan-type) taxonomy (`remediation/enrichment/scan_type_mapping.py`)

**Purpose:** prove the finding-category taxonomy (Infrastructure VM / SCA / Certificate
Mgmt / SAST / DAST) correctly classifies each `/remediate`-pipeline finding from its
`asset.type` alone, that batch tagging doesn't mutate its input, and that DAST remains a
documented, labeled category even though this repo's demo data has no DAST sample
finding yet.
**Preconditions (all TC-CAT):** `remediation/enrichment/scan_type_mapping.py`
importable; pure, in-memory functions only, no fixture files or network required.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CAT-01 | A `certificate` asset classifies as cert-mgmt | `classify_finding({"asset": {"type": "certificate"}})` | `"cert-mgmt"` | Matches | PASS |
| TC-CAT-02 | An `application` asset classifies as SCA | `classify_finding({"asset": {"type": "application"}})` | `"sca"` | Matches | PASS |
| TC-CAT-03 | A `windows-server` asset classifies as infra-vm | `classify_finding({"asset": {"type": "windows-server"}})` | `"infra-vm"` | Matches | PASS |
| TC-CAT-04 | A `unix-server` asset classifies as infra-vm | `classify_finding({"asset": {"type": "unix-server"}})` | `"infra-vm"` | Matches | PASS |
| TC-CAT-05 | Network and IoT/OT assets classify as infra-vm | Loop over `network-routing-switching`/`network-security-device`/`iot-ot-device` | All three return `"infra-vm"` | Matches | PASS |
| TC-CAT-06 | A missing `asset` key defaults to infra-vm rather than crashing | `classify_finding({})` | `"infra-vm"`, no `KeyError` | Matches | PASS |
| TC-CAT-07 | An unknown/future asset type defaults to infra-vm | `classify_finding({"asset": {"type": "some-future-asset-type"}})` | `"infra-vm"` | Matches | PASS |
| TC-CAT-08 | `tag_scan_types` adds fields without mutating input | Tag a one-finding list (`asset.type=="certificate"`) | Original dict has no `scan_type` key; tagged copy has `scan_type=="cert-mgmt"` and the matching `scan_type_label` | Matches | PASS |
| TC-CAT-09 | Tags a mixed batch correctly | Tag 3 findings of types certificate/application/windows-server | `scan_type` list equals `["cert-mgmt", "sca", "infra-vm"]` | Matches | PASS |
| TC-CAT-10 | DAST is a documented scan type with a label, even with no sample finding | Check `SCAN_TYPES`/`SCAN_TYPE_LABELS` | `"dast"` present in both (regression guard against silently dropping an unpopulated category) | Matches | PASS |
| TC-CAT-11 | Every scan type has a non-empty label | Loop over `SCAN_TYPES` | Each has a truthy entry in `SCAN_TYPE_LABELS` | Matches | PASS |

---

## Suite 16: Multi-language scanner pattern consistency (`tests/test_multilang_scanner_patterns.py`)

**Purpose:** these are static text-consistency checks, not live scanner-invocation
results — this environment has no Java, Go, PHP, or Node/npm runtime available, so
nothing in this suite compiles, executes, or lints the sample vulnerable code, and
nothing here claims the `vuln-scanner` subagent was actually invoked against these
fixtures (doing that requires a live Claude Code session running the `/vulnhunt`
pipeline, the same caveat documented for the Tenable/Armis connectors being built against
vendor docs rather than a live tenant). Instead, the suite proves two things stay in
sync: (1) each new fixture file under `vulnerable-demo-multilang/` genuinely contains the
specific vulnerable code pattern its own top-of-file "Planted vulnerabilities" comment
claims to plant (matching the numbering/CWE convention used by
`vulnerable-demo-app/app.py`), and (2) `.claude/agents/vuln-scanner.md`'s per-language
guidance documents a matching technique keyword for each language — so the fixtures and
the documentation are internally consistent with each other.
**Preconditions (all TC-LANG):** `vulnerable-demo-multilang/` directory exists alongside
(not inside) `vulnerable-demo-app/`, with all five fixture files present
(`VulnService.java`, `vuln-app.js`, `vulnapp.go`, `vuln-app.php`, `vuln-app.pl`);
`.claude/agents/vuln-scanner.md` exists.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-LANG-01 | Multilang fixture directory exists separately from the demo app | Check `vulnerable-demo-multilang/` and `vulnerable-demo-app/` both exist as directories | Both exist; the two paths are not equal (siblings, not nested) | Matches | PASS |
| TC-LANG-02 | `vulnerable-demo-app/app.py`'s planted-vulnerabilities header is untouched (regression guard) | Read `vulnerable-demo-app/app.py`; check for the literal header `"Planted vulnerabilities (for scoring / demo reference):"` | Header still present (this suite must never alter the original demo app or the finding count other suites depend on) | Present | PASS |
| TC-LANG-03 | All five language fixture files are present | List files directly in `vulnerable-demo-multilang/`; check for `VulnService.java`, `vuln-app.js`, `vulnapp.go`, `vuln-app.php`, `vuln-app.pl` | All 5 filenames present | All present | PASS |
| TC-LANG-04 | `VulnService.java` has the vulnerable banner and 3 numbered planted vulns | Read `VulnService.java`; check for `"deliberately vulnerable"`, `"DO NOT deploy"`, and the 3 numbered headers `"1. SQL Injection via Statement"`, `"2. Insecure deserialization"`, `"3. Hardcoded credential"` | All 5 strings present | All present | PASS |
| TC-LANG-05 | Java fixture plants SQL injection via `Statement`, not `PreparedStatement` | Check for `Statement stmt = conn.createStatement();` and the concatenated query string; check `"new PreparedStatement"` and `"PreparedStatement stmt"` are ABSENT; check `CWE-89` present | Vulnerable construction present; no `PreparedStatement` usage anywhere except the explanatory doc-comment; CWE tagged | Matches | PASS |
| TC-LANG-06 | Java fixture plants insecure deserialization | Check for `ObjectInputStream(rawIn)`, `ois.readObject()`, and `CWE-502` | All 3 present | All present | PASS |
| TC-LANG-07 | Java fixture plants a hardcoded credential | Check for `DB_PASSWORD = "SuperSecretP@ss123"` and `CWE-798` | Both present | Both present | PASS |
| TC-LANG-08 | `vuln-app.js` has the vulnerable banner and 3 numbered planted vulns | Read `vuln-app.js`; check for the banner strings and the 3 numbered headers (`Command injection via child_process.exec`, `Reflected XSS via unsanitized template string`, `Hardcoded API key`) | All present | All present | PASS |
| TC-LANG-09 | JS fixture plants command injection via `child_process.exec` | Check for `` exec(`ping -c 1 ${host}` `` and `CWE-78` | Both present | Both present | PASS |
| TC-LANG-10 | JS fixture plants reflected XSS via an unsanitized template string | Check for `<h1>Welcome back, ${name}!</h1>` and `CWE-79` | Both present | Both present | PASS |
| TC-LANG-11 | JS fixture plants a hardcoded (fake) API key | Check for `STRIPE_API_KEY = "sk_live_DEMO_FAKE_NOT_A_REAL_KEY...` and `CWE-798` | Both present | Both present | PASS |
| TC-LANG-12 | `vulnapp.go` has the vulnerable banner and 3 numbered planted vulns | Read `vulnapp.go`; check for the banner strings and the 3 numbered headers (`Command injection via exec.Command`, `SQL Injection via string-concatenated query`, `World-writable file permissions (0777)`) | All present | All present | PASS |
| TC-LANG-13 | Go fixture plants command injection via `exec.Command` | Check for `exec.Command("sh", "-c", "ping -c 1 "+host)` and `CWE-78` | Both present | Both present | PASS |
| TC-LANG-14 | Go fixture plants SQL injection via string-concatenated query | Check for `fmt.Sprintf("SELECT id, username, email FROM users WHERE id = %s", userID)` and `CWE-89` | Both present | Both present | PASS |
| TC-LANG-15 | Go fixture plants world-writable file permissions | Check for `os.WriteFile("/tmp/vulnapp-export.csv", data, 0777)` and `CWE-276` | Both present | Both present | PASS |
| TC-LANG-16 | `vuln-app.php` has the vulnerable banner and 3 numbered planted vulns | Read `vuln-app.php`; check for the banner strings and the 3 numbered headers (`SQL Injection via mysqli_query string concat`, `Local File Inclusion via include($_GET[...])`, `unserialize() on untrusted input`) | All present | All present | PASS |
| TC-LANG-17 | PHP fixture plants SQL injection via `mysqli_query` string concatenation | Check for `"SELECT id, username, email FROM users WHERE id = " . $user_id`, `mysqli_query($conn, $query)`, and `CWE-89` | All 3 present | All present | PASS |
| TC-LANG-18 | PHP fixture plants Local File Inclusion via `include($_GET[...])` | Check for `$page = $_GET['page'];`, `include($page . '.php');`, and `CWE-98` | All 3 present | All present | PASS |
| TC-LANG-19 | PHP fixture plants `unserialize()` on untrusted input | Check for `unserialize($raw)`, `$_COOKIE['session_data']`, and `CWE-502` | All 3 present | All present | PASS |
| TC-LANG-20 | `vuln-app.pl` has the vulnerable banner and 3 numbered planted vulns | Read `vuln-app.pl`; check for the banner strings and the 3 numbered headers (`Command injection via backticks with interpolated var`, `eval() on untrusted input`, `Hardcoded credential`) | All present | All present | PASS |
| TC-LANG-21 | Perl fixture plants command injection via backticks | Check for `` my $output = `ping -c 1 $host`; `` and `CWE-78` | Both present | Both present | PASS |
| TC-LANG-22 | Perl fixture plants `eval()` on untrusted input | Check for `my $result = eval "$expr";` and `CWE-95` | Both present | Both present | PASS |
| TC-LANG-23 | Perl fixture plants a hardcoded credential | Check for `$DB_PASSWORD = "SuperSecretP@ss123";` and `CWE-798` | Both present | Both present | PASS |
| TC-LANG-24 | `vuln-scanner.md` documents JavaScript with a specific technique keyword | Read `.claude/agents/vuln-scanner.md`; check for `"JavaScript"` and `"child_process.exec"` | Both present | Both present | PASS |
| TC-LANG-25 | `vuln-scanner.md` documents Java with a specific technique keyword | Check for `"Java"` and `"PreparedStatement"` | Both present | Both present | PASS |
| TC-LANG-26 | `vuln-scanner.md` documents Go with a specific technique keyword | Check for `"Go"` and `"html/template"` | Both present | Both present | PASS |
| TC-LANG-27 | `vuln-scanner.md` documents PHP and mentions `unserialize` | Check for `"PHP"` and `"unserialize"` | Both present | Both present | PASS |
| TC-LANG-28 | `vuln-scanner.md` documents Perl and mentions `Storable::thaw` | Check for `"Perl"` and `"Storable::thaw"` | Both present | Both present | PASS |
| TC-LANG-29 | `## Process` section mentions checking file extensions | Check the (lowercased) document text for `"extension"` | Present | Present | PASS |
| TC-LANG-30 | Pre-existing generic/Python/Docker/dependency-risk sections still present (regression guard) | Check for `"### Generic (all languages)"`, `"### Python"`, `"Container/Docker issues"`, and `"Dependency risk"` | All 4 present (the per-language rewrite must not have deleted the original guidance) | All present | PASS |
| TC-LANG-31 | `## Process` and `## Output format` sections still present, in order | Check both headings are present, and `## Process` appears before `## Output format` | Both present, in the expected order | Matches | PASS |

---

## Suite 17: Live Tenable connector (`remediation/connectors/tenable_connector.py`)

**Purpose:** prove the connector's auth, export-polling, and record-mapping logic is
correct against Tenable.io's documented API shapes, entirely via mocked HTTP — see
[remediation/connectors/README.md](remediation/connectors/README.md) for what this suite
does and does not prove (it has never called the real Tenable API).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CONN-01 | Session gets the correct `X-ApiKeys` auth header | Construct `TenableConnector("access123", "secret456", session=mock)` | Header equals `"accessKey=access123;secretKey=secret456"` | Matches | PASS |
| TC-CONN-02 | `request_export` returns the export UUID | Mock POST returns `{"export_uuid": "uuid-abc"}` | Returns `"uuid-abc"` | Matches | PASS |
| TC-CONN-03 | `request_export` includes a `since` filter when given | Call with `since=1700000000` | POST body's `filters.since == 1700000000` | Matches | PASS |
| TC-CONN-04 | `request_export` raises on an unexpected response shape | Mock POST returns a body with no `export_uuid` key | `TenableExportError` raised | Raised | PASS |
| TC-CONN-05 | Poll returns chunk IDs when status is `FINISHED` | Mock GET returns `{"status": "FINISHED", "chunks_available": [1,2]}` | Returns `[1, 2]` | Matches | PASS |
| TC-CONN-06 | Poll raises on `ERROR` status | Mock GET returns `{"status": "ERROR"}` | `TenableExportError` raised | Raised | PASS |
| TC-CONN-07 | Poll raises on timeout (regression guard) | Mock GET always returns `PROCESSING`, `timeout_seconds=0` | `TenableExportError` raised promptly, no infinite loop | Raised, no hang | PASS |
| TC-CONN-08 | `download_chunk` returns raw records | Mock GET returns a JSON array | Array returned unchanged | Matches | PASS |
| TC-CONN-09 | `to_csv_row` maps a documented-shape record correctly | Feed a full nested `plugin`/`asset` record | All 15 CSV fields map to the right values | All correct | PASS |
| TC-CONN-10 | `to_csv_row` handles a missing CVE gracefully | Feed a record with no `cve` list | `CVE` field is `""`, no `IndexError` | No error | PASS |
| TC-CONN-11 | `fetch_and_write_csv` writes a sample-compatible file | Full mocked export -> poll -> chunk flow, write to a temp file | Output CSV's header exactly matches `CSV_FIELDNAMES`; row values correct | Matches | PASS |

## Suite 18: Live Armis connector (`remediation/connectors/armis_connector.py`)

**Purpose:** same goal as Suite 17, for Armis's token-auth + paginated AQL search flow.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CONN-12 | `authenticate` sets the token and `Authorization` header | Mock POST returns `{"data": {"access_token": "tok-123"}}` | Token stored; session header set to `"tok-123"` | Matches | PASS |
| TC-CONN-13 | `authenticate` raises on a bad response shape | Mock POST returns a body with no `data.access_token` | `ArmisAuthError` raised | Raised | PASS |
| TC-CONN-14 | `search` triggers authentication automatically if not yet authenticated | Call `search()` on a fresh connector | POST (auth) called exactly once before the GET | Matches | PASS |
| TC-CONN-15 | `search_all_pages` follows the `next` cursor | Mock two pages: first `next=100`, second `next=None` | Combined results from both pages; exactly 2 GET calls | Matches | PASS |
| TC-CONN-16 | `search_all_pages` respects `max_pages` (regression guard) | Mock GET always returns a non-null `next` | Loop stops at `max_pages`, doesn't run forever | Stops correctly | PASS |
| TC-CONN-17 | `_alert_to_sample_shape` maps a raw alert correctly | Feed a raw alert dict | `alertType`/`title`/`cve` map correctly | Matches | PASS |
| TC-CONN-18 | `fetch_and_write_json` assembles devices with their alerts | Mock one alert referencing one device; mock that device's detail lookup | Output JSON has 1 device with 1 alert, correct field mapping | Matches | PASS |

---

## Suite 19: CISA KEV + EPSS enrichment (`remediation/enrichment/kev_epss.py`)

**Purpose:** prove the enrichment logic correctly parses both real APIs' documented
response shapes and assembles them onto findings correctly — and, uniquely in this test
suite, prove it actually works against the real live endpoints (see TC-ENR-13).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-ENR-01 | `fetch_cisa_kev` maps the documented KEV feed shape | Mock GET returns one KEV entry | Returned dict keyed by CVE ID with `date_added`/`known_ransomware_campaign_use` etc. | Matches | PASS |
| TC-ENR-02 | `fetch_cisa_kev` skips entries with no CVE ID | Mock GET returns an entry missing `cveID` | Entry excluded, no crash | Excluded | PASS |
| TC-ENR-03 | `fetch_epss_scores` maps the documented EPSS response shape | Mock GET returns one EPSS row | Score/percentile parsed as floats | Matches | PASS |
| TC-ENR-04 | `fetch_epss_scores` batches large CVE lists | Request scores for 150 CVEs (batch size is 100) | Exactly 2 GET calls (100 + 50) | 2 calls | PASS |
| TC-ENR-05 | `fetch_epss_scores` deduplicates input | Request the same CVE twice | Sent to the API once, not comma-doubled | Deduplicated | PASS |
| TC-ENR-06 | Findings without a CVE get null enrichment | Enrich a finding with `cve: null` | `kev` and `epss` both `null` | Both null | PASS |
| TC-ENR-07 | KEV-listed finding gets the full KEV record | Enrich a finding whose CVE is in the (mocked) KEV data | `kev.listed == true` plus the KEV metadata fields | Matches | PASS |
| TC-ENR-08 | Non-KEV-listed finding gets `{"listed": false}` | Enrich a finding whose CVE is NOT in the KEV data | `kev == {"listed": false}` (not null — "checked, not exploited" ≠ "not applicable") | Matches | PASS |
| TC-ENR-09 | Missing EPSS score doesn't crash | Enrich a finding whose CVE has no EPSS data | `epss` is `null`, no `KeyError` | No error | PASS |
| TC-ENR-10 | Original finding fields are preserved | Enrich a finding with extra fields like `title` | All original fields still present after enrichment | Preserved | PASS |
| TC-ENR-11 | `enrich_file` writes a correctly enriched JSON file | Full mocked KEV+EPSS flow via an injected session, write to a temp file | Output file's finding has `kev.listed == true` and the correct EPSS score | Matches | PASS |
| TC-ENR-12 | `enrich_file` defaults to overwriting the input, skips HTTP calls when no CVE present | Enrich a finding with `cve: null`, no `output_path` given | Returns the input path; session's `get` never called (no CVE = nothing to look up) | Matches | PASS |
| TC-ENR-13 | **Live smoke test**: PrintNightmare is really KEV-listed with high EPSS | Call the real `fetch_cisa_kev()` and `fetch_epss_scores(["CVE-2021-34527"])` against the actual public APIs | CVE-2021-34527 present in KEV; EPSS score > 0.9 | Matches (skips itself if network unavailable, never fails the build) | PASS |

---

## Suite 20: Configurable priority + SLA engine (`remediation/config/priority_engine.py`)

**Purpose:** prove the scoring/SLA math is correct against an in-memory rules dict (so
tests don't break if someone reasonably retunes the real rules file), plus validate the
real shipped rules file is well-formed and produces a sane result on real sample data.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-PRIO-01 | Low severity + generic asset → Low priority | Score a Low-severity finding on a non-critical asset | `priority == "Low"` | Matches | PASS |
| TC-PRIO-02 | Critical severity + domain controller → Critical priority | Score a Critical finding on a `WIN-DC01`-named asset | `priority == "Critical"` | Matches | PASS |
| TC-PRIO-03 | KEV-listed forces Critical regardless of score | Score a Low-severity, low-criticality finding with `kev.listed=true` | `priority == "Critical"`, reason mentions KEV | Matches | PASS |
| TC-PRIO-04 | KEV override can be disabled | Same as above with `kev_override.enabled=false` | `priority` stays `"Low"` (no forcing) | Matches | PASS |
| TC-PRIO-05 | High EPSS elevates to at least High | Score a Low finding with `epss.score=0.9` | `priority == "High"` | Matches | PASS |
| TC-PRIO-06 | Low EPSS does not elevate | Score a Low finding with `epss.score=0.1` | `priority` stays `"Low"` | Matches | PASS |
| TC-PRIO-07 | EPSS never downgrades an already-higher score | Score a Critical finding that also has `epss.score=0.6` | `priority` stays `"Critical"`, not pulled down to "High" | Matches | PASS |
| TC-PRIO-08 | SLA due date computed correctly, not breached | `first_seen` 2 days ago, High priority (7-day SLA) | Correct due date; `days_remaining=5`; not breached | Matches | PASS |
| TC-PRIO-09 | SLA breached when past due date | `first_seen` well before a 3-day Critical SLA window | `breached == true`, negative `days_remaining` | Matches | PASS |
| TC-PRIO-10 | Missing `first_seen` handled gracefully | Finding with `first_seen=None` | `due_date`/`breached` both `None`, no exception | Matches | PASS |
| TC-PRIO-11 | Batch scoring sorts highest priority first | Score a Low + a Critical finding together | Critical finding is first in the returned list | Matches | PASS |
| TC-PRIO-12 | Batch scoring doesn't mutate input | Score a findings list | Original dicts have no new keys added | Matches | PASS |
| TC-PRIO-13 | Real `priority_rules.yaml` loads with all expected keys | Load the real shipped file | All 7 top-level keys present | Matches | PASS |
| TC-PRIO-14 | Real rules file scores a known real finding correctly | Score PrintNightmare (FIND-1) from real sample data against the real rules file | `priority == "Critical"` | Matches | PASS |

## Suite 21: MITRE ATT&CK keyword tagging (`remediation/enrichment/attack_mapping.py`)

**Purpose:** prove the heuristic fires on realistic finding text, and — just as
importantly — proves it does NOT guess when there's no real signal (empty list, not a
fabricated technique). Also covers `build_attack_heatmap()` (TC-ATTACK-12–14), added
this wave to feed the `/risk` dashboard's tactic × technique heat map — it covers every
technique in the full known taxonomy, including techniques with zero matching findings
today, not just whatever happens to appear in the current sample data (see Suite 9's
`ApiRiskAttackHeatmap`, TC-DASH-88–89, for the API-level equivalent check).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-ATTACK-01 | SQL injection → T1190 | Tag a finding titled "SQL Injection..." | `technique_id == "T1190"` | Matches | PASS |
| TC-ATTACK-02 | Command injection → T1059 | Tag a finding titled "Command injection via shell=True" | `technique_id == "T1059"` | Matches | PASS |
| TC-ATTACK-03 | PrintNightmare-style RCE → T1210 | Tag a finding titled "...Print Spooler Remote Code Execution" | `technique_id == "T1210"` | Matches | PASS |
| TC-ATTACK-04 | Sudo privilege escalation → T1068 | Tag a finding mentioning "privilege escalation to root" | `technique_id == "T1068"` | Matches | PASS |
| TC-ATTACK-05 | Hardcoded secret → T1552 | Tag a finding titled "Hardcoded Stripe API key" | `technique_id == "T1552"` | Matches | PASS |
| TC-ATTACK-06 | Telnet exposure → T1021 | Tag a finding titled "Device Exposes Telnet Service" | `technique_id == "T1021"` | Matches | PASS |
| TC-ATTACK-07 | Certificate expiry is deliberately unmapped | Tag "SSL Certificate Expiry" | Empty list (not a forced/guessed technique) | Empty | PASS |
| TC-ATTACK-08 | No keyword match returns empty, not a guess | Tag unrelated text | Empty list | Empty | PASS |
| TC-ATTACK-09 | `all_matches=True` can return more than one technique | Tag "Command injection RCE via eval()" with `all_matches=True` | Result includes T1059 among possibly others | Matches | PASS |
| TC-ATTACK-10 | Batch tagging adds field without mutating input | Tag a findings list | Original dicts unchanged; tagged copies have `attack_techniques` | Matches | PASS |
| TC-ATTACK-11 | Batch tagging against real sample data | Tag all 14 real findings | PrintNightmare (FIND-1) gets ≥1 technique; SSL cert expiry (FIND-13) gets none | Matches | PASS |
| TC-ATTACK-12 | Heatmap counts real tagged findings | Tag 3 findings (two SQL-injection-style, one command-injection-style) via `tag_findings`; call `build_attack_heatmap(findings)` | Row keyed `T1190` has `count==2`; row keyed `T1059` has `count==1` | Matches | PASS |
| TC-ATTACK-13 | Heatmap ignores findings with no matched technique | Tag one certificate-expiry finding (no keyword match); call `build_attack_heatmap(findings)` | Every row's `count==0` | Matches | PASS |
| TC-ATTACK-14 | Heatmap includes every known tactic/technique even with zero findings | `build_attack_heatmap([])` (empty findings list) | Every known tactic/technique pair is present as a row; every row's `count==0` | Matches | PASS |

## Suite 22: ServiceNow adapter (`remediation/connectors/servicenow_connector.py`)

**Purpose:** prove the Table API request construction, idempotency check, and batch
error handling are correct against mocked HTTP shaped like ServiceNow's documentation —
see [remediation/connectors/README.md](remediation/connectors/README.md) for what this
does and doesn't prove (never exercised against a real ServiceNow instance).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-SNOW-01 | Session gets HTTP Basic auth configured | Construct `ServiceNowConnector("mycompany", "user1", "pass1")` | `session.auth == ("user1", "pass1")` | Matches | PASS |
| TC-SNOW-02 | Base URL built from instance name | Same construction | `base_url == "https://mycompany.service-now.com"` | Matches | PASS |
| TC-SNOW-03 | Default table is `incident` | Construct with no `table` argument | `table == "incident"` | Matches | PASS |
| TC-SNOW-04 | Can target a different table | Construct with `table="sn_vul_vulnerable_item"` | `table` reflects the override | Matches | PASS |
| TC-SNOW-05 | `build_incident_body` is a pure function, no network | Call directly with a sample finding | Correct body dict returned, no mock HTTP calls made | Matches | PASS |
| TC-SNOW-06 | `create_incident` and `build_incident_body` produce the same shape | Compare the body actually POSTed vs. the pure-function output | Identical dicts (regression guard for the refactor) | Matches | PASS |
| TC-SNOW-07 | Finds an existing incident by `correlation_id` | Mock a matching query result | Returns that incident record | Matches | PASS |
| TC-SNOW-08 | Returns `None` when nothing found | Mock an empty query result | `None` returned | Matches | PASS |
| TC-SNOW-09 | Creates a new incident when none exists | Mock empty lookup + successful POST | `_vulnhunter_status == "created"` | Matches | PASS |
| TC-SNOW-10 | Skips creation when an incident already exists | Mock a matching lookup | `_vulnhunter_status == "already_existed"`, POST never called | Matches | PASS |
| TC-SNOW-11 | `skip_if_exists=False` always creates, skips the lookup | Call with that flag | GET (lookup) never called, POST called once | Matches | PASS |
| TC-SNOW-12 | Incident body includes KEV/EPSS context | Create an incident for a KEV-listed, high-EPSS finding | Description mentions "KEV-listed" and "EPSS score" | Matches | PASS |
| TC-SNOW-13 | Severity maps to urgency/impact correctly | Create an incident for a Critical finding | `urgency == "1"`, `impact == "1"` | Matches | PASS |
| TC-SNOW-14 | Raises on an unexpected response shape | Mock a POST response with no `result` key | `ServiceNowError` raised | Raised | PASS |
| TC-SNOW-15 | Batch creates incidents for all findings | Run `create_incidents_for_findings` on a findings list | Correct count and status per finding | Matches | PASS |
| TC-SNOW-16 | Batch continues past a single finding's failure | Include one malformed finding in the batch | Both findings get a result; the bad one reports `status="error"` with a message, the batch doesn't abort | Matches | PASS |

---

## Suite 23: Local authentication (`dashboard/auth/`)

**Purpose:** prove password hashing (PBKDF2-HMAC-SHA256, stdlib only — no bcrypt/argon2/
passlib dependency), HMAC-signed session cookies (a from-scratch, stdlib-only
alternative to Starlette's `itsdangerous`-based `SessionMiddleware`), the local user
store (create/login/change-password, case-insensitive email, never leaking a password
hash), and the OIDC Authorization Code + PKCE client all behave correctly. Same "built
vs. verified" honesty as every connector in this repo (Tenable/Armis/ServiceNow/CISA
KEV+EPSS): the OIDC client is built against the real OpenID Connect Discovery and
Authorization Code + PKCE specs and tested entirely via mocked HTTP, but has never been
exercised against a real identity provider (Okta, Azure AD/Entra, Auth0, Google, etc.) —
`is_configured()` stays `False`, and the dashboard's SSO button stays hidden, until a
real operator supplies real `OIDC_*` credentials.
**Preconditions (all TC-AUTH):** `dashboard/auth/` (`passwords.py`, `sessions.py`,
`users.py`, `oidc.py`) importable. `UserStore` tests (TC-AUTH-12–21) each use a fresh
temporary `users.json` file passed explicitly via `path=...`, never the real, shipped
`dashboard/auth/users.json`; `SessionCookies` tests (TC-AUTH-06–11) use a fixed,
test-only secret, never any real deployment secret. TC-AUTH-22 (`RealSeedFileIsValid`)
instead calls `load_users()` with no `path` override, against the real, shipped
`users.json` (the two demo accounts: `admin@vulnhunter.local`, role `admin`;
`analyst@vulnhunter.local`, role `user`). `OidcFlow` tests (TC-AUTH-26–30) mock
`requests`-shaped session objects passed explicitly as `session=...`, so no real network
call or real identity provider is ever contacted; `OidcConfiguration` tests
(TC-AUTH-23–25) patch `os.environ` directly and restore it in `tearDown`.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-AUTH-01 | Correct password verifies against its own hash | `hash_password("correct horse battery staple")`; `verify_password()` with the same password | Returns `True` | True | PASS |
| TC-AUTH-02 | Malformed/blank/None stored hash fails closed instead of raising | `verify_password("anything", "not-a-real-hash")`, then with `""`, then with `None` | All three return `False`, no exception raised | All False, no error | PASS |
| TC-AUTH-03 | Hashing the same password twice yields different output (random salt per call) | Call `hash_password("same password")` twice | The two stored hash strings are not equal | Not equal | PASS |
| TC-AUTH-04 | Stored hash embeds its own iteration count and still verifies | `hash_password("x", iterations=1000)`; check for `"$1000$"`; `verify_password("x", stored)` | Iteration count present in the stored string; verification succeeds | Matches | PASS |
| TC-AUTH-05 | Wrong password does not verify | Hash `"correct horse battery staple"`; `verify_password("wrong password", stored)` | `False` | False | PASS |
| TC-AUTH-06 | Cookie's `exp` claim reflects the requested `max_age` | Record `time.time()`; `create_session_cookie({}, SECRET, max_age_seconds=3600)`; verify and read `claims["exp"]` | `exp` is within 5 seconds of `now + 3600` | Within delta | PASS |
| TC-AUTH-07 | Expired cookie is rejected | Create a cookie with `max_age_seconds=-1` (already expired); verify it | `None` | None | PASS |
| TC-AUTH-08 | Garbage, blank, or `None` cookie value fails closed, not with an exception | Verify `"not-a-real-cookie"`, `""`, and `None` as the cookie value | All three return `None`, no exception | All None, no error | PASS |
| TC-AUTH-09 | Tampering with the payload while keeping the old signature is rejected | Create a cookie; append `"x"` to its payload segment while leaving the signature segment untouched; verify | `None` (signature no longer matches) | None | PASS |
| TC-AUTH-10 | Valid cookie round-trips its claims | Create a cookie with `email`/`role` claims; verify it | Returned claims dict has the same `email` and `role` values | Matches | PASS |
| TC-AUTH-11 | Cookie signed with one secret fails verification under a different secret | Create a cookie with `SECRET`; verify it against `"a-different-secret"` | `None` | None | PASS |
| TC-AUTH-12 | Creating a user then logging in with the same credentials succeeds and never leaks the hash | `create_user("Someone@Example.com", "correcthorsebatterystaple", "Someone", role="admin", path=tmp)`; `verify_login("someone@example.com", "correcthorsebatterystaple", path=tmp)` | Non-`None` result; `role=="admin"`; `email=="someone@example.com"` (lowercased); no `password_hash` key in the result | Matches | PASS |
| TC-AUTH-13 | Creating a user with an already-registered email is rejected | `create_user("someone@example.com", ...)`; call `create_user` again with the same email | Second call raises `ValueError` | Raised | PASS |
| TC-AUTH-14 | Creating a user with a too-short password is rejected | `create_user("someone@example.com", "short", "Someone", path=tmp)` | `ValueError` raised (below `MIN_PASSWORD_LENGTH`) | Raised | PASS |
| TC-AUTH-15 | Creating a user with an unrecognized role is rejected | `create_user(..., role="superuser", path=tmp)` | `ValueError` raised (`role` not in `VALID_ROLES`) | Raised | PASS |
| TC-AUTH-16 | Loading from a missing users file returns an empty dict | `load_users(path)` where `path` has never been written | `{}` | Matches | PASS |
| TC-AUTH-17 | Login is case-insensitive on email | Create a user with a lowercase email; `verify_login` with the same email upper-cased | Non-`None` result (same account) | Matches | PASS |
| TC-AUTH-18 | Changing the password of an unknown user raises `KeyError` | `set_password("nobody@example.com", "newpassword12345", path=tmp)` with no such user in the store | `KeyError` raised | Raised | PASS |
| TC-AUTH-19 | After changing a password, the old password no longer works and the new one does | Create a user; `set_password` to a new password; `verify_login` with the old password, then with the new password | Old password returns `None`; new password returns a non-`None` result | Matches | PASS |
| TC-AUTH-20 | Logging in with an unknown email returns `None`, not an error | `verify_login("nobody@example.com", "anything", path=tmp)` against an empty store | `None` | None | PASS |
| TC-AUTH-21 | Logging in with the wrong password returns `None` | Create a user; `verify_login` with an incorrect password | `None` | None | PASS |
| TC-AUTH-22 | Real, shipped `users.json` is well-formed and has both demo roles | `load_users()` (no `path` override) against the real, shipped `dashboard/auth/users.json` | Returns a dict; role set includes both `"admin"` and `"user"`; every key is already lowercased; every `password_hash` starts with `"pbkdf2_sha256$"` | Matches | PASS |
| TC-AUTH-23 | `is_configured()` is `True` once all four OIDC env vars are set | Set `OIDC_ISSUER`/`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET`/`OIDC_REDIRECT_URI`; call `oidc.is_configured()` | `True` | True | PASS |
| TC-AUTH-24 | `is_configured()` is `False` when only some of the four env vars are set | Set only `OIDC_ISSUER` and `OIDC_CLIENT_ID`; call `is_configured()` | `False` | False | PASS |
| TC-AUTH-25 | `is_configured()` is `False` with none of the four env vars set | Ensure all four `OIDC_*` vars are unset; call `is_configured()` | `False` | False | PASS |
| TC-AUTH-26 | `build_authorize_url` includes the state, PKCE challenge, and client ID | `build_authorize_url("state-xyz", "challenge-abc", discovery_doc=DISCOVERY_DOC)` (mocked discovery doc, `client_id="client-123"` from env) | URL starts with the discovery doc's `authorization_endpoint`; contains `state=state-xyz`, `code_challenge=challenge-abc`, `code_challenge_method=S256`, `client_id=client-123` | Matches | PASS |
| TC-AUTH-27 | `discover()` fetches the standard `.well-known/openid-configuration` path | `oidc.discover("https://idp.example.com", session=mock_session)` | Mocked session's `get` called exactly once with `"https://idp.example.com/.well-known/openid-configuration"` | Matches | PASS |
| TC-AUTH-28 | `exchange_code_for_token` POSTs the `authorization_code` grant with the PKCE verifier and client secret | Mock a token-endpoint POST response; `exchange_code_for_token("auth-code", "verifier-xyz", discovery_doc=DISCOVERY_DOC, session=mock_session)` | Returns the mocked token response (`access_token=="at-123"`); POST body's `grant_type=="authorization_code"`, `code=="auth-code"`, `code_verifier=="verifier-xyz"`, `client_secret=="secret-abc"` | Matches | PASS |
| TC-AUTH-29 | `fetch_userinfo` sends the access token as a Bearer header | Mock the userinfo-endpoint GET response; `fetch_userinfo("at-123", discovery_doc=DISCOVERY_DOC, session=mock_session)` | Returns the mocked userinfo (`email=="person@example.com"`); GET call's `headers["Authorization"]=="Bearer at-123"` | Matches | PASS |
| TC-AUTH-30 | `generate_pkce_pair` produces a challenge that's the correct S256 hash of its own verifier | Call `generate_pkce_pair()`; independently recompute the expected S256 challenge from the returned verifier | Returned `challenge` equals the independently recomputed base64url(SHA-256(verifier)) value | Matches | PASS |
| TC-AUTH-31 | An unknown email still runs the real password-hash comparison (timing-safety regression) | Spy on `passwords.verify_password` (wraps the real function); call `verify_login("nobody@example.com", "anything")` | The spy is called exactly once - the deliberately-slow PBKDF2 comparison is never skipped just because the email doesn't exist | Called once | PASS |
| TC-AUTH-32 | A known-email-wrong-password login and an unknown-email login hit the identical code path | Spy on `passwords.verify_password`; call `verify_login()` once with a real email + wrong password, once with a fake email | The spy is called exactly twice - both cases reach the same comparison, closing the timing side-channel between them | Called twice | PASS |

---

## Suite 24: Compensating-control suggestions (`remediation/enrichment/compensating_controls.py`)

**Purpose:** prove the keyword heuristic fires the right suggestion category on
realistic finding text (exposed management service, injection, hardcoded secret,
certificate expiry), that an unmatched finding still gets a sane, non-empty default
rather than an empty list, and that batch tagging works against the real 14-finding
sample set without mutating its input. Same explicit non-authoritative caveat as
`attack_mapping.py`'s ATT&CK tagging (Suite 21): there is no single "the" correct
compensating control for a given vulnerability, so every suggestion here is a keyword
heuristic surfacing something to *consider* on the Exceptions request form — not an
approved or certified control, and not a substitute for a security engineer's own
judgment about what's actually appropriate for a given asset and environment.
**Preconditions (all TC-COMP):** `remediation/enrichment/compensating_controls.py`
importable; pure, in-memory functions only — no network, no mocked HTTP required.
TC-COMP-08 additionally reads the real, shipped `remediation/output/normalized-
findings.json` (the same 14-finding sample set used throughout this log) to confirm
every real finding gets a non-empty suggestion list.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-COMP-01 | Certificate-expiry finding suggests expiry monitoring | `suggest_compensating_controls({"title": "SSL certificate nearing expiration", "description": ""})` | At least one suggested control contains `"expiry"` | Matches | PASS |
| TC-COMP-02 | Exposed management-interface finding suggests a network ACL/firewall restriction | `suggest_compensating_controls({"title": "Telnet management interface exposed", "description": ""})` | At least one suggested control contains `"ACL"` or `"firewall"` | Matches | PASS |
| TC-COMP-03 | Hardcoded-secret finding suggests credential rotation | `suggest_compensating_controls({"title": "Hardcoded Stripe API key", "description": ""})` | At least one suggested control contains `"Rotate"` | Matches | PASS |
| TC-COMP-04 | Injection finding suggests a WAF rule | `suggest_compensating_controls({"title": "SQL Injection via string concatenation", "description": ""})` | At least one suggested control contains `"WAF"` | Matches | PASS |
| TC-COMP-05 | `suggest_compensating_controls` never returns an empty list | Call with 5 different titles (including `""` and unrelated text) | Every call returns a non-empty list | Matches | PASS |
| TC-COMP-06 | A title matching no keyword pattern falls back to `DEFAULT_CONTROLS` | `suggest_compensating_controls({"title": "Something entirely unrelated to any pattern", "description": ""})` | Returned list equals `DEFAULT_CONTROLS` exactly (not a guessed/fabricated suggestion) | Matches | PASS |
| TC-COMP-07 | `tag_compensating_controls` adds the field without mutating its input | Tag a one-finding list; compare the original dict's key set before/after | Original finding's keys unchanged (no `compensating_controls` key added to it); the returned (copied) finding has a `compensating_controls` key | Matches | PASS |
| TC-COMP-08 | Tagging the real, shipped sample findings never produces an empty suggestion list | Load the real `remediation/output/normalized-findings.json` (all 14 findings); `tag_compensating_controls(findings)` | Every tagged finding has a non-empty `compensating_controls` list | Matches | PASS |

---

## Suite 25: Jira connector (`remediation/connectors/jira_connector.py`)

**Purpose:** prove the Jira Cloud REST API v3 issue-body construction, the label-based
idempotency check, and batch error handling are correct against mocked HTTP shaped like
Atlassian's documentation — see
[remediation/connectors/README.md](remediation/connectors/README.md) for what this does
and doesn't prove (never exercised against a real Jira Cloud site). Jira has no
built-in correlation-id field the way ServiceNow's Table API does, so this connector
uses a `vulnhunter-{finding_id}` label as its idempotency key instead — searched for via
JQL before create, and stamped onto every issue it creates — which is a genuinely
different mechanism from ServiceNow's `correlation_id` field lookup, not just a
renamed copy of it. The issue description is also built as a minimal Atlassian Document
Format (ADF) document rather than a plain string, since that's what the v3 API requires.
**Preconditions (all TC-JIRA):** `remediation/connectors/jira_connector.py` importable;
`requests.Session` is replaced with a `MagicMock` in every test — no real Jira Cloud
site touched, no Atlassian API token required. `BuildIssueBodyPureFunction`'s 7 cases
call `build_issue_body` directly with no connector or session at all, exercising the
same code path the dashboard's preview mode would use to show what would be sent
without live credentials.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-JIRA-01 | `build_issue_body` builds the correct body with no network calls | Call `build_issue_body(SAMPLE_FINDING, "PROJ")` directly | `fields.project.key=="PROJ"`; `fields.summary` contains `"FIND-1"`; `fields.labels == ["vulnhunter-FIND-1"]` | Matches | PASS |
| TC-JIRA-02 | `create_issue` and `build_issue_body` produce the same shape (regression guard) | Mock `session.get`→`{"issues": []}`, `session.post`→a created issue; call `conn.create_issue(SAMPLE_FINDING)`; compare the posted JSON body to `build_issue_body(SAMPLE_FINDING, "PROJ")` | Identical dicts (the refactor that extracted `build_issue_body` must not have changed what `create_issue` actually sends) | Matches | PASS |
| TC-JIRA-03 | Description is a valid minimal ADF doc | Inspect `build_issue_body(...)["fields"]["description"]` | `type=="doc"`, `version==1`; `content[0].type=="paragraph"`; its `content[0].type=="text"` with a string `text` value | Matches | PASS |
| TC-JIRA-04 | Description text includes KEV and EPSS context | Extract the ADF text node from the built body | Text contains `"KEV-listed"`, `"EPSS score"`, and `"CVE-2021-34527"` | Matches | PASS |
| TC-JIRA-05 | Issue type defaults to Bug | `build_issue_body(SAMPLE_FINDING, "PROJ")` with no `issue_type` override | `fields.issuetype.name == "Bug"` | Matches | PASS |
| TC-JIRA-06 | Issue type can be overridden | `build_issue_body(SAMPLE_FINDING, "PROJ", issue_type="Task")` | `fields.issuetype.name == "Task"` | Matches | PASS |
| TC-JIRA-07 | Label is used as the idempotency key, distinct per finding | Build bodies for `SAMPLE_FINDING` (`FIND-1`) and a copy with `id="FIND-2"` | Labels equal `["vulnhunter-FIND-1"]` and `["vulnhunter-FIND-2"]` respectively | Matches | PASS |
| TC-JIRA-08 | Session gets HTTP Basic auth configured | Construct `JiraConnector(url, "e@acme.com", "tok1", "PROJ", session=mock)` | `session.auth == ("e@acme.com", "tok1")` | Matches | PASS |
| TC-JIRA-09 | Base URL stored and trailing slash stripped | Construct with `base_url="https://acme.atlassian.net/"` | `conn.base_url == "https://acme.atlassian.net"` | Matches | PASS |
| TC-JIRA-10 | Project key stored on the connector | Construct with `project_key="PROJ"` | `conn.project_key == "PROJ"` | Matches | PASS |
| TC-JIRA-11 | Finds an existing issue by its label via JQL | Mock `session.get`→`{"issues": [{"id": "10000", "key": "PROJ-1"}]}`; call `conn.find_existing_issue("FIND-1")` | Returns the issue with `key=="PROJ-1"`; the GET's `params["jql"]` contains `"vulnhunter-FIND-1"` | Matches | PASS |
| TC-JIRA-12 | Returns `None` when nothing is found | Mock `session.get`→`{"issues": []}`; call `find_existing_issue("FIND-999")` | `None` returned | Matches | PASS |
| TC-JIRA-13 | Creates a new issue when none exists | Mock empty lookup + successful POST (`key="PROJ-2"`); call `conn.create_issue(SAMPLE_FINDING)` | `_vulnhunter_status == "created"`, `key == "PROJ-2"` | Matches | PASS |
| TC-JIRA-14 | Skips creation when an issue already exists | Mock a matching lookup; call `create_issue(SAMPLE_FINDING)` | `_vulnhunter_status == "already_existed"`; `session.post` never called | Matches | PASS |
| TC-JIRA-15 | `skip_if_exists=False` always creates, skipping the lookup | Call `create_issue(SAMPLE_FINDING, skip_if_exists=False)` | `session.get` never called (no existence check performed); `session.post` called exactly once | Matches | PASS |
| TC-JIRA-16 | Raises on an unexpected response shape | Mock POST response `{"unexpected": "shape"}` (no `key`) | `JiraError` raised | Raised | PASS |
| TC-JIRA-17 | `create_issue` posts to the correct issue endpoint | Call `create_issue(SAMPLE_FINDING)`; inspect the POST URL | Equals `"https://acme.atlassian.net/rest/api/3/issue"` | Matches | PASS |
| TC-JIRA-18 | Batch creates issues for all findings | Mock empty lookup + successful POST; call `create_issues_for_findings([SAMPLE_FINDING])` | 1 result; `status=="created"`, `issue_key=="PROJ-1"` | Matches | PASS |
| TC-JIRA-19 | Batch continues past a single finding's failure | Mock POST to always return `{"unexpected": "shape"}`; call `create_issues_for_findings([SAMPLE_FINDING, {"id": "FIND-2", "title": "t", "asset": {}}])` | 2 results; both `status=="error"`; `results[0]["error"]` is not `None` (one malformed/failing finding must not abort the whole batch) | Matches | PASS |

---

## Suite 26: Splunk connector (`remediation/connectors/splunk_connector.py`)

**Purpose:** prove the HTTP Event Collector (HEC) event-envelope construction, token
header auth, and batch handling are correct against mocked HTTP shaped like Splunk's
documented HEC contract — see
[remediation/connectors/README.md](remediation/connectors/README.md) for what this does
and doesn't prove (never exercised against a real Splunk instance). Unlike Jira and
ServiceNow, this connector authenticates with a `Splunk <token>` header rather than
HTTP Basic auth, and — a deliberate design difference, not an oversight — has no
idempotency/dedup check before sending: HEC events are an append-only log stream, not a
ticket system, so re-sending the same finding on a pipeline re-run is normal and
expected (Splunk correlates/dedups downstream in search, not at ingest time).
TC-SPLUNK-18 exists specifically to document and prove that behavior — two sends of the
identical finding both succeed and both hit the wire, rather than the second being
silently skipped the way Jira/ServiceNow's `skip_if_exists` would.
**Preconditions (all TC-SPLUNK):** `remediation/connectors/splunk_connector.py`
importable; `requests.Session` is replaced with a `MagicMock` in every test (with a real
`dict` substituted for `.headers`, since the connector sets the `Authorization` header
directly on it rather than via `session.auth`) — no real Splunk instance touched, no HEC
token required. `BuildHecEventPureFunction`'s 8 cases call `build_hec_event` directly
with no connector or session at all, the same preview-mode code path as Jira's and
ServiceNow's pure body-builder tests.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-SPLUNK-01 | Event wraps the full finding, not a hand-picked subset | `build_hec_event(SAMPLE_FINDING)` | `event["event"] == SAMPLE_FINDING` | Matches | PASS |
| TC-SPLUNK-02 | Default sourcetype | `build_hec_event(SAMPLE_FINDING)` with no override | `event["sourcetype"] == "vulnhunter:finding"` | Matches | PASS |
| TC-SPLUNK-03 | Custom sourcetype can be passed through | `build_hec_event(SAMPLE_FINDING, sourcetype="custom:type")` | `event["sourcetype"] == "custom:type"` | Matches | PASS |
| TC-SPLUNK-04 | Index key is omitted when none is given | `build_hec_event(SAMPLE_FINDING)` with no `index` | `"index"` not in `event` | Matches | PASS |
| TC-SPLUNK-05 | Index key is included when given | `build_hec_event(SAMPLE_FINDING, index="vulnhunter_findings")` | `event["index"] == "vulnhunter_findings"` | Matches | PASS |
| TC-SPLUNK-06 | Event time is derived from `last_seen` | `build_hec_event(SAMPLE_FINDING)` where `last_seen=="2026-08-02"` | `event["time"]` equals `datetime(2026,8,2,tzinfo=UTC).timestamp()` | Matches | PASS |
| TC-SPLUNK-07 | Time defaults to now when `last_seen` is missing | Build from a finding with the `last_seen` key removed entirely, bracketed by `time.time()` before/after | `event["time"]` falls between the before/after bounds | Matches | PASS |
| TC-SPLUNK-08 | Time defaults to now when `last_seen` is unparseable | Build with `last_seen="not-a-date"`, bracketed by `time.time()` before/after | `event["time"]` falls between the before/after bounds (falls back to now rather than raising) | Matches | PASS |
| TC-SPLUNK-09 | Session gets the HEC token auth header | Construct `SplunkConnector(hec_url, "hec-tok-1", session=mock)` | `session.headers["Authorization"] == "Splunk hec-tok-1"` | Matches | PASS |
| TC-SPLUNK-10 | HEC URL stored as given | Construct with `hec_url="https://splunk:8088/services/collector/event"` | `conn.hec_url` equals that exact URL, unmodified | Matches | PASS |
| TC-SPLUNK-11 | `send_event` posts to the HEC URL | Mock POST→`{"text": "Success", "code": 0}`; call `conn.send_event(SAMPLE_FINDING)` | POST called with that exact HEC URL | Matches | PASS |
| TC-SPLUNK-12 | `send_event`'s body matches `build_hec_event`'s output | Call `conn.send_event(SAMPLE_FINDING, sourcetype="vulnhunter:finding", index="idx1")` | Posted JSON body equals `build_hec_event(SAMPLE_FINDING, sourcetype="vulnhunter:finding", index="idx1")` | Matches | PASS |
| TC-SPLUNK-13 | `send_event` returns the parsed HEC response | Mock POST→`{"text": "Success", "code": 0}` | `send_event(...)` returns that dict unchanged | Matches | PASS |
| TC-SPLUNK-14 | `send_event` raises on an HTTP error | Mock response's `raise_for_status` to raise `Exception("500 Server Error")` | Exception propagates out of `send_event` | Raised | PASS |
| TC-SPLUNK-15 | `send_event` raises on an unexpected response shape | Mock POST→`{"unexpected": "shape"}` (no `text` key) | `SplunkHECError` raised | Raised | PASS |
| TC-SPLUNK-16 | Batch sends events for all findings | Mock POST→success; call `send_events_for_findings([SAMPLE_FINDING])` | 1 result; `status=="sent"`, `error is None` | Matches | PASS |
| TC-SPLUNK-17 | Batch continues past a single finding's failure | Mock POST to always return `{"unexpected": "shape"}`; call `send_events_for_findings([SAMPLE_FINDING, {"id": "FIND-2"}])` | 2 results; both `status=="error"`; `results[0]["error"]` is not `None` (one bad record must not abort the whole batch) | Matches | PASS |
| TC-SPLUNK-18 | Batch has no dedup — resending the same finding twice, both succeed | Mock POST→success; call `send_events_for_findings([SAMPLE_FINDING, SAMPLE_FINDING])` (the identical finding object, twice) | 2 results, both `status=="sent"`; `session.post.call_count == 2` — unlike ServiceNow/Jira, there is no skip-if-exists here, and this is deliberate: HEC events are a stream, not a ticket to dedupe against | Matches | PASS |
| TC-SPLUNK-19 | Batch passes custom sourcetype and index through | Call `send_events_for_findings([SAMPLE_FINDING], sourcetype="custom:type", index="idx2")` | Posted body's `sourcetype=="custom:type"`, `index=="idx2"` | Matches | PASS |

---

## Suite 27: CrowdStrike Falcon connector (`remediation/connectors/crowdstrike_connector.py`)

**Purpose:** prove the connector's OAuth2 client-credentials auth flow, its
alert-ID-query-then-fetch-entities flow (CrowdStrike's documented two-step "query IDs,
then batch-resolve composite IDs into full alert objects" pattern — conceptually the same
shape as Armis's token-auth + paginated AQL search, just batch-fetch instead of cursor
pagination), and its mapping of a raw Falcon alert into VulnHunter's normalized Finding
schema are all correct against mocked HTTP shaped like CrowdStrike's documented Falcon
Alerts API — this connector has never been exercised against a real CrowdStrike tenant,
the same caveat that applies to every other connector in this repo (see
[remediation/connectors/README.md](remediation/connectors/README.md)). CrowdStrike Falcon
alerts are EDR/XDR behavioral detections ("suspicious PowerShell encoded command",
"process injection", etc.), not CVE-scoped vulnerability-scanner findings the way
Tenable/Armis records are — so `cve`, `cvss`, `kev`, and `epss` are always `None` on a
normalized CrowdStrike finding (TC-CS-11 proves this explicitly); that's a deliberate,
expected property of this source, not a gap in the mapping. Like Tenable and Armis, and
unlike the push-style Jira/Splunk/ServiceNow connectors, CrowdStrike is a **pull**
connector — there's nothing to "send," only alerts to fetch and normalize — so the
dashboard has no CrowdStrike send form, only a read-only reference page at `/xdr`.
**Preconditions (all TC-CS):** `remediation/connectors/crowdstrike_connector.py`
importable; every HTTP call goes through a mocked `requests.Session` (`MagicMock()`)
injected into `CrowdStrikeConnector`'s constructor — no real network calls, no real
CrowdStrike credentials, no real Falcon tenant touched.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CS-01 | Authenticate POSTs `client_id`/`client_secret` as form data | Construct connector with a mocked session; call `authenticate()` with a mocked POST returning `{"access_token": "tok-abc", "expires_in": 1799}` | POST called at `https://api.crowdstrike.com/oauth2/token` with `data == {"client_id": "client-id-1", "client_secret": "client-secret-1"}` | Matches | PASS |
| TC-CS-02 | Authenticate raises on an unexpected response shape | Mock POST returns `{"unexpected": "shape"}` (no `access_token` key); call `authenticate()` | `CrowdStrikeAuthError` raised | Raised | PASS |
| TC-CS-03 | Authenticate sets the bearer token and session header | Mock POST returns `{"access_token": "tok-abc", ...}`; call `authenticate()` | `session.headers["Authorization"] == "Bearer tok-abc"`; `conn._access_token == "tok-abc"` | Matches | PASS |
| TC-CS-04 | `_ensure_authenticated` only authenticates once | Call `fetch_alert_ids()` twice in a row | `session.post.call_count == 1` (the one auth call is not repeated on the second fetch) | Matches | PASS |
| TC-CS-05 | `_ensure_authenticated` triggers auth lazily on first use | Check `conn._access_token is None` before any call; call `fetch_alert_ids()` | `conn._access_token == "tok-abc"` afterward (auth happens on demand, not at construction) | Matches | PASS |
| TC-CS-06 | `filter` query param omitted when no filter given | Call `fetch_alert_ids()` with no `filter_query` | `"filter"` key absent from the GET `params` (negative test) | Absent | PASS |
| TC-CS-07 | `filter` query param passed through when given | Call `fetch_alert_ids(filter_query="status:'new'")` | GET `params["filter"] == "status:'new'"` | Matches | PASS |
| TC-CS-08 | `limit` query param is passed through | Call `fetch_alert_ids(limit=50)` | GET `params["limit"] == 50` | Matches | PASS |
| TC-CS-09 | Returns the raw `resources` array of alert IDs | Mock GET returns `{"resources": ["id1", "id2"]}` | `fetch_alert_ids()` returns `["id1", "id2"]` unchanged | Matches | PASS |
| TC-CS-10 | Alert-details fetch POSTs composite IDs and returns the resources array | Call `fetch_alert_details(["abcd1234:ind:5678"])`; mock POST returns `{"resources": [SAMPLE_ALERT]}` | POST to `https://api.crowdstrike.com/alerts/entities/alerts/v2` with body `{"composite_ids": ["abcd1234:ind:5678"]}`; returns `[SAMPLE_ALERT]` | Matches | PASS |
| TC-CS-11 | `cve`/`cvss`/`kev`/`epss` are always `None` on a normalized finding | `normalize_alert(SAMPLE_ALERT)` | All four fields are `None` (Falcon EDR/XDR behavioral detections have no CVE the way a scanner finding does — this is deliberate, not a mapping gap) | All `None` | PASS |
| TC-CS-12 | Missing behavior timestamps default both dates to today | Normalize an alert with `first_behavior`/`last_behavior` both removed | `first_seen` and `last_seen` both equal `datetime.date.today().isoformat()` | Matches | PASS |
| TC-CS-13 | Basic identity and asset fields map correctly | `normalize_alert(SAMPLE_ALERT)` | `source == "crowdstrike"`, `source_ref == "abcd1234:ind:5678"`, `title == "Suspicious PowerShell encoded command"`, `asset.name == "WIN-DC01"`, `asset.ip == "10.20.30.41"` | Matches | PASS |
| TC-CS-14 | Non-Windows platform maps to `unix-server` | Normalize an alert with `device.platform_name == "Linux"` | `asset.type == "unix-server"` (the connector's platform mapping is a simple two-bucket Windows/not-Windows fallback, not a full OS taxonomy) | Matches | PASS |
| TC-CS-15 | Severity defaults to Low when there's no severity info at all | Normalize an alert with both `severity` and `severity_name` keys removed | `severity == "Low"` | Matches | PASS |
| TC-CS-16 | A recognized `severity_name` tier wins over the numeric score | Normalize an alert with `severity_name="High"` but `severity=10` (a Low-range number) | `severity == "High"` — the named-tier path short-circuits and the numeric threshold path is never consulted | Matches | PASS |
| TC-CS-17 | Numeric severity ≥ 90 maps to Critical | Normalize an alert with `severity_name=None`, `severity=95` | `severity == "Critical"` | Matches | PASS |
| TC-CS-18 | Numeric severity ≥ 70 (and < 90) maps to High | Normalize an alert with `severity_name=None`, `severity=75` | `severity == "High"` | Matches | PASS |
| TC-CS-19 | Numeric severity < 40 maps to Low | Normalize an alert with `severity_name=None`, `severity=10` | `severity == "Low"` | Matches | PASS |
| TC-CS-20 | Numeric severity ≥ 40 (and < 70) maps to Medium | Normalize an alert with `severity_name=None`, `severity=50` | `severity == "Medium"` | Matches | PASS |
| TC-CS-21 | `first_behavior`/`last_behavior` are used as `first_seen`/`last_seen` when present | `normalize_alert(SAMPLE_ALERT)` | `first_seen == "2026-07-28T10:00:00Z"`, `last_seen == "2026-08-02T14:30:00Z"` | Matches | PASS |
| TC-CS-22 | Windows platform maps to `windows-endpoint` | `normalize_alert(SAMPLE_ALERT)` (`device.platform_name == "Windows"`) | `asset.type == "windows-endpoint"` | Matches | PASS |
| TC-CS-23 | Full orchestration chains ID-fetch, detail-fetch, and normalize | Mock the auth POST, then a details POST returning `[SAMPLE_ALERT]`, and a GET returning one alert ID; call `fetch_and_normalize_alerts()` | Returns 1 finding; `source_ref == "abcd1234:ind:5678"`, `source == "crowdstrike"` | Matches | PASS |
| TC-CS-24 | No alert IDs short-circuits to an empty list | Mock GET (alert-ID query) returns `{"resources": []}` | `fetch_and_normalize_alerts()` returns `[]` (detail-fetch and normalize are never invoked) | Matches | PASS |

---

## Suite 28: CMDB CSV import (`remediation/inventory/cmdb_import.py`)

**Purpose:** prove the CSV-upload reconciliation workflow on the Asset Inventory page
works correctly end to end: parsing an uploaded CSV via the stdlib `csv` module (not a
fabricated `.xlsx` binary parser - see the module docstring for why CSV is the honest
choice here, same reasoning as `dashboard/static/js/export.js`'s download side),
guessing which column is the asset name/owner/team via a keyword heuristic (same
non-authoritative-suggestion pattern as `attack_mapping.py`/`compensating_controls.py`),
classifying each row against the real, finding-derived asset list (matched / not-yet-seen
/ invalid), and bulk-writing owner/team into `asset_ownership.json` via the exact same
`asset_inventory.set_owner` upsert the single-asset "Edit owner" form already uses.
**Preconditions (all TC-CMDB):** `remediation/inventory/cmdb_import.py` importable;
`ApplyImport`'s tests use a temporary ownership file (never the real, shipped
`asset_ownership.json`).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-CMDB-01 | CSV text parses into headers and rows | `parse_csv_text("Hostname,Application Owner,Team\nWEB-PORTAL01,Web Ops,Platform\n")` | `headers == ["Hostname", "Application Owner", "Team"]`; one row dict keyed by those headers | Matches | PASS |
| TC-CMDB-02 | Quoted fields with embedded commas parse correctly | Parse a row with `"Domain controller, primary site"` as a quoted CSV field | The field value is the full string including the comma, not split into two fields | Matches | PASS |
| TC-CMDB-03 | Empty CSV text returns no rows | `parse_csv_text("")` | `rows == []` (no crash on empty input) | Matches | PASS |
| TC-CMDB-04 | Common header names are matched | `suggest_column_mapping(["Hostname", "Application Owner", "Team"])` | `{"asset_name": "Hostname", "owner": "Application Owner", "team": "Team"}` | Matches | PASS |
| TC-CMDB-05 | Alternate header names are also matched | `suggest_column_mapping(["Asset", "Contact", "Department"])` | `{"asset_name": "Asset", "owner": "Contact", "team": "Department"}` | Matches | PASS |
| TC-CMDB-06 | No keyword match returns `None`, not a guess | `suggest_column_mapping(["Column A", "Column B"])` | All three mapping values are `None` (negative test - never invents a mapping) | Matches | PASS |
| TC-CMDB-07 | A known asset matches case-insensitively and normalizes casing | Reconcile a row with `Hostname="web-portal01"` against known asset `"WEB-PORTAL01"` | Row lands in `matched`; its `asset_name` is normalized to the real `"WEB-PORTAL01"` casing | Matches | PASS |
| TC-CMDB-08 | An asset with no current findings is unmatched, not dropped | Reconcile a row for `"NEW-SERVER-01"` (not in the known-asset list) | Row lands in `unmatched` (not silently discarded) | Matches | PASS |
| TC-CMDB-09 | A row with no asset name is invalid | Reconcile a row with an empty `Hostname` value | Row lands in `invalid`; `matched`/`unmatched` both stay empty for this row | Matches | PASS |
| TC-CMDB-10 | A mixed batch classifies each row independently | Reconcile 3 rows: one known asset, one unknown, one with a blank name | Exactly 1 `matched`, 1 `unmatched`, 1 `invalid` | Matches | PASS |
| TC-CMDB-11 | No asset-name column mapped makes every row invalid | Reconcile with `column_mapping.asset_name = None` | Every row lands in `invalid` (there's no column to read a name from) | Matches | PASS |
| TC-CMDB-12 | Apply writes owner and team for each entry | `apply_import([{asset_name: "WEB-PORTAL01", owner: "Web Ops", team: "Platform"}, {asset_name: "WIN-DC01", owner: "Priya Nair", team: "Identity"}])` against a temp ownership file | `applied == 2`; the temp file's entries match exactly | Matches | PASS |
| TC-CMDB-13 | Entries with no asset name are skipped, not written | `apply_import([{asset_name: "", owner: "X", team: "Y"}])` | `applied == 0`, `skipped == 1`; the temp ownership file stays empty | Matches | PASS |
| TC-CMDB-14 | Applying for an unmatched (not-yet-seen) asset still stores ownership | `apply_import([{asset_name: "FUTURE-SERVER-01", owner: "Someone", team: "SomeTeam"}])` | The temp file gets a real entry for `"FUTURE-SERVER-01"` even though no finding against it exists yet - it applies the moment one does | Matches | PASS |

---

## Suite 29: Infoblox NIOS connector (`remediation/connectors/infoblox_connector.py`)

**Purpose:** prove the connector's HTTP Basic-auth session construction, its WAPI
`record:host` fetch (endpoint URL, `_return_fields`/`_max_results` query params), and its
mapping of a raw WAPI host-record object into VulnHunter's shared asset-inventory shape
(`name`, `ip`, `mac`, `type`, `source`, `source_ref`, `extra`) are all correct against
mocked HTTP shaped like Infoblox's publicly documented WAPI Guide — this connector has
never been exercised against a real Infoblox NIOS grid, the same caveat that applies to
every other connector in this repo (see
[remediation/connectors/README.md](remediation/connectors/README.md)). Unlike every
finding-producing connector above (Tenable through CrowdStrike), Infoblox is a DNS/IPAM
system, not a vulnerability scanner — it produces plain asset-inventory records, not
normalized Findings, and `mac`/`type` are always `None`/`"unknown"` because a
`record:host` object simply doesn't carry that data (TC-IBLOX-10 proves this
explicitly), a deliberate, honest property of this source, not a mapping gap. Like
Tenable/Armis/CrowdStrike, this is a **pull** connector — the dashboard has no send form,
only a read-only reference page at `/infoblox`.
**Preconditions (all TC-IBLOX):** `remediation/connectors/infoblox_connector.py`
importable; every HTTP call goes through a mocked `requests.Session` (`MagicMock()`)
injected into `InfobloxConnector`'s constructor — no real network calls, no real
Infoblox credentials, no real grid touched.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-IBLOX-01 | Session gets Basic auth credentials | Construct `InfobloxConnector("gm.example.com", "admin", "pw", session=mock)` | `session.auth == ("admin", "pw")` | Matches | PASS |
| TC-IBLOX-02 | Base URL uses the default WAPI version | Construct connector with no `api_version` argument | `base_url == "https://gm.example.com/wapi/v2.12"` (`DEFAULT_API_VERSION`) | Matches | PASS |
| TC-IBLOX-03 | Base URL honors a custom WAPI version | Construct connector with `api_version="v2.5"` | `base_url == "https://gm.example.com/wapi/v2.5"` | Matches | PASS |
| TC-IBLOX-04 | Session gets an `Accept: application/json` header | Construct the connector | `session.headers.update` called with `{"Accept": "application/json"}` | Matches | PASS |
| TC-IBLOX-05 | Fetch hits the correct `record:host` URL | Call `fetch_host_records()` | GET called at `{base_url}/record:host` | Matches | PASS |
| TC-IBLOX-06 | Fetch sends `_return_fields` and `_max_results` params | Call `fetch_host_records(max_results=250)` | `params["_return_fields"] == RETURN_FIELDS`, `params["_max_results"] == 250` | Matches | PASS |
| TC-IBLOX-07 | `_max_results` defaults to 1000 | Call `fetch_host_records()` with no argument | `params["_max_results"] == 1000` | Matches | PASS |
| TC-IBLOX-08 | Returns the raw JSON array unchanged | Mock GET returns `[{"name": "host1"}, {"name": "host2"}]` | `fetch_host_records()` returns that exact list | Matches | PASS |
| TC-IBLOX-09 | Fetch raises on an HTTP error | Mock GET's `raise_for_status()` to raise | `fetch_host_records()` raises | Raised | PASS |
| TC-IBLOX-10 | Normalize maps the documented shape, including the honest unknown fields | Normalize a host record with `_ref`, `name`, `ipv4addrs`, `view`, `extattrs` set | `ip` == first `ipv4addr`; `mac is None`; `type == "unknown"`; `source == "infoblox"`; `source_ref == record["_ref"]`; `extra["view"]`/`extra["extattrs"]` preserved | Matches | PASS |
| TC-IBLOX-11 | Multiple IPs on one host record take the first | Normalize a record with two `ipv4addrs` entries | `ip` equals the first entry's `ipv4addr`, not the second | Matches | PASS |
| TC-IBLOX-12 | No IPs (empty list or missing key) yields `ip=None`, not a crash | Normalize `{"ipv4addrs": []}` and a record missing `ipv4addrs` entirely | Both yield `ip is None`; `extra["extattrs"] == {}` | Matches | PASS |
| TC-IBLOX-13 | A missing `name` field yields `name=None`, not a crash | Normalize a record with no `name` key | `name is None`; `ip` still correctly extracted | Matches | PASS |
| TC-IBLOX-14 | Orchestration returns a fully normalized list | Mock GET returns two host records (one with an IP, one without); call `fetch_and_normalize_hosts()` | 2 assets returned; first has the expected `name`/`ip`; second has `ip is None`; both `source == "infoblox"` | Matches | PASS |
| TC-IBLOX-15 | Orchestration passes `max_results` through to the fetch | Call `fetch_and_normalize_hosts(max_results=42)` | `params["_max_results"] == 42` on the underlying GET | Matches | PASS |
| TC-IBLOX-16 | Orchestration handles an empty response | Mock GET returns `[]` | `fetch_and_normalize_hosts()` returns `[]` | Matches | PASS |

---

## Suite 30: Axonius connector (`remediation/connectors/axonius_connector.py`)

**Purpose:** prove the connector's `api-key`/`api-secret` header-based auth
construction, its `/api/devices` fetch (endpoint URL, offset/limit pagination body), and
its mapping of a raw (assumed-flattened) Axonius device record into VulnHunter's shared
asset-inventory shape are all correct against mocked HTTP shaped like Axonius's publicly
documented REST API — this connector has never been exercised against a real Axonius
tenant, the same caveat that applies to every other connector in this repo (see
[remediation/connectors/README.md](remediation/connectors/README.md)). Like Infoblox,
Axonius produces plain asset-inventory records, not vulnerability Findings — its
distinctive concept is aggregating asset data across many source adapters (CMDB, EDR,
cloud, network) into one inventory, so each normalized record keeps the reporting
`adapters` list in `extra` (TC-AXON-06 proves this). Two documented scope limits also
get explicit coverage: the exact response envelope key (`"assets"`) is the connector's
best guess against varying public documentation, and it fetches a single page only, not
a full offset/limit pagination loop. Like Infoblox, this is a **pull** connector with a
read-only reference page at `/axonius`, not a dashboard send form.
**Preconditions (all TC-AXON):** `remediation/connectors/axonius_connector.py`
importable; every HTTP call goes through a mocked `requests.Session` (`MagicMock()`)
injected into `AxoniusConnector`'s constructor — no real network calls, no real Axonius
credentials, no real tenant touched.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-AXON-01 | Session gets `api-key`/`api-secret` headers | Construct `AxoniusConnector(url, "key123", "secret456", session=mock)` | `session.headers.update` called with `header["api-key"] == "key123"`, `header["api-secret"] == "secret456"` | Matches | PASS |
| TC-AXON-02 | Base URL strips a trailing slash | Construct connector with `"https://axonius.example.com/"` | `base_url == "https://axonius.example.com"` | Matches | PASS |
| TC-AXON-03 | Session gets a `Content-Type: application/json` header | Construct the connector | `header["Content-Type"] == "application/json"` | Matches | PASS |
| TC-AXON-04 | Fetch hits the correct `/api/devices` URL | Call `fetch_devices()` | POST called at `{base_url}/api/devices` | Matches | PASS |
| TC-AXON-05 | Fetch sends the offset/limit pagination body | Call `fetch_devices(page_size=50, offset=100)` | POST `json` body `== {"page": {"offset": 100, "limit": 50}}` | Matches | PASS |
| TC-AXON-06 | Offset defaults to 0 | Call `fetch_devices(page_size=DEFAULT_PAGE_SIZE)` | `body["page"]["offset"] == 0`, `body["page"]["limit"] == DEFAULT_PAGE_SIZE` | Matches | PASS |
| TC-AXON-07 | Returns the raw JSON response unchanged | Mock POST returns `{"assets": [{"hostname": "h1"}]}` | `fetch_devices()` returns that exact dict | Matches | PASS |
| TC-AXON-08 | Fetch raises on an HTTP error | Mock POST's `raise_for_status()` to raise | `fetch_devices()` raises | Raised | PASS |
| TC-AXON-09 | Normalize maps the documented flattened shape | Normalize a device with `internal_axon_id`, `hostname`, `ip`, `mac`, `os_type="Windows"`, `adapters` set | `name`, `ip`, `mac` map directly; `type == "windows-server"`; `source == "axonius"`; `source_ref == "abc123"`; `extra["adapters"]` preserved | Matches | PASS |
| TC-AXON-10 | Falls back to `ips`/`macs` list variants when scalars are absent | Normalize a device with only `ips`/`macs` list keys | `ip`/`mac` equal the first entry of each list | Matches | PASS |
| TC-AXON-11 | `os_type="Linux"` maps to `unix-server` | Normalize a device with `os_type="Linux"` | `type == "unix-server"` | Matches | PASS |
| TC-AXON-12 | Missing or unrecognized `os_type` defaults to `unknown` | Normalize a device with an unrecognized `os_type` and one with no `os_type` at all | Both yield `type == "unknown"` (negative test — never guesses a specific platform) | Matches | PASS |
| TC-AXON-13 | No IPs or MACs (empty lists) yields `None` for both, not a crash | Normalize a device with `ips=[]`, `macs=[]` | `ip is None`, `mac is None` | Matches | PASS |
| TC-AXON-14 | A missing `adapters` key defaults to an empty list | Normalize a device with no `adapters` key | `extra["adapters"] == []` | Matches | PASS |
| TC-AXON-15 | Orchestration returns a fully normalized list | Mock POST returns two devices (one Linux, one with no OS info); call `fetch_and_normalize_devices()` | 2 assets returned; first `type == "unix-server"`, second `type == "unknown"`; both `source == "axonius"` | Matches | PASS |
| TC-AXON-16 | Orchestration handles an empty `assets` array | Mock POST returns `{"assets": []}` | `fetch_and_normalize_devices()` returns `[]` | Matches | PASS |
| TC-AXON-17 | Orchestration handles a response missing the `assets` key entirely | Mock POST returns `{}` | `fetch_and_normalize_devices()` returns `[]`, not a crash (documented envelope-key uncertainty handled defensively) | Matches | PASS |

---

## Suite 31: Pattern-matched asset owner/team/type suggestions (`remediation/inventory/pattern_recognition.py`)

**Purpose:** prove the transparent, weighted pattern-matching heuristic behind the
Asset Inventory's "suggested owner" feature is correct - and, just as importantly,
that it stays honestly scoped as a heuristic rather than drifting into an implicit
claim of machine learning. The module answers the ask for the tool to "learn from the
data and predict patterns for assets, hosts, IPs, MAC address, owners, or teams," but
deliberately implements it as three inspectable, explainable signals (hostname
naming-convention prefix, IP `/24` subnet locality, and asset-type match, plus MAC
vendor OUI matching for the type-suggestion case) combined via a small integer-weighted
vote - never a trained model. Real ML on this repo's ~13-asset demo dataset would be
overfitting theater, not a real capability - see the module's own docstring. Every
suggestion returns its confidence and the exact reasons it fired, so a human can verify
or reject it; nothing is ever auto-applied (`annotate_unowned_assets()` is a pure
read-side helper, and the dashboard's `/api/assets` route - see TC-DASH-101–103 - only
ever attaches a `suggestion` key, never writes one). **Preconditions (all TC-PATTERN):**
`remediation/inventory/pattern_recognition.py` importable; no file I/O, no network, no
mutation of any kind - every test is a pure function call against in-memory dicts.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-PATTERN-01 | Hostname prefix strips a trailing number with a separator | `hostname_prefix("WIN-APP07")` | `"WIN-APP"` | Matches | PASS |
| TC-PATTERN-02 | Hostname prefix strips a trailing number with no separator | `hostname_prefix("LNXDB03")` | `"LNXDB"` | Matches | PASS |
| TC-PATTERN-03 | No trailing number leaves the name unchanged but uppercased | `hostname_prefix("web-portal")` | `"WEB-PORTAL"` | Matches | PASS |
| TC-PATTERN-04 | Empty or `None` name returns an empty string, not a crash | `hostname_prefix("")`, `hostname_prefix(None)` | Both return `""` | Matches | PASS |
| TC-PATTERN-05 | A valid IPv4 address returns its first three octets | `ip_subnet("10.20.30.41")` | `"10.20.30"` | Matches | PASS |
| TC-PATTERN-06 | Two addresses differing only in the last octet share a subnet | `ip_subnet("10.20.30.99") == ip_subnet("10.20.30.1")` | `True` | Matches | PASS |
| TC-PATTERN-07 | `None` or a malformed address returns `None`, not a crash | `ip_subnet(None)`, `ip_subnet("not-an-ip")`, `ip_subnet("10.20.30")`, `ip_subnet("10.20.30.999")` | All four return `None` | Matches | PASS |
| TC-PATTERN-08 | A valid MAC address returns its uppercase vendor OUI | `mac_oui("aa:bb:cc:dd:ee:ff")` | `"AA:BB:CC"` | Matches | PASS |
| TC-PATTERN-09 | A hyphen-separated MAC address is also recognized | `mac_oui("AA-BB-CC-11-22-33")` | `"AA:BB:CC"` | Matches | PASS |
| TC-PATTERN-10 | `None` or a malformed MAC returns `None`, not a crash | `mac_oui(None)`, `mac_oui("not-a-mac")`, `mac_oui("aa:bb:cc")` | All three return `None` | Matches | PASS |
| TC-PATTERN-11 | A hostname-prefix match suggests the shared owner | `suggest_owner_team({"name": "WIN-APP09", ...}, [{"name": "WIN-APP07", "owner": "Web Ops", ...}])` | `owner == "Web Ops"`; a reason mentions `"Hostname pattern"` | Matches | PASS |
| TC-PATTERN-12 | A subnet match suggests the shared owner | Asset on `10.20.30.99` vs. a known asset on `10.20.30.41` (`Priya Nair`) | `owner == "Priya Nair"`; a reason mentions `"subnet"` | Matches | PASS |
| TC-PATTERN-13 | Asset-type alone (the weakest signal) still produces a match | Both assets `iot-ot-device`, no hostname/subnet overlap | `owner` equals the known asset's owner | Matches | PASS |
| TC-PATTERN-14 | Multiple agreeing signals raise confidence over a single weak one | Compare a type-only match vs. a hostname+subnet-agreeing match for the same target asset | The stronger match's `confidence` is strictly greater | Matches | PASS |
| TC-PATTERN-15 | No matching signal on any known asset returns `None` | Asset with an unrelated name/subnet/type vs. one known asset | `suggest_owner_team(...)` returns `None` | Matches | PASS |
| TC-PATTERN-16 | An empty known-assets list returns `None` | `suggest_owner_team(asset, [])` | `None` | Matches | PASS |
| TC-PATTERN-17 | A known asset with no owner is never a suggestion source | Known asset shares hostname prefix but `owner` is `None` | `suggest_owner_team(...)` returns `None` (negative test) | Matches | PASS |
| TC-PATTERN-18 | Conflicting signals pick the higher-weighted owner | One known asset matches by hostname prefix (weight 3, different owner), another matches only by type (weight 1) | The hostname-prefix match's owner wins | Matches | PASS |
| TC-PATTERN-19 | A hostname-prefix match suggests the shared type | `suggest_type({"name": "LNX-DB09", "type": "unknown"}, [{"name": "LNX-DB03", "type": "unix-server"}])` | `type == "unix-server"` | Matches | PASS |
| TC-PATTERN-20 | A subnet match suggests the shared type | Unknown-type asset on the same `/24` as a typed known asset | `type` equals the known asset's type | Matches | PASS |
| TC-PATTERN-21 | A MAC vendor OUI match suggests the shared type | Both assets share a MAC OUI, one is a known `iot-ot-device` | `type == "iot-ot-device"`; a reason mentions `"MAC vendor"` | Matches | PASS |
| TC-PATTERN-22 | A known asset with `type == "unknown"` is never a suggestion source | Known asset shares hostname prefix but its own type is `"unknown"` | `suggest_type(...)` returns `None` (negative test) | Matches | PASS |
| TC-PATTERN-23 | No matching signal on any known asset returns `None` | Asset with an unrelated name/subnet/MAC vs. one typed known asset | `suggest_type(...)` returns `None` | Matches | PASS |
| TC-PATTERN-24 | Only unowned rows are returned | `annotate_unowned_assets([owned_row, unowned_row])` | Result has exactly 1 row, matching the unowned one | Matches | PASS |
| TC-PATTERN-25 | Each unowned row gets a `suggestion` key | Same input as above, one owned row shares its type with the unowned one | `result[0]["suggestion"]["owner"]` equals the owned row's owner | Matches | PASS |
| TC-PATTERN-26 | No match still yields an explicit `None`, not a missing key | An unowned row with nothing in common with the owned row | `result[0]["suggestion"] is None` | Matches | PASS |
| TC-PATTERN-27 | Input rows are never mutated | Call `annotate_unowned_assets(rows)`, then inspect `rows[0]` | The original row dict has no `suggestion` key added to it | Matches | PASS |
| TC-PATTERN-28 | All-owned input returns an empty list | `annotate_unowned_assets([owned_row])` | `[]` | Matches | PASS |

---

## Suite 32: AI vulnerability taxonomy / illustrative MITRE ATLAS cross-reference (`remediation/enrichment/ai_vuln_taxonomy.py`)

**Purpose:** prove the ten-category AI/ML vulnerability taxonomy is internally
well-formed, its keyword heuristic correctly tags (or correctly declines to tag)
realistic finding text, and its heat-map builder aggregates real tagged findings
against the full known taxonomy - the exact same verification shape as
`test_attack_mapping.py` uses for MITRE ATT&CK tagging, since this module
deliberately mirrors that one's design and honesty posture (see the module
docstring: the `atlas_tactic`/`atlas_technique_id` fields are an illustrative
cross-reference built from this module's own reading of published ATLAS
documentation, not a verified mapping - confirm any specific ID against
atlas.mitre.org before citing it formally). **Preconditions (all TC-AIVULN):**
`remediation/enrichment/ai_vuln_taxonomy.py` importable; no file I/O beyond reading
this repo's own real `normalized-findings.json` for the honest-scope check below (no
mutation).

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-AIVULN-01 | Every taxonomy entry has all required fields | Iterate `AI_VULNERABILITIES` | Every entry has `id`, `name`, `summary`, `remediation`, `atlas_tactic`, `atlas_technique_id`, `atlas_technique_name` | Matches | PASS |
| TC-AIVULN-02 | Every entry's `id` is unique | Collect all `id`s from `AI_VULNERABILITIES` | `len(ids) == len(set(ids))` | Matches | PASS |
| TC-AIVULN-03 | `get_vulnerability` returns the matching entry | `get_vulnerability("prompt-injection")` | Returned entry's `name == "Prompt Injection"` | Matches | PASS |
| TC-AIVULN-04 | `get_vulnerability` returns `None` for an unknown id | `get_vulnerability("not-a-real-id")` | `None` | Matches | PASS |
| TC-AIVULN-05 | "Prompt injection" keyword matches the Prompt Injection category | `map_finding_to_ai_vuln({"title": "Prompt injection via unsanitized user message"})` | `result["id"] == "prompt-injection"` | Matches | PASS |
| TC-AIVULN-06 | "Jailbreak" also matches Prompt Injection | `map_finding_to_ai_vuln({"title": "Chatbot jailbreak bypasses content policy"})` | `result["id"] == "prompt-injection"` | Matches | PASS |
| TC-AIVULN-07 | "System prompt leak" matches Sensitive Information Disclosure | `map_finding_to_ai_vuln({"title": "System prompt leak via crafted query"})` | `result["id"] == "sensitive-info-disclosure"` | Matches | PASS |
| TC-AIVULN-08 | "Training data poisoning" matches Training Data / Model Poisoning | `map_finding_to_ai_vuln({"title": "Training data poisoning in fine-tuning pipeline"})` | `result["id"] == "training-data-model-poisoning"` | Matches | PASS |
| TC-AIVULN-09 | "Backdoored model" also matches Training Data / Model Poisoning | `map_finding_to_ai_vuln({"title": "Backdoored model returns malicious output on trigger phrase"})` | `result["id"] == "training-data-model-poisoning"` | Matches | PASS |
| TC-AIVULN-10 | "Unsafe pickle deserialization" matches AI Supply Chain Compromise | `map_finding_to_ai_vuln({"title": "Model checkpoint loaded via unsafe pickle deserialization"})` | `result["id"] == "supply-chain"` | Matches | PASS |
| TC-AIVULN-11 | "Model denial of service" matches Unbounded Consumption | `map_finding_to_ai_vuln({"title": "Model denial of service via oversized context"})` | `result["id"] == "unbounded-consumption"` | Matches | PASS |
| TC-AIVULN-12 | "Model extraction" matches Model Theft / IP Extraction | `map_finding_to_ai_vuln({"title": "Model extraction attack via systematic API querying"})` | `result["id"] == "model-theft"` | Matches | PASS |
| TC-AIVULN-13 | No keyword match returns `None`, not a guess | `map_finding_to_ai_vuln({"title": "SQL Injection via string concatenation"})` | `None` (negative test) | Matches | PASS |
| TC-AIVULN-14 | Honest scope: this repo's own real demo findings never match this taxonomy | Run `map_finding_to_ai_vuln` against every finding in the real, committed `normalized-findings.json` | Every finding returns `None` - this repo's demo app has no AI/ML component, so this is expected, not a bug | Matches | PASS |
| TC-AIVULN-15 | `tag_findings` adds the field without mutating input | `tag_findings([{"id": "FIND-1", "title": "Prompt injection", ...}])` | Input dict's key set unchanged; tagged output has an `ai_vulnerability` key | Matches | PASS |
| TC-AIVULN-16 | `tag_findings` sets `None` for a non-matching finding | `tag_findings([{"title": "Unrelated finding"}])` | `tagged[0]["ai_vulnerability"] is None` | Matches | PASS |
| TC-AIVULN-17 | `tag_findings` sets the matched id for a matching finding | `tag_findings([{"title": "Model theft via extraction"}])` | `tagged[0]["ai_vulnerability"] == "model-theft"` | Matches | PASS |
| TC-AIVULN-18 | Heat map includes every known vulnerability, including zero-count ones | `build_ai_atlas_heatmap([])` | `len(heatmap) == len(AI_VULNERABILITIES)`; every row's `count == 0` | Matches | PASS |
| TC-AIVULN-19 | Heat map counts real tagged findings | Tag 2 prompt-injection findings + 1 model-theft finding, then build the heat map | `prompt-injection` row `count == 2`; `model-theft` row `count == 1` | Matches | PASS |
| TC-AIVULN-20 | Heat map ignores findings with no matched vulnerability | Tag `[{"title": "SQL Injection"}]`, build the heat map | Every row's `count == 0` | Matches | PASS |
| TC-AIVULN-21 | Heat map rows carry the ATLAS cross-reference | `build_ai_atlas_heatmap([])` | The `prompt-injection` row's `atlas_technique_id == "AML.T0051"`, `atlas_tactic == "Initial Access"` | Matches | PASS |

---

## Suite 33: Infrastructure sub-category classification (`remediation/enrichment/infra_classification.py`)

**Purpose:** prove the OS/Network/Network Security/OT-IoT/Cloud sub-classification
behind the Infrastructure Vulnerabilities hub (`/infrastructure`) correctly maps every
real `asset.type` value in the schema, correctly declines to classify non-infra
findings (application/certificate) rather than forcing them into a bucket, and its
count-rollup shows the full known taxonomy - including Cloud Infrastructure, which
has no sample finding in this repo's demo data (same honest "real category, 0
findings" treatment as DAST - see the module docstring). **Preconditions (all
TC-INFRA):** `remediation/enrichment/infra_classification.py` importable; every test
constructs its own in-memory finding dicts, no file I/O.

| TC ID | Test Case | Test Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| TC-INFRA-01 | `windows-server` classifies as `os` | `classify_infra_finding({"asset": {"type": "windows-server"}})` | `"os"` | Matches | PASS |
| TC-INFRA-02 | `windows-endpoint` also classifies as `os` | `classify_infra_finding({"asset": {"type": "windows-endpoint"}})` | `"os"` | Matches | PASS |
| TC-INFRA-03 | `unix-server` classifies as `os` | `classify_infra_finding({"asset": {"type": "unix-server"}})` | `"os"` | Matches | PASS |
| TC-INFRA-04 | `network-routing-switching` classifies as `network` | `classify_infra_finding({"asset": {"type": "network-routing-switching"}})` | `"network"` | Matches | PASS |
| TC-INFRA-05 | `network-security-device` classifies as `network-security` | `classify_infra_finding({"asset": {"type": "network-security-device"}})` | `"network-security"` | Matches | PASS |
| TC-INFRA-06 | `iot-ot-device` classifies as `ot` | `classify_infra_finding({"asset": {"type": "iot-ot-device"}})` | `"ot"` | Matches | PASS |
| TC-INFRA-07 | `cloud-infrastructure` classifies as `cloud` | `classify_infra_finding({"asset": {"type": "cloud-infrastructure"}})` | `"cloud"` | Matches | PASS |
| TC-INFRA-08 | `application` asset type is not an infra category | `classify_infra_finding({"asset": {"type": "application"}})` | `None` (negative test - never forced into a bucket) | Matches | PASS |
| TC-INFRA-09 | `certificate` asset type is not an infra category | `classify_infra_finding({"asset": {"type": "certificate"}})` | `None` | Matches | PASS |
| TC-INFRA-10 | A missing/absent asset type returns `None`, not a crash | `classify_infra_finding({"asset": {}})`, `classify_infra_finding({})` | Both return `None` | Matches | PASS |
| TC-INFRA-11 | `tag_infra_categories` adds fields without mutating input | `tag_infra_categories([{"asset": {"type": "windows-server"}}])` | Input dict's key set unchanged; tagged output has `infra_category`/`infra_category_label` keys | Matches | PASS |
| TC-INFRA-12 | Tag sets the correct label for a real category | `tag_infra_categories([{"asset": {"type": "iot-ot-device"}}])` | `tagged[0]["infra_category"] == "ot"`; `tagged[0]["infra_category_label"] == "OT / IoT"` | Matches | PASS |
| TC-INFRA-13 | Tag sets `None`/`None` for a non-infra finding | `tag_infra_categories([{"asset": {"type": "application"}}])` | Both `infra_category` and `infra_category_label` are `None` | Matches | PASS |
| TC-INFRA-14 | Counts include every known category, including zero-count ones | `build_infra_category_counts([])` | `len(rows) == len(INFRA_CATEGORIES)`; every row's `count == 0` | Matches | PASS |
| TC-INFRA-15 | Cloud Infrastructure shows zero by default, honestly | `build_infra_category_counts(tag_infra_categories([{"asset": {"type": "windows-server"}}]))` | The `cloud` row's `count == 0` and `label == "Cloud Infrastructure"` | Matches | PASS |
| TC-INFRA-16 | Counts real tagged findings per category, excluding non-infra ones | Tag a mix of 6 infra findings (3 `os`, 1 each `network`/`network-security`/`ot`) plus 1 `application` finding, build the counts | `os` count `3`; `network`/`network-security`/`ot` each `1`; total across all rows `== 6` (the application finding excluded entirely) | Matches | PASS |

---

## Notable findings from testing (not just "all green")

Real issues surfaced during the development of this suite, listed here because a
test suite that never catches anything is less convincing than one with a track record:

1. **TC-SCAN-06 and TC-FIX-06 initially false-failed** — the first version of these
   assertions matched *any* occurrence of `"USER "` / `"STRIPE_API_KEY"` as plain
   substrings, which also matched explanatory comments (e.g. a Dockerfile comment reading
   `# VULN: no USER instruction...`). Fixed by tightening both to regex-match an actual
   directive/assignment (`^USER\s+\w+`, `ENV STRIPE_API_KEY=`) rather than any mention of
   the word.
2. **A real GitHub secret-scanning block**, caught outside this suite but directly related
   to TC-SEC-01's intent: the first push to the repository was rejected by GitHub's push
   protection because the demo's fake Stripe key was realistic enough to match Stripe's
   key-format detector. Fixed by reformatting the fake key so it can never match a real
   provider's format, and rewriting the (not-yet-pushed) local git history to remove the
   flagged string from every commit — confirmed via a full-history grep showing zero
   matches before re-pushing. TC-SEC-01 now guards against a regression of this exact
   class of issue going forward.
3. All other original 33 test cases passed on first implementation, which is expected —
   they assert behavior the pipeline stages were explicitly designed to produce (e.g.
   "the fixer never touches `main`"), rather than probing for unknown defects.
4. **A real mojibake bug**, caught while manually verifying the dashboard's rendered
   pages (not by a pre-written test): em-dashes and other non-ASCII characters from
   `SECURITY_REPORT.md`/`REMEDIATION_PLAN.md` were rendering as `â€"` instead of `—`.
   Root cause: `subprocess.run(..., text=True)` without an explicit `encoding="utf-8"`
   decodes `git show`'s UTF-8 output using the platform's default codec, which is
   `cp1252` on Windows — silently corrupting any non-ASCII byte sequence. Fixed by
   adding `encoding="utf-8"` to every `subprocess.run` call that reads git or CLI output
   across `dashboard/data.py`, `cli/vulnhunter.py`, `tests/test_pipeline_artifacts.py`,
   and `tests/test_cli.py`. TC-DASH-06 now guards against a regression.
5. **An actual infinite loop**, caught by the test suite itself hanging instead of
   finishing: `TenableConnector.poll_export_status`'s original timeout logic tracked
   elapsed time with `elapsed += poll_interval_seconds` — when `poll_interval_seconds`
   is `0` (used in tests specifically to avoid real sleeps), `elapsed` never advances
   past `0`, so `elapsed <= timeout_seconds` (with `timeout_seconds` also `0` in the
   timeout test) stayed true forever. Fixed by switching to a wall-clock deadline
   (`time.monotonic() + timeout_seconds`, checked each iteration) instead of an
   accumulator that a zero step size can get stuck on. TC-CONN-07 now specifically
   exercises the `timeout_seconds=0` case to guard against a regression.
6. **A hand-counting error**, caught by cross-checking `REMEDIATION_PLAN.md`'s prose
   summary against the dashboard's programmatically-computed KPI: the plan's summary
   line originally claimed "7 are KEV-listed," but manually recounting the per-finding
   table missed that `FIND-5` (OpenSSL DoS) is not KEV-listed despite its high EPSS
   score — the real, live-verified count is 6. Fixed by recomputing the count in Python
   directly from `normalized-findings.json` rather than hand-counting a markdown table,
   and correcting the prose. A reminder that a number written by a human into a report
   is exactly the kind of claim worth verifying against the underlying data before
   trusting it, even when the human is the one who built the pipeline.
7. **A dedicated security-review pass** (not a pre-written test - a deliberate read of
   the whole session's new code against common vulnerability classes) found four real
   issues, all fixed: (a) a timing-based email-enumeration side-channel in
   `dashboard/auth/users.py`'s `verify_login()` — an unknown email skipped the
   deliberately-slow PBKDF2 comparison entirely via an `or` short-circuit, making
   response timing distinguish "no such user" from "wrong password" even though both
   returned the same `None`; (b) CSV/formula-injection (CWE-1236) in the dashboard's
   CSV export — a cell starting with `=`/`+`/`-`/`@` (e.g. a crafted asset owner name)
   would be interpreted as a formula by Excel/Sheets on open; (c) an unescaped
   `data-tooltip` attribute in the topbar account chip (`auth.js`) that rendered
   OIDC-sourced email/role fields without `escapeHtml()`, the one inconsistency in an
   otherwise-consistently-escaped codebase; (d) the same class of gap in the
   Remediation Queue's asset-type filter dropdown (`queue.js`). All four are fixed and
   covered either by new regression tests (`tests/test_auth.py`, for (a)) or, for the
   two frontend XSS gaps, by consistent use of the same `escapeHtml()` helper already
   used everywhere else those fields render. See `CHANGELOG.md`'s `[Unreleased] Fixed`
   section for full detail on each.
