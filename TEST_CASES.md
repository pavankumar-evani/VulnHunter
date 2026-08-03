# VulnHunter — Test Cases & Results

Formal test case log for all eleven test files: `tests/test_pipeline_artifacts.py` (both
pipelines' real output artifacts), `tests/test_cli.py` (the headless CLI),
`tests/test_dashboard.py` (the web dashboard's FastAPI JSON API and SPA shell routes,
including the live queue, priority-rules editor, ServiceNow preview, AI-assist endpoint,
and on-demand reports), `tests/test_ai_assist.py` (pure prompt-construction logic for the
dashboard's AI-assist feature), `tests/test_reports.py` (the dashboard's on-demand
report-generation logic, both stub-data and real-artifact),
`tests/test_multilang_scanner_patterns.py` (static consistency checks between the
scanner's per-language detection guidance and the Java/JS/Go/PHP/Perl fixture files),
`tests/test_connectors.py` (live Tenable/Armis connectors), `tests/test_enrichment.py`
(live CISA KEV + EPSS enrichment), `tests/test_priority_engine.py` (the configurable
priority/SLA engine), `tests/test_attack_mapping.py` (MITRE ATT&CK keyword tagging), and
`tests/test_servicenow_connector.py` (the ServiceNow adapter). Every row below maps 1:1
to one `test_*` method in one of those files — there is no test case here without a
corresponding, runnable assertion, and no assertion in any suite that isn't documented
here.

**How to reproduce these results yourself:**
```bash
pip install -r dashboard/requirements.txt
pip install -r remediation/connectors/requirements.txt
pip install -r remediation/enrichment/requirements.txt
pip install -r remediation/config/requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
```

**Last run:** 219 / 219 passed, 0 failures, 0 errors. Raw output captured in
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
| Dashboard `/api/queue` (live queue) | `ApiLiveQueue` | TC-DASH-18 – 19 | 2/2 PASS |
| Dashboard `/api/priority-rules` editor | `ApiPriorityRules` | TC-DASH-20 – 22 | 3/3 PASS |
| Dashboard `/api/servicenow/*` | `ApiServiceNow` | TC-DASH-23 – 25 | 3/3 PASS |
| Dashboard SPA shell routes | `HtmlShellRoutesServeTheSpaShell` | TC-DASH-26 – 31 | 6/6 PASS |
| Dashboard `/api/ai-assist` | `ApiAiAssist` | TC-DASH-32 – 38 | 7/7 PASS |
| Dashboard `/api/reports/*` | `ApiReports` | TC-DASH-39 – 42 | 4/4 PASS |
| Dashboard AI-assist prompt construction | `PromptConstruction` | TC-AI-01 – 12 | 12/12 PASS |
| Dashboard report data generation | `GenerateReportData` | TC-REPORTGEN-01 – 07 | 7/7 PASS |
| Dashboard report HTML rendering | `RenderReportHtml` | TC-REPORTGEN-08 – 12 | 5/5 PASS |
| Dashboard report generation against real artifacts | `RealArtifactIntegration` | TC-REPORTGEN-13 – 14 | 2/2 PASS |
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
| ServiceNow construction + auth | `AuthAndConstruction`, `BuildIncidentBodyPureFunction` | TC-SNOW-01 – 06 | 6/6 PASS |
| ServiceNow incident creation | `FindExistingIncident`, `CreateIncident` | TC-SNOW-07 – 14 | 8/8 PASS |
| ServiceNow batch handling | `CreateIncidentsForFindingsBatch` | TC-SNOW-15 – 16 | 2/2 PASS |
| **Total** | | **219** | **219/219 PASS** |

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
underlying `subprocess.run`/binary-discovery call is explicitly mocked. As of this
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
real API usage/credits.

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
| TC-DASH-20 | `GET /api/priority-rules` returns the current rules YAML text | `GET /api/priority-rules` (against a temp copy of the real rules file, so the shipped file is never mutated) | HTTP 200; `rules_text` contains `sla_days` | Matches | PASS |
| TC-DASH-21 | Valid YAML POST saves the new rules | `POST /api/priority-rules` with `rules_text` edited to change `Medium: 30` to `Medium: 5` | HTTP 200; response message contains `"saved"`; the (temp) rules file on disk now contains `Medium: 5` | Matches | PASS |
| TC-DASH-22 | Invalid YAML POST is rejected and the file is left unchanged | `POST /api/priority-rules` with `rules_text="not: valid: yaml: ["` | HTTP 400; `detail` contains `"invalid YAML"`; rules file content identical to before the request | Matches | PASS |
| TC-DASH-23 | ServiceNow preview lists every finding without needing credentials | `GET /api/servicenow/preview` | HTTP 200; preview `finding_id`s equal exactly `FIND-1`...`FIND-14` | Matches | PASS |
| TC-DASH-24 | Sending without confirm never touches the network (critical safety test) | `POST /api/servicenow/send` with real-looking `instance`/`username`/`password`/`table` but `confirm` omitted | HTTP 200; `preview_only` true; `results` is `null` | Matches | PASS |
| TC-DASH-25 | Sending with confirm but missing credentials is rejected | `POST /api/servicenow/send` with empty `instance`/`username`/`password`, `table="incident"`, `confirm=true` | HTTP 400; `detail` contains `"required"` | Matches | PASS |
| TC-DASH-26 | Every known page route serves the identical SPA shell | `GET` each of `/`, `/vulnhunt`, `/remediate`, `/run`, `/queue`, `/priority-rules`, `/servicenow` | All return HTTP 200 with `text/html`, each containing `<script type="module" src="/static/js/app.js">`; all 7 responses are byte-identical | Matches | PASS |
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

## Suite 12: Multi-language scanner pattern consistency (`tests/test_multilang_scanner_patterns.py`)

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

## Suite 13: Live Tenable connector (`remediation/connectors/tenable_connector.py`)

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

## Suite 14: Live Armis connector (`remediation/connectors/armis_connector.py`)

**Purpose:** same goal as Suite 13, for Armis's token-auth + paginated AQL search flow.

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

## Suite 15: CISA KEV + EPSS enrichment (`remediation/enrichment/kev_epss.py`)

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

## Suite 16: Configurable priority + SLA engine (`remediation/config/priority_engine.py`)

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

## Suite 17: MITRE ATT&CK keyword tagging (`remediation/enrichment/attack_mapping.py`)

**Purpose:** prove the heuristic fires on realistic finding text, and — just as
importantly — proves it does NOT guess when there's no real signal (empty list, not a
fabricated technique).

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

## Suite 18: ServiceNow adapter (`remediation/connectors/servicenow_connector.py`)

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

## Notable findings from testing (not just "all green")

Three real issues surfaced during the development of this suite, listed here because a
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
