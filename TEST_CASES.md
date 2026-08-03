# VulnHunter — Test Cases & Results

Formal test case log for all five test files: `tests/test_pipeline_artifacts.py` (both
pipelines' real output artifacts), `tests/test_cli.py` (the headless CLI),
`tests/test_dashboard.py` (the web dashboard), `tests/test_connectors.py` (live
Tenable/Armis connectors), and `tests/test_enrichment.py` (live CISA KEV + EPSS
enrichment). Every row below maps 1:1 to one `test_*` method in one of those files —
there is no test case here without a corresponding, runnable assertion, and no assertion
in any suite that isn't documented here.

**How to reproduce these results yourself:**
```bash
pip install -r dashboard/requirements.txt
pip install -r remediation/connectors/requirements.txt
pip install -r remediation/enrichment/requirements.txt
python -m unittest discover -s tests -p "test_*.py" -v
```

**Last run:** 96 / 96 passed, 0 failures, 0 errors. Raw output captured in
[`tests/test_results.txt`](tests/test_results.txt).

**What these tests do NOT do:** they don't invoke the Claude Code subagents directly
(subagents only run inside an interactive Claude Code session — see
[KNOWLEDGE_TRANSFER.md §10](KNOWLEDGE_TRANSFER.md#10-troubleshooting--things-that-tripped-us-up)),
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
| Dashboard routes | `DashboardRoutesRender` | TC-DASH-09 – 17 | 9/9 PASS |
| Tenable connector | `TenableAuthAndExportRequest`, `TenablePollAndDownload`, `TenableRecordMapping`, `TenableWritesSampleCompatibleCsv` | TC-CONN-01 – 11 | 11/11 PASS |
| Armis connector | `ArmisAuthentication`, `ArmisPagination`, `ArmisDeviceAndAlertAssembly` | TC-CONN-12 – 18 | 7/7 PASS |
| KEV/EPSS fetching | `KevFetching`, `EpssFetching` | TC-ENR-01 – 05 | 5/5 PASS |
| KEV/EPSS enrichment assembly | `EnrichmentAssembly`, `EnrichFileIO` | TC-ENR-06 – 12 | 7/7 PASS |
| KEV/EPSS live smoke test | `LiveSmokeTest` | TC-ENR-13 | 1/1 PASS |
| **Total** | | **96** | **96/96 PASS** |

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

**Purpose:** prove the dashboard's parser agrees with the pipeline test suite about what
the artifacts say (no silent drift between the two), every route renders without error,
and the one route that could spend real money never does so in a test.

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
| TC-DASH-09 | Overview page loads | `GET /` via Flask test client | HTTP 200; contains "Security Posture Overview" | Matches | PASS |
| TC-DASH-10 | Overview page shows KEV/EPSS KPIs and asset-class coverage | Same request | Contains "CISA KEV-listed", "High EPSS", and the `certificate`/`application` asset types | Matches | PASS |
| TC-DASH-11 | Code scan page lists all findings | `GET /vulnhunt` | HTTP 200; `VULN-1` through `VULN-9` all present | All present | PASS |
| TC-DASH-12 | Remediation page lists all findings | `GET /remediate` | HTTP 200; `FIND-1` through `FIND-14` all present | All present | PASS |
| TC-DASH-13 | Playbook detail page loads | `GET /playbooks/FIND-4-sudo-baron-samedit-patch.yml` | HTTP 200; contains "Auto-approvable" | Matches | PASS |
| TC-DASH-14 | Unknown playbook returns 404 | `GET /playbooks/does-not-exist.yml` | HTTP 404 (negative test) | 404 | PASS |
| TC-DASH-15 | Run page loads | `GET /run` | HTTP 200; contains "Run a Pipeline" | Matches | PASS |
| TC-DASH-16 | Dry-run POST never calls the real API | `POST /run` with `confirm` field omitted | HTTP 200 after redirect; response contains "Dry run only"; no audit log written | Matches | PASS |
| TC-DASH-17 | `/api/status` returns correct counts | `GET /api/status` | JSON with `status: ok`, `vulnhunt_findings: 9`, `remediation_findings: 14` | Matches | PASS |

---

## Suite 10: Live Tenable connector (`remediation/connectors/tenable_connector.py`)

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

## Suite 11: Live Armis connector (`remediation/connectors/armis_connector.py`)

**Purpose:** same goal as Suite 10, for Armis's token-auth + paginated AQL search flow.

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

## Suite 12: CISA KEV + EPSS enrichment (`remediation/enrichment/kev_epss.py`)

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
