# VulnHunter — Test Cases & Results

Formal test case log for [`tests/test_pipeline_artifacts.py`](tests/test_pipeline_artifacts.py).
Every row below maps 1:1 to one `test_*` method in that file — there is no test case here
without a corresponding, runnable assertion, and no assertion in the suite that isn't
documented here.

**How to reproduce these results yourself:**
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

**Last run:** 33 / 33 passed, 0 failures, 0 errors (3.97s). Raw output captured in
[`tests/test_results.txt`](tests/test_results.txt).

**What these tests do NOT do:** they don't invoke the Claude Code subagents directly
(subagents only run inside an interactive Claude Code session — see
[KNOWLEDGE_TRANSFER.md §10](KNOWLEDGE_TRANSFER.md#10-troubleshooting--things-that-tripped-us-up)).
They validate the real artifacts those agents produced during the documented validation
run — git history for `/vulnhunt`, generated files for `/remediate` — which is what makes
this both real regression coverage and honest test evidence rather than a mocked demo.

---

## Summary by suite

| Suite | Test class | Test cases | Result |
|---|---|---|---|
| `/vulnhunt` scan | `VulnHuntScannerFindsRealVulnerabilities` | TC-SCAN-01 – 07 | 7/7 PASS |
| `/vulnhunt` fix | `VulnHuntFixerAppliesOnlyApprovedFixes` | TC-FIX-01 – 08 | 8/8 PASS |
| `/vulnhunt` report | `VulnHuntReportIsAccurate` | TC-RPT-01 – 03 | 3/3 PASS |
| `/remediate` normalize | `RemediationNormalizedFindingsAreWellFormed` | TC-NORM-01 – 07 | 7/7 PASS |
| `/remediate` plan | `RemediationPlanIsConsistentWithFindings` | TC-PLAN-01 – 02 | 2/2 PASS |
| `/remediate` playbooks | `RemediationPlaybooksMatchThePlan` | TC-PB-01 – 05 | 5/5 PASS |
| Cross-cutting safety | `NoRealSecretsLeakedAnywhere` | TC-SEC-01 | 1/1 PASS |
| **Total** | | **33** | **33/33 PASS** |

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
| TC-NORM-01 | Exactly 11 findings total | Parse the JSON array; count elements | 11 | 11 | PASS |
| TC-NORM-02 | Every finding has required fields | For each finding, check `id/source/source_ref/asset/title/severity/remediation_domain` present, and `asset.name/ip/type` present | All findings compliant | All compliant | PASS |
| TC-NORM-03 | All 3 sources represented | Collect distinct `source` values | `{tenable, armis, threat-intel}` | Matches exactly | PASS |
| TC-NORM-04 | Asset-type classification spot checks | Check known assets: `WIN-DC01`→windows-server, `LNX-DB03`→unix-server, `CSW-CORE01`→network-routing-switching, Axis camera→iot-ot-device | All 4 spot checks correct | All correct | PASS |
| TC-NORM-05 | `remediation_domain` only set for supported domains | For each finding: if `asset.type` is windows-server/unix-server, `remediation_domain` must equal it; otherwise must be `null` | Rule holds for all 11 | Holds | PASS |
| TC-NORM-06 | Exactly 7 findings eligible for automation | Count findings with non-null `remediation_domain` | 7 | 7 | PASS |
| TC-NORM-07 | No fabricated CVE IDs | For each non-null `cve`, regex-match `CVE-\d{4}-\d{4,}` | All CVEs well-formed (catches agent hallucination of a plausible-but-fake ID) | All well-formed | PASS |

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
3. All other test cases passed on first implementation, which is expected — they assert
   behavior the pipeline stages were explicitly designed to produce (e.g. "the fixer
   never touches `main`"), rather than probing for unknown defects.
