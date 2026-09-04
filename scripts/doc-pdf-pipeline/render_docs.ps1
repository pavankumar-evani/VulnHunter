<#
.SYNOPSIS
  Stage 2 of the 15-chapter pipeline: render each dark_print_src/*.html file
  to a raw PDF via headless Chrome. Run patch_dark.py first.

.NOTES
  Puppeteer/Playwright/anything using the Chrome DevTools remote-debugging
  protocol WILL NOT WORK on a machine where that protocol is disabled by an
  admin/enterprise policy (this shows up as Chrome printing "DevTools remote
  debugging is disallowed by the system admin." and/or a misleading "browser
  already running" error from the automation library, even against a brand
  new --user-data-dir). Plain --print-to-pdf does not depend on that
  protocol and is unaffected - this script uses only that.

  If you hit "already running" anyway: it means a PREVIOUS attempt's
  chrome.exe is still alive holding that exact --user-data-dir. This script
  always uses a fresh timestamped profile dir per run, so a same-second retry
  is the only way to actually collide - if it happens, find and kill only the
  chrome.exe process(es) whose command line contains this script's own
  profile-dir name (Get-CimInstance Win32_Process | Where-Object
  { $_.CommandLine -like '*<profile-dir-name>*' }) - never kill chrome.exe
  processes generally, the user's own real browser is very likely also
  running under that name.
#>

$scriptDir = $PSScriptRoot
$chromeCandidates = @(
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
)
$chrome = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $chrome) {
  throw "No Chrome or Edge install found in the usual locations. Edit `$chromeCandidates in this script to point at your browser."
}
Write-Output "Using browser: $chrome"

$srcDir = Join-Path $scriptDir "_build\dark_print_src"
$rawOut = Join-Path $scriptDir "_build\raw_out_dark"
$profileDir = Join-Path $scriptDir ("_build\chrome-profile-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))

if (-not (Test-Path $srcDir)) {
  throw "$srcDir does not exist - run patch_dark.py first."
}
New-Item -ItemType Directory -Force -Path $rawOut | Out-Null

# Order matches docs/enterprise-suite/MANIFEST.md.
$files = @(
  "hub.html", "executive-brief.html", "whitepaper.html", "architecture.html",
  "vuln-engine.html", "remediation-engine.html", "connectors.html",
  "rbac-governance.html", "ai-capabilities.html", "reporting.html",
  "pages.html", "developer-guide.html", "poc-methodology.html",
  "pricing.html", "user-guide.html"
)

$i = 0
foreach ($fname in $files) {
  $i++
  $srcPath = Join-Path $srcDir $fname
  $srcUri = ([uri]$srcPath).AbsoluteUri
  $outName = "{0:D2}_{1}.pdf" -f $i, ($fname -replace '\.html$', '')
  $outPath = Join-Path $rawOut $outName

  # Paths under this repo commonly contain spaces (e.g. an "OneDrive - Foo (Bar)"
  # parent folder). Chrome's own command-line parser splits --flag=value at any
  # unquoted space in value, then complains "Multiple targets are not supported
  # in headless mode" - embedding literal quotes in the value (not just relying
  # on PowerShell's own array-element quoting) is what actually avoids that.
  $argList = @(
    "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
    ('--user-data-dir="{0}"' -f $profileDir),
    ('--print-to-pdf="{0}"' -f $outPath),
    "--virtual-time-budget=8000",
    "--no-first-run", "--no-default-browser-check",
    $srcUri
  )
  $p = Start-Process -FilePath $chrome -ArgumentList $argList -PassThru -Wait -NoNewWindow `
        -RedirectStandardError "$scriptDir\_build\_stderr_$i.txt"
  $ok = Test-Path $outPath
  Write-Output ("[{0}/{1}] {2} -> {3}  exit={4} ok={5}" -f $i, $files.Count, $fname, $outName, $p.ExitCode, $ok)
}
Write-Output "Done. Run finalize_pdfs.py next."
