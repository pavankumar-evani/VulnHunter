<#
.SYNOPSIS
  Renders the 3 standalone documents (Developer & Contributor Guide,
  Commercial Brochure, Cloud Hosting & Commercial Launch Guide) from
  standalone-sources/*.html to PDF. Unlike the 15-chapter pipeline, these
  already have the dark theme and print-pagination CSS baked in - no
  patch_dark.py-equivalent step needed. See README.md for the same
  Puppeteer/DevTools-policy caveat that applies to render_docs.ps1.
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

$srcDir = Join-Path $scriptDir "standalone-sources"
$outDir = Join-Path $scriptDir "_build"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$docs = @(
  @{ src = "dev-guide-dark.html";    out = "VulnHunter_Developer_Contributor_Guide.pdf" },
  @{ src = "brochure-dark.html";     out = "VulnHunter_Commercial_Brochure.pdf" },
  @{ src = "cloud-guide-dark.html";  out = "VulnHunter_Cloud_Hosting_Guide.pdf" }
)

foreach ($doc in $docs) {
  $profileDir = Join-Path $outDir ("chrome-profile-" + [guid]::NewGuid().ToString('N').Substring(0,8))
  $srcPath = Join-Path $srcDir $doc.src
  $outPath = Join-Path $outDir $doc.out
  $srcUri = ([uri]$srcPath).AbsoluteUri

  # See render_docs.ps1 for why these two need embedded literal quotes: a
  # path containing spaces (common under this repo) otherwise gets split by
  # Chrome's own command-line parser, which then refuses with "Multiple
  # targets are not supported in headless mode."
  $argList = @(
    "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
    ('--user-data-dir="{0}"' -f $profileDir),
    ('--print-to-pdf="{0}"' -f $outPath),
    "--virtual-time-budget=8000",
    "--no-first-run", "--no-default-browser-check",
    $srcUri
  )
  $p = Start-Process -FilePath $chrome -ArgumentList $argList -PassThru -Wait -NoNewWindow
  Write-Output ("{0} -> {1}  exit={2} ok={3}" -f $doc.src, $doc.out, $p.ExitCode, (Test-Path $outPath))
}
Write-Output "Done. Output in $outDir"
