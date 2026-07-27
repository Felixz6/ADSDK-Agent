# capture-screenshots.ps1
# Capture 8 named screenshots of the AdSDK Agent frontend via headless Chrome.
# Chrome headless --screenshot captures after the page paints; --virtual-time-budget
# lets lazy-loaded React routes and async data settle before the shot is taken.
#
# Usage:
#   ./capture-screenshots.ps1                          # default: port 5174 -> docs/screenshots
#   ./capture-screenshots.ps1 -Port 5174 -Out real-device   # real-device run -> docs/screenshots/real-device
#   ./capture-screenshots.ps1 -NamePrefix 'real-'     # prefix each filename (e.g. real-01-home.png)

param(
  [int]$Port = 5174,
  [string]$Out = "",
  [string]$NamePrefix = ""
)

$ErrorActionPreference = "Stop"

$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$base = "http://127.0.0.1:$Port"
$leaf = if ([string]::IsNullOrEmpty($Out)) { "screenshots" } else { Join-Path "screenshots" $Out }
$out = Join-Path $PSScriptRoot "docs\$leaf"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# name => url path. Hit a URL hash route so the SPA router lands directly on the page
# (avoids a transient default-route flash before client-side navigation).
$pages = [ordered]@{
  "01-home.png"             = "/"
  "02-new-analysis.png"     = "/analysis/new"
  "03-tasks.png"            = "/tasks"
  "04-static-analysis.png" = "/static"
  "05-dynamic-analysis.png" = "/dynamic"
  "06-traffic.png"          = "/traffic"
  "07-reports.png"          = "/reports"
  "08-environment.png"      = "/environment"
}

foreach ($name in $pages.Keys) {
  $url = $base + $pages[$name]
  $dest = Join-Path $out ($NamePrefix + $name)
  # --hide-scrollbars keeps the viewport clean; window-size = desktop 1440x900.
  & $chrome --headless=new --disable-gpu --no-sandbox --hide-scrollbars `
    --window-size=1440,900 --virtual-time-budget=4000 `
    --screenshot="$dest" "$url" 2>$null
  if (Test-Path $dest) {
    $kb = [math]::Round((Get-Item $dest).Length / 1KB, 1)
    Write-Host "OK  $($NamePrefix + $name)  (${kb} KB)  <- $url"
  } else {
    Write-Host "FAIL $($NamePrefix + $name)  <- $url"
  }
}
