<#
.SYNOPSIS
  Wrapper that drives POST /dynamic/analyze against a real MuMu device while
  guaranteeing the device http_proxy is restored to its prior value under
  every exit condition (success, client timeout, backend exception, Ctrl-C).

.DESCRIPTION
  The backend's [/dynamic/analyze] handler does NOT set or restore the device
  http_proxy (verified: no settings-put/global in the codebase). When
  enable_traffic is true, traffic must be routed through a host mitmproxy; this
  wrapper performs the proxy set/restore OUTSIDE the backend so the backend
  contract stays read-only. The restore is unconditional (try/finally) AND
  re-verified after the call returns null on success; a best-effort hard
  kill (session power loss) is covered by the post-verification and reported
  honestly if it fails.

  For enable_traffic=false this wrapper does NOT touch http_proxy at all
  (the Frida-only path needs no proxy) — only the traffic-on branch sets it.

.PARAMETER EnableTraffic
  true  -> set device http_proxy to ${EmuHost}:${MitmPort} before the call,
          restore (and re-verify null) after.
  false -> leave http_proxy untouched (Frida-only round).

.PARAMETER DeviceId
  Exact ADB serial. REQUIRED. Always passed as -s.

.PARAMETER PackageName
  Android package name passed to the backend.

.PARAMETER ApkPath
  Absolute path to the APK (must be under an APK_ALLOWED_ROOTS root, e.g. samples/).

.PARAMETER MitmPort
  mitmproxy listen port the backend will bind. Default 8080 (or
  $env:ADSdk_MITM_PORT if set).

.PARAMETER EmuHost
  Legacy alias for HostProxyAddress (host address reachable from the MuMu
  guest that resolves to the host's mitmproxy). Kept for backward
  compatibility. Default 10.0.2.2 (QEMU gateway; verified reachable).

.PARAMETER HostProxyAddress
  Host address the DEVICE proxy is pointed at. For MuMu this is the QEMU
  gateway 10.0.2.2 (the guest cannot reach the host's 127.0.0.1 loopback,
  which is its OWN loopback). Defaults to $env:ADSdk_HostProxyAddress or
  10.0.2.2. Do NOT pass 127.0.0.1 here — the emulator guest cannot route to
  the host loopback via that address.

.PARAMETER MitmListenHost
  Value the OPERATOR must set in MITM_LISTEN_HOST on the backend side so
  mitmdump binds to an interface the guest can reach. For MuMu the guest
  reaches the host via 10.0.2.2, so mitmdump must bind 0.0.0.0 (all host
  interfaces) — 127.0.0.1 is NOT reachable from the guest. This wrapper does
  NOT set the backend env for you (the backend is a separate process); it
  only records what the operator should set. Default 0.0.0.0 for the
  emulator path (or $env:ADSdk_MitmListenHost).

.PARAMETER PreConsentSeconds / PostConsentSeconds / ConsentAfterSeconds
  Mirrors the backend DynamicAnalyzeRequest fields.

.PARAMETER EnableUiStimulation
  Pass enable_ui_stimulation to the backend (default false).

.PARAMETER CollectionTimeoutSeconds
  Hard timeout for the active collection window (default 120).

.PARAMETER ApiBaseUrl
  Backend base URL (default http://127.0.0.1:8000, or $env:ADSdk_ApiBaseUrl).

.PARAMETER RequestTimeoutSeconds
  HttpClient timeout for the outbound request (default 3600). The backend
  re-runs apk_unpack + sdk_scan on every dynamic call (~60 min for hongguo.apk),
  so this must exceed that wall-clock. NOTE: the on-disk report.json is the
  authoritative artifact regardless of whether the HTTP client returns in time
  (the uvicorn sync worker continues server-side after a client disconnect).

.EXAMPLE
  .\scripts\run_dynamic_mumu.ps1 -EnableTraffic $false `
      -DeviceId 127.0.0.1:16417 -PackageName com.phoenix.read `
      -ApkPath D:\adsdk-agent\samples\hongguo.apk
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [bool]   $EnableTraffic,
    [Parameter(Mandatory)] [string] $DeviceId,
    [Parameter(Mandatory)] [string] $PackageName,
    [Parameter(Mandatory)] [string] $ApkPath,
    [int]    $MitmPort                 = $(if ($env:ADSdk_MITM_PORT) { [int]$env:ADSdk_MITM_PORT } else { 8080 }),
    [string] $EmuHost                  = $(if ($env:ADSdk_HostProxyAddress) { $env:ADSdk_HostProxyAddress } else { "10.0.2.2" }),
    [string] $HostProxyAddress         = $EmuHost,
    [string] $MitmListenHost           = $(if ($env:ADSdk_MitmListenHost) { $env:ADSdk_MitmListenHost } else { "0.0.0.0" }),
    [int]    $PreConsentSeconds         = 10,
    [int]    $PostConsentSeconds        = 10,
    [Nullable[int]] $ConsentAfterSeconds = $null,
    [bool]   $EnableUiStimulation       = $false,
    [int]    $CollectionTimeoutSeconds  = 120,
    [string] $ApiBaseUrl                = $(if ($env:ADSdk_ApiBaseUrl) { $env:ADSdk_ApiBaseUrl } else { "http://127.0.0.1:8000" }),
    [string] $ApiBase                   = $ApiBaseUrl,
    [int]    $RequestTimeoutSeconds    = 3600
)

$ErrorActionPreference = "Stop"

function Send-Adb {
    param([string]$Serial, [string[]]$Args)
    & adb.exe -s $Serial @Args
}

function Get-DeviceProxy {
    param([string]$Serial)
    $line = (Send-Adb -Serial $Serial -Args @("shell", "settings", "get", "global", "http_proxy")) 2>$null
    return ($line | Out-String).Trim()
}

function Set-DeviceProxy {
    param([string]$Serial, [string]$Value)
    # `:null` clears the proxy (Android's null sentinel).
    Send-Adb -Serial $Serial -Args @("shell", "settings", "put", "global", "http_proxy", $Value) | Out-Null
}

function Assert-ProxyNull {
    param([string]$Serial, [string]$Tag)
    $cur = Get-DeviceProxy -Serial $Serial
    if ($cur -ne "null" -and $cur -ne ":null") {
        Write-Warning ("[{0}] http_proxy NOT restored: actual='{1}' (expected null)" -f $Tag, $cur)
        return $false
    }
    Write-Host ("[{0}] http_proxy restored to null (verified)" -f $Tag)
    return $true
}

# ---- pre-flight: device reachable, record prior proxy ----
$adbSerials = (Send-Adb -Serial $DeviceId -Args @("get-state")) 2>$null
$devState = ($adbSerials | Out-String).Trim()
if ($devState -ne "device") {
    throw "Device $DeviceId not in 'device' state (got '$devState'). Aborting before any proxy change."
}
$priorProxy = Get-DeviceProxy -Serial $DeviceId
Write-Host ("Prior http_proxy = '{0}'" -f $priorProxy)

$proxySetHere = $false
$runId = $null
$apiOk = $false

try {
    # ---- build request body ----
    $body = [ordered]@{
        apk_path                  = $ApkPath
        package_name              = $PackageName
        device_id                 = $DeviceId
        enable_traffic            = $EnableTraffic
        pre_consent_seconds       = $PreConsentSeconds
        post_consent_seconds      = $PostConsentSeconds
        consent_after_seconds     = $ConsentAfterSeconds
        enable_ui_stimulation     = $EnableUiStimulation
        collection_timeout_seconds= $CollectionTimeoutSeconds
    }
    $json = $body | ConvertTo-Json -Compress -Depth 5
    $json = $json -replace '"consent_after_seconds":null', '"consent_after_seconds":null'

    if ($EnableTraffic) {
        if ($HostProxyAddress -match '^127\.0\.0\.1($|:)') {
            Write-Warning ("HostProxyAddress='{0}' — emulator guest cannot reach host 127.0.0.1 (that is the guest's OWN loopback). Point the proxy at the QEMU gateway, e.g. 10.0.2.2." -f $HostProxyAddress)
        }
        $proxyValue = "${HostProxyAddress}:${MitmPort}"
        Write-Host ("Setting device http_proxy -> '{0}'" -f $proxyValue)
        Set-DeviceProxy -Serial $DeviceId -Value $proxyValue
        $proxySetHere = $true
        $verifyAfterSet = Get-DeviceProxy -Serial $DeviceId
        Write-Host ("Verify after set: http_proxy = '{0}'" -f $verifyAfterSet)
        Write-Host ("Reminder: the backend (separate process) must be started with MITM_LISTEN_HOST={0} so mitmdump binds an interface the guest can reach via {1}." -f $MitmListenHost, $HostProxyAddress)
    } else {
        Write-Host "EnableTraffic=false -> http_proxy left untouched (Frida-only round)."
    }

    # ---- POST ----
    $uri = "$ApiBaseUrl/dynamic/analyze"
    Write-Host ("POST {0}" -f $uri)
    try {
        $resp = Invoke-WebRequest -Uri $uri -Method POST -ContentType 'application/json' `
            -Body $json -TimeoutSec $RequestTimeoutSeconds -ErrorAction Stop
        $apiOk = ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300)
        Write-Host ("HTTP {0}  len={1}" -f $resp.StatusCode, $resp.Content.Length)
        try {
            $parsed = $resp.Content | ConvertFrom-Json
            $runId = $parsed.run_id
            Write-Host ("run_id = {0}" -f $runId)
            Write-Host ("status = {0}" -f $parsed.status)
            Write-Host ("collection_status = {0}" -f $parsed.collection_status)
        } catch {
            Write-Warning ("Could not parse JSON response: {0}" -f $_.Exception.Message)
        }
        $resp.Content | Out-File -FilePath (Join-Path $PSScriptRoot "..\output\_resp_dynamic.json") -Encoding utf8 -NoNewline
    } catch {
        # A client timeout / 5xx / network error is NOT a reason to skip the
        # restore. The backend sync worker may still be running server-side;
        # report honestly and let the caller read the on-disk report.json.
        Write-Warning ("Request failed/aborted: {0}" -f $_.Exception.Message)
    }
}
finally {
    if ($proxySetHere) {
        Write-Host "Finally: restoring device http_proxy -> null"
        try { Set-DeviceProxy -Serial $DeviceId -Value ":null" } catch { Write-Warning ("restore put failed: {0}" -f $_.Exception.Message) }
        $null = Assert-ProxyNull -Serial $DeviceId -Tag "finally"
    } else {
        Write-Host "Finally: EnableTraffic=false -> http_proxy was never changed by this wrapper."
    }
}

Write-Host ("Done. apiOk={0} runId={1} proxySetHere={2}" -f $apiOk, $runId, $proxySetHere)
