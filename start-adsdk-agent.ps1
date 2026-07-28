[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunDir = Join-Path $Root ".run"
$BackendPidFile = Join-Path $RunDir "backend-shell.pid"
$FrontendPidFile = Join-Path $RunDir "frontend-shell.pid"

$VenvScripts = Join-Path $Root ".venv\Scripts"
$VenvPython = Join-Path $VenvScripts "python.exe"
$WebDir = Join-Path $Root "web"
$PackageJson = Join-Path $WebDir "package.json"

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(300)) {
            return $false
        }

        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Get-PowerShellExecutable {
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwsh) {
        return $pwsh.Source
    }

    $windowsPowerShell = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($windowsPowerShell) {
        return $windowsPowerShell.Source
    }

    throw "未找到 pwsh.exe 或 powershell.exe。"
}

function Start-ServiceWindow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    $shell = Get-PowerShellExecutable
    $escapedTitle = $Title.Replace("'", "''")
    $escapedWorkingDirectory = $WorkingDirectory.Replace("'", "''")

    $wrappedCommand = @"
`$Host.UI.RawUI.WindowTitle = '$escapedTitle'
Set-Location -LiteralPath '$escapedWorkingDirectory'
$Command
"@

    $process = Start-Process `
        -FilePath $shell `
        -ArgumentList @(
            "-NoExit",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", $wrappedCommand
        ) `
        -WorkingDirectory $WorkingDirectory `
        -PassThru

    Set-Content -LiteralPath $PidFile -Value $process.Id -Encoding ascii
    return $process
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    throw "未找到虚拟环境：$VenvPython`n请先执行：py -3.14 -m venv .venv"
}

if (-not (Test-Path -LiteralPath $PackageJson -PathType Leaf)) {
    throw "未找到前端项目：$PackageJson"
}

$RequiredVenvCommands = @(
    "frida.exe",
    "frida-ps.exe",
    "mitmdump.exe"
)

foreach ($commandName in $RequiredVenvCommands) {
    $commandPath = Join-Path $VenvScripts $commandName

    if (-not (Test-Path -LiteralPath $commandPath -PathType Leaf)) {
        throw "虚拟环境缺少 $commandName。请先激活 .venv 并执行：python -m pip install -r requirements.txt"
    }
}

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
}
if (-not $npm) {
    throw "未找到 npm，请先安装 Node.js 并确认 npm 可用。"
}

New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

Write-Host ""
Write-Host "AdSDK Agent 一键启动" -ForegroundColor Cyan
Write-Host "项目目录：$Root"
Write-Host "Python 环境：$VenvPython"
Write-Host ""

if (Test-TcpPort -Port 8000) {
    Write-Host "后端端口 8000 已在监听，跳过重复启动。" -ForegroundColor Yellow
}
else {
    $escapedPython = $VenvPython.Replace("'", "''")
    $escapedVenvScripts = $VenvScripts.Replace("'", "''")

    $backendCommand = @"
`$env:PYTHONUTF8 = '1'
`$env:PATH = '$escapedVenvScripts;' + `$env:PATH
& '$escapedPython' -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"@

    $backendProcess = Start-ServiceWindow `
        -Title "AdSDK Agent Backend :8000" `
        -WorkingDirectory $Root `
        -Command $backendCommand `
        -PidFile $BackendPidFile

    Write-Host "后端启动窗口已打开，Shell PID：$($backendProcess.Id)" -ForegroundColor Green
}

if (Test-TcpPort -Port 5173) {
    Write-Host "前端端口 5173 已在监听，跳过重复启动。" -ForegroundColor Yellow
}
else {
    $frontendCommand = @"
& npm.cmd run dev -- --host 127.0.0.1
"@

    $frontendProcess = Start-ServiceWindow `
        -Title "AdSDK Agent Frontend :5173" `
        -WorkingDirectory $WebDir `
        -Command $frontendCommand `
        -PidFile $FrontendPidFile

    Write-Host "前端启动窗口已打开，Shell PID：$($frontendProcess.Id)" -ForegroundColor Green
}

Write-Host ""
Write-Host "正在等待服务就绪……"

$backendReady = $false
$frontendReady = $false

for ($i = 0; $i -lt 60; $i++) {
    if (-not $backendReady) {
        $backendReady = Test-TcpPort -Port 8000
    }

    if (-not $frontendReady) {
        $frontendReady = Test-TcpPort -Port 5173
    }

    if ($backendReady -and $frontendReady) {
        break
    }

    Start-Sleep -Milliseconds 500
}

Write-Host ""

if ($backendReady) {
    Write-Host "后端已就绪：http://127.0.0.1:8000" -ForegroundColor Green
}
else {
    Write-Host "后端尚未在 8000 端口就绪，请查看后端窗口。" -ForegroundColor Yellow
}

if ($frontendReady) {
    Write-Host "前端已就绪：http://127.0.0.1:5173" -ForegroundColor Green
    Start-Process "http://127.0.0.1:5173"
}
else {
    Write-Host "前端尚未在 5173 端口就绪，请查看前端窗口。" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "停止服务时，双击 stop-adsdk-agent.bat。" -ForegroundColor Cyan
