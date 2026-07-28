[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunDir = Join-Path $Root ".run"

$PidFiles = @(
    Join-Path $RunDir "backend-shell.pid"
    Join-Path $RunDir "frontend-shell.pid"
)

function Stop-ProcessTreeFromPidFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) {
        return
    }

    $rawPid = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    $processId = 0

    if ([int]::TryParse([string]$rawPid, [ref]$processId)) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "正在停止进程树 PID $processId ……" -ForegroundColor Yellow
            & taskkill.exe /PID $processId /T /F | Out-Host
        }
    }

    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "AdSDK Agent 一键停止" -ForegroundColor Cyan
Write-Host ""

foreach ($pidFile in $PidFiles) {
    Stop-ProcessTreeFromPidFile -PidFile $pidFile
}

# 兜底处理：仅停止命令行中明确包含当前项目路径的 uvicorn / Vite / npm 进程。
$escapedRoot = [Regex]::Escape($Root)
$ownedProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.CommandLine -and
        $_.CommandLine -match $escapedRoot -and
        (
            $_.CommandLine -match "uvicorn\s+app\.main:app" -or
            $_.CommandLine -match "vite" -or
            $_.CommandLine -match "npm(\.cmd)?\s+run\s+dev"
        )
    }

foreach ($ownedProcess in $ownedProcesses) {
    Write-Host "停止残留项目进程 PID $($ownedProcess.ProcessId) ……" -ForegroundColor Yellow
    & taskkill.exe /PID $ownedProcess.ProcessId /T /F | Out-Host
}

if (Test-Path -LiteralPath $RunDir) {
    $remaining = Get-ChildItem -LiteralPath $RunDir -Force -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item -LiteralPath $RunDir -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "前后端停止命令已完成。" -ForegroundColor Green
