[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Msg) { Write-Host "`n==> $Msg" -ForegroundColor Cyan }
function Write-Ok([string]$Msg)   { Write-Host "✔ $Msg" -ForegroundColor Green }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run uninstall.ps1 from an Administrator PowerShell prompt."
}

$DataDir = "C:\ProgramData\TailAuth"
$InstallDir = "C:\Program Files\TailAuth"
$Port = 8443
$cfgPath = Join-Path $DataDir "config.json"
if (Test-Path $cfgPath) {
    try {
        $cfg = Get-Content -Raw -Path $cfgPath | ConvertFrom-Json
        if ($cfg.https_port) { $Port = [int]$cfg.https_port }
    } catch {}
}

$svc = Get-Service -Name "TailAuth" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Step "Stopping and removing TailAuth Windows Service"
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name "TailAuth" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    & sc.exe delete TailAuth | Out-Null
    Write-Ok "Removed TailAuth service"
}

$tailscaleCmd = Get-Command tailscale -ErrorAction SilentlyContinue
if (-not $tailscaleCmd -and (Test-Path "C:\Program Files\Tailscale\tailscale.exe")) {
    $tailscaleCmd = Get-Item "C:\Program Files\Tailscale\tailscale.exe"
}
if ($tailscaleCmd) {
    Write-Step "Removing Tailscale Serve rule on port $Port"
    $tsExe = if ($tailscaleCmd.Source) { $tailscaleCmd.Source } else { $tailscaleCmd.FullName }
    & $tsExe serve --https=$Port off 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $tsExe serve clear "https:$Port" 2>$null
    }
}

Write-Step "Cleaning PowerShell profile(s)"
$profileTargets = @(
    (Join-Path $env:USERPROFILE "Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
    (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1")
) | Select-Object -Unique

foreach ($prof in $profileTargets) {
    if (Test-Path $prof) {
        $content = Get-Content -Raw -Path $prof
        $cleaned = [regex]::Replace($content, "(?ms)^# tailauth-begin\r?\n.*?^# tailauth-end\r?\n?", "")
        [System.IO.File]::WriteAllText($prof, $cleaned, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok "Cleaned $prof"
    }
}

Write-Step "Removing $InstallDir from Machine PATH and disk"
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$filtered = @($machinePath -split ";" | Where-Object { $_ -ne "" -and $_ -ne $InstallDir })
[Environment]::SetEnvironmentVariable("Path", ($filtered -join ";"), "Machine")
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
}

if ($Purge -and (Test-Path $DataDir)) {
    Write-Step "Purging $DataDir"
    Remove-Item -Recurse -Force $DataDir
}

Write-Ok "TailAuth uninstalled cleanly."
