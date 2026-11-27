[CmdletBinding()]
param(
    [int]$Port = 8443,
    [int]$Timeout = 60,
    [string[]]$AllowTsUser = @(),
    [switch]$SkipEnroll,
    [switch]$NoProfile
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Msg) { Write-Host "`n==> $Msg" -ForegroundColor Cyan }
function Write-Ok([string]$Msg)   { Write-Host "✔ $Msg" -ForegroundColor Green }
function Write-Warn([string]$Msg) { Write-Host "! $Msg" -ForegroundColor Yellow }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run install.ps1 from an Administrator PowerShell prompt."
}

$ScriptDir = $PSScriptRoot
if (-not (Test-Path (Join-Path $ScriptDir "Cargo.toml"))) {
    throw "Run install.ps1 from the tailauth repository directory."
}

Write-Step "Checking prerequisites (Tailscale, Rust)"
$tailscaleCmd = Get-Command tailscale -ErrorAction SilentlyContinue
if (-not $tailscaleCmd) {
    $fallbackTs = "C:\Program Files\Tailscale\tailscale.exe"
    if (Test-Path $fallbackTs) {
        $tailscaleExe = $fallbackTs
    } else {
        throw "tailscale.exe not found. Install Tailscale for Windows first: https://tailscale.com/download/windows"
    }
} else {
    $tailscaleExe = $tailscaleCmd.Source
}

$tsService = Get-Service -Name "Tailscale" -ErrorAction SilentlyContinue
if ($tsService -and $tsService.Status -ne "Running") {
    Write-Warn "Starting Tailscale Windows service..."
    Start-Service -Name "Tailscale"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path (Join-Path $cargoBin "cargo.exe")) {
        $env:PATH = "$cargoBin;$env:PATH"
    } else {
        Write-Warn "Rust toolchain (cargo/rustc) not found."
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            $ans = Read-Host "Install Rust via winget (Rustlang.Rustup) now? [Y/n]"
            if ($ans -eq "" -or $ans -match "^[Yy]") {
                & winget install --id Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements
                $env:PATH = "$cargoBin;$env:PATH"
            }
        }
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            throw "Rust toolchain is required. Install from https://rustup.rs and re-run install.ps1."
        }
    }
}

Write-Step "Verifying Tailscale connection and HTTPS certificate capability"
$tsFqdn = $null
while ($true) {
    $rawStatus = & $tailscaleExe status --json 2>$null
    if (-not $rawStatus) {
        throw "Failed to query 'tailscale status --json'. Ensure Tailscale is logged in."
    }
    $status = $rawStatus | ConvertFrom-Json
    if ($status.BackendState -ne "Running" -or -not $status.Self.DNSName) {
        throw "Tailscale is not connected (state=$($status.BackendState)). Connect Tailscale and re-run install.ps1."
    }
    $tsFqdn = $status.Self.DNSName.TrimEnd(".")
    $certCount = 0
    if ($status.CertDomains) {
        $certCount = @($status.CertDomains).Count
    }
    if ($certCount -gt 0) {
        break
    }
    Write-Warn "Tailscale MagicDNS & HTTPS Certificates are not enabled on your tailnet yet."
    Write-Host "  1. Open: https://login.tailscale.com/admin/dns"
    Write-Host "  2. Enable 'MagicDNS' and 'HTTPS Certificates'"
    Read-Host "Press Enter once enabled to re-check (or Ctrl+C to abort)" | Out-Null
}
Write-Ok "Tailscale FQDN: $tsFqdn"

Write-Step "Building tailauth.exe (release)"
Push-Location $ScriptDir
try {
    & cargo build --release
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build --release failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
$builtExe = Join-Path $ScriptDir "target\release\tailauth.exe"
if (-not (Test-Path $builtExe)) {
    throw "Built binary not found at $builtExe"
}
Write-Ok "Built $builtExe"

$InstallDir = "C:\Program Files\TailAuth"
$DataDir = "C:\ProgramData\TailAuth"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Step "Securing $DataDir and writing config.json"
& icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:RX" | Out-Null

$cfgObj = [ordered]@{
    fqdn = $tsFqdn
    https_port = $Port
    listen_addr = "127.0.0.1:$Port"
    socket_path = "\\.\pipe\tailauth"
    store_path = "$DataDir\credentials.json"
    timeout_secs = $Timeout
    allowed_tailscale_users = @($AllowTsUser)
}
$cfgJson = $cfgObj | ConvertTo-Json -Depth 4
$cfgPath = Join-Path $DataDir "config.json"
[System.IO.File]::WriteAllText($cfgPath, "$cfgJson`n", (New-Object System.Text.UTF8Encoding($false)))
& icacls $cfgPath /grant:r "*S-1-5-32-545:R" | Out-Null

$credPath = Join-Path $DataDir "credentials.json"
if (-not (Test-Path $credPath)) {
    [System.IO.File]::WriteAllText($credPath, "{}`n", (New-Object System.Text.UTF8Encoding($false)))
}
& icacls $credPath /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
Write-Ok "Saved $cfgPath"

Write-Step "Installing tailauth.exe and TailAuth Windows Service"
$existingSvc = Get-Service -Name "TailAuth" -ErrorAction SilentlyContinue
if ($existingSvc) {
    if ($existingSvc.Status -ne "Stopped") {
        Stop-Service -Name "TailAuth" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    & sc.exe delete TailAuth | Out-Null
    for ($w = 0; $w -lt 20; $w++) {
        if (-not (Get-Service -Name "TailAuth" -ErrorAction SilentlyContinue)) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
}

$destExe = Join-Path $InstallDir "tailauth.exe"
Copy-Item -Force $builtExe $destExe

$tsudoCmd = "@`"$destExe`" sudo %*`r`n"
[System.IO.File]::WriteAllText((Join-Path $InstallDir "tsudo.cmd"), $tsudoCmd, [System.Text.Encoding]::ASCII)

$binPath = "`"$destExe`" service"
New-Service -Name "TailAuth" `
    -BinaryPathName $binPath `
    -DisplayName "TailAuth Phone Fingerprint Service" `
    -Description "Tailnet WebAuthn phone-fingerprint elevation service for TailAuth." `
    -StartupType Automatic | Out-Null
& sc.exe failure TailAuth reset= 86400 actions= restart/2000/restart/2000/restart/5000 | Out-Null
Start-Service -Name "TailAuth"
Write-Ok "TailAuth Windows Service started"

Write-Step "Configuring Tailscale Serve HTTPS proxy on port $Port"
& $tailscaleExe serve --bg --yes --https=$Port "http://127.0.0.1:$Port" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $tailscaleExe serve --bg --https=$Port "http://127.0.0.1:$Port"
}
Write-Ok "Exposed https://${tsFqdn}:${Port} (Tailnet-only)"

Write-Step "Verifying local daemon health"
$healthy = $false
for ($i = 0; $i -lt 15; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:${Port}/health" -TimeoutSec 2
        if ($resp.ok) {
            $healthy = $true
            break
        }
    } catch {
        Start-Sleep -Milliseconds 300
    }
}
if (-not $healthy) {
    $svcState = (Get-Service -Name "TailAuth" -ErrorAction SilentlyContinue).Status
    Write-Warn "TailAuth service status: $svcState"
    $svcLog = Join-Path $DataDir "service.log"
    if (Test-Path $svcLog) {
        Write-Host "--- $svcLog ---"
        Get-Content -Tail 20 -Path $svcLog
    }
    throw "Daemon health check failed on 127.0.0.1:${Port}"
}
Write-Ok "Daemon health endpoint OK"

Write-Step "Updating Machine PATH"
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$pathParts = @($machinePath -split ";" | Where-Object { $_ -ne "" })
if ($pathParts -notcontains $InstallDir) {
    $newPath = ($pathParts + $InstallDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:PATH = "$InstallDir;$env:PATH"
    Write-Ok "Added $InstallDir to Machine PATH"
} else {
    Write-Ok "$InstallDir already in Machine PATH"
}

if (-not $NoProfile) {
    Write-Step "Adding 'sudo' wrapper to PowerShell profile(s)"
    $block = @"
# tailauth-begin
function sudo {
    if (`$args.Count -eq 0) {
        & "$destExe" --help
    } else {
        & "$destExe" sudo @args
    }
}
# tailauth-end
"@
    $profileTargets = @(
        (Join-Path $env:USERPROFILE "Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
        (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1")
    ) | Select-Object -Unique

    foreach ($prof in $profileTargets) {
        $profDir = Split-Path -Parent $prof
        New-Item -ItemType Directory -Force -Path $profDir | Out-Null
        $existing = ""
        if (Test-Path $prof) {
            $existing = Get-Content -Raw -Path $prof
            $existing = [regex]::Replace($existing, "(?ms)^# tailauth-begin\r?\n.*?^# tailauth-end\r?\n?", "")
        }
        $updated = ($existing.TrimEnd() + "`r`n`r`n" + $block + "`r`n").TrimStart()
        [System.IO.File]::WriteAllText($prof, $updated, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok "Updated $prof"
    }
}

if (-not $SkipEnroll) {
    Write-Step "Enrolling phone fingerprint for Windows user '$env:USERNAME'"
    Write-Host "Make sure your phone is connected to the same Tailnet, then scan the QR code below."
    & $destExe enroll --user $env:USERNAME
} else {
    Write-Warn "Skipping enrollment (-SkipEnroll). Run 'tailauth enroll --user $env:USERNAME' as Administrator."
}

Write-Host "`nTailAuth Windows installation complete!" -ForegroundColor Green
Write-Host "  • Open a new PowerShell window and run: sudo whoami /priv"
Write-Host "  • In CMD / scripts, use: tsudo <command>"
Write-Host "  • Press Enter at the QR prompt any time to fall back to Windows UAC / password."
