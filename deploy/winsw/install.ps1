# dossier Windows Service install script (Plan 013 WI-4.1)
#
# Prerequisites:
#   - Python 3.12+ installed and on PATH
#   - WinSW.exe (v2.12.0+) downloaded and renamed to dossier-service.exe
#     in the deploy directory (e.g. C:\ProgramData\dossier\)
#   - Postgres reachable from this host
#   - regista provision already run for the target project
#
# Usage (PowerShell as admin):
#   .\install.ps1 -InstallDir C:\ProgramData\dossier
#
# What this script does:
#   1. Creates the install directory structure
#   2. Creates a Python venv and installs dossier + regista
#   3. Generates the environment file (dossier-env.cmd) from prompts
#   4. Installs and starts the Windows Service via WinSW

param(
    [string]$InstallDir = "C:\ProgramData\dossier",
    [string]$RegistaRef = "",  # pin to a SHA; empty = latest from main
    [switch]$SkipVenv
)

$ErrorActionPreference = "Stop"

# --- 1. Directory structure ---
$Dirs = @("", "venv", "logs", "secrets")
foreach ($d in $Dirs) {
    $path = Join-Path $InstallDir $d
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# --- 2. Python venv + install ---
if (-not $SkipVenv) {
    Write-Host "Creating Python venv..."
    python -m venv "$InstallDir\venv"

    $Pip = "$InstallDir\venv\Scripts\pip.exe"
    & $Pip install --upgrade pip

    if ($RegistaRef) {
        & $Pip install "regista @ git+https://github.com/hraedon/regista.git@$RegistaRef"
    } else {
        & $Pip install "regista @ git+https://github.com/hraedon/regista.git@main"
    }

    Write-Host "Installing dossier..."
    & $Pip install -e ".[auth-ldap]"
}

# --- 3. Environment file ---
$EnvFile = "$InstallDir\dossier-env.cmd"
if (-not (Test-Path $EnvFile)) {
    Write-Host "Generating dossier-env.cmd..."
    $Dsn = Read-Host "Enter the Postgres DSN (e.g. postgresql://user:pass@host:5432/db)"
    $Project = Read-Host "Enter the project slug (e.g. dossier)"
    $KeyPath = Read-Host "Enter the path to the HMAC keyset file"
    $SessionSecret = -join ((48..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})

    @"
@echo off
set REGISTA_DSN=$Dsn
set DOSSIER_PROJECT=$Project
set REGISTA_KEY_PATH=$KeyPath
set DOSSIER_SESSION_SECRET=$SessionSecret
set DOSSIER_SECURE_COOKIES=true
set DOSSIER_AUTH_BACKEND=local
set DOSSIER_USERS_PATH=$InstallDir\users.json
set DOSSIER_PASSWORD_SCRYPT_N=16384
"@ | Set-Content -Path $EnvFile -Encoding ASCII

    Write-Host "dossier-env.cmd created. Session secret auto-generated."
    Write-Host "NOTE: scrypt N set to 16384 for Windows compatibility (Plan 016 spike)."
} else {
    Write-Host "dossier-env.cmd already exists, skipping."
}

# --- 4. WinSW service ---
$ServiceExe = "$InstallDir\dossier-service.exe"
$ServiceXml = "$InstallDir\dossier-service.xml"

if (-not (Test-Path $ServiceExe)) {
    Write-Host ""
    Write-Host "WinSW not found at $ServiceExe"
    Write-Host "Download WinSW v2.12.0+ from https://github.com/winsw/winsw/releases"
    Write-Host "Rename WinSW-x64.exe to dossier-service.exe and place it in $InstallDir"
    Write-Host "Then re-run this script with -SkipVenv"
    exit 1
}

# Copy the XML config if not present
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path "$ScriptDir\dossier-service.xml") {
    Copy-Item "$ScriptDir\dossier-service.xml" $ServiceXml -Force
}

Write-Host "Installing service..."
& $ServiceExe install

Write-Host "Starting service..."
& $ServiceExe start

Write-Host ""
Write-Host "dossier service installed and started."
Write-Host "  Web UI: http://localhost:8000"
Write-Host "  Logs:   $InstallDir\logs"
Write-Host "  Config: $InstallDir\dossier-env.cmd"
Write-Host ""
Write-Host "To manage the service:"
Write-Host "  Stop:   $ServiceExe stop"
Write-Host "  Start:  $ServiceExe start"
Write-Host "  Remove: $ServiceExe uninstall"
