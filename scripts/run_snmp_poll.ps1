<#
.SYNOPSIS
    Run Background SNMP Poller Service for School Network Monitor.
.DESCRIPTION
    Polls configured switches in config.yaml for FDP/LLDP neighbors and FDB MAC table.
#>

[CmdletBinding()]
param(
    [switch]$Once
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location -Path $ProjectRoot

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment not found at $VenvPython. Please run .\rebuild_project.bat first."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " School Network Monitor - SNMP Poller Service            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if ($Once) {
    Write-Host "[INFO] Executing single-pass SNMP poll..." -ForegroundColor Green
    & $VenvPython -m services.snmp_poller --once
} else {
    Write-Host "[INFO] Starting continuous SNMP Poller background loop..." -ForegroundColor Green
    & $VenvPython -m services.snmp_poller
}
