<#
  attack_driver.ps1 -- run attacker_medium_il.ps1 at Medium IL via runas.

  ASCII ONLY (workspace invariant #34).
#>
[CmdletBinding()]
param(
    [switch]$Disrupt,
    [int]$TimeoutSec = 120,
    [string]$OutDir = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\runtime'
)
$ErrorActionPreference='Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$mode  = if ($Disrupt) { 'attack' } else { 'recon' }
$out       = Join-Path $OutDir "${mode}_medium_$stamp.json"
$sentinel  = Join-Path $OutDir "${mode}_medium_$stamp.done"
$stderrLog = Join-Path $OutDir "${mode}_medium_$stamp.stderr.log"
$wrapper   = Join-Path $env:TEMP  "svc_attack_$stamp.bat"

Remove-Item $out,$sentinel,$stderrLog -EA SilentlyContinue

$attacker = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\attacker_medium_il.ps1'
$disruptFlag = if ($Disrupt) { '-Disrupt' } else { '' }

$batContent = "@echo off`r`n" +
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$attacker`" -Out `"$out`" -Sentinel `"$sentinel`" $disruptFlag > `"$stderrLog`" 2>&1`r`n" +
    "exit /b %ERRORLEVEL%`r`n"
Set-Content -Path $wrapper -Value $batContent -Encoding ASCII

Write-Host "[driver] mode      : $mode"
Write-Host "[driver] wrapper   : $wrapper"
Write-Host "[driver] out       : $out"
Write-Host "[driver] sentinel  : $sentinel"
Write-Host "[driver] stderrLog : $stderrLog"
Write-Host "[driver] timeoutSec: $TimeoutSec"
Write-Host "[driver] spawning at Medium IL (runas /trustlevel:0x20000)..."

$rcOut = & cmd /c "runas /trustlevel:0x20000 `"$wrapper`" 2>&1"
Write-Host "[driver] runas emit:"
$rcOut | ForEach-Object { Write-Host "  $_" }

$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not (Test-Path $sentinel)) {
    Start-Sleep -Milliseconds 400
}
if (-not (Test-Path $sentinel)) {
    Write-Host "[driver] TIMEOUT after $TimeoutSec s - sentinel not written"
    if (Test-Path $stderrLog) {
        Write-Host "--- stderr ---"
        Get-Content $stderrLog -Raw | Write-Host
    }
    Remove-Item $wrapper -EA SilentlyContinue
    exit 2
}
Start-Sleep -Milliseconds 200

if (-not (Test-Path $out)) {
    Write-Host "[driver] sentinel present but JSON missing"
    if (Test-Path $stderrLog) { Get-Content $stderrLog -Raw | Write-Host }
    Remove-Item $wrapper -EA SilentlyContinue
    exit 3
}
$json = Get-Content $out -Raw
$obj = $json | ConvertFrom-Json
Write-Host ""
Write-Host "=== MEDIUM-IL $($mode.ToUpper()) RESULTS ==="
Write-Host ("  identity      : {0}" -f $obj.env.identity)
Write-Host ("  isElevated    : {0}" -f $obj.env.isElevated)
Write-Host ("  integrity     : {0}" -f $obj.env.integrityLevel)
Write-Host ("  verdict       : {0}" -f $obj.verdict)
Write-Host ("  issue count   : {0}" -f $obj.issues.Count)
Write-Host ""
if ($obj.issues.Count -gt 0) {
    Write-Host "--- ISSUES ---"
    foreach ($i in $obj.issues) { Write-Host "  * $i" }
}
Write-Host ""
Write-Host "Full JSON: $out"
Remove-Item $wrapper -EA SilentlyContinue

if ($obj.verdict -eq 'DETECTED') { exit 7 }
if ($obj.issues.Count -gt 0) { exit 8 }
exit 0
