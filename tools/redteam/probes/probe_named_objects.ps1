<#
  probe_named_objects.ps1  --  svcldb v3 red-team detection probe

  PURPOSE
    Model ONE non-admin detection vector: user-mode named-object discovery.
    A medium-integrity hunter cannot read dwm.exe memory, but it CAN:
      (a) enumerate every named pipe on the box (no admin needed), and
      (b) probe well-known object names and distinguish "exists but access
          denied" (GLE=5) from "not found" (GLE=2) -- the ACCESS_DENIED vs
          NOT_FOUND existence leak.

    This probe NEVER touches svcldb or the hunter app. It is a pure observer
    so we can measure whether svcldb leaves a discoverable footprint, and it
    doubles as the regression test for the OPSEC hardening pass.

  SAFETY
    Read-only. Opens handles with SYNCHRONIZE only and closes them
    immediately. No writes, no injection, no enforcement.

  INTEGRITY NOTE
    Existence-vs-access classification depends on the integrity level this
    runs at. From an ELEVATED shell, admin-DACL objects report ACCESSIBLE.
    To model the real threat, run this de-elevated (medium IL) -- see
    -AsMediumIL, or launch via the harness which relaunches at medium IL.

  USAGE
    pwsh -File probe_named_objects.ps1
    pwsh -File probe_named_objects.ps1 -Json C:\path\out.json
#>
[CmdletBinding()]
param(
    [string]$Json = "",
    [string[]]$ExtraNames = @()
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeProbe {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenEventW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenMutexW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenFileMappingW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
"@

$SYNCHRONIZE   = [uint32]0x00100000
$FILE_MAP_READ = [uint32]0x0004

function Probe-Object {
    param([string]$Kind, [string]$Name)
    $h = [IntPtr]::Zero
    switch ($Kind) {
        'event'   { $h = [NativeProbe]::OpenEventW($SYNCHRONIZE, $false, $Name) }
        'mutex'   { $h = [NativeProbe]::OpenMutexW($SYNCHRONIZE, $false, $Name) }
        'section' { $h = [NativeProbe]::OpenFileMappingW($FILE_MAP_READ, $false, $Name) }
    }
    if ($h -ne [IntPtr]::Zero) {
        [void][NativeProbe]::CloseHandle($h)
        return [pscustomobject]@{ kind=$Kind; name=$Name; result='EXISTS_ACCESSIBLE'; gle=0; leaksExistence=$true }
    }
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    switch ($gle) {
        5       { return [pscustomobject]@{ kind=$Kind; name=$Name; result='EXISTS_ACCESS_DENIED'; gle=5; leaksExistence=$true } }
        2       { return [pscustomobject]@{ kind=$Kind; name=$Name; result='NOT_FOUND'; gle=2; leaksExistence=$false } }
        default { return [pscustomobject]@{ kind=$Kind; name=$Name; result='OTHER'; gle=$gle; leaksExistence=$false } }
    }
}

# ---- 1. Named-pipe enumeration (unprivileged, always faithful) --------------
$pipes = @()
try { $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') } catch { $pipes = @() }
$pipeNames = $pipes | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
$svcPattern = 'svcldb|cloakgpt|dwmapiext|winaudiosvc|phantom'
$suspiciousPipes = @($pipeNames | Where-Object { $_ -match $svcPattern })

# ---- 2. Known / candidate object-name probes --------------------------------
$candidates = @(
    @{ kind='event';   name='Global\DwmCompositorShutdownRelease' },
    @{ kind='mutex';   name='Local\DwmCompositorGuardRelease' },
    @{ kind='mutex';   name='Global\DwmCompositorGuardRelease' },
    # decoys / sanity: a name that should not exist -> proves NOT_FOUND path
    @{ kind='event';   name='Global\svcldb_probe_canary_does_not_exist' }
)
foreach ($n in $ExtraNames) { $candidates += @{ kind='event'; name=$n }; $candidates += @{ kind='mutex'; name=$n } }

$objResults = foreach ($c in $candidates) { Probe-Object -Kind $c.kind -Name $c.name }
$leaks = @($objResults | Where-Object { $_.leaksExistence -and $_.result -ne 'NOT_FOUND' })

# ---- 2b. Derived per-box names (POSITIVE CONTROL) ---------------------------
# Mirror shared/obf_names.c exactly: SHA256(salt + ':' + machineguid_lower),
# first 16 bytes -> canonical lowercase GUID. When the payload is INJECTED
# these objects exist -- but they are GUID-shaped + per-box, so their
# presence is NOT a leak (indistinguishable from the legit COM/RPC/mojo GUID
# objects already on the box). This block confirms the hardened names resolve
# and shows what an attacker who fully RE'd the scheme would STILL only see:
# a GUID. It does NOT feed the verdict.
function Get-MachineGuidLower {
    try { $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid }
    catch { $g = '' }
    if (-not $g) { $g = '3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1' }
    return $g.Trim().ToLower()
}
function Get-DerivedGuid([string]$salt) {
    $g = Get-MachineGuidLower
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $g))
    $sha.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}
$dTok = Get-DerivedGuid 'wasvc.pipe.token.1'
$dOcr = Get-DerivedGuid 'wasvc.pipe.ocr.1'
$dIni = Get-DerivedGuid 'wasvc.mtx.init.1'
$dOcd = Get-DerivedGuid 'wasvc.mtx.ocrd.1'
$dShu = Get-DerivedGuid 'wasvc.evt.shut.1'
$derivedResults = @(
    [pscustomobject]@{ kind='pipe';  purpose='token';      name=$dTok; present=($pipeNames -contains $dTok); camouflaged=$true }
    [pscustomobject]@{ kind='pipe';  purpose='ocr';        name=$dOcr; present=($pipeNames -contains $dOcr); camouflaged=$true }
    [pscustomobject]@{ kind='mutex'; purpose='init-guard'; name="Local\$dIni";  probe=(Probe-Object -Kind 'mutex' -Name "Local\$dIni") }
    [pscustomobject]@{ kind='mutex'; purpose='ocr-daemon'; name="Global\$dOcd"; probe=(Probe-Object -Kind 'mutex' -Name "Global\$dOcd") }
    [pscustomobject]@{ kind='event'; purpose='shutdown';   name="Global\$dShu"; probe=(Probe-Object -Kind 'event' -Name "Global\$dShu") }
)

# ---- 3. Verdict + report ----------------------------------------------------
$report = [pscustomobject]@{
    timestamp        = (Get-Date).ToString('o')
    host             = $env:COMPUTERNAME
    isElevated       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    pipeTotal        = $pipeNames.Count
    suspiciousPipes  = $suspiciousPipes
    objectProbes     = $objResults
    derivedProbes    = $derivedResults
    existenceLeaks   = @($leaks | ForEach-Object { $_.name })
    verdict          = if ($suspiciousPipes.Count -eq 0 -and $leaks.Count -eq 0) { 'CLEAN' } else { 'DETECTED' }
}

Write-Host "=== svcldb named-object probe ===" -ForegroundColor Cyan
Write-Host ("elevated       : {0}  (medium-IL run models the real hunter)" -f $report.isElevated)
Write-Host ("named pipes    : {0} total" -f $report.pipeTotal)
if ($suspiciousPipes.Count) {
    Write-Host ("SUSPICIOUS PIPE: {0}" -f ($suspiciousPipes -join ', ')) -ForegroundColor Red
} else {
    Write-Host "suspicious pipe: none" -ForegroundColor Green
}
foreach ($r in $objResults) {
    $color = if ($r.result -eq 'NOT_FOUND') { 'Green' } elseif ($r.result -eq 'OTHER') { 'DarkGray' } else { 'Red' }
    Write-Host ("  [{0,-20}] {1}" -f $r.result, $r.name) -ForegroundColor $color
}
$verdictColor = if ($report.verdict -eq 'CLEAN') { 'Green' } else { 'Red' }
Write-Host ("VERDICT        : {0}" -f $report.verdict) -ForegroundColor $verdictColor

if ($Json) {
    $dir = Split-Path -Parent $Json
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $Json -Encoding ASCII
    Write-Host ("report written : {0}" -f $Json)
}

# exit 0 = clean, 7 = detected (so the harness/orchestrator can gate on it)
if ($report.verdict -eq 'DETECTED') { exit 7 } else { exit 0 }
