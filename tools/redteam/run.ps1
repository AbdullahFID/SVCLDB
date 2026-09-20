<#
  run.ps1 -- svcldb v3 red-team orchestrator (SAFE by default).

  Runs the co-evolution measurement: point the hunter + probes at
  whatever svcldb state is live and produce one scorecard. Designed so
  the hider (App A) never learns it is being measured.

  SAFETY MODEL (device-lock)
  --------------------------
  The DEFAULT run is 100% read-only (pipe enum, object probes, module
  wall, window enum). Nothing here can lock the device.

  The ENFORCEMENT test (-Enforce) is the ONLY path that can freeze
  input, and it is wrapped in four independent releases so you always
  get control back:
    1. Auto-release watchdog -- a separate process force-kills the
       enforcer after -AutoReleaseSec wall-clock seconds no matter what.
    2. Escape hotkey -- Ctrl+Alt+Shift+F9 is whitelisted and wired
       straight to release+exit.
    3. PID kill in finally{} -- taskkill is unaffected by input-block.
    4. Reboot -- nothing here survives a reboot.
  -Enforce is OFF by default and must be passed explicitly.

  INTEGRITY
  ---------
  The hunter's existence/wall classification is integrity-sensitive.
  Pass -MediumIL to relaunch the hunter de-elevated (via
  runas /trustlevel:0x20000) so it models the real non-admin proctor.
  From an elevated shell the DWM wall misreports as INCONCLUSIVE.

  USAGE
    # safe detection scorecard (run from a NON-elevated shell ideally):
    pwsh -File tools\redteam\run.ps1

    # force the hunter to medium IL even from an elevated shell:
    pwsh -File tools\redteam\run.ps1 -MediumIL

    # DANGEROUS input-denial test, auto-released after 15s:
    pwsh -File tools\redteam\run.ps1 -Enforce -AutoReleaseSec 15
#>
[CmdletBinding()]
param(
    [switch]$MediumIL,
    [switch]$Enforce,
    [int]$AutoReleaseSec = 15,
    [string]$OutDir = "$PSScriptRoot\runtime"
)

$ErrorActionPreference = 'Stop'
$repo       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # ...\svcldb
$hunter     = Join-Path (Split-Path -Parent $repo) 'hooksdll\proctor-sim\src\lib\svcldb-hunter.js'
$probe      = Join-Path $PSScriptRoot 'probes\probe_named_objects.ps1'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

function Write-Head($t) { Write-Host ""; Write-Host ("=== {0} ===" -f $t) -ForegroundColor Cyan }

# --- de-elevation helper: relaunch a command at medium IL -------------
# runas /trustlevel:0x20000 drops the elevated token to a restricted
# (medium-IL-equivalent) context -- enough to model a non-admin hunter
# without needing the interactive user's token.
function Invoke-MediumIL($cmd) {
    $tmp = Join-Path $env:TEMP ("svc_mil_{0}.txt" -f ([guid]::NewGuid().ToString('N')))
    $full = "$cmd > `"$tmp`" 2>&1"
    try {
        cmd /c "runas /trustlevel:0x20000 `"cmd /c $full`"" | Out-Null
        Start-Sleep -Milliseconds 400
        if (Test-Path $tmp) { Get-Content $tmp -Raw }
    } finally {
        # best-effort; the child may still be flushing
    }
}

$scorecard = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    host      = $env:COMPUTERNAME
    mode      = if ($Enforce) { 'enforce' } elseif ($MediumIL) { 'detect-mediumIL' } else { 'detect' }
    results   = [ordered]@{}
    verdict   = 'CLEAN'
}

# --- 1. named-object probe -------------------------------------------
Write-Head "named-object probe"
$probeJson = Join-Path $OutDir 'named_objects.json'
$probeExit = 0
try {
    if ($MediumIL) {
        Invoke-MediumIL "pwsh -NoProfile -ExecutionPolicy Bypass -File `"$probe`" -Json `"$probeJson`""
        Write-Host "(ran de-elevated; see $probeJson)"
    } else {
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $probe -Json $probeJson
        $probeExit = $LASTEXITCODE
    }
} catch { Write-Host "probe error: $_" -ForegroundColor Yellow }
$scorecard.results['named_objects'] = @{ json = $probeJson; exit = $probeExit }
if ($probeExit -eq 7) { $scorecard.verdict = 'DETECTED' }

# --- 2. svcldb hunter (proctor-sim) ----------------------------------
Write-Head "svcldb hunter (proctor-sim)"
$huntJson = Join-Path $OutDir 'hunt.json'
if (-not (Test-Path $hunter)) {
    Write-Host "hunter not found at $hunter" -ForegroundColor Yellow
} else {
    if ($MediumIL) {
        Invoke-MediumIL "node `"$hunter`" --json `"$huntJson`""
        Write-Host "(ran de-elevated; see $huntJson)"
    } else {
        & node $hunter --json $huntJson
        if ($LASTEXITCODE -eq 7) { $scorecard.verdict = 'DETECTED' }
    }
    $scorecard.results['hunter'] = @{ json = $huntJson }
    if (Test-Path $huntJson) {
        try { if ((Get-Content $huntJson -Raw | ConvertFrom-Json).verdict -eq 'DETECTED') { $scorecard.verdict = 'DETECTED' } } catch {}
    }
}

# --- 3. enforcement (DANGEROUS, opt-in) -------------------------------
if ($Enforce) {
    Write-Head "INPUT-DENIAL ENFORCEMENT (auto-release ${AutoReleaseSec}s)"
    Write-Host "Escape hotkey: Ctrl+Alt+Shift+F9. Watchdog will force-release." -ForegroundColor Yellow
    $enforcer = Join-Path $PSScriptRoot 'probes\probe_input_denial.ps1'
    if (-not (Test-Path $enforcer)) {
        Write-Host "enforcement probe not yet present ($enforcer) -- skipping." -ForegroundColor Yellow
        Write-Host "(build probes\probe_input_denial.ps1 to run the LL-swallow test.)" -ForegroundColor DarkGray
    } else {
        # Watchdog: hard-kill the enforcer after the bound no matter what.
        $wd = Start-Job -ScriptBlock {
            param($sec)
            Start-Sleep -Seconds $sec
            Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" |
                Where-Object { $_.CommandLine -match 'probe_input_denial' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } -ArgumentList $AutoReleaseSec
        try {
            & pwsh -NoProfile -ExecutionPolicy Bypass -File $enforcer -AutoReleaseSec $AutoReleaseSec -EscapeHotkey 'CtrlAltShiftF9'
        } finally {
            Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" |
                Where-Object { $_.CommandLine -match 'probe_input_denial' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            Stop-Job $wd -ErrorAction SilentlyContinue; Remove-Job $wd -ErrorAction SilentlyContinue
            Write-Host "enforcement released." -ForegroundColor Green
        }
    }
}

# --- scorecard --------------------------------------------------------
Write-Head "SCORECARD"
$scPath = Join-Path $OutDir 'scorecard.json'
$scorecard | ConvertTo-Json -Depth 6 | Set-Content -Path $scPath -Encoding ASCII
$col = if ($scorecard.verdict -eq 'CLEAN') { 'Green' } else { 'Red' }
Write-Host ("mode    : {0}" -f $scorecard.mode)
Write-Host ("verdict : {0}" -f $scorecard.verdict) -ForegroundColor $col
Write-Host ("scorecard: {0}" -f $scPath)
if ($scorecard.verdict -eq 'DETECTED') { exit 7 } else { exit 0 }
