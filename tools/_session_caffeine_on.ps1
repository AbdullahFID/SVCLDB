# Save current lid setting + set to 'Do Nothing' + start a keep-awake pinger.
# Companion: _session_caffeine_off.ps1 restores the saved state.

$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\WinAudioSvc'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$backup = Join-Path $root '_lid_backup.json'
$pidfile = Join-Path $root '_caffeine.pid'

# --- 1) Snapshot active scheme + current LIDACTION values (AC + DC) ---
$activeLine = (powercfg -getactivescheme)  # e.g. "Power Scheme GUID: ...  (Balanced)"
if ($activeLine -match 'GUID:\s+([0-9a-fA-F-]+)') { $scheme = $Matches[1] } else { throw "cannot parse scheme" }

$q = powercfg -q $scheme SUB_BUTTONS LIDACTION
$ac = ($q | Select-String 'Current AC Power Setting Index:\s+(0x[0-9a-fA-F]+)').Matches[0].Groups[1].Value
$dc = ($q | Select-String 'Current DC Power Setting Index:\s+(0x[0-9a-fA-F]+)').Matches[0].Groups[1].Value

$state = [pscustomobject]@{ scheme = $scheme; ac_lidaction = $ac; dc_lidaction = $dc; saved_utc = (Get-Date).ToUniversalTime().ToString('o') }
$state | ConvertTo-Json | Set-Content -Path $backup -Encoding ASCII
Write-Host "[saved] scheme=$scheme ac=$ac dc=$dc  -> $backup"

# --- 2) Override lid to 'Do Nothing' (0) on both AC and DC ---
powercfg -setacvalueindex $scheme SUB_BUTTONS LIDACTION 0
powercfg -setdcvalueindex $scheme SUB_BUTTONS LIDACTION 0
powercfg -setactive $scheme
Write-Host "[set] LIDACTION=0 (Do Nothing) AC+DC on active scheme"

# --- 3) Start a detached keep-awake process using SetThreadExecutionState.
# Kill any previous instance we started.
if (Test-Path $pidfile) {
    $old = Get-Content $pidfile -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue }
    Remove-Item $pidfile -Force -ErrorAction SilentlyContinue
}

$stub = @'
Add-Type -Name PWR -Namespace S -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern uint SetThreadExecutionState(uint esFlags);
"@
# ES_CONTINUOUS(0x80000000) | ES_SYSTEM_REQUIRED(0x01) | ES_DISPLAY_REQUIRED(0x02) | ES_AWAYMODE_REQUIRED(0x40)
[void][S.PWR]::SetThreadExecutionState(0x80000043)
while ($true) {
    [void][S.PWR]::SetThreadExecutionState(0x80000043)
    Start-Sleep -Seconds 30
}
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($stub))
$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-WindowStyle','Hidden','-EncodedCommand',$encoded) -PassThru -WindowStyle Hidden
Set-Content -Path $pidfile -Value $p.Id -Encoding ASCII
Write-Host "[caffeine] pid=$($p.Id) (writes SetThreadExecutionState every 30s)"
Write-Host "OK"
