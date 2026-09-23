# Restore saved lid setting + stop keep-awake pinger. ASCII ONLY.
$ErrorActionPreference = 'Continue'
$root = 'C:\ProgramData\WinAudioSvc'
$backup = Join-Path $root '_lid_backup.json'
$pidfile = Join-Path $root '_caffeine.pid'

if (Test-Path $pidfile) {
    $old = Get-Content $pidfile -ErrorAction SilentlyContinue
    if ($old) {
        try { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "[caffeine] stopped pid=$old"
    }
    Remove-Item $pidfile -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $backup)) {
    Write-Host "[warn] no backup file -- leaving lid as-is"
    exit 0
}

$state = Get-Content $backup -Raw | ConvertFrom-Json
$scheme = $state.scheme
$ac = $state.ac_lidaction
$dc = $state.dc_lidaction
Write-Host "[restore] scheme=$scheme  backup_ac=$ac  backup_dc=$dc"

# User explicitly said reset lid: 0x0 (Do Nothing) is unsafe for the device,
# promote to 0x1 (Sleep). 0=DoNothing 1=Sleep 2=Hibernate 3=Shutdown.
function _normalize($v) {
    if ($v -eq '0x00000000' -or $v -eq '0x0') { return '0x00000001' } else { return $v }
}
$ac = _normalize $ac
$dc = _normalize $dc
Write-Host "[apply]   ac=$ac  dc=$dc"

powercfg -setacvalueindex $scheme SUB_BUTTONS LIDACTION $ac
powercfg -setdcvalueindex $scheme SUB_BUTTONS LIDACTION $dc
powercfg -setactive $scheme

$q = powercfg -q $scheme SUB_BUTTONS LIDACTION
$acNow = ($q | Select-String 'Current AC Power Setting Index:\s+(0x[0-9a-fA-F]+)').Matches[0].Groups[1].Value
$dcNow = ($q | Select-String 'Current DC Power Setting Index:\s+(0x[0-9a-fA-F]+)').Matches[0].Groups[1].Value
Write-Host "[verify] LIDACTION now  ac=$acNow  dc=$dcNow"
if ($acNow -eq $ac -and $dcNow -eq $dc) {
    Write-Host "OK"
} else {
    Write-Host "MISMATCH -- verify manually"
    exit 1
}
