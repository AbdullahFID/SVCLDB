# Version of the persistence test that forces prod-strict semantics
# via SVCLDB_STRICT_UNLOAD=1 (dev-bypass build honors this env var).
# Expected: admin --unload from powershell parent -> sentinel NOT
# written -> winlogon watchdog auto-reinjects within ~30s.
$ErrorActionPreference='Continue'
$env:SVCLDB_STRICT_UNLOAD = '1'

# Nuke any stale .dwm_clean_shutdown from prior tests so this test is
# starting clean.
Remove-Item 'C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown' -Force -EA SilentlyContinue

Write-Host "=== pre: verify payload alive ==="
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
$pre = $LASTEXITCODE
Write-Host "pre exit=$pre  (0=loaded)"
if ($pre -ne 0) { Write-Host "payload not alive to start with -- aborting test"; exit 1 }

Write-Host ""
Write-Host "=== fire: admin --unload with SVCLDB_STRICT_UNLOAD=1 (env inherited) ==="
$p = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--unload' -Wait -PassThru -WindowStyle Hidden
Write-Host "  unload exit=$($p.ExitCode)"

Write-Host ""
Write-Host "=== immediate post-unload status (payload should be dying/dead) ==="
Start-Sleep -Milliseconds 500
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
Write-Host "  post-500ms exit=$LASTEXITCODE"

Write-Host ""
Write-Host "=== verify sentinel was NOT written ==="
if (Test-Path 'C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown') {
    Write-Host "  .dwm_clean_shutdown STILL EXISTS -- gate broken"
} else {
    Write-Host "  .dwm_clean_shutdown ABSENT -- watchdog should reinject"
}

Write-Host ""
Write-Host "=== watching for winlogon-watchdog auto-reinject (up to 45s) ==="
for ($t = 1; $t -le 45; $t++) {
    Start-Sleep -Seconds 1
    & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  T+${t}s: RESTORED (payload loaded again via watchdog)"
        Write-Host ""
        Write-Host "=== VERDICT: admin non-destructive unload is TRANSIENT (watchdog restored in ${t}s) ==="
        exit 0
    }
    Write-Host "  T+${t}s: still gone"
}
Write-Host ""
Write-Host "=== VERDICT: watchdog did NOT auto-reinject in 45s -- FIX INCOMPLETE ==="
exit 7
