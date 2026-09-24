# Force fresh resolve + arm + verify -- for validating multi-build support work.
$ErrorActionPreference = 'Continue'
$deploy = 'C:\ProgramData\WinAudioSvc'
$logs   = @("$deploy\msvc_dbg_a.dat", "$deploy\msvc_dbg_b.dat", "$deploy\msvc_dbg_f.dat")

Write-Host "== BEFORE =="
Get-ChildItem $logs, "$deploy\offsets.blob", "$deploy\offsets.blob.sig" -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize

$before = @{}
foreach ($p in $logs) { $before[$p] = if (Test-Path $p) { (Get-Item $p).Length } else { 0 } }

Write-Host "`n== deleting offsets.blob.sig to force fresh resolve =="
Remove-Item "$deploy\offsets.blob.sig" -Force -ErrorAction SilentlyContinue

Write-Host "`n== ARM: sihost.exe --reinject --quiet =="
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath "$deploy\sihost.exe" `
    -ArgumentList '--reinject','--quiet' -PassThru -Wait -NoNewWindow
$sw.Stop()
Write-Host "exit=$($p.ExitCode) elapsed=$($sw.ElapsedMilliseconds)ms"

Start-Sleep -Seconds 5

Write-Host "`n== AFTER =="
Get-ChildItem $logs, "$deploy\offsets.blob", "$deploy\offsets.blob.sig" -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize

Write-Host "`n== deltas =="
foreach ($p in $logs) {
    $now = if (Test-Path $p) { (Get-Item $p).Length } else { 0 }
    "{0,-50} +{1}" -f (Split-Path $p -Leaf), ($now - $before[$p]) | Write-Host
}

Write-Host "`n== offsets.blob sizeof =="
$blobSz = (Get-Item "$deploy\offsets.blob" -ErrorAction SilentlyContinue).Length
$expectedV2 = 192 + 96
$blobKind = switch ($blobSz) {
    168 { 'legacy v1' }
    192 { 'v1.7 (no validation snapshot)' }
    288 { 'v2 (WITH validation snapshot -- WHAT WE WANT)' }
    default { "UNKNOWN size $blobSz" }
}
Write-Host "  offsets.blob = $blobSz bytes -- $blobKind"

Write-Host "`n== payload.log tail (msvc_dbg_a.dat) =="
pwsh -NoProfile -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 `
    -Path "$deploy\msvc_dbg_a.dat" -Tail 40 |
    Select-String -Pattern 'blob:|blob-ext:|validate:|hooks_install|HANDSHAKE|IsOverlayPrevented|ForceFullDirty|SAFE-MODE|compose_degraded|get_backbuffer|Present fired count=6' |
    Select-Object -First 30

Write-Host "`n== launcher.log tail (msvc_dbg_b.dat) =="
pwsh -NoProfile -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 `
    -Path "$deploy\msvc_dbg_b.dat" -Tail 20 |
    Select-String -Pattern 'reinject|resolver|CHANGED|refreshed|inject ok|helper' |
    Select-Object -First 15
