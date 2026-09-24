# Test: corrupt offsets.blob validation snapshot -> payload should SAFE-MODE.
# Restores blob afterwards.
$ErrorActionPreference = 'Stop'
$blob = 'C:\ProgramData\WinAudioSvc\offsets.blob'
$backup = "$blob.bak-safemode-test"
$logs = @{
    payload  = 'C:\ProgramData\WinAudioSvc\msvc_dbg_a.dat'
    launcher = 'C:\ProgramData\WinAudioSvc\msvc_dbg_b.dat'
}
$before_size = @{}
foreach ($k in $logs.Keys) { $before_size[$k] = if (Test-Path $logs[$k]) { (Get-Item $logs[$k]).Length } else { 0 } }

Write-Host "== 1. backing up blob =="
Copy-Item $blob $backup -Force
$sz = (Get-Item $blob).Length
Write-Host "  blob is $sz bytes (expect 304 for v2)"
if ($sz -ne 304) { Write-Host "  NOT v2 blob -- can't test snapshot validation"; exit 2 }

Write-Host "`n== 2. corrupting prologue_present bytes (offset 192+16 = 208, 32 bytes) =="
$data = [IO.File]::ReadAllBytes($blob)
# ext layout: magic(4) + tds(4) + size(4) + flags(4) = 16 bytes header, THEN prologue_present[32] at offset 192+16 = 208
for ($i = 0; $i -lt 32; $i++) { $data[208 + $i] = 0xFF }
[IO.File]::WriteAllBytes($blob, $data)
Write-Host "  wrote 32 x 0xFF at offset 208 (prologue_present)"

Write-Host "`n== 3. sihost.exe --reinject (expect SAFE-MODE) =="
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' `
    -ArgumentList '--reinject','--quiet' -PassThru -Wait -NoNewWindow
$sw.Stop()
Write-Host "  exit=$($p.ExitCode)  elapsed=$($sw.ElapsedMilliseconds)ms"

Start-Sleep -Seconds 3

Write-Host "`n== 4. payload log tail (looking for SAFE-MODE) =="
pwsh -NoProfile -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 `
    -Path $logs.payload -Tail 30 |
    Select-String -Pattern 'blob|validate|SAFE-MODE|hooks|degraded|Present fired count=[0-9]+' |
    Select-Object -Last 20

Write-Host "`n== 5. dwm alive check =="
Get-Process dwm -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table -AutoSize

Write-Host "`n== 6. RESTORING blob + re-arming =="
Copy-Item $backup $blob -Force
Remove-Item $backup -Force
$p2 = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' `
    -ArgumentList '--reinject','--quiet' -PassThru -Wait -NoNewWindow
Write-Host "  restore-arm exit=$($p2.ExitCode)"

Start-Sleep -Seconds 3
Write-Host "`n== 7. payload log tail after restore (looking for hooks_install: SUCCESS + Present) =="
pwsh -NoProfile -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 `
    -Path $logs.payload -Tail 20 |
    Select-String -Pattern 'validate|hooks_install|Present fired count=' |
    Select-Object -Last 10
