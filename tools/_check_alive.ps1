& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
Write-Host "status exit=$LASTEXITCODE"
$dwm = Get-Process dwm -EA SilentlyContinue
Write-Host "dwm pid=$($dwm.Id) start=$($dwm.StartTime)"
$sihosts = Get-Process sihost -EA SilentlyContinue
foreach ($s in $sihosts) { Write-Host "  sihost pid=$($s.Id) path=$($s.Path)" }
Write-Host "=== last 12 launcher.log lines ==="
pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\launcher.log -Tail 12
Write-Host "=== last 8 payload.log lines ==="
pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\payload.log -Tail 8
