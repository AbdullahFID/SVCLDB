$ErrorActionPreference='Stop'
$OutDir = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\runtime'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out       = Join-Path $OutDir "unload_medium_$stamp.json"
$sentinel  = Join-Path $OutDir "unload_medium_$stamp.done"
$stderrLog = Join-Path $OutDir "unload_medium_$stamp.stderr.log"
$wrapper   = Join-Path $env:TEMP  "svc_unload_$stamp.bat"
$attacker  = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\attack_unload_only.ps1'
Remove-Item $out,$sentinel,$stderrLog -EA SilentlyContinue

$batContent = "@echo off`r`n" +
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$attacker`" -Out `"$out`" -Sentinel `"$sentinel`" > `"$stderrLog`" 2>&1`r`n" +
    "exit /b %ERRORLEVEL%`r`n"
Set-Content -Path $wrapper -Value $batContent -Encoding ASCII

Write-Host "[unload-driver] out       : $out"
Write-Host "[unload-driver] launching at medium IL..."
& cmd /c "runas /trustlevel:0x20000 `"$wrapper`" 2>&1" | Out-Null
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline -and -not (Test-Path $sentinel)) { Start-Sleep -Milliseconds 300 }
if (-not (Test-Path $sentinel)) { Write-Host 'TIMEOUT'; if (Test-Path $stderrLog) { Get-Content $stderrLog -Raw | Write-Host }; exit 2 }
Start-Sleep -Milliseconds 200
$obj = Get-Content $out -Raw | ConvertFrom-Json
Write-Host ""
Write-Host "=== D4 UNLOAD DEEP-DIVE ==="
Write-Host ("identity       : {0}" -f $obj.env.identity)
Write-Host ("isElevated     : {0}" -f $obj.env.isElevated)
Write-Host ("integrity      : {0}" -f $obj.env.integrityLevel)
Write-Host ("preStatus exit : {0} (0 = payload alive)" -f $obj.preStatus.exitCode)
Write-Host ""
Write-Host ("VECTOR A -- sihost.exe --unload:")
Write-Host ("  exitCode     : {0}" -f $obj.vecA_unload.exitCode)
Write-Host ("  postA status : {0}" -f $obj.postA_status.exitCode)
Write-Host ("  KILLED?      : {0}" -f $obj.vecA_killedPayload)
Write-Host ""
Write-Host ("VECTOR B -- direct SetEvent on derived shutdown event ({0}):" -f $obj.derivedShutdownEvent)
Write-Host ("  opened       : {0}" -f $obj.vecB_directSetEvent.opened)
Write-Host ("  gle          : {0}" -f $obj.vecB_directSetEvent.gle)
Write-Host ("  setEventOk   : {0}" -f $obj.vecB_directSetEvent.setEventOk)
Write-Host ("  postB status : {0}" -f $obj.postB_status.exitCode)
Write-Host ""
Write-Host ("VECTOR C -- sihost.exe --kill:")
Write-Host ("  exitCode     : {0}" -f $obj.vecC_kill.exitCode)
Write-Host ("  postC status : {0}" -f $obj.postC_status.exitCode)
Write-Host ""
Write-Host ("VERDICT        : {0}" -f $obj.verdict)
foreach ($i in $obj.issues) { Write-Host "  * $i" }
Write-Host ""
Write-Host "Full JSON: $out"
Remove-Item $wrapper -EA SilentlyContinue
if ($obj.verdict -eq 'KILLED_BY_MEDIUM_IL') { exit 7 } else { exit 0 }
