# Wrapper: run a given PowerShell script at a FAITHFUL medium-IL user
# context by scheduling it as a Task Scheduler task with RunLevel=Limited.
# That uses the interactive user's UAC-filtered token = real medium IL,
# admin group deny-only, matches how a proctor/exam app actually runs.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Script,
    [string]$ExtraArgs = '',
    [string]$OutFile = "$env:TEMP\svc_medium_out_$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    [int]$TimeoutSec = 240,
    [string]$TaskName = "svc_medium_probe_$(Get-Date -Format 'yyyyMMddHHmmss')"
)

# Build .bat that runs the target script + writes DONE marker
$bat = "$env:TEMP\svc_medium_run_$(Get-Date -Format 'yyyyMMddHHmmss').bat"
$cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Script`" $ExtraArgs >`"$OutFile`" 2>&1"
Set-Content -Path $bat -Value @"
@echo off
$cmd
echo DONE_MARKER_2026>>`"$OutFile`"
"@ -Encoding ASCII

Write-Host "[medium-IL] script  : $Script" -ForegroundColor DarkGray
Write-Host "[medium-IL] args    : $ExtraArgs" -ForegroundColor DarkGray
Write-Host "[medium-IL] outfile : $OutFile" -ForegroundColor DarkGray

# Determine interactive user (the console user's SID, not necessarily my elevated whoami)
$consoleUser = $env:USERNAME  # in the elevated shell we're logged in as; matches interactive user

$act    = New-ScheduledTaskAction    -Execute 'cmd.exe' -Argument "/c `"$bat`""
$prin   = New-ScheduledTaskPrincipal -UserId $consoleUser -RunLevel Limited -LogonType Interactive
$sett   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::FromSeconds($TimeoutSec))
$trig   = New-ScheduledTaskTrigger    -Once -At (Get-Date).AddSeconds(5)

$task = New-ScheduledTask -Action $act -Principal $prin -Settings $sett -Trigger $trig
try {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
} catch {
    Write-Host "[medium-IL] task register/start failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item $bat -Force -EA SilentlyContinue
    return
}

# Poll for the DONE marker
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 700
    if (Test-Path $OutFile) {
        $txt = Get-Content $OutFile -Raw -EA SilentlyContinue
        if ($txt -and $txt -match 'DONE_MARKER_2026') { break }
    }
}

# Cleanup
try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -EA SilentlyContinue } catch {}
Remove-Item $bat -Force -EA SilentlyContinue

if (Test-Path $OutFile) {
    Write-Host "----- BEGIN medium-IL output -----" -ForegroundColor DarkGray
    Get-Content $OutFile -Raw
    Write-Host "----- END medium-IL output   -----" -ForegroundColor DarkGray
} else {
    Write-Host "[medium-IL] no output file was created" -ForegroundColor Red
}
