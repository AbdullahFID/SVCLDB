#requires -RunAsAdministrator
# Kill payload inside DWM (best-effort) + delete install dir.

$InstallDir = 'C:\ProgramData\WinAudioSvc'
$InjectExe  = Join-Path $InstallDir 'sihost.exe'  # not used — launcher unload path is via named event

# Signal cooperative unload (payload's shutdown watcher picks this up).
try {
    Add-Type -MemberDefinition @'
        [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenEvent(uint desiredAccess, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetEvent(IntPtr h);
        [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
'@ -Name Ev -Namespace Native
    $h = [Native.Ev]::OpenEvent(2, $false, 'Global\SVCLDB_Shutdown')
    if ($h -ne [IntPtr]::Zero) {
        [Native.Ev]::SetEvent($h) | Out-Null
        [Native.Ev]::CloseHandle($h) | Out-Null
        Write-Host 'Signaled payload shutdown; waiting 2s for it to unload...'
        Start-Sleep -Seconds 2
    } else {
        Write-Host 'Payload not running (no shutdown event).'
    }
} catch {}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Write-Warning "Could not remove $InstallDir — probably file locks. Reboot + retry."
    } else {
        Write-Host "Removed $InstallDir"
    }
}
