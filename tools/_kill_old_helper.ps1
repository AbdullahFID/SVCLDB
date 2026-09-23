# Kill the pre-HMAC helper thread by signaling the OLD SHA256-derived
# iso-halt event. Admin-only. This is a one-time upgrade transient
# helper -- fresh installs never have this issue.

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class N {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenEventW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
"@

$machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid.Trim().ToLower()
function Get-Sha256Guid($salt) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $machineGuid))
    $sha.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}

# Try SALT_EVT_ISO_HALT AND SALT_MTX_SENTINEL (both trigger helper exit)
foreach ($salt in @('wasvc.evt.iso.halt.1', 'wasvc.mtx.sentinel.1', 'wasvc.mtx.emerg.hk.1')) {
    $name = 'Global\' + (Get-Sha256Guid $salt)
    $h = [N]::OpenEventW(0x0002, $false, $name)  # EVENT_MODIFY_STATE
    if ($h -ne [IntPtr]::Zero) {
        [N]::SetEvent($h) | Out-Null
        [N]::CloseHandle($h) | Out-Null
        Write-Host "[SIGNAL] $salt -> $name"
    } else {
        Write-Host "[MISS  ] $salt -> $name (gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
}
Start-Sleep -Seconds 2

# Check if old pipes are gone
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
foreach ($salt in @('wasvc.pipe.iso.1', 'wasvc.pipe.iso.cmd.1')) {
    $name = Get-Sha256Guid $salt
    $present = $pipes -contains $name
    Write-Host "  OLD $salt pipe present: $present"
}
