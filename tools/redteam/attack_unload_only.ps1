<#
  attack_unload_only.ps1 -- SINGLE-SHOT D4 test at Medium IL.

  Verifies whether medium-IL can actually kill the payload via
  sihost.exe --unload. We can't rely on the launcher's exit code
  (ExitProcess(0) is unconditional) so we:
    1. Confirm payload alive (sihost.exe --status exit==0) from admin FIRST
       (that's the caller — this script is invoked by the driver).
    2. Drop to medium IL.
    3. Try 3 kill vectors:
       a) `sihost.exe --unload`
       b) Direct SetEvent on derived shutdown event
       c) `sihost.exe --kill` (should fail on dwm because dwm is SYSTEM)
    4. Wait 1s.
    5. Check payload state again via --status.

  Result written to $Out.

  Called only via attack_driver_unload.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][string]$Sentinel
)

$ErrorActionPreference='Continue'
$r = [ordered]@{}
$r.startedUtc = (Get-Date).ToUniversalTime().ToString('o')

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class IntDrop {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    public static extern bool ConvertStringSidToSidA(string sid, out IntPtr psid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool SetTokenInformation(IntPtr tok, int cls, IntPtr info, uint sz);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LocalFree(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }
    public static bool DropToMedium() {
        IntPtr sid;
        if (!ConvertStringSidToSidA("S-1-16-8192", out sid)) return false;
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0088u, out tok)) { LocalFree(sid); return false; }
        try {
            uint sidLen = GetLengthSid(sid);
            uint sz = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + sidLen;
            IntPtr buf = Marshal.AllocHGlobal((int)sz);
            try {
                TOKEN_MANDATORY_LABEL tml;
                tml.Label.Sid = sid;
                tml.Label.Attributes = 0x00000020u;
                Marshal.StructureToPtr(tml, buf, false);
                return SetTokenInformation(tok, 25, buf, sz);
            } finally { Marshal.FreeHGlobal(buf); }
        } finally {
            CloseHandle(tok);
            LocalFree(sid);
        }
    }
}
public static class N {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenEventW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
"@

# 1. Sanity - are we currently NOT admin?
$r.env = [ordered]@{
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$dropOk = [IntDrop]::DropToMedium()
$r.env.integrityDropOk = $dropOk
try {
    $wg = whoami /groups /fo csv | ConvertFrom-Csv
    $m = $wg | Where-Object { $_.'Group Name' -like 'Mandatory Label*' } | Select-Object -First 1
    if ($m) { $r.env.integrityLevel = $m.'Group Name' }
} catch {}

# 2. Pre-check: is payload alive right now? (settle in case a reinject
# just landed - init_thread takes ~700ms to publish the shutdown event)
Start-Sleep -Milliseconds 1200
$pre = & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status 2>&1
$r.preStatus = @{ output = ($pre | Out-String).Trim(); exitCode = $LASTEXITCODE }

# 3. Derive shutdown event name
function Get-MachineGuidLower {
    try { $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -EA Stop).MachineGuid } catch { $g = '' }
    if (-not $g) { $g = '3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1' }
    return $g.Trim().ToLower()
}
function Get-DerivedGuid([string]$salt) {
    $g = Get-MachineGuidLower
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $g))
    $sha.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}
$evtShutdown = 'Global\' + (Get-DerivedGuid 'wasvc.evt.shut.1')
$r.derivedShutdownEvent = $evtShutdown

# 4. VECTOR A: sihost.exe --unload
$r.vecA_unload = @{}
try {
    $p = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--unload' -Wait -PassThru -WindowStyle Hidden
    $r.vecA_unload.exitCode = $p.ExitCode
    $r.vecA_unload.startedOk = $true
} catch { $r.vecA_unload.error = "$_" }
Start-Sleep -Milliseconds 800
$s = & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status 2>&1
$r.postA_status = @{ output = ($s | Out-String).Trim(); exitCode = $LASTEXITCODE }
$r.vecA_killedPayload = ($r.preStatus.exitCode -eq 0 -and $r.postA_status.exitCode -ne 0)

# 5. VECTOR B: Direct SetEvent
$r.vecB_directSetEvent = @{}
$SYNCHRONIZE=0x00100000; $EVENT_MODIFY_STATE=0x0002
$h = [N]::OpenEventW([uint32]($SYNCHRONIZE -bor $EVENT_MODIFY_STATE), $false, $evtShutdown)
if ($h -ne [IntPtr]::Zero) {
    $r.vecB_directSetEvent.opened = $true
    $ok = [N]::SetEvent($h)
    $r.vecB_directSetEvent.setEventOk = $ok
    [void][N]::CloseHandle($h)
    Start-Sleep -Milliseconds 800
    $s2 = & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status 2>&1
    $r.postB_status = @{ output = ($s2 | Out-String).Trim(); exitCode = $LASTEXITCODE }
} else {
    $r.vecB_directSetEvent.opened = $false
    $r.vecB_directSetEvent.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
}

# 6. VECTOR C: sihost.exe --kill (should fail; dwm is SYSTEM)
$r.vecC_kill = @{}
try {
    $p2 = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--kill' -Wait -PassThru -WindowStyle Hidden
    $r.vecC_kill.exitCode = $p2.ExitCode
} catch { $r.vecC_kill.error = "$_" }
Start-Sleep -Milliseconds 800
$s3 = & 'C:\ProgramData\WinAudioSvc\sihost.exe' --status 2>&1
$r.postC_status = @{ output = ($s3 | Out-String).Trim(); exitCode = $LASTEXITCODE }

# 7. Verdict
$r.verdict = 'CLEAN'
$r.issues = @()
if ($r.preStatus.exitCode -ne 0) {
    $r.verdict = 'INCONCLUSIVE'
    $r.issues += "Pre-status was $($r.preStatus.exitCode); payload wasn't alive at test start"
}
if ($r.vecA_killedPayload) {
    $r.verdict = 'KILLED_BY_MEDIUM_IL'
    $r.issues += "VECTOR A: sihost.exe --unload from medium-IL killed the payload (pre-status=0 post-status=$($r.postA_status.exitCode))"
}
if ($r.vecB_directSetEvent.setEventOk -and $r.postB_status.exitCode -ne 0) {
    $r.verdict = 'KILLED_BY_MEDIUM_IL'
    $r.issues += "VECTOR B: direct SetEvent on derived shutdown event from medium-IL killed the payload"
}

$r.completedUtc = (Get-Date).ToUniversalTime().ToString('o')
$r | ConvertTo-Json -Depth 8 | Set-Content -Path $Out -Encoding ASCII
'done' | Set-Content -Path $Sentinel -Encoding ASCII
exit 0
