<#
  attacker_medium_il.ps1 -- Aggressive medium-IL red-team attacker.

  Runs at Medium IL (no admin group, integrity=Medium, non-elevated).
  Simulates the most aggressive proctor / exam-app style detection +
  DoS attempts a normal-user app could throw. Writes results to $Out.

  DO NOT run this elevated. Driver script (attack_driver.ps1) spawns
  us via runas /trustlevel:0x20000 for proper Medium-IL context.

  ASCII ONLY (per workspace invariant #34 - PS5.1 reads utf-8 as cp1252
  without BOM; em-dashes / smart quotes / box-drawing get mojibaked).

  P0 attack surface enumerated:

  RECON:
    R1  process enum (WMI + tasklist)
    R2  OpenProcess DWM with PROCESS_VM_READ (should FAIL at medium IL)
    R3  Toolhelp32 module snapshot + .NET Modules enum of DWM
    R4  Named-pipe enum + derived-name presence probe
    R5  Named-object existence probe (legacy + derived-per-box)
    R6  Window class sweep + DWMWA_CLOAKED
    R7  Message-only window sweep
    R9  Filesystem enum of C:\ProgramData\WinAudioSvc
    R10 sihost.exe on-disk strings scan
    R11 GetShellWindow
    R12 GDI screenshot capture-leak attempt
    R13 RegisterHotKey collision probe

  DISRUPT (only with -Disrupt):
    D1  OpenProcess DWM with TERMINATE (should FAIL)
    D2  Signal derived shutdown event (P0 KILL vuln test)
    D3  Signal iso-halt event
    D4  --unload from medium IL
    D5  BlockInput
    D6  Pre-create init-guard mutex collision
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][string]$Sentinel,
    [switch]$Disrupt
)

$ErrorActionPreference='Continue'
$results = [ordered]@{}
$results.startedUtc = (Get-Date).ToUniversalTime().ToString('o')
$results.env = [ordered]@{
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    integrityLevel = 'unknown'
    pid = $PID
    host = $env:COMPUTERNAME
}
try {
    $wg = whoami /groups /fo csv | ConvertFrom-Csv
    $mand = $wg | Where-Object { $_.'Group Name' -like 'Mandatory Label*' } | Select-Object -First 1
    if ($mand) { $results.env.integrityLevelPreDrop = $mand.'Group Name' }
} catch {}

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
        // TOKEN_ADJUST_DEFAULT | TOKEN_QUERY = 0x80|0x8 = 0x88
        if (!OpenProcessToken(GetCurrentProcess(), 0x0088u, out tok)) { LocalFree(sid); return false; }
        try {
            uint sidLen = GetLengthSid(sid);
            uint sz = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + sidLen;
            IntPtr buf = Marshal.AllocHGlobal((int)sz);
            try {
                TOKEN_MANDATORY_LABEL tml;
                tml.Label.Sid = sid;
                tml.Label.Attributes = 0x00000020u; // SE_GROUP_INTEGRITY
                Marshal.StructureToPtr(tml, buf, false);
                // TokenIntegrityLevel = 25
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
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenMutexW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenFileMappingW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateMutexW(IntPtr sa, bool ownInitial, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool BlockInput(bool block);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr GetShellWindow();
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr FindWindowW(string cls, string name);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern int GetClassNameW(IntPtr hwnd, StringBuilder buf, int max);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder buf, int max);
    public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc cb, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr GetTopWindow(IntPtr parent);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr GetWindow(IntPtr hwnd, uint cmd);
    [DllImport("dwmapi.dll", SetLastError=true)]
    public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out int val, int sz);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern int RegisterHotKey(IntPtr hwnd, int id, uint mods, uint vk);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern int UnregisterHotKey(IntPtr hwnd, int id);
}
"@

# Drop OUR OWN token integrity to Medium (SAFER strips admin group but often
# leaves integrity at High on Win11 24H2 when caller was elevated).
# Once dropped we can only stay dropped -- irreversible.
$dropOk = [IntDrop]::DropToMedium()
$results.env.integrityDropOk = $dropOk
try {
    $wg2 = whoami /groups /fo csv | ConvertFrom-Csv
    $m2 = $wg2 | Where-Object { $_.'Group Name' -like 'Mandatory Label*' } | Select-Object -First 1
    if ($m2) { $results.env.integrityLevel = $m2.'Group Name' }
} catch {}

$SYNCHRONIZE = 0x00100000
$EVENT_MODIFY_STATE = 0x0002
$FILE_MAP_READ = 0x0004
$PROCESS_TERMINATE = 0x0001
$PROCESS_VM_READ  = 0x0010
$PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
$INVALID_HANDLE = [IntPtr](-1)
$GW_HWNDNEXT = 2

function Get-MachineGuidLower {
    try { $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -EA Stop).MachineGuid }
    catch { $g = '' }
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

$derived = [ordered]@{
    pipeToken    = '\\.\pipe\' + (Get-DerivedGuid 'wasvc.pipe.token.1')
    pipeOcr      = '\\.\pipe\' + (Get-DerivedGuid 'wasvc.pipe.ocr.1')
    pipeIso      = '\\.\pipe\' + (Get-DerivedGuid 'wasvc.pipe.iso.1')
    pipeIsoCmd   = '\\.\pipe\' + (Get-DerivedGuid 'wasvc.pipe.iso.cmd.1')
    mtxInit      = 'Local\'    + (Get-DerivedGuid 'wasvc.mtx.init.1')
    mtxOcrd      = 'Global\'   + (Get-DerivedGuid 'wasvc.mtx.ocrd.1')
    evtShutdown  = 'Global\'   + (Get-DerivedGuid 'wasvc.evt.shut.1')
    evtIsoHalt   = 'Global\'   + (Get-DerivedGuid 'wasvc.evt.iso.halt.1')
    evtIsoChat   = 'Global\'   + (Get-DerivedGuid 'wasvc.evt.iso.chat.1')
}
$results.derivedNames = $derived

# ------------------------------------------------------------------ R1
Write-Host "[R1] process enum"
$procs = @{}
try {
    $procs.dwm = @(Get-Process dwm -EA SilentlyContinue | Select-Object Id, ProcessName, StartTime)
    $procs.winlogon = @(Get-Process winlogon -EA SilentlyContinue | Select-Object Id, ProcessName, StartTime)
    $procs.sihost = @(Get-Process sihost -EA SilentlyContinue | Select-Object Id, ProcessName, @{n='Path';e={ try { $_.Path } catch { '<denied>' } }})
    $procs.svchelper = @(Get-Process svchelper -EA SilentlyContinue | Select-Object Id, ProcessName, @{n='Path';e={ try { $_.Path } catch { '<denied>' } }})
    $procs.byNamePattern = @(Get-CimInstance Win32_Process -EA SilentlyContinue |
        Where-Object { $_.Name -match 'svcldb|cloak|dwmapi|winaudio|wasvc' -or $_.ExecutablePath -match 'svcldb|cloakgpt|winaudiosvc|wasvc' } |
        Select-Object ProcessId, Name, ExecutablePath)
} catch { $procs.error = "$_" }
$results.R1_processes = $procs

# ------------------------------------------------------------------ R2
Write-Host "[R2] OpenProcess DWM PROCESS_VM_READ"
$r2 = @{}
try {
    $dwmProc = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
    if ($dwmProc) {
        $r2.dwmPid = $dwmProc.Id
        $h = [N]::OpenProcess([uint32]$PROCESS_VM_READ, $false, [uint32]$dwmProc.Id)
        if ($h -ne [IntPtr]::Zero) {
            $r2.canReadDwmMemory = $true
            $r2.gle = 0
            [void][N]::CloseHandle($h)
        } else {
            $r2.canReadDwmMemory = $false
            $r2.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $h2 = [N]::OpenProcess([uint32]$PROCESS_QUERY_LIMITED_INFORMATION, $false, [uint32]$dwmProc.Id)
        if ($h2 -ne [IntPtr]::Zero) { $r2.canQueryLimited = $true; [void][N]::CloseHandle($h2) }
        else { $r2.canQueryLimited = $false; $r2.gleQueryLimited = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    }
} catch { $r2.error = "$_" }
$results.R2_openProcessDwm = $r2

# ------------------------------------------------------------------ R3
Write-Host "[R3] Toolhelp32 module snapshot of DWM"
$r3 = @{}
try {
    $dwmProc = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
    if ($dwmProc) {
        $snap = [N]::CreateToolhelp32Snapshot([uint32]0x00000008, [uint32]$dwmProc.Id)
        if ($snap -eq $INVALID_HANDLE) {
            $r3.canSnapshot = $false
            $r3.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        } else {
            $r3.canSnapshot = $true
            [void][N]::CloseHandle($snap)
        }
        try {
            $m = $dwmProc.Modules
            $r3.dotnetModulesCount = $m.Count
            $r3.dotnetModulesSuspicious = @($m | Where-Object { $_.ModuleName -match 'svcldb|dwmapi|cloak|wasvc|wl_input' } | ForEach-Object { $_.ModuleName })
        } catch {
            $r3.dotnetModulesError = "$_"
        }
    }
} catch { $r3.error = "$_" }
$results.R3_dwmModuleSnapshot = $r3

# ------------------------------------------------------------------ R4
Write-Host "[R4] named-pipe scan"
$r4 = @{}
try {
    $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\'))
    $pipeNames = $pipes | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
    $r4.total = $pipeNames.Count
    $r4.svcPatternHits = @($pipeNames | Where-Object { $_ -match 'svcldb|cloakgpt|dwmapiext|winaudiosvc|phantom|wasvc' })
    $derPipes = @($derived.pipeToken, $derived.pipeOcr, $derived.pipeIso, $derived.pipeIsoCmd) | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
    $r4.derivedPresentByGuid = @{}
    foreach ($n in $derPipes) { $r4.derivedPresentByGuid[$n] = ($pipeNames -contains $n) }
    $guidRegex = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $r4.guidShapedTotal = @($pipeNames | Where-Object { $_ -match $guidRegex }).Count
} catch { $r4.error = "$_" }
$results.R4_namedPipes = $r4

# ------------------------------------------------------------------ R5
Write-Host "[R5] named-object existence probes"
$r5 = @{ legacy = @{}; derivedByGuid = @{} }
$legacyProbes = @(
    @{ kind='event'; name='Global\DwmCompositorShutdownRelease' },
    @{ kind='mutex'; name='Local\DwmCompositorGuardRelease' },
    @{ kind='mutex'; name='Global\DwmCompositorGuardRelease' },
    @{ kind='event'; name='Global\svcldb_shutdown_v1' },
    @{ kind='mutex'; name='Local\svcldb_initguard_v1' },
    @{ kind='mutex'; name='Global\svcldb_ocr_daemon_v1_mutex' },
    @{ kind='event'; name='Global\svcldb_probe_canary_does_not_exist' }
)
function Probe-One($kind, $name) {
    $h = [IntPtr]::Zero
    switch ($kind) {
        'event'   { $h = [N]::OpenEventW([uint32]$SYNCHRONIZE, $false, $name) }
        'mutex'   { $h = [N]::OpenMutexW([uint32]$SYNCHRONIZE, $false, $name) }
        'section' { $h = [N]::OpenFileMappingW([uint32]$FILE_MAP_READ, $false, $name) }
    }
    if ($h -ne [IntPtr]::Zero) {
        [void][N]::CloseHandle($h)
        return @{ result='EXISTS_ACCESSIBLE'; gle=0; leaksExistence=$true }
    }
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    switch ($gle) {
        5       { return @{ result='EXISTS_ACCESS_DENIED'; gle=5; leaksExistence=$true } }
        2       { return @{ result='NOT_FOUND'; gle=2; leaksExistence=$false } }
        default { return @{ result='OTHER'; gle=$gle; leaksExistence=$false } }
    }
}
foreach ($p in $legacyProbes) { $r5.legacy[$p.name] = (Probe-One $p.kind $p.name) }
$derivedProbes = @(
    @{ kind='event'; name=$derived.evtShutdown },
    @{ kind='mutex'; name=$derived.mtxInit },
    @{ kind='mutex'; name=$derived.mtxOcrd },
    @{ kind='event'; name=$derived.evtIsoHalt },
    @{ kind='event'; name=$derived.evtIsoChat }
)
foreach ($p in $derivedProbes) { $r5.derivedByGuid[$p.name] = (Probe-One $p.kind $p.name) }
$results.R5_namedObjects = $r5

# ------------------------------------------------------------------ R6
Write-Host "[R6] window class sweep"
$suspiciousClassRegex = 'SysCompositorSink|MSDiagEventSink|svcldb|cloak|dwmapiext|wasvc'
$r6 = @{}
$topLevelWindows = New-Object System.Collections.Generic.List[object]
$cbTop = [N+EnumWindowsProc]{
    param($hwnd, $lp)
    $sb1 = New-Object System.Text.StringBuilder 256
    $sb2 = New-Object System.Text.StringBuilder 256
    [N]::GetClassNameW($hwnd, $sb1, 256) | Out-Null
    [N]::GetWindowTextW($hwnd, $sb2, 256) | Out-Null
    $owningPid = [uint32]0
    [N]::GetWindowThreadProcessId($hwnd, [ref]$owningPid) | Out-Null
    $topLevelWindows.Add([pscustomobject]@{ hwnd=$hwnd.ToString(); class=$sb1.ToString(); title=$sb2.ToString(); pid=$owningPid; visible=[N]::IsWindowVisible($hwnd) })
    return $true
}
[N]::EnumWindows($cbTop, [IntPtr]::Zero) | Out-Null
$r6.withClasses = $topLevelWindows.Count
$r6.suspiciousByClass = @($topLevelWindows | Where-Object { $_.class -match $suspiciousClassRegex })

$cloaked = @()
foreach ($w in $topLevelWindows) {
    try {
        $val = 0
        $rc = [N]::DwmGetWindowAttribute([IntPtr]([int64]$w.hwnd), 14, [ref]$val, 4)
        if ($rc -eq 0 -and $val -ne 0) { $cloaked += [pscustomobject]@{ hwnd=$w.hwnd; class=$w.class; title=$w.title; pid=$w.pid; cloakedFlag=$val } }
    } catch {}
}
$r6.cloakedTotal = $cloaked.Count
$r6.cloakedSuspicious = @($cloaked | Where-Object { $_.class -match $suspiciousClassRegex })

$childWindows = New-Object System.Collections.Generic.List[object]
$cbChild = [N+EnumWindowsProc]{
    param($hwnd, $lp)
    $sb1 = New-Object System.Text.StringBuilder 256
    [N]::GetClassNameW($hwnd, $sb1, 256) | Out-Null
    $childWindows.Add([pscustomobject]@{ hwnd=$hwnd.ToString(); class=$sb1.ToString() })
    return $true
}
$progman = [N]::FindWindowW('Progman', $null)
if ($progman -ne [IntPtr]::Zero) { [N]::EnumChildWindows($progman, $cbChild, [IntPtr]::Zero) | Out-Null }
$workerW = [N]::FindWindowW('WorkerW', $null)
if ($workerW -ne [IntPtr]::Zero) { [N]::EnumChildWindows($workerW, $cbChild, [IntPtr]::Zero) | Out-Null }
$r6.progmanWorkerChildren = $childWindows.Count
$r6.progmanWorkerSuspicious = @($childWindows | Where-Object { $_.class -match $suspiciousClassRegex })
$results.R6_windows = $r6

# ------------------------------------------------------------------ R7
Write-Host "[R7] message-only window sweep"
$r7 = @{ count = 0; suspicious = @() }
$HWND_MESSAGE = [IntPtr](-3)
$msgWin = [N]::GetTopWindow($HWND_MESSAGE)
$seen = @{}
while ($msgWin -ne [IntPtr]::Zero -and -not $seen.ContainsKey($msgWin.ToString())) {
    $seen[$msgWin.ToString()] = $true
    $sb = New-Object System.Text.StringBuilder 256
    [N]::GetClassNameW($msgWin, $sb, 256) | Out-Null
    $cls = $sb.ToString()
    $r7.count++
    if ($cls -match $suspiciousClassRegex) {
        $owningPid = [uint32]0
        [N]::GetWindowThreadProcessId($msgWin, [ref]$owningPid) | Out-Null
        $r7.suspicious += [pscustomobject]@{ hwnd=$msgWin.ToString(); class=$cls; pid=$owningPid }
    }
    $msgWin = [N]::GetWindow($msgWin, [uint32]$GW_HWNDNEXT)
}
$results.R7_messageOnly = $r7

# ------------------------------------------------------------------ R9
Write-Host "[R9] filesystem enum"
$r9 = @{}
$prog = 'C:\ProgramData\WinAudioSvc'
if (Test-Path $prog) {
    $items = @(Get-ChildItem $prog -Force -EA SilentlyContinue | Select-Object Name, Length, LastWriteTime, @{n='Attr';e={$_.Attributes.ToString()}})
    $r9.progDataWinAudioSvc = $items
    $exe = Join-Path $prog 'sihost.exe'
    if (Test-Path $exe) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($exe)
            $r9.sihostReadableBytes = $bytes.Length
        } catch { $r9.sihostReadError = "$_" }
    }
    $cfg = Join-Path $prog 'config.dat'
    if (Test-Path $cfg) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($cfg)
            $r9.configDatReadableBytes = $bytes.Length
        } catch { $r9.configDatReadError = "$_" }
    }
}
if (Test-Path 'C:\Program Files\svchelper') {
    $r9.progFilesSvchelper = @(Get-ChildItem 'C:\Program Files\svchelper' -Force -EA SilentlyContinue | Select-Object Name, Length)
}
$results.R9_filesystem = $r9

# ------------------------------------------------------------------ R10
Write-Host "[R10] sihost.exe strings scan"
$r10 = @{}
try {
    $bytes = [System.IO.File]::ReadAllBytes('C:\ProgramData\WinAudioSvc\sihost.exe')
    $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
    $textU = [System.Text.Encoding]::Unicode.GetString($bytes)
    $patterns = @(
        'wasvc.pipe.token','wasvc.pipe.ocr','wasvc.mtx.init','wasvc.mtx.ocrd','wasvc.evt.shut',
        'wasvc.evt.iso','wasvc.pipe.iso','wasvc.cls.iso',
        'svcldb','cloakgpt','dwmapiext','CloakGPT','winaudiosvc',
        'svcldb-config-wrap','svcldb-handshake','svcldb-solve',
        'SysCompositorSink','MSDiagEventSink','NetSvcCoord','NetSvcInputAck',
        'openrouter-proxy.c-viperdevelopment','rrrpkmzdnaodmvsuxdkw.supabase',
        'X-Svc-Relay','wa.ocr.v1','wa.hs.v1','HANDSHAKE SKIPPED',
        'ImGui READY','hooks_install','sub_check','peb_unlink','pe_wipe'
    )
    $hits = @{}
    $hitsU = @{}
    foreach ($p in $patterns) {
        $c = ([regex]::Matches($text,  [regex]::Escape($p))).Count
        $u = ([regex]::Matches($textU, [regex]::Escape($p))).Count
        if ($c -gt 0) { $hits[$p]  = $c }
        if ($u -gt 0) { $hitsU[$p] = $u }
    }
    $r10.asciiHits = $hits
    $r10.utf16Hits = $hitsU
} catch { $r10.error = "$_" }
$results.R10_sihostStrings = $r10

# ------------------------------------------------------------------ R11
Write-Host "[R11] shell window enum"
$r11 = @{}
$shell = [N]::GetShellWindow()
if ($shell -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 256
    [N]::GetClassNameW($shell, $sb, 256) | Out-Null
    $r11.shellClass = $sb.ToString()
    $owningPid = [uint32]0
    [N]::GetWindowThreadProcessId($shell, [ref]$owningPid) | Out-Null
    $r11.shellPid = $owningPid
}
$results.R11_shell = $r11

# ------------------------------------------------------------------ R12
Write-Host "[R12] GDI screenshot capture-leak"
Add-Type -AssemblyName System.Drawing -EA SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms -EA SilentlyContinue
$r12 = @{ shotPath = "$env:TEMP\svc_attack_shot.png" }
try {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap($b.Width, $b.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
    $bmp.Save($r12.shotPath)
    $g.Dispose(); $bmp.Dispose()
    $r12.shotBytes = (Get-Item $r12.shotPath).Length
    $r12.captured = $true
    $r12.note = 'Capture-stealth: a normal screenshot should NOT contain the overlay pixels.'
} catch { $r12.error = "$_" }
$results.R12_gdiCapture = $r12

# ------------------------------------------------------------------ R13
Write-Host "[R13] RegisterHotKey collision probe"
$r13 = @{ hotkeys = @{} }
$try = @(
    @{ id=1001; mods=2; vk=0x42; name='Ctrl+B' },
    @{ id=1002; mods=2; vk=0x0D; name='Ctrl+Enter' },
    @{ id=1003; mods=7; vk=0x50; name='Ctrl+Alt+Shift+P' },
    @{ id=1004; mods=2; vk=0x4B; name='Ctrl+K' }
)
foreach ($t in $try) {
    $ok = [N]::RegisterHotKey([IntPtr]::Zero, [int]$t.id, [uint32]$t.mods, [uint32]$t.vk)
    if ($ok -ne 0) {
        $r13.hotkeys[$t.name] = @{ registered=$true }
        [N]::UnregisterHotKey([IntPtr]::Zero, [int]$t.id) | Out-Null
    } else {
        $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $r13.hotkeys[$t.name] = @{ registered=$false; gle=$gle }
    }
}
$results.R13_hotkeys = $r13

# ------------------------------------------------------------------ DISRUPT
if ($Disrupt) {
    Write-Host "[D1] OpenProcess DWM with TERMINATE"
    $d1 = @{}
    try {
        $dwmProc = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
        if ($dwmProc) {
            $h = [N]::OpenProcess([uint32]$PROCESS_TERMINATE, $false, [uint32]$dwmProc.Id)
            if ($h -ne [IntPtr]::Zero) { $d1.canTerminate = $true; [void][N]::CloseHandle($h) }
            else { $d1.canTerminate = $false; $d1.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        }
    } catch { $d1.error = "$_" }
    $results.D1_terminateDwm = $d1

    Write-Host "[D2] Signal DERIVED shutdown event - CRITICAL P0 VULN TEST"
    $d2 = @{ eventName = $derived.evtShutdown }
    try {
        $h = [N]::OpenEventW([uint32]($SYNCHRONIZE -bor $EVENT_MODIFY_STATE), $false, $derived.evtShutdown)
        if ($h -ne [IntPtr]::Zero) {
            $d2.openedForWrite = $true
            $ok = [N]::SetEvent($h)
            $d2.setEventOk = $ok
            [void][N]::CloseHandle($h)
        } else {
            $d2.openedForWrite = $false
            $d2.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    } catch { $d2.error = "$_" }
    $results.D2_shutdownEvent = $d2

    Write-Host "[D3] Signal iso-halt event"
    $d3 = @{ eventName = $derived.evtIsoHalt }
    try {
        $h = [N]::OpenEventW([uint32]($SYNCHRONIZE -bor $EVENT_MODIFY_STATE), $false, $derived.evtIsoHalt)
        if ($h -ne [IntPtr]::Zero) { $d3.openedForWrite=$true; $ok=[N]::SetEvent($h); $d3.setEventOk=$ok; [void][N]::CloseHandle($h) }
        else { $d3.openedForWrite=$false; $d3.gle=[Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    } catch { $d3.error="$_" }
    $results.D3_isoHalt = $d3

    Write-Host "[D4] --unload from medium IL"
    $d4 = @{}
    try {
        $exe = 'C:\ProgramData\WinAudioSvc\sihost.exe'
        if (Test-Path $exe) {
            $p = Start-Process -FilePath $exe -ArgumentList '--unload' -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            $d4.startedOk = $true
            $d4.exitCode = $p.ExitCode
        } else { $d4.notFound = $true }
    } catch { $d4.error = "$_" }
    $results.D4_unloadCommand = $d4

    Write-Host "[D5] BlockInput probe"
    $d5 = @{}
    try {
        $ok = [N]::BlockInput($true)
        $d5.blockInputOk = $ok
        if ($ok) { [N]::BlockInput($false) | Out-Null }
        else { $d5.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    } catch { $d5.error = "$_" }
    $results.D5_blockInput = $d5

    Write-Host "[D6] Pre-create derived init-guard mutex"
    $d6 = @{ mtxName = $derived.mtxInit }
    try {
        $h = [N]::CreateMutexW([IntPtr]::Zero, $false, $derived.mtxInit)
        if ($h -ne [IntPtr]::Zero) {
            $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $d6.createOk = $true
            $d6.alreadyExisted = ($gle -eq 183)
            $d6.gle = $gle
            [void][N]::CloseHandle($h)
        } else {
            $d6.createOk = $false
            $d6.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    } catch { $d6.error = "$_" }
    $results.D6_initGuardCollision = $d6
}

# ------------------------------------------------------------------ VERDICT
$verdict = 'CLEAN'
$issues = @()

if ($results.R1_processes.byNamePattern.Count -gt 0) {
    $issues += "R1: process(es) match svcldb-related name pattern"
    $verdict = 'DETECTED'
}
if ($results.R2_openProcessDwm.canReadDwmMemory) {
    $issues += 'R2: medium-IL CAN read dwm memory (CATASTROPHIC)'
    $verdict = 'DETECTED'
}
if ($results.R3_dwmModuleSnapshot.dotnetModulesSuspicious -and $results.R3_dwmModuleSnapshot.dotnetModulesSuspicious.Count -gt 0) {
    $issues += "R3: .NET Modules enum returned suspicious: $($results.R3_dwmModuleSnapshot.dotnetModulesSuspicious -join ',')"
    $verdict = 'DETECTED'
}
if ($results.R4_namedPipes.svcPatternHits -and $results.R4_namedPipes.svcPatternHits.Count -gt 0) {
    $issues += "R4: pipe name matches svcldb pattern: $($results.R4_namedPipes.svcPatternHits -join ',')"
    $verdict = 'DETECTED'
}
foreach ($k in $results.R4_namedPipes.derivedPresentByGuid.Keys) {
    if ($results.R4_namedPipes.derivedPresentByGuid[$k]) {
        $issues += "R4: derived pipe $k present AND attacker recomputed its name from medium-IL info (salt in sihost.exe + HKLM MachineGuid). DERIVATION LEAK."
    }
}
foreach ($k in $results.R5_namedObjects.legacy.Keys) {
    $rr = $results.R5_namedObjects.legacy[$k]
    if ($rr.result -ne 'NOT_FOUND' -and $k -notlike '*canary*') {
        $issues += "R5: legacy object $k still present: $($rr.result)"
        $verdict = 'DETECTED'
    }
}
foreach ($k in $results.R5_namedObjects.derivedByGuid.Keys) {
    $rr = $results.R5_namedObjects.derivedByGuid[$k]
    if ($rr.result -ne 'NOT_FOUND') {
        $issues += "R5: DERIVED object $k probeable from medium-IL: result=$($rr.result). P0 GAP if attacker can also SIGNAL it."
    }
}
if ($results.R6_windows.suspiciousByClass -and $results.R6_windows.suspiciousByClass.Count -gt 0) {
    $issues += "R6: suspicious top-level class(es)"
    $verdict = 'DETECTED'
}
if ($results.R6_windows.progmanWorkerSuspicious -and $results.R6_windows.progmanWorkerSuspicious.Count -gt 0) {
    $issues += "R6: suspicious progman/workerw child class(es)"
    $verdict = 'DETECTED'
}
if ($results.R7_messageOnly.suspicious -and $results.R7_messageOnly.suspicious.Count -gt 0) {
    $issues += "R7: suspicious message-only class(es)"
    $verdict = 'DETECTED'
}
$loudPatterns = @(
    'svcldb','cloakgpt','dwmapiext','CloakGPT','svcldb-solve','svcldb-handshake','svcldb-config-wrap','wasvc.',
    'SysCompositorSink','NetSvcCoord','NetSvcInputAck',
    'openrouter-proxy.c-viperdevelopment','rrrpkmzdnaodmvsuxdkw.supabase',
    'X-Svc-Relay','HANDSHAKE SKIPPED','hooks_install','peb_unlink','pe_wipe','sub_check'
)
$hitsFound = @()
foreach ($p in $loudPatterns) {
    if ($results.R10_sihostStrings.asciiHits.ContainsKey($p)) { $hitsFound += "ascii:$p($($results.R10_sihostStrings.asciiHits[$p]))" }
    if ($results.R10_sihostStrings.utf16Hits.ContainsKey($p)) { $hitsFound += "utf16:$p($($results.R10_sihostStrings.utf16Hits[$p]))" }
}
if ($hitsFound.Count -gt 0) {
    $issues += "R10: sihost.exe on-disk strings leak identifiers to any user reading the file: $($hitsFound -join ', ')"
}
foreach ($k in $results.R13_hotkeys.Keys) {
    if ($results.R13_hotkeys[$k].registered) {
        $issues += "R13: attacker registered hotkey $k (svcldb uses LL hook so this is expected; noted for LL-hook priority race audit)"
    }
}
if ($Disrupt) {
    if ($results.D1_terminateDwm.canTerminate) { $issues += 'D1: medium-IL CAN OpenProcess TERMINATE on dwm.exe (CATASTROPHIC)'; $verdict='DETECTED' }
    if ($results.D2_shutdownEvent.openedForWrite -and $results.D2_shutdownEvent.setEventOk) {
        $issues += 'D2: medium-IL OPENED + SIGNALED derived shutdown event. If payload treats this as authoritative -> KILL VULN.'
        $verdict = 'DETECTED'
    }
    if ($results.D3_isoHalt.openedForWrite -and $results.D3_isoHalt.setEventOk) {
        $issues += 'D3: medium-IL OPENED + SIGNALED derived iso-halt event.'
    }
    if ($results.D4_unloadCommand.exitCode -eq 0) {
        $issues += 'D4: --unload succeeded from medium-IL (CATASTROPHIC)'
        $verdict = 'DETECTED'
    }
    if ($results.D5_blockInput.blockInputOk) {
        $issues += 'D5: medium-IL BlockInput() succeeded (should require UIAccess/admin)'
    }
    if ($results.D6_initGuardCollision.createOk -and $results.D6_initGuardCollision.alreadyExisted) {
        $issues += 'D6: medium-IL opened derived init-guard mutex (already existed - payload alive - existence leak)'
    }
}

$results.verdict = $verdict
$results.issues = $issues
$results.completedUtc = (Get-Date).ToUniversalTime().ToString('o')

$results | ConvertTo-Json -Depth 10 | Set-Content -Path $Out -Encoding ASCII
'done' | Set-Content -Path $Sentinel -Encoding ASCII
Write-Host "DONE -> verdict=$verdict issues=$($issues.Count)"
exit 0
