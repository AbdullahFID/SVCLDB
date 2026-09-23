<#
  attack_v4.ps1 -- svcldb aggressive audit driver (2026-09-23)

  Runs at either MEDIUM IL (default) or ADMIN (-Elevated). Measures:

    TIER A -- generic anomaly detector (NO product knowledge):
      * process enumeration (name, path, session, parent, cmdline stats)
      * loaded-module enumeration on dwm.exe + winlogon.exe from OUR IL
      * top-level window enum (class name, title, DWMWA_CLOAKED)
      * message-only window enum (EnumChildWindows HWND_MESSAGE)
      * named-pipe enum (statistical -- how many GUID-shaped pipes on this
        box, and how many NON-guid-shaped ones look weird)
      * BaseNamedObjects directory listing (NtQueryDirectoryObject) at our IL
      * scheduled tasks + services + autorun registry keys (anomaly stats)
      * GDI/DXGI display enum (any hardware overlay planes that shouldn't
        be there)

    TIER B -- attacker HAS reverse-engineered our binary (knows salts +
    derivation). Same probes, but now specifically hunting derived names.

    DISRUPT / KILL -- non-destructive first, then destructive:
      * OpenProcess(dwm, terminate/vm_read/suspend_resume/set_quota)
      * pipe DoS: hold OCR pipe forever (max_instances=1 exhaustion)
      * mutex squat: pre-create Local\<obf-guid-init> before reinject
      * shutdown event signal from medium IL (should ACCESS_DENIED)
      * hotkey collision: RegisterHotKey with our combos
      * LL keyboard hook swallow (probe already exists, we invoke it)
      * ClipCursor / SetForegroundWindow spam
      * fake-hwnd probe: EnumWindows for our class + WM_CLOSE
      * DwmSetWindowAttribute abuse
      * Destructive last-resort: TerminateProcess(dwm) via admin only (P1)

  OUTPUT: JSON scorecard at tools/redteam/runtime/attack_v4_<mode>.json.
#>
[CmdletBinding()]
param(
    [switch]$Elevated,       # set when running from an admin shell
    [switch]$Disrupt,        # attempt non-destructive kill vectors
    [switch]$DestructiveKill,# attempt admin TerminateProcess(dwm) at the end
    [string]$OutDir = "$PSScriptRoot\runtime",
    [int]$HotkeyCollisionSec = 3,
    [int]$MutexSquatSec = 8,
    [int]$PipeDosSec = 5
)

$ErrorActionPreference = 'Continue'
$Global:ProgressPreference = 'SilentlyContinue'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# -------------------------------------------------------------------
# 0. Environment header
# -------------------------------------------------------------------
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ilMode = if ($isElevated) { 'admin' } else { 'medium' }
$GENERIC_READ  = [System.Convert]::ToUInt32('80000000', 16)
$GENERIC_WRITE = [System.Convert]::ToUInt32('40000000', 16)
$GENERIC_RW    = [System.Convert]::ToUInt32('C0000000', 16)
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$json = Join-Path $OutDir "attack_v4_${ilMode}_${stamp}.json"

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host " svcldb attack_v4  --  mode=$ilMode  disrupt=$Disrupt  destr=$DestructiveKill" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "host        : $env:COMPUTERNAME"
Write-Host "user        : $env:USERNAME  session=$((Get-Process -Id $PID).SessionId)"
Write-Host "elevated    : $isElevated"
Write-Host "outfile     : $json"

# ---- Token diagnostics --------------------------------------------------
# We need to know if this "medium IL" context is faithful to a real UAC-
# filtered user token. Print IL + Administrators group membership + state.
$whoami = whoami /groups /priv 2>&1 | Out-String
$ilLine  = ($whoami -split "`r?`n") | Where-Object { $_ -match 'Mandatory Label' } | Select-Object -First 1
$adminLine = ($whoami -split "`r?`n") | Where-Object { $_ -match 'BUILTIN\\Administrators' } | Select-Object -First 1
Write-Host "IL          : $($ilLine -replace '\s+', ' ')" -ForegroundColor DarkGray
Write-Host "Admin group : $($adminLine -replace '\s+', ' ')" -ForegroundColor DarkGray
$adminDenyOnly = ($adminLine -match 'Deny-only|Use for deny only')
$adminEnabled  = ($adminLine -match 'Enabled')
$isFaithfulMediumIL = ($adminDenyOnly -or -not $adminEnabled) -and -not $isElevated
Write-Host "faithful med-IL model: $isFaithfulMediumIL" -ForegroundColor $(if ($isFaithfulMediumIL -or $isElevated) { 'Green' } else { 'Yellow' })


$report = [ordered]@{
    schema      = 'attack_v4'
    timestamp   = (Get-Date).ToString('o')
    host        = $env:COMPUTERNAME
    user        = $env:USERNAME
    session     = (Get-Process -Id $PID).SessionId
    elevated    = $isElevated
    disrupt     = [bool]$Disrupt
    destructive = [bool]$DestructiveKill
    il_line              = $ilLine
    admin_group_line     = $adminLine
    faithful_medium_il_model = $isFaithfulMediumIL
    dwm_pid     = 0
    winlogon_pid= 0
    tier_a      = [ordered]@{}
    tier_b      = [ordered]@{}
    disrupt_res = [ordered]@{}
    verdict     = 'PENDING'
    findings    = @()
}

# -------------------------------------------------------------------
# 1. Native P/Invoke helpers (loaded once)
# -------------------------------------------------------------------
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class N {
    // Process access
    public const uint PROCESS_TERMINATE               = 0x0001;
    public const uint PROCESS_VM_READ                 = 0x0010;
    public const uint PROCESS_SUSPEND_RESUME          = 0x0800;
    public const uint PROCESS_SET_QUOTA               = 0x0100;
    public const uint PROCESS_SET_INFORMATION         = 0x0200;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_QUERY_INFORMATION       = 0x0400;
    public const uint PROCESS_ALL_ACCESS              = 0x1F0FFF;
    public const uint EVENT_MODIFY_STATE              = 0x0002;
    public const uint MUTEX_ALL_ACCESS                = 0x1F0001;
    public const uint SYNCHRONIZE                     = 0x00100000;
    public const uint FILE_MAP_READ                   = 0x0004;

    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool   CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr OpenEventW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr OpenMutexW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr CreateMutexW(IntPtr lpSa, bool initialOwner, string name);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr OpenFileMappingW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetEvent(IntPtr h);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    // Toolhelp modules
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool Module32FirstW(IntPtr h, ref MODULEENTRY32W me);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool Module32NextW(IntPtr h, ref MODULEENTRY32W me);
    public const uint TH32CS_SNAPMODULE   = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct MODULEENTRY32W {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string szExePath;
    }

    // Window enum
    public delegate bool WNDENUMPROC(IntPtr hwnd, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool EnumWindows(WNDENUMPROC proc, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool EnumChildWindows(IntPtr parent, WNDENUMPROC proc, IntPtr lparam);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hwnd, StringBuilder buf, int max);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder buf, int max);
    [DllImport("user32.dll", SetLastError=true)] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr FindWindowW(string clsName, string winName);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, uint attr, out int val, int cb);
    public const uint DWMWA_CLOAKED = 14;

    // Hotkeys
    [DllImport("user32.dll", SetLastError=true)] public static extern bool RegisterHotKey(IntPtr hwnd, int id, uint mods, uint vk);
    [DllImport("user32.dll")] public static extern bool UnregisterHotKey(IntPtr hwnd, int id);
    public const uint MOD_ALT = 0x1, MOD_CTRL = 0x2, MOD_SHIFT = 0x4, MOD_WIN = 0x8;

    // ClipCursor / SetForegroundWindow
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
    [DllImport("user32.dll", SetLastError=true)] public static extern bool ClipCursor(ref RECT rect);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool ClipCursor(IntPtr rect);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool SetForegroundWindow(IntPtr h);

    // TerminateProcess (destructive only)
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr h, uint code);

    // NtQueryDirectoryObject for \BaseNamedObjects listing
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)] public static extern int NtOpenDirectoryObject(out IntPtr h, uint access, ref OBJECT_ATTRIBUTES oa);
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)] public static extern int NtQueryDirectoryObject(IntPtr h, IntPtr buffer, uint length, bool singleEntry, bool restart, ref uint context, out uint retLen);
    [DllImport("ntdll.dll")] public static extern void RtlInitUnicodeString(ref UNICODE_STRING us, [MarshalAs(UnmanagedType.LPWStr)] string s);
    public const uint DIRECTORY_QUERY = 0x0001;
    public const uint DIRECTORY_TRAVERSE = 0x0002;

    // NtQuerySystemInformation for cross-process handle enumeration
    [DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int siClass, IntPtr buf, uint len, out uint retLen);

    // AttachThreadInput to check foreground-lock behavior
    [DllImport("user32.dll", SetLastError=true)] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool attach);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
}

public class Enumerator {
    public class Win { public IntPtr h; public uint pid; public string cls; public string title; public bool visible; public int cloaked; }
    static List<Win> _list = new List<Win>();
    static bool cb(IntPtr h, IntPtr l) {
        uint pid; N.GetWindowThreadProcessId(h, out pid);
        var cn = new StringBuilder(256); N.GetClassNameW(h, cn, 256);
        var wn = new StringBuilder(512); N.GetWindowTextW(h, wn, 512);
        int cloaked; N.DwmGetWindowAttribute(h, N.DWMWA_CLOAKED, out cloaked, 4);
        _list.Add(new Win{ h=h, pid=pid, cls=cn.ToString(), title=wn.ToString(),
                          visible=N.IsWindowVisible(h), cloaked=cloaked });
        return true;
    }
    public static List<Win> AllTopLevel() {
        _list = new List<Win>();
        N.EnumWindows(new N.WNDENUMPROC(cb), IntPtr.Zero);
        return _list;
    }
    public static List<Win> AllMessageOnly() {
        _list = new List<Win>();
        // HWND_MESSAGE = (HWND)-3; enumerate via GetWindow-like walk with FindWindowExW
        // Simpler: EnumChildWindows(NULL) misses HWND_MESSAGE children; use EnumChildWindows on hwnd (IntPtr(-3)) which works.
        N.EnumChildWindows(new IntPtr(-3), new N.WNDENUMPROC(cb), IntPtr.Zero);
        return _list;
    }
}
"@ -ErrorAction Stop | Out-Null

# -------------------------------------------------------------------
# 2. Helpers -- derived object names (for tier B)
# -------------------------------------------------------------------
function Get-MachineGuidLower {
    try { return (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid.Trim().ToLower() }
    catch { return '3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1' }
}
function Derive-Guid([string]$salt) {
    $g = Get-MachineGuidLower
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($salt + ':' + $g))
    $sha.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}
$derived = @{
    pipe_token   = Derive-Guid 'wasvc.pipe.token.1'
    pipe_ocr     = Derive-Guid 'wasvc.pipe.ocr.1'
    pipe_iso     = Derive-Guid 'wasvc.pipe.iso.1'
    pipe_iso_cmd = Derive-Guid 'wasvc.pipe.iso.cmd.1'
    mtx_init     = Derive-Guid 'wasvc.mtx.init.1'
    mtx_ocrd     = Derive-Guid 'wasvc.mtx.ocrd.1'
    evt_shut     = Derive-Guid 'wasvc.evt.shut.1'
    evt_iso_halt = Derive-Guid 'wasvc.evt.iso.halt.1'
    evt_iso_chat = Derive-Guid 'wasvc.evt.iso.chat.1'
    cls_iso_inp  = Derive-Guid 'wasvc.cls.iso.input.1'
}

# -------------------------------------------------------------------
# 3. Tier A -- generic anomaly detector
# -------------------------------------------------------------------
Write-Host "`n--- TIER A (generic anomaly detector) ---" -ForegroundColor Yellow

# 3.1 Process enum
Write-Host "[A1] process enum..."
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, SessionId
$report.tier_a.process_total = $procs.Count

# Find dwm, winlogon, sihost, svchelper
$dwm = $procs | Where-Object { $_.Name -ieq 'dwm.exe' }
$winlogon = $procs | Where-Object { $_.Name -ieq 'winlogon.exe' -and $_.SessionId -ne 0 }
$sihosts = $procs | Where-Object { $_.Name -ieq 'sihost.exe' }
$svchelper = $procs | Where-Object { $_.Name -ieq 'svchelper.exe' }
$explorers = $procs | Where-Object { $_.Name -ieq 'explorer.exe' }

$report.dwm_pid = @($dwm)[0].ProcessId
$report.winlogon_pid = @($winlogon)[0].ProcessId

$report.tier_a.dwm_count = @($dwm).Count
$report.tier_a.winlogon_count = @($winlogon).Count
$report.tier_a.sihost_count = @($sihosts).Count
$report.tier_a.sihost_paths = @($sihosts | ForEach-Object { $_.ExecutablePath })
$report.tier_a.svchelper_count = @($svchelper).Count
$report.tier_a.svchelper_paths = @($svchelper | ForEach-Object { $_.ExecutablePath })
$report.tier_a.explorer_count = @($explorers).Count

# Anomaly heuristics
$anomalies_a = @()
if (@($sihosts).Count -gt 1) {
    # OK if legit + ours; but check paths for anything suspicious
    $paths = @($sihosts | ForEach-Object { $_.ExecutablePath })
    $winSihosts = @($paths | Where-Object { $_ -like '*\Windows\System32\sihost.exe' })
    $otherSihosts = @($paths | Where-Object { $_ -notlike '*\Windows\System32\sihost.exe' })
    if ($otherSihosts.Count -gt 0) {
        # Not automatically a hit — sihost outside System32 is unusual but common in some apps.
        # We flag it as SUSPICIOUS with severity 1 (a paranoid EDR would note it, not necessarily flag).
        $anomalies_a += @{ level='low'; kind='sihost_outside_system32'; detail=($otherSihosts -join ';') }
    }
}
if (@($svchelper).Count -gt 0) {
    # svchelper is our Electron shell -- named 'svchelper.exe' is unusual + suspicious.
    $anomalies_a += @{ level='med'; kind='svchelper_process_present'; detail=($svchelper | Select-Object -First 1 -ExpandProperty ExecutablePath) }
}
$report.tier_a.anomalies_process = $anomalies_a

# 3.2 Module enumeration for dwm + winlogon FROM OUR IL (this is the sensitive one)
Write-Host "[A2] module enum on dwm.exe + winlogon.exe from IL=$ilMode ..."
function Get-Modules([int]$pid_target) {
    $snap = [N]::CreateToolhelp32Snapshot([N]::TH32CS_SNAPMODULE -bor [N]::TH32CS_SNAPMODULE32, [uint32]$pid_target)
    if ($snap -eq [IntPtr]::new(-1)) {
        return @{ ok=$false; gle=[Runtime.InteropServices.Marshal]::GetLastWin32Error(); modules=@() }
    }
    try {
        $me = New-Object N+MODULEENTRY32W
        $me.dwSize = [Runtime.InteropServices.Marshal]::SizeOf($me)
        $list = @()
        if ([N]::Module32FirstW($snap, [ref]$me)) {
            do {
                $list += [pscustomobject]@{ name = $me.szModule; path = $me.szExePath; size = $me.modBaseSize }
                $me.dwSize = [Runtime.InteropServices.Marshal]::SizeOf($me)
            } while ([N]::Module32NextW($snap, [ref]$me))
        }
        return @{ ok=$true; gle=0; modules=$list }
    } finally { [N]::CloseHandle($snap) | Out-Null }
}
$dwmMods = Get-Modules $report.dwm_pid
$wlMods  = Get-Modules $report.winlogon_pid
$report.tier_a.dwm_modules = @{
    accessible = $dwmMods.ok
    gle = $dwmMods.gle
    count = @($dwmMods.modules).Count
    suspicious_names = @($dwmMods.modules | Where-Object { $_.name -match '(?i)svcldb|cloakgpt|dwmapiext|winaudiosvc|MSDiagEventSink|hooksdll' } | ForEach-Object { $_.name })
}
$report.tier_a.winlogon_modules = @{
    accessible = $wlMods.ok
    gle = $wlMods.gle
    count = @($wlMods.modules).Count
    suspicious_names = @($wlMods.modules | Where-Object { $_.name -match '(?i)svcldb|cloakgpt|dwmapiext|winaudiosvc|wl_input|hooksdll' } | ForEach-Object { $_.name })
}
if ($report.tier_a.dwm_modules.suspicious_names.Count -gt 0) {
    $report.findings += "TIER_A: dwm module list leaks: $($report.tier_a.dwm_modules.suspicious_names -join ',')"
}
if ($report.tier_a.winlogon_modules.suspicious_names.Count -gt 0) {
    $report.findings += "TIER_A: winlogon module list leaks: $($report.tier_a.winlogon_modules.suspicious_names -join ',')"
}

# 3.3 Named-pipe enum + statistics
Write-Host "[A3] named-pipe statistical enum..."
$pipes = @()
try { $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' } } catch {}
$guidRe = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
$guidPipes = @($pipes | Where-Object { $_ -match $guidRe })
$plainPipes = @($pipes | Where-Object { $_ -notmatch $guidRe })
$susPipes = @($pipes | Where-Object { $_ -match '(?i)svcldb|cloakgpt|dwmapiext|winaudiosvc' })
$report.tier_a.pipes = @{
    total = $pipes.Count
    guid_shaped = $guidPipes.Count
    plain = $plainPipes.Count
    suspicious_by_name = $susPipes
    sample_guid = @($guidPipes | Get-Random -Count ([Math]::Min(5,$guidPipes.Count)))
}
if ($susPipes.Count -gt 0) { $report.findings += "TIER_A: pipe names match product regex: $($susPipes -join ',')" }

# 3.4 \BaseNamedObjects listing
Write-Host "[A4] \BaseNamedObjects directory listing..."
function List-BNODirectory {
    $oa = New-Object N+OBJECT_ATTRIBUTES
    $us = New-Object N+UNICODE_STRING
    [N]::RtlInitUnicodeString([ref]$us, "\BaseNamedObjects")
    $usPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($us))
    [Runtime.InteropServices.Marshal]::StructureToPtr($us, $usPtr, $false)
    $oa.Length = [Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.ObjectName = $usPtr
    $oa.Attributes = 0x40  # OBJ_CASE_INSENSITIVE
    $dirH = [IntPtr]::Zero
    $st = [N]::NtOpenDirectoryObject([ref]$dirH, [N]::DIRECTORY_QUERY -bor [N]::DIRECTORY_TRAVERSE, [ref]$oa)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($usPtr)
    if ($st -ne 0) { return @{ ok=$false; status=$st; names=@() } }
    try {
        $bufSize = 65536
        $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
        $names = @()
        $ctx = [uint32]0
        $restart = $true
        while ($true) {
            $ret = [uint32]0
            $st = [N]::NtQueryDirectoryObject($dirH, $buf, [uint32]$bufSize, $false, $restart, [ref]$ctx, [ref]$ret)
            $restart = $false
            if ($st -ne 0 -or $ret -eq 0) { break }
            # OBJECT_DIRECTORY_INFORMATION array; each = UNICODE_STRING Name; UNICODE_STRING TypeName;
            $ptr = $buf
            while ($true) {
                $len = [Runtime.InteropServices.Marshal]::ReadInt16($ptr)
                if ($len -eq 0) { break }
                $maxLen = [Runtime.InteropServices.Marshal]::ReadInt16($ptr, 2)
                $strPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, [IntPtr]::Size + 0)  # offset 8 on x64
                if ($strPtr -eq [IntPtr]::Zero) { break }
                $name = [Runtime.InteropServices.Marshal]::PtrToStringUni($strPtr, [int]($len / 2))
                # type UNICODE_STRING follows
                $typeOff = 16
                $typeLen = [Runtime.InteropServices.Marshal]::ReadInt16($ptr, $typeOff)
                $typePtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $typeOff + 8)
                $type = ""
                if ($typePtr -ne [IntPtr]::Zero -and $typeLen -gt 0) {
                    $type = [Runtime.InteropServices.Marshal]::PtrToStringUni($typePtr, [int]($typeLen / 2))
                }
                if ($name) { $names += @{ name=$name; type=$type } }
                $ptr = [IntPtr]::Add($ptr, 32)  # sizeof(OBJECT_DIRECTORY_INFORMATION) on x64
            }
        }
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        return @{ ok=$true; status=0; names=$names }
    } finally { [N]::CloseHandle($dirH) | Out-Null }
}
$bno = List-BNODirectory
$report.tier_a.bno_accessible = $bno.ok
if ($bno.ok) {
    $report.tier_a.bno_total = @($bno.names).Count
    $susBno = @($bno.names | Where-Object { $_.name -match '(?i)svcldb|cloakgpt|dwmapiext|winaudiosvc|MSDiag' })
    $report.tier_a.bno_suspicious = @($susBno | ForEach-Object { "$($_.type):$($_.name)" })
    $guidBno = @($bno.names | Where-Object { $_.name -match $guidRe })
    $report.tier_a.bno_guid_count = $guidBno.Count
    if ($susBno.Count -gt 0) { $report.findings += "TIER_A: BNO leaks: $($report.tier_a.bno_suspicious -join ',')" }
} else {
    $report.tier_a.bno_status = $bno.status
}

# 3.5 Window enum
Write-Host "[A5] top-level + message-only window enum..."
$topWindows = [Enumerator]::AllTopLevel()
$msgWindows = [Enumerator]::AllMessageOnly()
$dwmWindows = @($topWindows | Where-Object { $_.pid -eq $report.dwm_pid })
$susWinTop = @($topWindows | Where-Object { $_.cls -match '(?i)svcldb|cloakgpt|dwmapiext|MSDiagEventSink|SysCompositorSink' -or $_.title -match '(?i)svcldb|cloakgpt' })
$susWinMsg = @($msgWindows | Where-Object { $_.cls -match '(?i)svcldb|cloakgpt|dwmapiext|MSDiagEventSink|SysCompositorSink' })
# Enrich each suspicious window with owning process name (so we know if it's DWM-owned = camouflaged vs external = IOC)
foreach ($w in $susWinTop) {
    $p = Get-Process -Id $w.pid -EA SilentlyContinue
    $w | Add-Member -NotePropertyName owner_name -NotePropertyValue $(if ($p) { $p.ProcessName } else { '?' }) -Force
    $w | Add-Member -NotePropertyName owner_path -NotePropertyValue $(if ($p) { try { $p.Path } catch { '?' } } else { '?' }) -Force
}
foreach ($w in $susWinMsg) {
    $p = Get-Process -Id $w.pid -EA SilentlyContinue
    $w | Add-Member -NotePropertyName owner_name -NotePropertyValue $(if ($p) { $p.ProcessName } else { '?' }) -Force
}
$cloakedByDwm = @($topWindows | Where-Object { $_.cloaked -ne 0 })
$report.tier_a.windows_top_total = $topWindows.Count
$report.tier_a.windows_msg_total = $msgWindows.Count
$report.tier_a.windows_dwm_owned = @($dwmWindows | ForEach-Object { "$($_.cls):$($_.title)" })
$report.tier_a.windows_suspicious_top = @($susWinTop | ForEach-Object { "$($_.cls):$($_.title):pid=$($_.pid):owner=$($_.owner_name)" })
$report.tier_a.windows_suspicious_msg = @($susWinMsg | ForEach-Object { "$($_.cls):pid=$($_.pid):owner=$($_.owner_name)" })
$report.tier_a.windows_dwm_cloaked_count = $cloakedByDwm.Count
if ($susWinTop.Count -gt 0 -or $susWinMsg.Count -gt 0) {
    $report.findings += "TIER_A: window class/title leak: top=$($susWinTop.Count) msg=$($susWinMsg.Count)"
}

# 3.6 Services + scheduled tasks + autoruns (light scan)
Write-Host "[A6] services + scheduled tasks + autoruns..."
$svcSus = @(Get-CimInstance Win32_Service -EA SilentlyContinue |
            Where-Object { $_.Name -match '(?i)svcldb|cloakgpt|winaudiosvc' -or $_.PathName -match '(?i)svcldb|cloakgpt|winaudiosvc' } |
            ForEach-Object { "$($_.Name):$($_.State):$($_.PathName)" })
$taskSus = @(Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -match '(?i)svcldb|cloakgpt|winaudiosvc|Ghidra' -or $_.Description -match '(?i)svcldb|cloakgpt' } | ForEach-Object { $_.TaskName })
$runHits = @()
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
    try {
        $r = Get-ItemProperty -Path $k -EA SilentlyContinue
        if ($r) {
            $r.PSObject.Properties | ForEach-Object {
                if ($_.Value -is [string] -and $_.Value -match '(?i)svcldb|cloakgpt|winaudiosvc') {
                    $runHits += "$k\$($_.Name) = $($_.Value)"
                }
            }
        }
    } catch {}
}
$report.tier_a.services_suspicious = $svcSus
$report.tier_a.tasks_suspicious = $taskSus
$report.tier_a.autoruns_suspicious = $runHits
if ($svcSus.Count -gt 0)  { $report.findings += "TIER_A: services: $($svcSus -join ',')" }
if ($taskSus.Count -gt 0) { $report.findings += "TIER_A: tasks: $($taskSus -join ',')" }
if ($runHits.Count -gt 0) { $report.findings += "TIER_A: autoruns: $($runHits -join ',')" }

# 3.7 dwm.exe attribute deltas (memory/handle/thread — a heuristic baseline)
Write-Host "[A7] dwm.exe attribute snapshot (no baseline compare)..."
$dwmProc = Get-Process -Id $report.dwm_pid -EA SilentlyContinue
if ($dwmProc) {
    $report.tier_a.dwm_attrs = @{
        threads       = $dwmProc.Threads.Count
        handles       = $dwmProc.HandleCount
        ws_mb         = [math]::Round($dwmProc.WorkingSet64 / 1MB, 1)
        privbytes_mb  = [math]::Round($dwmProc.PrivateMemorySize64 / 1MB, 1)
        commit_mb     = [math]::Round($dwmProc.PagedMemorySize64 / 1MB, 1)
    }
}

# -------------------------------------------------------------------
# 4. Tier B -- attacker HAS RE'd binary (knows derived names + salts)
# -------------------------------------------------------------------
Write-Host "`n--- TIER B (targeted, RE'd binary) ---" -ForegroundColor Yellow

# 4.1 Named-pipe existence probe with the DERIVED names
Write-Host "[B1] derived pipe existence probes..."
$pipeExists = @{}
foreach ($k in @('pipe_token','pipe_ocr','pipe_iso','pipe_iso_cmd')) {
    $full = "\\.\pipe\" + $derived[$k]
    $exists = $pipes -contains $derived[$k]
    $pipeExists[$k] = @{ name = $derived[$k]; exists_in_enum = $exists }
    # Try to open for READ (validation of DACL)
    $h = [N]::CreateFileW($full, $GENERIC_READ, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)  # GENERIC_READ, OPEN_EXISTING
    if ($h -ne [IntPtr]::new(-1) -and $h -ne [IntPtr]::Zero) {
        $pipeExists[$k].open_result = 'GRANTED_READ'
        [N]::CloseHandle($h) | Out-Null
    } else {
        $pipeExists[$k].open_result = "DENIED_gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
}
$report.tier_b.pipes = $pipeExists

# 4.2 Named-object existence probe (derived events/mutexes)
Write-Host "[B2] derived event/mutex existence probes..."
$objChecks = @()
$candidates = @(
    @{ kind='event'; scope='Global'; key='evt_shut';     access=[N]::SYNCHRONIZE },
    @{ kind='event'; scope='Global'; key='evt_shut';     access=[N]::EVENT_MODIFY_STATE },
    @{ kind='event'; scope='Global'; key='evt_iso_halt'; access=[N]::EVENT_MODIFY_STATE },
    @{ kind='event'; scope='Global'; key='evt_iso_chat'; access=[N]::EVENT_MODIFY_STATE },
    @{ kind='mutex'; scope='Local';  key='mtx_init';     access=[N]::SYNCHRONIZE },
    @{ kind='mutex'; scope='Local';  key='mtx_init';     access=[N]::MUTEX_ALL_ACCESS },
    @{ kind='mutex'; scope='Global'; key='mtx_ocrd';     access=[N]::SYNCHRONIZE }
)
foreach ($c in $candidates) {
    $name = "$($c.scope)\$($derived[$c.key])"
    $h = [IntPtr]::Zero
    if ($c.kind -eq 'event') { $h = [N]::OpenEventW($c.access, $false, $name) }
    else                     { $h = [N]::OpenMutexW($c.access, $false, $name) }
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($h -ne [IntPtr]::Zero) {
        $result = 'EXISTS_ACCESSIBLE'
        [N]::CloseHandle($h) | Out-Null
    } elseif ($gle -eq 5) { $result = 'EXISTS_ACCESS_DENIED' }
    elseif ($gle -eq 2) { $result = 'NOT_FOUND' }
    else { $result = "OTHER_gle=$gle" }
    $objChecks += [pscustomobject]@{
        kind = $c.kind
        name = $name
        access_bits = ('0x{0:X}' -f $c.access)
        result = $result
    }
}
$report.tier_b.objects = $objChecks

# Tier B findings: any EXISTS_ACCESSIBLE with a write bit is a KILL vector
$killable = @($objChecks | Where-Object { $_.result -eq 'EXISTS_ACCESSIBLE' -and ($_.access_bits -eq ('0x{0:X}' -f [N]::EVENT_MODIFY_STATE) -or $_.access_bits -eq ('0x{0:X}' -f [N]::MUTEX_ALL_ACCESS)) })
if ($killable.Count -gt 0) {
    foreach ($k in $killable) { $report.findings += "TIER_B: KILL VECTOR -- $($k.kind) $($k.name) writable from IL=$ilMode" }
}

# 4.3 Access to dwm.exe (VM_READ, TERMINATE, SUSPEND) from our IL
Write-Host "[B3] OpenProcess(dwm) capability from IL=$ilMode ..."
$capChecks = @()
foreach ($accessName in @('PROCESS_QUERY_LIMITED_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_VM_READ','PROCESS_TERMINATE','PROCESS_SUSPEND_RESUME','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_ALL_ACCESS')) {
    $bit = [N]::$accessName
    $h = [N]::OpenProcess($bit, $false, [uint32]$report.dwm_pid)
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($h -ne [IntPtr]::Zero) {
        $capChecks += [pscustomobject]@{ access=$accessName; granted=$true; gle=0 }
        [N]::CloseHandle($h) | Out-Null
    } else {
        $capChecks += [pscustomobject]@{ access=$accessName; granted=$false; gle=$gle }
    }
}
$report.tier_b.dwm_access = $capChecks
$report.tier_b.dwm_terminate_granted = [bool](($capChecks | Where-Object { $_.access -eq 'PROCESS_TERMINATE' -and $_.granted }))
$report.tier_b.dwm_vm_read_granted   = [bool](($capChecks | Where-Object { $_.access -eq 'PROCESS_VM_READ' -and $_.granted }))
if ($report.tier_b.dwm_terminate_granted -and -not $isElevated) {
    $report.findings += "TIER_B: MEDIUM_IL granted PROCESS_TERMINATE on dwm.exe -- catastrophic"
}
if ($report.tier_b.dwm_vm_read_granted -and -not $isElevated) {
    $report.findings += "TIER_B: MEDIUM_IL granted PROCESS_VM_READ on dwm.exe -- memory scan enabled"
}

# 4.4 Class-name FindWindow with derived iso-input class
$hClass = [N]::FindWindowW($derived.cls_iso_inp, $null)
$report.tier_b.iso_input_hwnd = if ($hClass -ne [IntPtr]::Zero) { "0x{0:X}" -f $hClass.ToInt64() } else { 'NOT_FOUND' }
if ($hClass -ne [IntPtr]::Zero) {
    $report.findings += "TIER_B: FindWindow(iso-input class) succeeded -- our helper's window enumerable + addressable"
}

# -------------------------------------------------------------------
# 5. Disrupt / non-destructive kill
# -------------------------------------------------------------------
if ($Disrupt) {
    Write-Host "`n--- DISRUPT (non-destructive) ---" -ForegroundColor Yellow

    # 5.1 Signal shutdown event (should ACCESS_DENIED for medium IL)
    Write-Host "[D1] attempt to signal Global\<evt_shut> (should be DENIED for medium IL)..."
    $ev = [N]::OpenEventW([N]::EVENT_MODIFY_STATE, $false, "Global\$($derived.evt_shut)")
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($ev -ne [IntPtr]::Zero) {
        [N]::SetEvent($ev) | Out-Null
        [N]::CloseHandle($ev) | Out-Null
        $report.disrupt_res.evt_shut_signal = @{ result='SIGNALED'; gle=0 }
        $report.findings += "DISRUPT: shutdown event SIGNAL succeeded from IL=$ilMode -- payload will exit"
    } else {
        $report.disrupt_res.evt_shut_signal = @{ result='DENIED'; gle=$gle }
    }

    # 5.2 Mutex squat attack — pre-create Local\<mtx_init>
    Write-Host "[D2] mutex-squat: create Local\<mtx_init> for ${MutexSquatSec}s (blocks reinjection)..."
    $mtxName = "Local\$($derived.mtx_init)"
    $mtx = [N]::CreateMutexW([IntPtr]::Zero, $false, $mtxName)
    $mtxGle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $report.disrupt_res.mutex_squat = @{
        name = $mtxName
        created = ($mtx -ne [IntPtr]::Zero)
        already_existed = ($mtxGle -eq 183)  # ERROR_ALREADY_EXISTS
        gle = $mtxGle
        hold_sec = $MutexSquatSec
    }
    if ($mtx -ne [IntPtr]::Zero) {
        Write-Host "  squatting for ${MutexSquatSec}s (payload reinject during this window should DoS on init-guard)"
        Start-Sleep -Seconds $MutexSquatSec
        [N]::CloseHandle($mtx) | Out-Null
    }
    if ($mtxGle -ne 183 -and $mtx -ne [IntPtr]::Zero) {
        # We were the FIRST to create; if payload is running, payload's mutex existed BEFORE us, so we should get ALREADY_EXISTS.
        # If we did NOT get ALREADY_EXISTS, it means the mutex namespace collision does NOT apply cross-session
        # (Local\ is per-session; DWM's session vs ours). In that case the attack does NOT work.
        $report.findings += "DISRUPT: mutex_squat created FRESH (not already existing) -- Local\<mtx> is not visible to DWM's session; attack ineffective this way"
    } elseif ($mtxGle -eq 183) {
        $report.findings += "DISRUPT: mutex_squat COLLIDED with DWM's Local\<mtx> -- reinject WILL DoS if we hold the handle open (visible across sessions)"
    }

    # 5.3 Pipe DoS: hold OCR pipe forever
    Write-Host "[D3] pipe DoS: connect to OCR pipe + hold for ${PipeDosSec}s..."
    $ocrPipeName = "\\.\pipe\$($derived.pipe_ocr)"
    $ocrH = [N]::CreateFileW($ocrPipeName, $GENERIC_RW, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)  # GENERIC_RW
    if ($ocrH -ne [IntPtr]::new(-1) -and $ocrH -ne [IntPtr]::Zero) {
        Write-Host "  connected to OCR pipe; holding for ${PipeDosSec}s"
        Start-Sleep -Seconds $PipeDosSec
        [N]::CloseHandle($ocrH) | Out-Null
        $report.disrupt_res.pipe_dos_ocr = @{ connected=$true; held_sec=$PipeDosSec }
        $report.findings += "DISRUPT: OCR pipe connect from IL=$ilMode succeeded -- max_instances=1 pipe can be held to DoS OCR feature"
    } else {
        $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $report.disrupt_res.pipe_dos_ocr = @{ connected=$false; gle=$gle }
    }

    # 5.4 Hotkey collision — register some of our known combos with a temp hwnd
    Write-Host "[D4] hotkey-collision -- try to reserve Ctrl+B, Ctrl+D, Ctrl+Alt+R, Ctrl+Shift+Alt+K..."
    $combos = @(
        @{ id=91; mods=([N]::MOD_CTRL); vk=[uint32]0x42; label='Ctrl+B' },                       # QUICK_ASK
        @{ id=92; mods=([N]::MOD_CTRL); vk=[uint32]0x44; label='Ctrl+D' },                       # DEEPER_SOLVE
        @{ id=93; mods=([N]::MOD_CTRL -bor [N]::MOD_ALT); vk=[uint32]0x52; label='Ctrl+Alt+R' }, # RESET_POS
        @{ id=94; mods=([N]::MOD_CTRL -bor [N]::MOD_SHIFT -bor [N]::MOD_ALT); vk=[uint32]0x4B; label='Ctrl+Shift+Alt+K' } # KILL_ALL
    )
    $hkResults = @()
    foreach ($c in $combos) {
        $ok = [N]::RegisterHotKey([IntPtr]::Zero, $c.id, $c.mods, $c.vk)
        $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $hkResults += [pscustomobject]@{ label=$c.label; registered=$ok; gle=$gle }
        if ($ok) { [N]::UnregisterHotKey([IntPtr]::Zero, $c.id) | Out-Null }
    }
    $report.disrupt_res.hotkey_collisions = $hkResults
    # RegisterHotKey with a system-wide combo COMPETES; if we register it, real user Ctrl+B doesn't reach any other app.
    # svcldb uses LL-hook (not RegisterHotKey), so this DOESN'T hijack our path — but it might make a normal Windows sound / no-op.
    # Which is exactly the useful measurement.

    # 5.5 ClipCursor DoS
    Write-Host "[D5] ClipCursor to (0,0,1,1) then release after 1s..."
    $rect = New-Object N+RECT
    $rect.L=0; $rect.T=0; $rect.R=1; $rect.B=1
    $clipOk = [N]::ClipCursor([ref]$rect)
    if ($clipOk) {
        Start-Sleep -Seconds 1
        [N]::ClipCursor([IntPtr]::Zero) | Out-Null
        $report.disrupt_res.clipcursor = @{ effective=$true }
    } else {
        $report.disrupt_res.clipcursor = @{ effective=$false; gle=[Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    }

    # 5.6 sihost.exe --unload from OUR IL (via Process.Start w/ UseShellExecute=false so
    # requireAdministrator surfaces ERROR_ELEVATION_REQUIRED synchronously instead of
    # blocking on an invisible UAC prompt from a non-interactive context).
    Write-Host "[D6] sihost.exe --unload from IL=$ilMode (should ELEVATION_REQUIRED on medium)..."
    $ulRes = @{}
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'C:\ProgramData\WinAudioSvc\sihost.exe'
        $psi.Arguments = '--unload'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $waited = $proc.WaitForExit(4000)
        if ($waited) {
            $ulRes = @{ exit = $proc.ExitCode; blocked = $false; stdout = $proc.StandardOutput.ReadToEnd().Trim() }
        } else {
            try { $proc.Kill() } catch {}
            $ulRes = @{ exit = -1; blocked = $true; stdout = 'HUNG_KILLED' }
        }
    } catch {
        $win32 = $_.Exception -as [System.ComponentModel.Win32Exception]
        $native = if ($win32) { $win32.NativeErrorCode } else { -1 }
        $ulRes = @{ exit = -1; error = $_.Exception.Message; native = $native }
    }
    $report.disrupt_res.sihost_unload = $ulRes
    if ($ulRes.exit -eq 0 -and -not $isElevated) {
        $report.findings += "DISRUPT: sihost --unload succeeded from IL=$ilMode -- P0 kill vector"
    }
    if ($ulRes.native -eq 740) {  # ERROR_ELEVATION_REQUIRED
        $report.disrupt_res.sihost_unload.classified = 'ELEVATION_REQUIRED (good -- medium IL cannot spawn)'
    }
    # After a moment, check payload liveness
    Start-Sleep -Seconds 1
    $ev = [N]::OpenEventW([N]::SYNCHRONIZE, $false, "Global\$($derived.evt_shut)")
    $payloadStill = ($ev -ne [IntPtr]::Zero)
    if ($ev -ne [IntPtr]::Zero) { [N]::CloseHandle($ev) | Out-Null }
    $report.disrupt_res.payload_still_after_unload = $payloadStill
}

# -------------------------------------------------------------------
# 6. Destructive kill (only when --DestructiveKill AND -Elevated)
# -------------------------------------------------------------------
if ($DestructiveKill -and $isElevated) {
    Write-Host "`n--- DESTRUCTIVE KILL (admin only) ---" -ForegroundColor Red
    $h = [N]::OpenProcess([N]::PROCESS_TERMINATE, $false, [uint32]$report.dwm_pid)
    if ($h -ne [IntPtr]::Zero) {
        Write-Host "  TerminateProcess(dwm.exe pid=$($report.dwm_pid))"
        [N]::TerminateProcess($h, 1) | Out-Null
        [N]::CloseHandle($h) | Out-Null
        $report.disrupt_res.dwm_terminated = $true
        $report.findings += "DESTRUCTIVE: admin TerminateProcess(dwm.exe) issued -- winlogon should respawn dwm within ~2s"
    } else {
        $report.disrupt_res.dwm_terminated = $false
        $report.disrupt_res.dwm_terminate_gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
}

# -------------------------------------------------------------------
# 7. Verdict + save
# -------------------------------------------------------------------
$critical = @($report.findings | Where-Object { $_ -match 'KILL VECTOR|P0 kill|catastrophic|payload will exit|SIGNAL succeeded|MEDIUM_IL granted' })
if ($critical.Count -gt 0) { $report.verdict = 'CRITICAL' }
elseif ($report.findings.Count -gt 0) { $report.verdict = 'MINOR_LEAKS' }
else { $report.verdict = 'CLEAN' }

Write-Host "`n==============================================================" -ForegroundColor Cyan
Write-Host " VERDICT: $($report.verdict)" -ForegroundColor $(if ($report.verdict -eq 'CLEAN') { 'Green' } elseif ($report.verdict -eq 'MINOR_LEAKS') { 'Yellow' } else { 'Red' })
Write-Host " findings: $($report.findings.Count)"
foreach ($f in $report.findings) { Write-Host "  * $f" -ForegroundColor $(if ($f -match 'KILL|catastrophic|CRITICAL') { 'Red' } else { 'Yellow' }) }
Write-Host "==============================================================" -ForegroundColor Cyan

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $json -Encoding ASCII
Write-Host "`nJSON scorecard: $json"

# exit code convention
if ($report.verdict -eq 'CRITICAL') { exit 7 }
elseif ($report.verdict -eq 'MINOR_LEAKS') { exit 5 }
else { exit 0 }
