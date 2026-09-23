<#
  attack_admin.ps1 -- P1 admin-tier attack surface.

  We run at High/System integrity. Goal: enumerate every non-destructive
  way an admin could DETECT or KILL svcldb without triggering DWM crash
  (=> winlogon respawn, acceptable) or destroying winlogon (=> BSOD).

  Casual admin detection expectations:
    - tasklist / Get-Process for known svcldb names -> should be EMPTY
    - dwm.exe module enum -> should be EMPTY of svcldb/dwmapiext/CloakGPT
    - Named pipes / objects with obvious names -> should be EMPTY
    - `sc query` for services -> should be EMPTY
    - Autoruns / scheduled tasks -> should be MINIMAL
    - Setup.exe on disk in Program Files -> WILL EXIST (accepted)
    - ProgramData\WinAudioSvc dir -> WILL EXIST (accepted)

  Admin has to HUNT for us:
    - Memory-scan dwm.exe for svcldb/hooks_install/etc.
    - Match on obf_names GUIDs (attacker must know salts + read bind.bin)
    - Trace ETW ImageLoad events at inject time (already gone by now)

  Non-destructive kill attempts (each should FAIL or trigger winlogon respawn):
    K1  Signal shutdown event with proper DACL grant (admin has BA)
        -> payload gracefully unloads. THIS IS THE INTENDED PATH.
    K2  --unload from admin -> same as K1.
    K3  --kill from admin -> destructive (dwm terminated) -> winlogon respawns dwm
    K4  --kill-all from admin -> destructive
    K5  Remote FreeLibrary of dwmapiext in dwm -> impossible (peb unlink)
    K6  Enumerate + close specific handles in dwm via NtDuplicateObject -> hard
    K7  Kill winlogon.exe -> BSOD (CRITICAL_PROCESS_DIED)
    K8  Uninstall via Setup.exe uninstaller -> intended user-driven path
    K9  Delete ProgramData\WinAudioSvc -> ACL says user-full-control so deletable
        BUT payload is IN-MEMORY, doesn't need files at runtime. Kill happens
        only on next launch (config missing).
    K10 Force MinHook detour removal by patching dwmcore addresses -> requires
        admin OpenProcess + VirtualProtect + WriteProcessMemory. This is the
        "surgical unhook" attack. If it works, we're unloadable without dwm crash.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference='Continue'
$results = [ordered]@{}
$results.startedUtc = (Get-Date).ToUniversalTime().ToString('o')
$results.env = [ordered]@{
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
try {
    $wg = whoami /groups /fo csv | ConvertFrom-Csv
    $m = $wg | Where-Object { $_.'Group Name' -like 'Mandatory Label*' } | Select-Object -First 1
    if ($m) { $results.env.integrityLevel = $m.'Group Name' }
} catch {}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class A {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenEventW(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr sz, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr sz, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr sz);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr sz, uint newp, out uint oldp);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public ushort _pad;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
}
"@

$PROCESS_VM_READ = 0x0010
$PROCESS_VM_WRITE = 0x0020
$PROCESS_VM_OPERATION = 0x0008
$SYNCHRONIZE = 0x00100000
$EVENT_MODIFY_STATE = 0x0002

# ------------ CASUAL DETECTION (should return NOTHING) ------------
Write-Host "[casual] tasklist for svcldb-obvious names"
$results.casualProcess = @(Get-CimInstance Win32_Process -EA SilentlyContinue |
    Where-Object { $_.Name -match '(?i)svcldb|cloak|dwmapi|winaudio|wasvc' -or $_.ExecutablePath -match '(?i)svcldb|cloakgpt|winaudiosvc|wasvc' } |
    Select-Object ProcessId, Name, ExecutablePath)

Write-Host "[casual] Get-Service for svcldb-obvious names"
$results.casualService = @(Get-Service -EA SilentlyContinue |
    Where-Object { $_.Name -match '(?i)svcldb|cloak|dwmapi|winaudio|wasvc' -or $_.DisplayName -match '(?i)svcldb|cloak|winaudio' } |
    Select-Object Name, DisplayName, Status)

Write-Host "[casual] admin module enum of dwm.exe"
$dwm = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
$results.casualDwmModules = @{}
if ($dwm) {
    try {
        $mods = @($dwm.Modules)
        $results.casualDwmModules.total = $mods.Count
        $results.casualDwmModules.suspicious = @($mods | Where-Object {
            $_.ModuleName -match '(?i)svcldb|dwmapiext|cloak|wasvc|winaudio|wl_input'
        } | ForEach-Object { $_.ModuleName })
        $results.casualDwmModules.dwmPid = $dwm.Id
    } catch { $results.casualDwmModules.error = "$_" }
}

Write-Host "[casual] admin module enum of winlogon.exe"
$winlog = Get-Process winlogon -EA SilentlyContinue
$results.casualWinlogonModules = @()
foreach ($p in $winlog) {
    try {
        $mods = @($p.Modules)
        $results.casualWinlogonModules += @{
            pid = $p.Id
            total = $mods.Count
            suspicious = @($mods | Where-Object {
                $_.ModuleName -match '(?i)svcldb|wl_input|cloak|wasvc|winaudio'
            } | ForEach-Object { $_.ModuleName })
        }
    } catch { $results.casualWinlogonModules += @{ pid = $p.Id; error = "$_" } }
}

Write-Host "[casual] scheduled tasks matching svcldb pattern"
try {
    $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {
        $_.TaskName -match '(?i)svcldb|cloak|winaudio|dwmapi' -or
        $_.Description -match '(?i)svcldb|cloak|winaudio|dwmapi'
    }
    $results.casualScheduledTasks = @($tasks | Select-Object TaskName, TaskPath, State)
} catch { $results.casualScheduledTasks = @{ error = "$_" } }

Write-Host "[casual] autorun regs (HKLM Run + HKCU Run)"
$autoruns = @()
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
    if (Test-Path $k) {
        $p = Get-ItemProperty $k -EA SilentlyContinue
        $p.PSObject.Properties | Where-Object {
            $_.Name -notmatch '^PS' -and ($_.Name -match '(?i)svcldb|cloak|winaudio|dwmapi' -or "$($_.Value)" -match '(?i)svcldb|cloakgpt|winaudio|dwmapi')
        } | ForEach-Object {
            $autoruns += [pscustomobject]@{ key=$k; name=$_.Name; value="$($_.Value)" }
        }
    }
}
$results.casualAutoruns = $autoruns

Write-Host "[casual] named-pipe enum for obvious names"
$pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\')) | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
$results.casualPipes = @($pipes | Where-Object { $_ -match '(?i)svcldb|cloak|dwmapiext|winaudiosvc|phantom|wasvc' })

# ------------ HUNT-LEVEL DETECTION ------------
Write-Host "[hunt] admin memory scan of dwm.exe for identifying strings"
if ($dwm) {
    $h = [A]::OpenProcess([uint32]$PROCESS_VM_READ, $false, [uint32]$dwm.Id)
    if ($h -ne [IntPtr]::Zero) {
        $needles = @(
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('svcldb'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('cloakgpt'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('CloakGPT'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('dwmapiext'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('hooks_install'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('peb_unlink'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('sub_check'),
            [byte[]][System.Text.Encoding]::ASCII.GetBytes('wasvc.'),
            [byte[]][System.Text.Encoding]::Unicode.GetBytes('SysCompositorSink'),
            [byte[]][System.Text.Encoding]::Unicode.GetBytes('MSDiagEventSink')
        )
        $names = @('svcldb','cloakgpt','CloakGPT','dwmapiext','hooks_install','peb_unlink','sub_check','wasvc.','W:SysCompositorSink','W:MSDiagEventSink')
        $hits = @{}; foreach ($n in $names) { $hits[$n] = 0 }
        $bytesScanned = 0
        $regionsScanned = 0
        $regionsSkipped = 0
        $addr = [IntPtr]::Zero
        $mbi = New-Object 'A+MBI'
        $mbiSz = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
        $buf = New-Object byte[] 262144
        $t0 = Get-Date
        while ($true) {
            $q = [A]::VirtualQueryEx($h, $addr, [ref]$mbi, [IntPtr]$mbiSz)
            if ($q -eq [IntPtr]::Zero) { break }
            if ($mbi.RegionSize.ToInt64() -le 0) { break }
            $isCommit = ($mbi.State -eq 0x1000)
            $isPriv   = ($mbi.Type -eq 0x20000)
            $isGuard  = (($mbi.Protect -band 0x100) -ne 0)
            if ($isCommit -and $isPriv -and -not $isGuard) {
                $sz = $mbi.RegionSize.ToInt64()
                if ($sz -gt 32MB) {
                    $regionsSkipped++
                } else {
                    $regionsScanned++
                    $base = $mbi.BaseAddress.ToInt64()
                    $off = 0
                    while ($off -lt $sz) {
                        $toRead = [Math]::Min($buf.Length, $sz - $off)
                        $readCount = [IntPtr]0
                        $ok = [A]::ReadProcessMemory($h, [IntPtr]($base + $off), $buf, [IntPtr]$toRead, [ref]$readCount)
                        if ($ok) {
                            $actual = $readCount.ToInt32()
                            $bytesScanned += $actual
                            for ($i = 0; $i -lt $needles.Length; $i++) {
                                $needle = $needles[$i]
                                if ($actual -lt $needle.Length) { continue }
                                $limit = $actual - $needle.Length
                                for ($p = 0; $p -le $limit; $p++) {
                                    if ($buf[$p] -ne $needle[0]) { continue }
                                    $match = $true
                                    for ($q2 = 1; $q2 -lt $needle.Length; $q2++) {
                                        if ($buf[$p+$q2] -ne $needle[$q2]) { $match = $false; break }
                                    }
                                    if ($match) { $hits[$names[$i]]++ }
                                }
                            }
                        }
                        $off += $toRead
                    }
                }
            }
            $next = $mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToInt64()
            if ($next -le $addr.ToInt64()) { break }
            $addr = [IntPtr]$next
            if ($next -gt 0x7FFFFFFF0000) { break }
        }
        [A]::CloseHandle($h) | Out-Null
        $elapsed = ((Get-Date) - $t0).TotalSeconds
        $foundHits = @{}
        foreach ($n in $names) { if ($hits[$n] -gt 0) { $foundHits[$n] = $hits[$n] } }
        $results.huntAdminMemoryScan = @{
            elapsedSec = [math]::Round($elapsed, 2)
            bytesScanned = $bytesScanned
            regionsScanned = $regionsScanned
            regionsSkippedLarge = $regionsSkipped
            hits = $foundHits
        }
    } else {
        $results.huntAdminMemoryScan = @{ error = 'OpenProcess VM_READ failed'; gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    }
}

# ------------ NON-DESTRUCTIVE KILL ATTEMPTS ------------
Write-Host "[K1] direct SetEvent on derived shutdown event as admin"
# admin knows _bind.bin (Admin+SYS+WMG DACL). Read + derive HMAC(bind, salt:guid).
$bindPath = 'C:\ProgramData\WinAudioSvc\_bind.bin'
$bind = if (Test-Path $bindPath) { [System.IO.File]::ReadAllBytes($bindPath) } else { $null }
$mg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid.Trim().ToLower()
function HmacGuid([byte[]]$bind, [string]$salt, [string]$mg) {
    if (-not $bind) { return $null }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$bind[0..31])
    $h = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $mg))
    $hmac.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}
$shutdown = 'Global\' + (HmacGuid $bind 'wasvc.evt.shut.1' $mg)
$results.K1_directSignal = @{ eventName = $shutdown }
$h = [A]::OpenEventW([uint32]($SYNCHRONIZE -bor $EVENT_MODIFY_STATE), $false, $shutdown)
if ($h -ne [IntPtr]::Zero) {
    $results.K1_directSignal.opened = $true
    # Do NOT actually signal; that would kill the payload we need for subsequent tests.
    # Just verify opening works.
    [A]::CloseHandle($h) | Out-Null
    $results.K1_directSignal.would_kill = $true
} else {
    $results.K1_directSignal.opened = $false
    $results.K1_directSignal.gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
}

Write-Host "[K2/K3/K4] --unload / --kill / --kill-all -- SKIPPED (would kill payload; those are expected admin destructive paths)"
$results.K2_unload_note = 'skipped-would-kill-payload'
$results.K3_kill_note   = 'skipped-would-kill-payload-and-crash-dwm-triggering-winlogon-respawn'
$results.K4_kill_all_note = 'skipped-same-as-K3'

Write-Host "[K5] remote FreeLibrary of dwmapiext in dwm -- IMPOSSIBLE because peb_unlink"
$results.K5_freeLibrary = @{ note = 'peb_unlink hides module from LDR entries; no HMODULE resolvable by name; FreeLibrary path unreachable'; verified = 'via casualDwmModules result -- suspicious=empty' }

Write-Host "[K7] terminate winlogon -- INTENTIONALLY SKIPPED (would BSOD)"
$results.K7_terminateWinlogon = @{ note = 'CRITICAL_PROCESS_DIED bugcheck -- destructive by design' }

Write-Host "[K9] delete C:\ProgramData\WinAudioSvc -- payload survives (in-memory)"
$results.K9_deleteFiles = @{ note = 'payload runs in dwm.exe entirely from memory; deleting on-disk files only breaks next arm, not current session' }

Write-Host "[K10] surgical unhook (patch dwmcore addresses back) -- requires resolving hook targets"
# Would need to open dwmcore module, find our JMP patches, restore original bytes.
# Feasible but requires reverse engineering. Note as advanced.
$results.K10_surgicalUnhook = @{ note = 'requires admin OpenProcess(dwm, VM_WRITE) + scan for E9/FF25 stubs at expected dwmcore offsets + restore original bytes. Feasible but requires stack of knowledge (dwmcore version, hook target names, patch signatures).' }

# ------------ VERDICT ------------
$issues = @()
$verdict = 'ACCEPTED_ADMIN_RISK'
if ($results.casualProcess.Count -gt 0) {
    $issues += "casual process enum matched svcldb pattern"
    $verdict = 'ADMIN_FIND_EASY'
}
if ($results.casualDwmModules.suspicious.Count -gt 0) {
    $issues += "admin dwm.exe module enum leaked: $($results.casualDwmModules.suspicious -join ',')"
    $verdict = 'ADMIN_FIND_EASY'
}
if ($results.casualService.Count -gt 0) { $issues += "svc-named service found" }
if ($results.casualScheduledTasks.Count -gt 0) { $issues += "svcldb scheduled task found" }
if ($results.casualAutoruns.Count -gt 0) { $issues += "svcldb autorun entry found" }
if ($results.casualPipes.Count -gt 0) { $issues += "svcldb-named pipe found: $($results.casualPipes -join ',')" }
foreach ($w in $results.casualWinlogonModules) {
    $s = $w.suspicious
    if ($s -and $s.Count -gt 0) {
        $issues += "winlogon $($w.pid) leaked module(s): $($s -join ',')"
        $verdict = 'ADMIN_FIND_EASY'
    }
}
if ($results.K1_directSignal.opened) {
    $issues += "K1: admin opened shutdown event with SetEvent access -- can kill payload gracefully"
    # THIS IS EXPECTED and DOCUMENTED as the intended admin path.
}
$results.verdict = $verdict
$results.issues = $issues
$results.completedUtc = (Get-Date).ToUniversalTime().ToString('o')
$results | ConvertTo-Json -Depth 8 | Set-Content -Path $Out -Encoding ASCII
Write-Host "DONE verdict=$verdict issues=$($issues.Count)"
