<#
  admin_thread_probe.ps1 -- ADMIN adversary: identify + SuspendThread svcldb's
  threads inside dwm.exe, and verify the v3.1 thread-integrity watchdog.

  Models a privileged (admin + SeDebug) attacker that walks dwm's threads,
  fingerprints the ones whose Win32 start address lands inside the manual-
  mapped payload module, and SuspendThread()s them to freeze our input path.

  Watchdog detection trick: SuspendThread returns the PREVIOUS suspend count.
  1. Suspend T   (count 0 -> 1, returns 0)
  2. wait > watchdog window (~4.5s)
  3. Suspend T again -> if it returns 0, something RESUMED T in between (the
     watchdog) => T was the poll thread and the watchdog recovered it.
     if it returns >=1, T stayed suspended (watchdog doesn't cover it / it IS
     the watchdog / it's a non-critical thread).
  Each thread is fully resumed afterward, so the box is left healthy.

  Requires elevation. Usage:
    powershell -File admin_thread_probe.ps1 -DwmPid 14444 -BaseHex 00000202247D0000
#>
[CmdletBinding()]
param(
    [int]$DwmPid = 14444,
    [string]$BaseHex = "00000202247D0000",
    [uint64]$Span = 0x100000
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class TP {
    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32 { public uint dwSize; public uint cntUsage; public uint th32ThreadID; public uint th32OwnerProcessID; public int tpBasePri; public int tpDeltaPri; public uint dwFlags; }

    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint SuspendThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, IntPtr ret);

    const uint TH32CS_SNAPTHREAD = 0x4;
    const uint THREAD_QUERY_INFORMATION = 0x40;
    const uint THREAD_SUSPEND_RESUME = 0x2;
    const int  ThreadQuerySetWin32StartAddress = 9;

    public static List<uint[]> FindPayloadThreads(uint pid, ulong lo, ulong hi) {
        var res = new List<uint[]>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == (IntPtr)(-1)) return res;
        var te = new THREADENTRY32(); te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
        if (Thread32First(snap, ref te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                IntPtr h = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
                if (h == IntPtr.Zero) continue;
                IntPtr start;
                int st = NtQueryInformationThread(h, ThreadQuerySetWin32StartAddress, out start, IntPtr.Size, IntPtr.Zero);
                CloseHandle(h);
                if (st != 0) continue;
                ulong sa = (ulong)start.ToInt64();
                if (sa >= lo && sa < hi) res.Add(new uint[]{ te.th32ThreadID, (uint)(sa - lo) });  // store offset from base
            } while (Thread32Next(snap, ref te));
        }
        CloseHandle(snap);
        return res;
    }

    // Suspend, wait, re-suspend to detect watchdog resume, then fully resume.
    // Returns: prev1|prev2|finalResumeCount
    public static string ProbeThread(uint tid, int waitMs) {
        IntPtr h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid);
        if (h == IntPtr.Zero) return "OPEN_FAIL gle=" + Marshal.GetLastWin32Error();
        uint prev1 = SuspendThread(h);
        System.Threading.Thread.Sleep(waitMs);
        uint prev2 = SuspendThread(h);
        // fully resume (undo our 1 or 2 suspends + any residual)
        int guard = 0; uint r;
        do { r = ResumeThread(h); guard++; } while (r != 0xFFFFFFFF && r > 1 && guard < 64);
        CloseHandle(h);
        string verdict = (prev2 == 0) ? "WATCHDOG_RESUMED (poll path recovered)" : "stayed-suspended";
        return "prev1=" + prev1 + " prev2=" + prev2 + " -> " + verdict;
    }
}
"@

$lo = [uint64]("0x$BaseHex")
$hi = $lo + $Span
Write-Host ("=== enumerating dwm(pid=$DwmPid) threads with start-addr in payload [0x{0:X}..0x{1:X}] ===" -f $lo,$hi)
$threads = [TP]::FindPayloadThreads([uint32]$DwmPid, $lo, $hi)
Write-Host ("svcldb threads found: {0}" -f $threads.Count)
foreach ($t in $threads) { Write-Host ("  TID {0}  start=base+0x{1:X}" -f $t[0], $t[1]) }
if ($threads.Count -eq 0) { Write-Host "NONE FOUND -- base wrong or payload gone"; exit 1 }

Write-Host ""
Write-Host "=== per-thread SuspendThread + watchdog-recovery probe (4.5s window each) ==="
foreach ($t in $threads) {
    $r = [TP]::ProbeThread([uint32]$t[0], 4500)
    Write-Host ("  TID {0} (base+0x{1:X}): {2}" -f $t[0], $t[1], $r)
}
Write-Host "=== DONE (all threads resumed) ==="
