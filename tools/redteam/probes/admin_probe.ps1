# admin_probe.ps1 -- admin-tier detection sweep for svcldb (v2, C# scanner).
#
# The non-admin hunter reports CLEAN. This probe uses admin capabilities:
# OpenProcess(dwm, VM_READ), module enumeration, and a fast C# private-memory
# string scanner. Not asking "can admin find us at all" (persistent admin +
# kernel driver obviously will) -- asking "how visible are we to a TRIVIAL
# admin looker that greps memory / enumerates modules". Each hit is a real
# IOC to weigh vs. cost of hiding it.

param([string]$Json = 'C:\Users\abdul\Desktop\svcldb\tools\redteam\runtime\admin_probe.json')
$ErrorActionPreference = 'Stop'

$dwm = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
if (-not $dwm) { throw 'dwm not running' }
$dwmPid = $dwm.Id
Write-Host ("dwm pid: {0}" -f $dwmPid)

# ---- 1. Module enumeration -------------------------------------------
$mods = @()
try { $mods = @($dwm.Modules | ForEach-Object { $_.ModuleName }) } catch {}
$sus = @($mods | Where-Object { $_ -match 'svcldb|cloakgpt|dwmapiext|winaudiosvc|MSDiagEventSink' })
Write-Host ("modules loaded in dwm: {0}  suspicious: [{1}]" -f $mods.Count, ($sus -join ','))

# ---- 2. C# scanner (in-process, fast) --------------------------------
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class MemScan {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [StructLayout(LayoutKind.Sequential)]
    struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public ushort _pad;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    public class Result {
        public long BytesScanned;
        public int  RegionsScanned;
        public int  RegionsSkippedLarge;
        public Dictionary<string,int> Hits = new Dictionary<string,int>();
    }
    static int CountOccurrences(byte[] hay, int hayLen, byte[] needle) {
        int c = 0, n = needle.Length;
        if (n == 0 || hayLen < n) return 0;
        int last = hayLen - n;
        byte b0 = needle[0];
        for (int i = 0; i <= last; i++) {
            if (hay[i] != b0) continue;
            int j = 1;
            while (j < n && hay[i+j] == needle[j]) j++;
            if (j == n) c++;
        }
        return c;
    }
    public static Result Scan(int pid, string[] ascii, string[] wide, long maxRegionBytes) {
        var r = new Result();
        var asciiPats = new byte[ascii.Length][];
        for (int i = 0; i < ascii.Length; i++) { asciiPats[i] = Encoding.ASCII.GetBytes(ascii[i]); r.Hits[ascii[i]] = 0; }
        var widePats = new byte[wide.Length][];
        for (int i = 0; i < wide.Length; i++) { widePats[i] = Encoding.Unicode.GetBytes(wide[i]); r.Hits["W:" + wide[i]] = 0; }

        IntPtr h = OpenProcess(0x0410, false, (uint)pid);
        if (h == IntPtr.Zero) throw new Exception("OpenProcess failed " + Marshal.GetLastWin32Error());
        try {
            IntPtr addr = IntPtr.Zero;
            int mbiSize = Marshal.SizeOf(typeof(MBI));
            byte[] buf = new byte[262144];   // 256 KB chunks
            while (true) {
                MBI mbi;
                if (VirtualQueryEx(h, addr, out mbi, (IntPtr)mbiSize) == IntPtr.Zero) break;
                long region = mbi.RegionSize.ToInt64();
                if (region <= 0) break;
                bool commit  = (mbi.State  == 0x1000);
                bool priv    = (mbi.Type   == 0x20000);
                bool guarded = ((mbi.Protect & 0x100) != 0);
                if (commit && priv && !guarded) {
                    if (region > maxRegionBytes) { r.RegionsSkippedLarge++; }
                    else {
                        r.RegionsScanned++;
                        long baseAddr = mbi.BaseAddress.ToInt64();
                        long remaining = region;
                        long offset = 0;
                        while (remaining > 0) {
                            int toRead = (int)Math.Min(buf.Length, remaining);
                            IntPtr rd;
                            IntPtr readAt = new IntPtr(baseAddr + offset);
                            if (ReadProcessMemory(h, readAt, buf, (IntPtr)toRead, out rd)) {
                                int actual = rd.ToInt32();
                                r.BytesScanned += actual;
                                for (int i = 0; i < asciiPats.Length; i++) r.Hits[ascii[i]] += CountOccurrences(buf, actual, asciiPats[i]);
                                for (int i = 0; i < widePats.Length;  i++) r.Hits["W:" + wide[i]] += CountOccurrences(buf, actual, widePats[i]);
                            }
                            offset += toRead; remaining -= toRead;
                        }
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + region;
                if (next <= addr.ToInt64()) break;   // safety
                addr = new IntPtr(next);
                if (next > 0x00007FFFFFFFFFFFL) break;   // usermode ceiling
            }
        } finally { CloseHandle(h); }
        return r;
    }
}
"@

$ascii = @(
  'wasvc.pipe.token.1', 'wasvc.pipe.ocr.1', 'wasvc.mtx.init.1', 'wasvc.mtx.ocrd.1', 'wasvc.evt.shut.1',
  'svcldb', 'cloakgpt', 'dwmapiext', 'winaudiosvc',
  'svcldb-config-wrap-v3', 'svcldb-handshake-v1', 'svcldb-ocr-v1', 'wa.ocr.v1', 'wa.hs.v1', 'SysCompositorSink',
  'obf_pipe_token', 'obf_mutex_initguard',
  'hooks_install', 'sub_check', 'HANDSHAKE SKIPPED', 'CVisual', 'CWindowNode'
)
$wide = @('MSDiagEventSink', 'SysCompositorSink', 'svcldb', 'cloakgpt', 'CVisual', 'CWindowNode')

Write-Host "=== C# memory scan (cap 32 MB / region) ==="
$t0 = Get-Date
$r = [MemScan]::Scan([int]$dwmPid, [string[]]$ascii, [string[]]$wide, [long]33554432)
Write-Host ("scanned {0:N0} bytes across {1} regions ({2} regions >32MB skipped)  [{3:N1}s]" -f $r.BytesScanned, $r.RegionsScanned, $r.RegionsSkippedLarge, ((Get-Date)-$t0).TotalSeconds)
Write-Host "=== HITS (any nonzero = admin string-grep on dwm memory finds it) ==="
$hits = @{}
$found = 0
foreach ($k in ($r.Hits.Keys | Sort-Object)) {
    if ($r.Hits[$k] -gt 0) { $hits[$k] = $r.Hits[$k]; $found++; Write-Host ("  {0,6}  {1}" -f $r.Hits[$k], $k) -ForegroundColor Yellow }
}
if ($found -eq 0) { Write-Host "  (no targets found in scanned regions -- admin trivial grep is CLEAN)" -ForegroundColor Green }

$report = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    dwmPid = $dwmPid
    isElevated = $true
    modulesLoaded = $mods.Count
    suspiciousModules = $sus
    bytesScanned = $r.BytesScanned
    regionsScanned = $r.RegionsScanned
    regionsSkippedLarge = $r.RegionsSkippedLarge
    hits = $hits
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $Json -Encoding ASCII
Write-Host ("report: " + $Json)
