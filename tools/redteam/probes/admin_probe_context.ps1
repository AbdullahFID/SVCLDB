# admin_probe_context.ps1 -- like admin_probe.ps1 but on each hit for a target
# pattern it dumps a printable context window so we can see EXACTLY what the
# leaking string is (a salt? a URL? a path? a decrypted config field?).
#
# Read-only. Elevated. Scans dwm private committed memory.
param(
  [string[]]$Ascii = @('svcldb','cloakgpt','dwmapiext','winaudiosvc','hooks_install','handshake','overlay','inject'),
  [string[]]$Wide  = @('svcldb','cloakgpt','dwmapiext','overlay'),
  [int]$MaxPerPattern = 12,
  [int]$Context = 96
)
$ErrorActionPreference = 'Stop'
$dwm = Get-Process dwm -EA SilentlyContinue | Select-Object -First 1
if (-not $dwm) { throw 'dwm not running' }
$dwmPid = $dwm.Id
Write-Host ("dwm pid: {0}" -f $dwmPid)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class MemCtx {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool i,uint p);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,IntPtr s,out IntPtr r);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h,IntPtr a,out MBI m,IntPtr l);
    [StructLayout(LayoutKind.Sequential)] struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public ushort _pad; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    public class Hit { public string Pattern; public bool Wide; public long Addr; public string Context; }
    static string Printable(byte[] buf, int start, int len) {
        var sb = new StringBuilder();
        for (int i = start; i < start + len && i < buf.Length && i >= 0; i++) {
            byte b = buf[i];
            if (b >= 0x20 && b < 0x7f) sb.Append((char)b);
            else if (b == 0) sb.Append('.');
            else sb.Append('?');
        }
        return sb.ToString();
    }
    public static List<Hit> Scan(int pid, string[] ascii, string[] wide, int maxPer, int ctx, long maxRegion) {
        var hits = new List<Hit>();
        var counts = new Dictionary<string,int>();
        var aPat = new byte[ascii.Length][];
        for (int i=0;i<ascii.Length;i++){ aPat[i]=Encoding.ASCII.GetBytes(ascii[i]); counts["a:"+ascii[i]]=0; }
        var wPat = new byte[wide.Length][];
        for (int i=0;i<wide.Length;i++){ wPat[i]=Encoding.Unicode.GetBytes(wide[i]); counts["w:"+wide[i]]=0; }
        IntPtr h = OpenProcess(0x0410, false, (uint)pid);
        if (h == IntPtr.Zero) throw new Exception("OpenProcess failed " + Marshal.GetLastWin32Error());
        try {
            IntPtr addr = IntPtr.Zero; int mbiSize = Marshal.SizeOf(typeof(MBI));
            byte[] buf = new byte[1048576];
            while (true) {
                MBI mbi;
                if (VirtualQueryEx(h, addr, out mbi, (IntPtr)mbiSize) == IntPtr.Zero) break;
                long region = mbi.RegionSize.ToInt64();
                if (region <= 0) break;
                bool commit=(mbi.State==0x1000); bool priv=(mbi.Type==0x20000); bool guarded=((mbi.Protect&0x100)!=0);
                if (commit && priv && !guarded && region <= maxRegion) {
                    long baseAddr = mbi.BaseAddress.ToInt64(); long remaining = region; long offset = 0;
                    while (remaining > 0) {
                        int toRead = (int)Math.Min(buf.Length, remaining);
                        IntPtr rd; IntPtr readAt = new IntPtr(baseAddr + offset);
                        if (ReadProcessMemory(h, readAt, buf, (IntPtr)toRead, out rd)) {
                            int actual = rd.ToInt32();
                            for (int p=0;p<aPat.Length;p++){
                                var pat=aPat[p]; string key="a:"+ascii[p];
                                for (int i=0;i+pat.Length<=actual;i++){ bool m=true; for(int j=0;j<pat.Length;j++){ if(buf[i+j]!=pat[j]){m=false;break;} }
                                    if(m){ if(counts[key]<maxPer){ int s=Math.Max(0,i-16); hits.Add(new Hit{Pattern=ascii[p],Wide=false,Addr=baseAddr+offset+i,Context=Printable(buf,s,ctx)}); } counts[key]++; i+=pat.Length-1; } }
                            }
                            for (int p=0;p<wPat.Length;p++){
                                var pat=wPat[p]; string key="w:"+wide[p];
                                for (int i=0;i+pat.Length<=actual;i++){ bool m=true; for(int j=0;j<pat.Length;j++){ if(buf[i+j]!=pat[j]){m=false;break;} }
                                    if(m){ if(counts[key]<maxPer){ int s=Math.Max(0,i-32); hits.Add(new Hit{Pattern=wide[p],Wide=true,Addr=baseAddr+offset+i,Context=Printable(buf,s,ctx*2)}); } counts[key]++; i+=pat.Length-1; } }
                            }
                        }
                        offset += toRead; remaining -= toRead;
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + region;
                if (next <= addr.ToInt64()) break;
                addr = new IntPtr(next);
                if (next > 0x00007FFFFFFFFFFFL) break;
            }
        } finally { CloseHandle(h); }
        return hits;
    }
}
"@

$hits = [MemCtx]::Scan([int]$dwmPid, [string[]]$Ascii, [string[]]$Wide, [int]$MaxPerPattern, [int]$Context, [long]33554432)
Write-Host ("total hit contexts captured: {0}" -f $hits.Count)
foreach ($grp in ($hits | Group-Object { ($(if($_.Wide){'W:'}else{'A:'})) + $_.Pattern })) {
    Write-Host ("`n=== {0}  ({1} shown) ===" -f $grp.Name, $grp.Count) -ForegroundColor Cyan
    foreach ($hh in $grp.Group) {
        Write-Host ("  0x{0:x}  {1}" -f $hh.Addr, $hh.Context) -ForegroundColor Yellow
    }
}
