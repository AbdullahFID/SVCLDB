<#
  probe_capture_leak.ps1 -- NON-ADMIN screen-capture leak probe (v3.1 co-evolution).

  The overlay is "capture-stealth by design": svcldb's RenderContent hook
  checks svcldb_capture_active() and SKIPS drawing the overlay for any frame
  that DWM is rendering for a capture consumer. That defeats the common
  capture paths (GDI BitBlt, PrintWindow, DXGI Desktop Duplication,
  Windows.Graphics.Capture) because they all drive the hooked render path.

  BUT a determined NON-ADMIN proctor has other capture paths. This probe
  drives several of them and dumps a PNG for each so a human/agent can see
  whether the overlay LEAKED into that path:

    1. gdi   -- BitBlt / CopyFromScreen (baseline; should be CLEAN/hidden)
    2. print -- PrintWindow(GetDesktopWindow, PW_RENDERFULLCONTENT)
    3. mag   -- Magnification API windowed magnifier readback
               (svcldb does NOT hook SyncMagnifierRenderTargetCaptureBits --
                THIS is the suspected leak path)

  All three are unprivileged. No admin, no dwm handle. Output PNGs land in
  -OutDir (default tools\redteam\runtime\capture\).

  Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File probe_capture_leak.ps1
    powershell ... -File probe_capture_leak.ps1 -Methods gdi,mag -Scale 0.5
#>
[CmdletBinding()]
param(
    [string[]]$Methods = @('gdi','print','mag'),
    [double]$Scale = 0.5,
    [string]$OutDir = "$PSScriptRoot\..\runtime\capture"
)

$ErrorActionPreference = 'Stop'
# Normalize -Methods: when passed via `powershell -File ... -Methods gdi,print,mag`
# the whole CSV binds as ONE string element; split it back into an array.
$Methods = @($Methods | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = Get-Date -Format 'HHmmss'

Add-Type -AssemblyName System.Drawing

$src = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Threading;

public static class CapLeak {
    [DllImport("user32.dll")] static extern IntPtr GetDesktopWindow();
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("user32.dll", SetLastError=true)] static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();

    const int SM_CXSCREEN = 0, SM_CYSCREEN = 1;
    const uint PW_RENDERFULLCONTENT = 0x00000002;

    public static void ScreenSize(out int w, out int h) {
        SetProcessDPIAware();
        w = GetSystemMetrics(SM_CXSCREEN);
        h = GetSystemMetrics(SM_CYSCREEN);
    }

    // 1. GDI BitBlt via Graphics.CopyFromScreen
    public static void CaptureGdi(string path, double scale) {
        int w, h; ScreenSize(out w, out h);
        using (var bmp = new Bitmap(w, h, PixelFormat.Format32bppArgb))
        using (var g = Graphics.FromImage(bmp)) {
            g.CopyFromScreen(0, 0, 0, 0, new Size(w, h), CopyPixelOperation.SourceCopy);
            Save(bmp, path, scale);
        }
    }

    // 2. PrintWindow of the desktop with full-content flag
    public static void CapturePrint(string path, double scale) {
        int w, h; ScreenSize(out w, out h);
        IntPtr hwnd = GetDesktopWindow();
        using (var bmp = new Bitmap(w, h, PixelFormat.Format32bppArgb))
        using (var g = Graphics.FromImage(bmp)) {
            IntPtr hdc = g.GetHdc();
            try { PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT); }
            finally { g.ReleaseHdc(hdc); }
            Save(bmp, path, scale);
        }
    }

    static void Save(Bitmap bmp, string path, double scale) {
        if (scale > 0 && scale < 1.0) {
            int nw = (int)(bmp.Width * scale), nh = (int)(bmp.Height * scale);
            using (var small = new Bitmap(nw, nh, PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(small)) {
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                g.DrawImage(bmp, 0, 0, nw, nh);
                small.Save(path, ImageFormat.Png);
            }
        } else {
            bmp.Save(path, ImageFormat.Png);
        }
    }
}
"@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Drawing, System.Windows.Forms

# --- Magnification API probe (separate C# w/ its own message pump) ------
# WC_MAGNIFIER samples the source rect through the DWM magnification path.
# If svcldb doesn't suppress the overlay on that path, it appears here.
$magSrc = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Threading;

public static class MagCap {
    [DllImport("magnification.dll")] static extern bool MagInitialize();
    [DllImport("magnification.dll")] static extern bool MagUninitialize();
    [DllImport("magnification.dll")] static extern bool MagSetWindowSource(IntPtr hwnd, RECT rect);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int left, top, right, bottom; }

    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateWindowExW(uint exStyle, string cls, string name, uint style,
        int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32.dll")] static extern bool UpdateWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr h);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr d,int dx,int dy,int w,int h,IntPtr s,int sx,int sy,int rop);

    const uint WS_POPUP = 0x80000000; const uint WS_CHILD = 0x40000000; const uint WS_VISIBLE = 0x10000000;
    const uint WS_EX_LAYERED = 0x80000; const uint WS_EX_TRANSPARENT = 0x20;
    const int SM_CXSCREEN = 0, SM_CYSCREEN = 1;

    public static string Capture(string path, double scale) {
        SetProcessDPIAware();
        if (!MagInitialize()) return "MagInitialize failed";
        try {
            int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
            // Host window (layered so it doesn't steal the screen visually), off to a corner.
            IntPtr host = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT, "Static", "h",
                WS_POPUP, 0, 0, sw, sh, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (host == IntPtr.Zero) return "host create failed";
            IntPtr mag = CreateWindowExW(0, "Magnifier", "m", WS_CHILD | WS_VISIBLE,
                0, 0, sw, sh, host, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (mag == IntPtr.Zero) { DestroyWindow(host); return "magnifier create failed"; }
            ShowWindow(host, 5); // SW_SHOW
            RECT full; full.left = 0; full.top = 0; full.right = sw; full.bottom = sh;
            bool ok = MagSetWindowSource(mag, full);
            UpdateWindow(mag);
            // pump + let the magnification engine sample a few frames
            for (int i = 0; i < 6; i++) { UpdateWindow(mag); Thread.Sleep(60); }
            // Read the magnifier window pixels via BitBlt of its DC.
            RECT wr; GetWindowRect(mag, out wr);
            int w = wr.right - wr.left, h = wr.bottom - wr.top;
            if (w <= 0 || h <= 0) { w = sw; h = sh; }
            using (var bmp = new Bitmap(w, h, PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(bmp)) {
                IntPtr dst = g.GetHdc();
                IntPtr sdc = GetDCApi(mag);
                try { BitBlt(dst, 0, 0, w, h, sdc, 0, 0, 0x00CC0020 /*SRCCOPY*/); }
                finally { g.ReleaseHdc(dst); ReleaseDCApi(mag, sdc); }
                int nw = (scale>0 && scale<1.0)?(int)(w*scale):w, nh = (scale>0 && scale<1.0)?(int)(h*scale):h;
                using (var small = new Bitmap(nw, nh, PixelFormat.Format32bppArgb))
                using (var g2 = Graphics.FromImage(small)) { g2.DrawImage(bmp,0,0,nw,nh); small.Save(path, ImageFormat.Png); }
            }
            DestroyWindow(host);
            return ok ? "ok" : "MagSetWindowSource returned false (captured anyway)";
        } finally { MagUninitialize(); }
    }

    [DllImport("user32.dll", EntryPoint="GetDC")] static extern IntPtr _GetDC(IntPtr h);
    [DllImport("user32.dll", EntryPoint="ReleaseDC")] static extern int _ReleaseDC(IntPtr h, IntPtr dc);
    static IntPtr GetDCApi(IntPtr h) { return _GetDC(h); }
    static int ReleaseDCApi(IntPtr h, IntPtr dc) { return _ReleaseDC(h, dc); }
}
"@

$results = @{}

foreach ($m in $Methods) {
    $out = Join-Path $OutDir ("cap_{0}_{1}.png" -f $m, $stamp)
    try {
        switch ($m) {
            'gdi'   { [CapLeak]::CaptureGdi($out, $Scale); $results[$m] = "saved $out" }
            'print' { [CapLeak]::CapturePrint($out, $Scale); $results[$m] = "saved $out" }
            'mag'   {
                Add-Type -TypeDefinition $magSrc -ReferencedAssemblies System.Drawing, System.Windows.Forms -ErrorAction SilentlyContinue
                $r = [MagCap]::Capture($out, $Scale); $results[$m] = "$r -> $out"
            }
            default { $results[$m] = "unknown method" }
        }
    } catch { $results[$m] = "ERROR: $($_.Exception.Message)" }
}

Write-Host "=== capture-leak probe ==="
foreach ($k in $results.Keys) { Write-Host ("  {0,-6} {1}" -f $k, $results[$k]) }
