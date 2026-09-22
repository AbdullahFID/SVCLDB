## probe_wda_capture.ps1 -- WDA_EXCLUDEFROMCAPTURE bypass verification.
##
## Creates a fullscreen borderless top-most window painted a distinctive
## color (magenta #FF00FF), calls SetWindowDisplayAffinity(hwnd,
## WDA_EXCLUDEFROMCAPTURE=0x11), triggers the payload's debug capture via
## the dev-bypass Global\svcldb_dev_dbg_cap event, then analyzes the
## resulting dcaux-d (DWM backbuffer) and dcaux-g (GDI BitBlt) PNGs for
## magenta pixel content.
##
## Expected outcome:
##   DWM PNG  -> LOTS of magenta pixels    (WDA bypass verified)
##   GDI PNG  -> ~zero magenta pixels      (WDA enforced by standard path)
##
## Requires: elevated PowerShell, payload built with SVCLDB_DEV_AUTH=1
## already injected into dwm.exe (dev_trigger armed).

$ErrorActionPreference = 'Stop'

## ── Bring up the WDA-protected window in a background job ────────────
$magentaR = 255; $magentaG = 0; $magentaB = 255
$deployDir = 'C:\ProgramData\WinAudioSvc'
$logHead   = "[wda-probe]"

Write-Host "$logHead cleaning stale dcaux files..."
Get-ChildItem "$deployDir\dcaux-*.*" -ErrorAction SilentlyContinue | Remove-Item -Force

## Background job hosts the WDA window (isolated PowerShell process so its
## STA WinForms message loop doesn't block the driver script).
$job = Start-Job -ScriptBlock {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    Add-Type -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError=true)]
public static extern bool SetWindowDisplayAffinity(System.IntPtr hwnd, uint dwAffinity);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool GetWindowDisplayAffinity(System.IntPtr hwnd, out uint pdwAffinity);
'@ -Name Wda -Namespace Probe

    $form                 = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = 'None'
    $form.WindowState     = 'Maximized'
    $form.TopMost         = $true
    $form.BackColor       = [System.Drawing.Color]::FromArgb(255, 0, 255)  ## magenta
    $form.ShowInTaskbar   = $false

    $lbl              = New-Object System.Windows.Forms.Label
    $lbl.AutoSize     = $false
    $lbl.Dock         = 'Fill'
    $lbl.BackColor    = [System.Drawing.Color]::FromArgb(255, 0, 255)
    $lbl.ForeColor    = [System.Drawing.Color]::White
    $lbl.Text         = "WDA_EXCLUDEFROMCAPTURE PROBE`n`nIf you can see this MAGENTA fullscreen`nyour eyes work. Standard capture apps`nwill see this as BLACK. Our DWM capture`nshould see MAGENTA (bypass verified)."
    $lbl.TextAlign    = 'MiddleCenter'
    $lbl.Font         = New-Object System.Drawing.Font('Segoe UI', 36, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($lbl)

    ## Apply WDA_EXCLUDEFROMCAPTURE the moment the handle exists.
    $form.Add_HandleCreated({
        $h = $form.Handle
        $WDA_EXCLUDEFROMCAPTURE = 0x11
        $ok = [Probe.Wda]::SetWindowDisplayAffinity($h, $WDA_EXCLUDEFROMCAPTURE)
        $out = 0
        [Probe.Wda]::GetWindowDisplayAffinity($h, [ref]$out) | Out-Null
        Write-Output "WDA set: ok=$ok reported_affinity=0x$($out.ToString('X'))"
    })

    ## Auto-close after 12 seconds so the driver never hangs.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 12000
    $timer.Add_Tick({ $timer.Stop(); $form.Close() })
    $timer.Start()

    [System.Windows.Forms.Application]::Run($form)
}

Write-Host "$logHead waiting 2s for WDA window to appear + affinity applied..."
Start-Sleep -Seconds 2

## Verify a WDA-protected window is currently on the top.
$jobOut = Receive-Job -Job $job -Keep
if ($jobOut) { $jobOut | ForEach-Object { Write-Host "$logHead job says: $_" } }

## ── Trigger the debug capture ────────────────────────────────────────
Write-Host "$logHead triggering Global\svcldb_dev_dbg_cap..."
$ev = [System.Threading.EventWaitHandle]::OpenExisting('Global\svcldb_dev_dbg_cap')
$ev.Set() | Out-Null
Write-Host "$logHead waiting 5s for capture files..."
Start-Sleep -Seconds 5

## ── Tear down the WDA window ────────────────────────────────────────
Write-Host "$logHead stopping WDA probe job..."
Stop-Job -Job $job -ErrorAction SilentlyContinue
Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

## ── Analyze captured PNGs ────────────────────────────────────────────
$dcauxD = Get-ChildItem "$deployDir\dcaux-d-*.png" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$dcauxG = Get-ChildItem "$deployDir\dcaux-g-*.png" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $dcauxD -or -not $dcauxG) {
    Write-Host "$logHead ERROR: capture files not produced. DWM: $dcauxD  GDI: $dcauxG"
    exit 2
}

Write-Host "$logHead DWM PNG: $($dcauxD.FullName) ($($dcauxD.Length) bytes)"
Write-Host "$logHead GDI PNG: $($dcauxG.FullName) ($($dcauxG.Length) bytes)"

Add-Type -AssemblyName System.Drawing

function Count-MagentaPixels {
    param([string]$path)
    $bmp = [System.Drawing.Bitmap]::FromFile($path)
    try {
        ## Fast LockBits BGRA scan.
        $rect = New-Object System.Drawing.Rectangle 0,0,$bmp.Width,$bmp.Height
        $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                              [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $stride  = $data.Stride
            $rows    = $bmp.Height
            $cols    = $bmp.Width
            $ptr     = $data.Scan0
            $bufLen  = [Math]::Abs($stride) * $rows
            $buf     = New-Object byte[] $bufLen
            [System.Runtime.InteropServices.Marshal]::Copy($ptr, $buf, 0, $bufLen)
        } finally {
            $bmp.UnlockBits($data)
        }
    } finally {
        $bmp.Dispose()
    }

    $magenta = 0
    $blackish = 0
    $sampled = 0
    ## Sample every 4th pixel on every 4th row for speed (16x downsample).
    for ($y = 0; $y -lt $rows; $y += 4) {
        $rowBase = $y * $stride
        for ($x = 0; $x -lt $cols; $x += 4) {
            $i = $rowBase + ($x * 4)
            $b = $buf[$i]; $g = $buf[$i + 1]; $r = $buf[$i + 2]
            $sampled++
            ## "Magenta-ish" tolerance: red > 200, green < 60, blue > 200.
            if (($r -gt 200) -and ($g -lt 60) -and ($b -gt 200)) { $magenta++ }
            ## "Blackish": all channels < 20 (WDA-blackout signature).
            elseif (($r -lt 20) -and ($g -lt 20) -and ($b -lt 20)) { $blackish++ }
        }
    }
    return [pscustomobject]@{
        Path      = $path
        Width     = $cols
        Height    = $rows
        Sampled   = $sampled
        Magenta   = $magenta
        Blackish  = $blackish
        MagentaPct  = [math]::Round(100.0 * $magenta / $sampled, 2)
        BlackishPct = [math]::Round(100.0 * $blackish / $sampled, 2)
    }
}

$dwmStats = Count-MagentaPixels $dcauxD.FullName
$gdiStats = Count-MagentaPixels $dcauxG.FullName

Write-Host ""
Write-Host "============================================================"
Write-Host "  DWM backbuffer capture (dcaux-d):"
Write-Host "    dims       = $($dwmStats.Width)x$($dwmStats.Height)"
Write-Host "    sampled    = $($dwmStats.Sampled) px"
Write-Host "    MAGENTA    = $($dwmStats.Magenta) ($($dwmStats.MagentaPct)%)"
Write-Host "    blackish   = $($dwmStats.Blackish) ($($dwmStats.BlackishPct)%)"
Write-Host ""
Write-Host "  GDI BitBlt capture (dcaux-g):"
Write-Host "    dims       = $($gdiStats.Width)x$($gdiStats.Height)"
Write-Host "    sampled    = $($gdiStats.Sampled) px"
Write-Host "    MAGENTA    = $($gdiStats.Magenta) ($($gdiStats.MagentaPct)%)"
Write-Host "    blackish   = $($gdiStats.Blackish) ($($gdiStats.BlackishPct)%)"
Write-Host "============================================================"
Write-Host ""

if ($dwmStats.MagentaPct -gt 50) {
    Write-Host "[PASS] DWM capture contains the WDA-protected magenta window."
    Write-Host "       Our DWM-side path IS immune to WDA_EXCLUDEFROMCAPTURE."
} else {
    Write-Host "[FAIL] DWM capture does NOT contain the WDA window (magenta=$($dwmStats.MagentaPct)%)."
    Write-Host "       The DWM path is being filtered somehow. Investigate."
}

if ($gdiStats.MagentaPct -lt 5) {
    Write-Host "[PASS] GDI capture correctly BLACKS OUT the WDA window (as WDA specifies)."
    Write-Host "       Confirms WDA_EXCLUDEFROMCAPTURE is actually being enforced on this box."
} else {
    Write-Host "[NOTE] GDI capture still sees the magenta window (magenta=$($gdiStats.MagentaPct)%)."
    Write-Host "       Windows may not be enforcing WDA_EXCLUDEFROMCAPTURE for this window class."
}
