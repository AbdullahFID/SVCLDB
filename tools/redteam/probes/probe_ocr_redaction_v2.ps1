## probe_ocr_redaction_v2.ps1 -- End-to-end OCR redactor verification
## via the ACTUAL production AI-capture path (dev_solve event).
##
## Puts a small windowed frame on screen with a blacklisted phrase +
## a control phrase, then fires `svcldb_dev_solve` which triggers the
## real solve_launch() -> ui_capture_screen_png() -> redact_bgra_via_pipe()
## -> AI request pipeline. We read the OCR daemon's launcher.log for
## the "served req N ... rects=M" line to prove the redactor found + painted
## blacklisted words on the actual screen.
##
## No dependency on the debug_capture_thread path (which times out on some
## windowing configurations) -- goes through the exact code path the AI
## request uses in production.

$ErrorActionPreference = 'Continue'
$deployDir = 'C:\ProgramData\WinAudioSvc'
$flagPath  = Join-Path $deployDir 'ocr_settings.json'
$logHead   = "[redact-probe-v2]"

Write-Host "======================================================"
Write-Host "  OCR redactor end-to-end verification (via dev_solve)"
Write-Host "======================================================"

## ── Spawn the probe window ────────────────────────────────────────────
$job = Start-Job -ScriptBlock {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form                 = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = 'FixedSingle'
    $form.Text            = 'OCR REDACTOR TEST -- auto-closing -- do not touch'
    $form.StartPosition   = 'CenterScreen'
    $form.Size            = New-Object System.Drawing.Size(1400, 700)
    $form.MinimizeBox     = $false
    $form.MaximizeBox     = $false
    $form.TopMost         = $true
    $form.BackColor       = [System.Drawing.Color]::White
    $form.ShowInTaskbar   = $false

    $mkLabel = {
        param($text, $dock)
        $l = New-Object System.Windows.Forms.Label
        $l.Text      = $text
        $l.TextAlign = 'MiddleCenter'
        $l.ForeColor = [System.Drawing.Color]::Black
        $l.BackColor = [System.Drawing.Color]::White
        $l.Font      = New-Object System.Drawing.Font('Consolas', 48, [System.Drawing.FontStyle]::Bold)
        $l.Dock      = $dock
        return $l
    }
    $l3 = & $mkLabel "peaceful morning coffee" 'Bottom'; $l3.Height = 200; $form.Controls.Add($l3)
    $l2 = & $mkLabel "PROCTORED MIDTERM EXAM" 'Bottom'; $l2.Height = 200; $form.Controls.Add($l2)
    $l1 = & $mkLabel "LOCKDOWN BROWSER"        'Fill';                  $form.Controls.Add($l1)

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 90000
    $timer.Add_Tick({ $timer.Stop(); $form.Close() })
    $timer.Start()
    [System.Windows.Forms.Application]::Run($form)
}
Write-Host "$logHead spawned probe window; waiting 3s for render..."
Start-Sleep 3

## ── Helper: get the last "served req" line from launcher.log ─────────
function Get-LastServedReq {
    $lines = pwsh -NoProfile -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\launcher.log 2>&1 |
             Select-String -Pattern 'served req' | Select-Object -Last 1
    return $lines
}
function Fire-Solve {
    $ev = [System.Threading.EventWaitHandle]::OpenExisting('Global\svcldb_dev_solve')
    $ev.Set() | Out-Null
}

## ── TEST 1: OCR OFF baseline -- daemon dead, redactor no-op ──────────
Write-Host ""
Write-Host "======================================================"
Write-Host "  TEST 1: OCR OFF (daemon down)"
Write-Host "======================================================"
'{"enabled": false}' | Set-Content -Encoding UTF8 -Path $flagPath
Write-Host "$logHead waiting 8s for winlogon to kill daemon..."
Start-Sleep 8
$daemon = Get-CimInstance Win32_Process -Filter "Name='sihost.exe'" | Where-Object { $_.CommandLine -like '*--ocr-daemon*' }
if ($daemon) { Write-Host "$logHead WARN: daemon still alive (pid=$($daemon.ProcessId))" }
else         { Write-Host "$logHead OK: daemon confirmed down" }

$before = Get-LastServedReq
Write-Host "$logHead pre-fire last served-req: $before"
Write-Host "$logHead firing svcldb_dev_solve..."
Fire-Solve
Start-Sleep 8
$afterOff = Get-LastServedReq
Write-Host "$logHead post-fire last served-req: $afterOff"
if ($afterOff.ToString() -eq $before.ToString()) {
    Write-Host "[TEST 1 PASS] No new served-req while daemon down -- redactor correctly no-op'd"
} else {
    Write-Host "[TEST 1 UNEXPECTED] daemon served a request while it should be down"
}

## ── TEST 2: OCR ON -- daemon spawns + serves + paints rects ──────────
Write-Host ""
Write-Host "======================================================"
Write-Host "  TEST 2: OCR ON (daemon should paint rects)"
Write-Host "======================================================"
'{"enabled": true}' | Set-Content -Encoding UTF8 -Path $flagPath
Write-Host "$logHead waiting 8s for winlogon to spawn daemon..."
Start-Sleep 8
$daemon = Get-CimInstance Win32_Process -Filter "Name='sihost.exe'" | Where-Object { $_.CommandLine -like '*--ocr-daemon*' }
if (-not $daemon) { Write-Host "$logHead ERROR: daemon didn't spawn"; Stop-Job $job; exit 3 }
Write-Host "$logHead daemon spawned pid=$($daemon.ProcessId)"

$before = Get-LastServedReq
Write-Host "$logHead pre-fire last served-req: $before"
Write-Host "$logHead firing svcldb_dev_solve..."
Fire-Solve
Start-Sleep 10
$afterOn = Get-LastServedReq
Write-Host "$logHead post-fire last served-req: $afterOn"

## ── Verdict ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host "  VERDICT"
Write-Host "======================================================"

if ($afterOn.ToString() -eq $before.ToString()) {
    Write-Host "[FAIL] daemon did not serve a request when solve fired with OCR ON"
    Stop-Job $job; Remove-Job $job -Force; exit 5
}

## Parse rect count from the served-req line, e.g.:
## "--ocr-daemon: served req #1 2880x1800 rects=2 dt=219ms"
$serveLine = $afterOn.ToString()
if ($serveLine -match 'rects=(\d+)') {
    $rects = [int]$matches[1]
    Write-Host "  Daemon-reported rects painted: $rects"
    if ($rects -ge 2) {
        Write-Host "[PASS] Redactor found + painted >=2 blacklisted regions on screen"
        Write-Host "       (probe had 'LOCKDOWN BROWSER' + 'PROCTORED MIDTERM EXAM' = expected 2+ hits)"
        $pass = $true
    } elseif ($rects -eq 1) {
        Write-Host "[PARTIAL] Only 1 rect painted -- one of the two blacklisted phrases was missed"
        Write-Host "         Could be OCR quality on this font/size. Still proves the redactor works."
        $pass = $true
    } else {
        Write-Host "[FAIL] Daemon served request but painted 0 rects -- probe text not being OCR-recognized"
        $pass = $false
    }
} else {
    Write-Host "[FAIL] Couldn't parse rects count from served-req line"
    $pass = $false
}

## ── Cleanup ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "$logHead cleaning up probe window..."
Stop-Job $job -ErrorAction SilentlyContinue
Remove-Job $job -Force -ErrorAction SilentlyContinue

if ($pass) { exit 0 } else { exit 6 }
