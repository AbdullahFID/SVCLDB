#requires -Version 5
# ---------------------------------------------------------------------------
# test_unload_timing.ps1  --  v-next shutdown-latency validation harness
# ---------------------------------------------------------------------------

param(
    [int]$Iterations = 3,
    [string]$SihostPath  = 'C:\ProgramData\WinAudioSvc\sihost.exe',
    [string]$LogPath     = 'C:\ProgramData\WinAudioSvc\payload.log',
    [string]$DlogScript  = 'C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1'
)

$results = @()

function Get-DecryptedLog {
    param([int]$Tail = 200)
    return (& pwsh -File $DlogScript -Path $LogPath -Tail $Tail 2>&1 | Out-String)
}

function Parse-Timing {
    param([string]$LogText)
    $r = New-Object psobject
    $r | Add-Member -MemberType NoteProperty -Name SignalRcvd     -Value $false
    $r | Add-Member -MemberType NoteProperty -Name InstantHideMs  -Value -1
    $r | Add-Member -MemberType NoteProperty -Name ParallelMs     -Value -1
    $r | Add-Member -MemberType NoteProperty -Name WaitCode       -Value -1
    $r | Add-Member -MemberType NoteProperty -Name Workers        -Value -1
    $r | Add-Member -MemberType NoteProperty -Name CompleteMs     -Value -1

    if ($LogText -match 'shutdown signal received') { $r.SignalRcvd = $true }
    if ($LogText -match 'instant-hide armed @ \+(\d+)ms') {
        $r.InstantHideMs = [int]$Matches[1]
    }
    if ($LogText -match 'parallel-stops: (\d+) workers, WaitForMultiple=(\d+) .*@ \+(\d+)ms') {
        $r.Workers    = [int]$Matches[1]
        $r.WaitCode   = [int]$Matches[2]
        $r.ParallelMs = [int]$Matches[3]
    }
    if ($LogText -match 'shutdown_watcher complete @ \+(\d+)ms') {
        $r.CompleteMs = [int]$Matches[1]
    }
    return $r
}

for ($i = 1; $i -le $Iterations; $i++) {
    Write-Host ""
    $line = "===== ITERATION {0} / {1} =====" -f $i, $Iterations
    Write-Host $line -ForegroundColor Cyan

    Write-Host "[*] arming payload via --reinject --quiet"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $SihostPath --reinject --quiet 2>&1 | Out-Null
    $reCode = $LASTEXITCODE
    $sw.Stop()
    $msg = "[*] --reinject exit={0} wall={1}ms" -f $reCode, $sw.ElapsedMilliseconds
    Write-Host $msg
    if ($reCode -ne 0) {
        Write-Host "[!] reinject failed, skipping" -ForegroundColor Red
        continue
    }
    Start-Sleep -Milliseconds 3500

    Write-Host "[*] running --unload"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $SihostPath --unload 2>&1 | Out-Null
    $unlCode = $LASTEXITCODE
    $sw.Stop()
    $unloadWall = $sw.ElapsedMilliseconds
    $msg = "[*] --unload exit={0} wall={1}ms" -f $unlCode, $unloadWall
    Write-Host $msg

    Start-Sleep -Milliseconds 800

    $log = Get-DecryptedLog -Tail 60
    $t = Parse-Timing -LogText $log

    $r = New-Object psobject
    $r | Add-Member -MemberType NoteProperty -Name Iter          -Value $i
    $r | Add-Member -MemberType NoteProperty -Name UnloadWallMs  -Value $unloadWall
    $r | Add-Member -MemberType NoteProperty -Name Signal        -Value $t.SignalRcvd
    $r | Add-Member -MemberType NoteProperty -Name InstantHideMs -Value $t.InstantHideMs
    $r | Add-Member -MemberType NoteProperty -Name ParallelMs    -Value $t.ParallelMs
    $r | Add-Member -MemberType NoteProperty -Name WaitCode      -Value $t.WaitCode
    $r | Add-Member -MemberType NoteProperty -Name Workers       -Value $t.Workers
    $r | Add-Member -MemberType NoteProperty -Name CompleteMs    -Value $t.CompleteMs
    $results += $r

    $msg = "  instant-hide      @ +{0} ms" -f $t.InstantHideMs
    Write-Host $msg
    $msg = "  parallel-stops    @ +{0} ms  waitcode={1} workers={2}" -f $t.ParallelMs, $t.WaitCode, $t.Workers
    Write-Host $msg
    $msg = "  shutdown complete @ +{0} ms" -f $t.CompleteMs
    Write-Host $msg

    Start-Sleep -Milliseconds 1500
}

Write-Host ""
Write-Host "===== SUMMARY =====" -ForegroundColor Green
$results | Format-Table -AutoSize

$fail = 0
foreach ($r in $results) {
    if ($r.InstantHideMs -lt 0 -or $r.InstantHideMs -gt 20) {
        $m = "[FAIL] Iter {0}: instant-hide {1}ms (want -le 20ms)" -f $r.Iter, $r.InstantHideMs
        Write-Host $m -ForegroundColor Red
        $fail++
    }
    if ($r.CompleteMs -lt 0 -or $r.CompleteMs -gt 3000) {
        $m = "[FAIL] Iter {0}: shutdown-complete {1}ms (want -le 3000ms)" -f $r.Iter, $r.CompleteMs
        Write-Host $m -ForegroundColor Red
        $fail++
    }
    if ($r.WaitCode -gt 0) {
        $m = "[WARN] Iter {0}: parallel WaitFor={1} (0=clean, 258=timeout)" -f $r.Iter, $r.WaitCode
        Write-Host $m -ForegroundColor Yellow
    }
}
if ($fail -eq 0) {
    Write-Host "[PASS] all iterations met latency gates" -ForegroundColor Green
    exit 0
} else {
    $m = "[FAIL] {0} assertion(s) failed" -f $fail
    Write-Host $m -ForegroundColor Red
    exit 1
}
