# ═══════════════════════════════════════════════════════════════════════
# svcldb-probe.ps1 -- End-to-end test harness for AutoSolver + Agent
#
# Fires the DEV-BYPASS `Global\svcldb_dev_solve` (or _agent_start / _agent_stop)
# event that init_thread arms when built with SVCLDB_DEV_AUTH=1, then tails
# the encrypted payload log and prints matching decrypted lines. Lets us
# exercise the solve pipeline without needing a mouse-hold trigger, so
# CI-style regression testing is possible.
#
# Usage:
#   pwsh -File tools\svcldb-probe.ps1 solve            # fire ONE solve cycle
#   pwsh -File tools\svcldb-probe.ps1 agent-start      # start agent mode
#   pwsh -File tools\svcldb-probe.ps1 agent-stop       # stop agent
#   pwsh -File tools\svcldb-probe.ps1 tail 40          # decrypt last 40 lines
#   pwsh -File tools\svcldb-probe.ps1 status           # is payload loaded?
#
# The event names ONLY exist when the payload is a DEV-BYPASS build
# (SVCLDB_DEV_BYPASS_AUTH). PROD builds omit them entirely.
# ═══════════════════════════════════════════════════════════════════════

param(
    [Parameter(Position=0)] [string] $Action = "help",
    [Parameter(Position=1)] [int]    $TailN  = 25,
    [switch] $NoWait,
    [switch] $Quiet
)

$ErrorActionPreference = "Stop"
$PayloadLog = "C:\ProgramData\WinAudioSvc\payload.log"
$DecryptScript = "C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1"

# ── Load the SetEvent P/Invoke shim ───────────────────────────────────
if (-not ("SvcldbProbe.EventSignaler" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace SvcldbProbe {
    public static class EventSignaler {
        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
        public static extern IntPtr OpenEventA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool SetEvent(IntPtr hEvent);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr hObject);
        public const uint EVENT_MODIFY_STATE = 0x0002;
    }
}
"@
}

function Fire-Event([string] $name) {
    $h = [SvcldbProbe.EventSignaler]::OpenEventA(
            [SvcldbProbe.EventSignaler]::EVENT_MODIFY_STATE, $false, $name)
    if ($h -eq [IntPtr]::Zero) {
        $gle = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "[FAIL] OpenEventA('$name') failed gle=$gle" -ForegroundColor Red
        Write-Host "       (event not found -- payload not loaded, or not a DEV build)" -ForegroundColor Yellow
        return $false
    }
    $ok = [SvcldbProbe.EventSignaler]::SetEvent($h)
    [SvcldbProbe.EventSignaler]::CloseHandle($h) | Out-Null
    if (-not $ok) {
        Write-Host "[FAIL] SetEvent('$name') returned false" -ForegroundColor Red
        return $false
    }
    if (-not $Quiet) { Write-Host "[OK]   fired: $name" -ForegroundColor Green }
    return $true
}

function Show-Tail([int] $n, [string[]] $Highlight = @()) {
    if (-not (Test-Path $DecryptScript)) {
        Write-Host "[WARN] dlog.ps1 missing at $DecryptScript" -ForegroundColor Yellow
        return
    }
    if (-not (Test-Path $PayloadLog)) {
        Write-Host "[WARN] no payload log yet at $PayloadLog" -ForegroundColor Yellow
        return
    }
    $lines = pwsh -File $DecryptScript -Path $PayloadLog -Tail $n 2>&1
    foreach ($ln in $lines) {
        $s = [string] $ln
        $col = "Gray"
        foreach ($h in $Highlight) {
            if ($s -match $h) { $col = "Cyan"; break }
        }
        if ($s -match "FAIL|ERROR|abort") { $col = "Red" }
        elseif ($s -match "done|ready|OK|SUCCESS|fired") { $col = "Green" }
        Write-Host $s -ForegroundColor $col
    }
}

function Await-Solve([int] $timeout_sec = 45) {
    # Poll the log looking for the "solve: done" or "solve: ai FAILED" or
    # "solve: capture FAILED" or "solve: imgproc FAILED" tail line that
    # solve_thread emits at completion.
    $t0 = Get-Date
    $marker_re = 'solve:\s+(done|ai FAILED|capture FAILED|imgproc FAILED)'
    while (((Get-Date) - $t0).TotalSeconds -lt $timeout_sec) {
        Start-Sleep -Milliseconds 700
        $lines = pwsh -File $DecryptScript -Path $PayloadLog -Tail 12 2>&1
        foreach ($ln in $lines) {
            if ($ln -match $marker_re) {
                Write-Host ""
                Write-Host "[END]  $ln" -ForegroundColor Cyan
                return $Matches[1]
            }
        }
    }
    Write-Host "[TIMEOUT] no solve terminator in $timeout_sec s" -ForegroundColor Yellow
    return "timeout"
}

switch ($Action.ToLower()) {
    "solve" {
        if (-not (Fire-Event "Global\svcldb_dev_solve")) { exit 2 }
        if ($NoWait) { exit 0 }
        $result = Await-Solve 60
        Write-Host ""
        Write-Host "── log tail after solve ──" -ForegroundColor Yellow
        Show-Tail 30 @('solve:', 'ai:', 'imgproc:', 'ground:', 'dot')
        if ($result -eq "done") { exit 0 } else { exit 3 }
    }
    "agent-start" {
        if (-not (Fire-Event "Global\svcldb_dev_agent_start")) { exit 2 }
        Start-Sleep -Seconds 2
        Show-Tail 20 @('agent:')
    }
    "agent-stop" {
        if (-not (Fire-Event "Global\svcldb_dev_agent_stop")) { exit 2 }
        Start-Sleep -Seconds 1
        Show-Tail 15 @('agent:')
    }
    "tail" {
        Show-Tail $TailN
    }
    "status" {
        $dwm  = Get-Process dwm -ErrorAction SilentlyContinue
        if (-not $dwm) { Write-Host "dwm.exe not found (?!)" -ForegroundColor Red; exit 5 }
        Write-Host "dwm.exe pid=$($dwm.Id)"
        $shExists = $false
        try {
            $h = [SvcldbProbe.EventSignaler]::OpenEventA(0x0002, $false, "Global\svcldb_dev_solve")
            if ($h -ne [IntPtr]::Zero) {
                $shExists = $true
                [SvcldbProbe.EventSignaler]::CloseHandle($h) | Out-Null
            }
        } catch {}
        if ($shExists) {
            Write-Host "payload   = LOADED (dev event exists)" -ForegroundColor Green
        } else {
            Write-Host "payload   = NOT LOADED (dev event missing; or PROD build)" -ForegroundColor Yellow
        }
        $cfg = Get-Item C:\ProgramData\WinAudioSvc\config.dat -ErrorAction SilentlyContinue
        if ($cfg) { Write-Host "config.dat= $($cfg.Length) bytes @ $($cfg.LastWriteTime)" }
        Write-Host "log       = $PayloadLog"
    }
    default {
        Write-Host "svcldb-probe.ps1 -- test harness (dev-bypass builds only)"
        Write-Host ""
        Write-Host "  solve            fire ONE solve cycle + wait for result"
        Write-Host "  agent-start      start agent mode"
        Write-Host "  agent-stop       stop agent"
        Write-Host "  tail [N]         decrypt last N log lines (default 25)"
        Write-Host "  status           inject + log + config status"
        Write-Host ""
        Write-Host "  -NoWait          don't wait for solve to finish"
        Write-Host "  -Quiet           suppress fire confirmation"
    }
}
