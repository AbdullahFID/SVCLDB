# ============================================================
# keylogger_probe_run.ps1 — unattended driver for keylogger_probe.exe
#
# Steps:
#  1. Spawn cmd.exe /c "keylogger_probe.exe > log.txt 2>&1" — lets
#     the OS handle stdout redirection; PowerShell just tracks the
#     child PID + kills when done.
#  2. Give the probe ~2s to bind all 3 channels.
#  3. Synthesize hotkey combos via SendInput (LL hooks see synth).
#  4. Wait for propagation.
#  5. Kill the probe (Ctrl+Break can't cleanly reach a detached child
#     with piped stdout; the probe's per-event lines are already in
#     the log file, we reconstruct the summary from those).
#  6. Read + print the log + reconstructed summary.
#
# Params:
#   -Tag <string>     : label written into the log filename
#                       (e.g. "baseline" or "with-svcldb")
#   -PressCount <int> : how many times each combo is synth-pressed
#   -PauseMs   <int>  : ms delay between key presses (>=50 recommended)
#
# ADMIN required if the shell we're running in is elevated (UIPI
# would otherwise block SendInput -> lower-integrity foreground).
# ============================================================

param(
    [string]$Tag        = "baseline",
    [int]   $PressCount = 3,
    [int]   $PauseMs    = 120
)

$ErrorActionPreference = 'Stop'

$toolsDir = 'C:\Users\abdul\Desktop\svcldb\tools'
$exe      = Join-Path $toolsDir 'keylogger_probe.exe'
$log      = Join-Path $toolsDir ("keylogger_probe_{0}.log" -f $Tag)

if (-not (Test-Path $exe)) {
    throw "probe binary missing: $exe (build with cl /nologo /W3 /O2 keylogger_probe.c user32.lib)"
}
if (Test-Path $log) { Remove-Item $log -Force }

Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SI {
    // Explicit-layout INPUT that matches the Windows x64 layout
    // (type=4 + pad=4 + union=32 = total 40). Only the KEYBDINPUT
    // fields inside the union are meaningful; the rest is padding.
    [StructLayout(LayoutKind.Explicit, Size = 40)]
    public struct INPUT {
        [FieldOffset(0)]  public uint    type;         // 1 = keyboard
        [FieldOffset(8)]  public ushort  wVk;
        [FieldOffset(10)] public ushort  wScan;
        [FieldOffset(12)] public uint    dwFlags;
        [FieldOffset(16)] public uint    time;
        [FieldOffset(24)] public IntPtr  dwExtraInfo;
    }
    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public const int  VK_CONTROL = 0x11, VK_SHIFT = 0x10, VK_MENU = 0x12;

    public static uint Down(ushort vk) {
        INPUT[] a = new INPUT[1];
        a[0].type = 1;
        a[0].wVk  = vk;
        return SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
    }
    public static uint Up(ushort vk) {
        INPUT[] a = new INPUT[1];
        a[0].type    = 1;
        a[0].wVk     = vk;
        a[0].dwFlags = KEYEVENTF_KEYUP;
        return SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
    }
    public static int Sizeof() { return Marshal.SizeOf(typeof(INPUT)); }
    public static uint LastErr() { return (uint)Marshal.GetLastWin32Error(); }
}
"@

# Sanity check — must be 40 on x64.
$isz = [SI]::Sizeof()
Write-Host ("SI.INPUT size: {0} (expected 40 for x64)" -f $isz)
$test = [SI]::Down([uint16]0x11)
[SI]::Up([uint16]0x11) | Out-Null
Write-Host ("SendInput probe (Ctrl down+up): return={0} lastErr={1}" -f $test, [SI]::LastErr())

function Send-Combo {
    param([int[]]$Mods, [int]$Vk)
    foreach ($m in $Mods)             { [SI]::Down([uint16]$m); Start-Sleep -Milliseconds 15 }
    [SI]::Down([uint16]$Vk); Start-Sleep -Milliseconds 30
    [SI]::Up([uint16]$Vk);   Start-Sleep -Milliseconds 15
    foreach ($m in ($Mods | Sort-Object -Descending)) { [SI]::Up([uint16]$m); Start-Sleep -Milliseconds 15 }
}

# Combos we test — chosen to be safe (no KILL_ALL, no QUIT).
$combos = @(
    @{ Label = 'Ctrl+Alt+G        TOGGLE     '; Mods = @(0x11, 0x12);       Vk = 0x47 },
    @{ Label = 'Ctrl+Alt+N        NEW_CHAT   '; Mods = @(0x11, 0x12);       Vk = 0x4E },
    @{ Label = 'Ctrl+Alt+M        CYCLE_TIER '; Mods = @(0x11, 0x12);       Vk = 0x4D },
    @{ Label = 'Ctrl+Alt+A        COPY_ANSWR '; Mods = @(0x11, 0x12);       Vk = 0x41 },
    @{ Label = 'Ctrl+Shift+Alt+L  LATEX      '; Mods = @(0x11, 0x10, 0x12); Vk = 0x4C },
    @{ Label = 'Ctrl+Shift+Alt+D  DIRECT     '; Mods = @(0x11, 0x10, 0x12); Vk = 0x44 }
)

Write-Host ""
Write-Host "=== keylogger probe run  [Tag=$Tag  PressCount=$PressCount  PauseMs=$PauseMs] ==="
Write-Host ""

# Spawn probe DIRECTLY (no cmd.exe wrapper) with stdout redirected
# to file. Start-Process handles redirection natively so we don't
# need PowerShell buffer plumbing.
$proc = Start-Process -FilePath $exe -RedirectStandardOutput $log `
                       -RedirectStandardError  ($log + '.err') `
                       -WindowStyle Hidden -PassThru
Write-Host ("probe PID={0} (stdout -> $log)" -f $proc.Id)
Start-Sleep -Seconds 2
$probePid = $proc.Id

Write-Host ("Synthesizing {0} presses per combo across {1} combos..." -f $PressCount, $combos.Count)
foreach ($c in $combos) {
    for ($i = 0; $i -lt $PressCount; $i++) {
        Send-Combo -Mods $c.Mods -Vk $c.Vk
        Start-Sleep -Milliseconds $PauseMs
    }
    Write-Host ("  sent {0} x [{1}]" -f $PressCount, $c.Label.Trim())
}

Start-Sleep -Milliseconds 1000

if ($probePid) { Stop-Process -Id $probePid -Force -EA 0 }
Start-Sleep -Milliseconds 400

Write-Host ""
Write-Host "=== raw probe events ($log) ==="
if (Test-Path $log) { Get-Content $log } else { Write-Host "(no log written)" }

Write-Host ""
Write-Host "=== reconstructed summary [Tag=$Tag] ==="
if (Test-Path $log) {
    $lines = Get-Content $log
    foreach ($c in $combos) {
        $needle = [regex]::Escape($c.Label.Trim())
        $ll   = ($lines | Select-String -Pattern ("LL   seen: \[" + $needle)).Count
        $poll = ($lines | Select-String -Pattern ("POLL seen: \[" + $needle)).Count
        $ri   = ($lines | Select-String -Pattern ("RI   seen: \[" + $needle)).Count
        Write-Host ("  {0}  LL={1,3}  POLL={2,3}  RI={3,3}   expected~{4}" -f $c.Label, $ll, $poll, $ri, $PressCount)
    }
    Write-Host ""
    $ll_evt   = ($lines | Select-String -Pattern 'LL   hook installed').Count
    $poll_evt = ($lines | Select-String -Pattern 'POLL thread up').Count
    $ri_evt   = ($lines | Select-String -Pattern 'raw-input sink registered').Count
    Write-Host ("  channels ready: LL={0}  POLL={1}  RI={2}  (each should be 1)" -f $ll_evt, $poll_evt, $ri_evt)
}
Write-Host ""
