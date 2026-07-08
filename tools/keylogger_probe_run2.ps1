param(
    [int]$PressCount = 3
)
$ErrorActionPreference = 'Stop'
$exe = 'C:\Users\abdul\Desktop\svcldb\tools\keylogger_probe.exe'
$log = 'C:\Users\abdul\Desktop\svcldb\tools\keylogger_probe_letters.log'
if (Test-Path $log) { Remove-Item $log -Force }

Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SI2 {
    [StructLayout(LayoutKind.Explicit, Size = 40)]
    public struct INPUT {
        [FieldOffset(0)]  public uint    type;
        [FieldOffset(8)]  public ushort  wVk;
        [FieldOffset(10)] public ushort  wScan;
        [FieldOffset(12)] public uint    dwFlags;
        [FieldOffset(16)] public uint    time;
        [FieldOffset(24)] public IntPtr  dwExtraInfo;
    }
    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public static uint Down(ushort vk) {
        INPUT[] a = new INPUT[1]; a[0].type=1; a[0].wVk=vk;
        return SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
    }
    public static uint Up(ushort vk) {
        INPUT[] a = new INPUT[1]; a[0].type=1; a[0].wVk=vk; a[0].dwFlags=KEYEVENTF_KEYUP;
        return SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
    }
}
"@

$proc = Start-Process -FilePath $exe -RedirectStandardOutput $log -RedirectStandardError ($log + '.err') -WindowStyle Hidden -PassThru
Write-Host ("probe PID={0}" -f $proc.Id)
Start-Sleep -Seconds 3

$letters = @(0x51, 0x57, 0x59, 0x5A)
Write-Host 'Test A: plain letters (Q W Y Z) without modifiers'
foreach ($vk in $letters) {
    for ($i = 0; $i -lt $PressCount; $i++) {
        [SI2]::Down([uint16]$vk) | Out-Null; Start-Sleep -Milliseconds 40
        [SI2]::Up([uint16]$vk)   | Out-Null; Start-Sleep -Milliseconds 250
    }
    Write-Host ("  sent {0} x letter vk=0x{1:X2}" -f $PressCount, $vk)
}

Start-Sleep -Milliseconds 1000
Stop-Process -Id $proc.Id -Force -EA 0
Start-Sleep -Milliseconds 400

Write-Host ''
if (Test-Path $log) {
    $lines = Get-Content $log
    $ll_count = ($lines | Select-String -Pattern 'LL ev').Count
    Write-Host ("  LL ev-lines observed: {0}" -f $ll_count)
    Write-Host ''
    Write-Host '=== raw LL events (first 30 lines) ==='
    $lines | Select-String -Pattern 'LL ev' | Select-Object -First 30 | ForEach-Object { Write-Host $_.Line }
    Write-Host ''
    Write-Host '=== all raw log lines matching Q/W/Y/Z (vk=0x51/0x57/0x59/0x5A) ==='
    $lines | Select-String -Pattern 'vk=0x(51|57|59|5A)' | Select-Object -First 30 | ForEach-Object { Write-Host $_.Line }
}
