Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Kp { [DllImport("kernel32.dll", SetLastError=true, CallingConvention=CallingConvention.Winapi)] public static extern int SetThreadExecutionState(int esFlags); [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y); [DllImport("user32.dll")] public static extern bool GetCursorPos(out System.Drawing.Point p); }' -Language CSharp
Add-Type -AssemblyName System.Drawing
[Kp]::SetThreadExecutionState(-2147483645)  # ES_CONTINUOUS(0x80000000) | ES_SYSTEM_REQUIRED(0x01) | ES_DISPLAY_REQUIRED(0x02)
while ($true) {
    Set-Content -Path C:\Users\abdul\Desktop\svcldb\.keepalive -Value (Get-Date).ToString('o') -Force
    $p = New-Object System.Drawing.Point
    [Kp]::GetCursorPos([ref]$p)
    [Kp]::SetCursorPos($p.X + 1, $p.Y)
    Start-Sleep -Milliseconds 300
    [Kp]::SetCursorPos($p.X, $p.Y)
    Start-Sleep -Seconds 90
}
