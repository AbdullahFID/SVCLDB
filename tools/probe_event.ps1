$sig = @"
using System;
using System.Runtime.InteropServices;
public class E {
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr OpenEventA(uint access, bool inherit, string name);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type -TypeDefinition $sig -Language CSharp -ErrorAction SilentlyContinue

$name = 'Global\DwmCompositorShutdownRelease'
$h = [E]::OpenEventA(0x100000, $false, $name)
if ($h -eq [IntPtr]::Zero) {
    $gle = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "[$((Get-Date).ToString('HH:mm:ss.fff'))] EVENT NOT FOUND — GLE=$gle" -ForegroundColor Red
} else {
    Write-Host "[$((Get-Date).ToString('HH:mm:ss.fff'))] EVENT FOUND — handle=$h" -ForegroundColor Green
    [E]::CloseHandle($h) | Out-Null
}
