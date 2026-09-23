# quick check: what exit code does sihost --unload return at Medium IL?
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class IntDrop {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    public static extern bool ConvertStringSidToSidA(string sid, out IntPtr psid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool SetTokenInformation(IntPtr tok, int cls, IntPtr info, uint sz);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }
    public static bool DropToMedium() {
        IntPtr sid;
        if (!ConvertStringSidToSidA("S-1-16-8192", out sid)) return false;
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0088u, out tok)) { LocalFree(sid); return false; }
        try {
            uint sidLen = GetLengthSid(sid);
            uint sz = (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) + sidLen;
            IntPtr buf = Marshal.AllocHGlobal((int)sz);
            try {
                TOKEN_MANDATORY_LABEL tml;
                tml.Label.Sid = sid;
                tml.Label.Attributes = 0x00000020u;
                Marshal.StructureToPtr(tml, buf, false);
                return SetTokenInformation(tok, 25, buf, sz);
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); LocalFree(sid); }
    }
}
"@
$ok = [IntDrop]::DropToMedium()
Write-Host "drop to medium: $ok"
whoami /groups | Select-String 'Mandatory Label|Administrators' | ForEach-Object { Write-Host "  $_" }
Write-Host "identity: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "isElevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

Write-Host ""
Write-Host "=== sihost.exe --unload ==="
$p = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--unload' -Wait -PassThru -WindowStyle Hidden
Write-Host "exit code: $($p.ExitCode)"

Write-Host ""
Write-Host "=== sihost.exe --status ==="
$p2 = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--status' -Wait -PassThru -WindowStyle Hidden
Write-Host "exit code: $($p2.ExitCode)"

Write-Host ""
Write-Host "=== sihost.exe --kill ==="
$p3 = Start-Process -FilePath 'C:\ProgramData\WinAudioSvc\sihost.exe' -ArgumentList '--kill' -Wait -PassThru -WindowStyle Hidden
Write-Host "exit code: $($p3.ExitCode)"

'done' | Set-Content -Path 'C:\Users\abdul\Desktop\svcldb\tools\redteam\runtime\_test_sihost_medium.done' -Encoding ASCII
