<#
  probe_input_denial.ps1 -- svcldb v3 red-team ENFORCEMENT probe (DANGEROUS).

  Models the "prevent the user from operating the overlay" arm of a hostile
  proctor: a MEDIUM-IL process installs global low-level keyboard + mouse
  hooks (WH_KEYBOARD_LL / WH_MOUSE_LL) and SWALLOWS every event (returns 1
  without CallNextHookEx). While it runs, the physical keyboard + mouse are
  frozen for all normal apps -- a real, brief device lock.

  This is the empirical test of the architecture claim discussed with the
  user: svcldb's overlay control survives a hostile LL-swallow because svcldb
  ALSO reads input via (a) GetAsyncKeyState polling (kernel-global, not gated
  by the LL chain) and (b) a RIDEV_INPUTSINK raw-input sink, and re-installs
  its own LL hook every 500 ms to reclaim the chain head. This probe cannot
  see svcldb's reaction directly; correlate with payload.log after the run.

  THREE INDEPENDENT RELEASES (you always get control back):
    1. Internal auto-release: a background thread that does NOT touch input
       posts WM_QUIT after -AutoReleaseSec seconds no matter what.
    2. Escape hotkey: Ctrl+Alt+Shift+F9 (tracked from hook events, so it works
       even while everything else is swallowed) releases immediately.
    3. External: the caller/orchestrator taskkills this process by PID; a
       reboot is the final backstop. taskkill is unaffected by input-block.

  USAGE (normally launched de-elevated by the orchestrator):
    powershell -NoProfile -ExecutionPolicy Bypass -File probe_input_denial.ps1 -AutoReleaseSec 7
#>
[CmdletBinding()]
param(
    [int]$AutoReleaseSec = 7,
    [string]$EscapeHotkey = 'CtrlAltShiftF9'   # cosmetic; combo is fixed in the hook
)

$cs = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class Enforcer {
    const int WH_KEYBOARD_LL = 13, WH_MOUSE_LL = 14, HC_ACTION = 0;
    const int WM_KEYDOWN = 0x100, WM_SYSKEYDOWN = 0x104, WM_KEYUP = 0x101, WM_SYSKEYUP = 0x105;
    const uint WM_QUIT = 0x0012;
    const int VK_CONTROL=0x11, VK_MENU=0x12, VK_SHIFT=0x10, VK_F9=0x78;
    const int VK_LCONTROL=0xA2, VK_RCONTROL=0xA3, VK_LMENU=0xA4, VK_RMENU=0xA5, VK_LSHIFT=0xA0, VK_RSHIFT=0xA1;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError=true)] static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
    [DllImport("user32.dll")] static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint min, uint max);
    [DllImport("user32.dll")] static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();

    [StructLayout(LayoutKind.Sequential)]
    struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int ptx; public int pty; }

    static HookProc kbDel, msDel;   // keep delegates alive (no GC)
    static IntPtr kbHook, msHook;
    static uint mainTid;
    static long kbCount, msCount;
    static bool ctrl, alt, shift, escaped;

    static IntPtr KbProc(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode == HC_ACTION) {
            Interlocked.Increment(ref kbCount);
            int msg = wParam.ToInt32();
            int vk = Marshal.ReadInt32(lParam);
            bool down = (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN);
            bool up   = (msg == WM_KEYUP   || msg == WM_SYSKEYUP);
            if (vk==VK_CONTROL||vk==VK_LCONTROL||vk==VK_RCONTROL) { if(down)ctrl=true; else if(up)ctrl=false; }
            else if (vk==VK_MENU||vk==VK_LMENU||vk==VK_RMENU)     { if(down)alt=true;  else if(up)alt=false; }
            else if (vk==VK_SHIFT||vk==VK_LSHIFT||vk==VK_RSHIFT)  { if(down)shift=true;else if(up)shift=false; }
            if (down && vk==VK_F9 && ctrl && alt && shift) { escaped=true; PostThreadMessage(mainTid, WM_QUIT, IntPtr.Zero, IntPtr.Zero); return (IntPtr)1; }
            return (IntPtr)1;   // SWALLOW everything
        }
        return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }
    static IntPtr MsProc(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode == HC_ACTION) { Interlocked.Increment(ref msCount); return (IntPtr)1; }   // SWALLOW mouse
        return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }

    public static string Run(int seconds) {
        mainTid = GetCurrentThreadId();
        kbDel = new HookProc(KbProc); msDel = new HookProc(MsProc);
        IntPtr h = GetModuleHandle(null);
        kbHook = SetWindowsHookEx(WH_KEYBOARD_LL, kbDel, h, 0);
        msHook = SetWindowsHookEx(WH_MOUSE_LL, msDel, h, 0);
        if (kbHook == IntPtr.Zero && msHook == IntPtr.Zero) return "HOOK_INSTALL_FAILED gle=" + Marshal.GetLastWin32Error();
        var wd = new Thread(delegate() { Thread.Sleep(seconds * 1000); PostThreadMessage(mainTid, WM_QUIT, IntPtr.Zero, IntPtr.Zero); });
        wd.IsBackground = true; wd.Start();
        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0) { }
        if (kbHook != IntPtr.Zero) UnhookWindowsHookEx(kbHook);
        if (msHook != IntPtr.Zero) UnhookWindowsHookEx(msHook);
        return string.Format("kbSwallowed={0} mouseSwallowed={1} escaped={2} kbHookOK={3} msHookOK={4}",
            kbCount, msCount, escaped, kbHook != IntPtr.Zero, msHook != IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $cs -Language CSharp

$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output ("ENFORCE_START elevated={0} autoRelease={1}s escape=Ctrl+Alt+Shift+F9 at={2}" -f $elev, $AutoReleaseSec, (Get-Date).ToString('HH:mm:ss.fff'))
$r = [Enforcer]::Run($AutoReleaseSec)
Write-Output ("ENFORCE_DONE {0} at={1}" -f $r, (Get-Date).ToString('HH:mm:ss.fff'))
