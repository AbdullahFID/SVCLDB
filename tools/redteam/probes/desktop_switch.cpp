// desktop_switch.cpp -- SEB secure-desktop simulator + rescue + input DIAGNOSTIC.
//
// Models what Safe Exam Browser (and WinLogon/UAC) do: CreateDesktop +
// SwitchDesktop to a *different* Windows Desktop object, with a focused window
// on it. Our payload's input plumbing (GetAsyncKeyState poll + WH_KEYBOARD_LL
// hooks + RegisterHotKey) is per-input-desktop; this probe reproduces the switch
// so we can iterate without real SEB.
//
// DIAGNOSTIC: the blue window on the test desktop is a live INPUT METER. It
// shows on-screen counters for keydowns / clicks / mouse-moves IT receives, and
// logs its own GetAsyncKeyState (from a thread genuinely ON the test desktop).
// This isolates the failure layer:
//   * counters climb while you type/click  => physical input DOES reach the new
//     desktop, so a frozen svcldb overlay means OUR hooks aren't catching it.
//   * counters stay 0                       => input never reaches the new desktop
//     at all (foreground/focus/switch issue), a different (harder) problem.
//
// SAFETY (you can NEVER get stranded):
//   * A watchdog thread unconditionally SwitchDesktop()s back to Default after
//     --hold seconds and hard-exits -- even if everything else wedges.
//   * `--rescue` force-switches input back to Default immediately.
//   * Everything is timestamped to desktop_switch.log next to this exe.
//
// Build:  cl /nologo /EHsc desktop_switch.cpp /link user32.lib gdi32.lib
// Usage:
//   desktop_switch.exe [--hold N] [--delay N]   switch after --delay s, hold N s.
//   desktop_switch.exe --rescue                 force back to Default NOW.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

static const wchar_t *RESCUE_EVENT = L"Global\\svcldb_desktop_rescue";
static const wchar_t *TEST_DESK    = L"svcldb_secure_test";

static char g_logpath[MAX_PATH] = {0};

static void init_logpath(void) {
    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    char *slash = strrchr(exe, '\\');
    if (slash) *(slash + 1) = 0; else exe[0] = 0;
    _snprintf(g_logpath, sizeof(g_logpath), "%sdesktop_switch.log", exe);
}

static void lg(const char *fmt, ...) {
    FILE *f = fopen(g_logpath, "a");
    if (!f) f = stderr;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fprintf(f, "\n");
    if (f != stderr) fclose(f); else fflush(f);
}

static HDESK g_default = NULL;
static DWORD g_hold_s = 20;
static int   g_inject = 1;   /* --noinject disables synthetic SendInput (real-key-only test) */

static int do_switch(HDESK d) {
    if (!d) return 0;
    for (int i = 0; i < 10; ++i) { if (SwitchDesktop(d)) return 1; Sleep(50); }
    return 0;
}

static void switch_back(const char *why) {
    if (do_switch(g_default)) { lg("switch_back OK (%s)", why); return; }
    HDESK d = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (do_switch(d)) { lg("switch_back OK via fresh Default (%s)", why); if (d) CloseDesktop(d); return; }
    if (d) CloseDesktop(d);
    lg("switch_back FAILED (%s) err=%lu -- LAST RESORT: reboot", why, GetLastError());
}

static HANDLE g_ev = NULL;

static DWORD WINAPI watchdog(LPVOID unused) {
    (void)unused;
    DWORD r = WaitForSingleObject(g_ev, g_hold_s * 1000);
    lg("watchdog fire reason=%s -> returning input to Default",
       r == WAIT_OBJECT_0 ? "rescue-signal" : "timeout");
    switch_back(r == WAIT_OBJECT_0 ? "rescue-signal" : "timeout");
    ExitProcess(0);
    return 0;
}

// Synthesize a Ctrl+B keystroke onto the ACTIVE input desktop. Called from the
// window thread (which is on the test desktop + foreground), so SendInput
// delivers to the test desktop's input queue + updates its async key state --
// letting us measure all readers against identical injected input, no human.
static void inject_ctrl_b(void) {
    /* Inject Ctrl+Right (MOVE_RIGHT) -- a real, non-rebound keyboard hotkey. */
    INPUT in[4]; memset(in, 0, sizeof(in));
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_CONTROL;
    in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = VK_RIGHT; in[1].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;
    in[2].type = INPUT_KEYBOARD; in[2].ki.wVk = VK_RIGHT; in[2].ki.dwFlags = KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP;
    in[3].type = INPUT_KEYBOARD; in[3].ki.wVk = VK_CONTROL; in[3].ki.dwFlags = KEYEVENTF_KEYUP;
    UINT sent = SendInput(4, in, sizeof(INPUT));
    lg("win: SendInput(Ctrl+Right) => %u sent (err=%lu)", sent, sent == 4 ? 0 : GetLastError());
}

// Round-6 test (make-or-break for a STEALTHY fix): does RIDEV_INPUTSINK raw
// input work on a HIDDEN, non-foreground window on the switched desktop?
// RIDEV_INPUTSINK is explicitly "receive input even without foreground", so if
// WM_INPUT arrives here on a hidden window, the fix = create a hidden INPUTSINK
// window on the new desktop and read hotkeys/mouse from raw input (no focus
// stolen from SEB). If nothing arrives, focus-free user-mode input on a foreign
// secure desktop is effectively impossible from ring 3.
static DWORD WINAPI rawinput_probe_thread(LPVOID param) {
    HDESK test = (HDESK)param;
    if (!SetThreadDesktop(test)) { lg("rawinput: SetThreadDesktop failed %lu", GetLastError()); return 1; }
    WNDCLASSA wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = DefWindowProcA;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = "svcldb_ri_wnd";
    RegisterClassA(&wc);
    // Hidden top-level window (NOT visible, NOT activated) as the raw-input target.
    HWND hwnd = CreateWindowExA(WS_EX_NOACTIVATE, "svcldb_ri_wnd", "",
        WS_POPUP, 0, 0, 1, 1, NULL, NULL, wc.hInstance, NULL);
    RAWINPUTDEVICE rid[2];
    rid[0].usUsagePage = 0x01; rid[0].usUsage = 0x06; rid[0].dwFlags = RIDEV_INPUTSINK; rid[0].hwndTarget = hwnd; // keyboard
    rid[1].usUsagePage = 0x01; rid[1].usUsage = 0x02; rid[1].dwFlags = RIDEV_INPUTSINK; rid[1].hwndTarget = hwnd; // mouse
    BOOL ok = RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));
    lg("rawinput: hidden INPUTSINK window hwnd=%p reg=%d err=%lu", hwnd, ok, ok ? 0 : GetLastError());
    int wm_input = 0, kb = 0, ms = 0;
    DWORD start = GetTickCount();
    MSG m;
    while (GetTickCount() - start < 16000) {
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            if (m.message == WM_INPUT) {
                wm_input++;
                UINT sz = 0;
                GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
                BYTE buf[512];
                if (sz <= sizeof(buf) &&
                    GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) == sz) {
                    RAWINPUT *ri = (RAWINPUT *)buf;
                    if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                        kb++;
                        if (kb <= 12) lg("rawinput: WM_INPUT KEYBOARD vk=0x%02X msg=0x%X (kb#%d)",
                                         ri->data.keyboard.VKey, ri->data.keyboard.Message, kb);
                    } else if (ri->header.dwType == RIM_TYPEMOUSE) {
                        ms++;
                    }
                }
            }
            TranslateMessage(&m); DispatchMessageA(&m);
        }
        Sleep(15);
    }
    lg("rawinput: RESULT total WM_INPUT=%d keyboard=%d mouse=%d", wm_input, kb, ms);
    return 0;
}

// ── Live input meter window on the test desktop ──
static volatile LONG g_keydowns = 0, g_clicks = 0, g_moves = 0;
static int  g_last_vk = 0;
static int  g_have_focus = 0;

static LRESULT CALLBACK TestWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        g_last_vk = (int)w; InterlockedIncrement(&g_keydowns);
        lg("win: WM_KEYDOWN vk=0x%02X (total kd=%ld)", (int)w, g_keydowns);
        InvalidateRect(h, NULL, FALSE); return 0;
    case WM_LBUTTONDOWN: case WM_RBUTTONDOWN: case WM_MBUTTONDOWN:
        InterlockedIncrement(&g_clicks);
        lg("win: mouse button down (total clicks=%ld)", g_clicks);
        InvalidateRect(h, NULL, FALSE); return 0;
    case WM_MOUSEMOVE:
        InterlockedIncrement(&g_moves); return 0;
    case WM_SETFOCUS:  g_have_focus = 1; lg("win: WM_SETFOCUS (got focus)"); return 0;
    case WM_KILLFOCUS: g_have_focus = 0; lg("win: WM_KILLFOCUS (lost focus)"); return 0;
    case WM_TIMER: {
        if (g_inject) inject_ctrl_b();   /* synthesize input unless --noinject */
        SHORT b  = GetAsyncKeyState('B');
        SHORT c  = GetAsyncKeyState(VK_CONTROL);
        SHORT lb = GetAsyncKeyState(VK_LBUTTON);
        lg("win(on-test) async: B=0x%04hX CTRL=0x%04hX LBTN=0x%04hX | msgs kd=%ld clk=%ld mv=%ld focus=%d",
           b, c, lb, g_keydowns, g_clicks, g_moves, g_have_focus);
        InvalidateRect(h, NULL, FALSE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        HBRUSH br = CreateSolidBrush(RGB(12, 22, 66));
        FillRect(dc, &rc, br); DeleteObject(br);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(225, 230, 255));
        char msg[900];
        _snprintf(msg, sizeof(msg) - 1,
            "svcldb  --  SEB-STYLE SECURE DESKTOP (simulated)\n\n"
            "MASH some keys, move + drag the mouse, click around.\n\n"
            "INPUT METER (this window, on the test desktop):\n"
            "    keydowns = %ld     clicks = %ld     mouse-moves = %ld\n"
            "    last key vk = 0x%02X     focus = %s\n\n"
            "If these numbers CLIMB, input reaches this desktop.\n"
            "Now watch the svcldb overlay: does Ctrl+B / drag do anything to IT?\n\n"
            "Auto-returns to your normal desktop on its own. Don't reboot.",
            g_keydowns, g_clicks, g_moves, g_last_vk, g_have_focus ? "YES" : "no");
        msg[sizeof(msg) - 1] = 0;
        DrawTextA(dc, msg, -1, &rc, DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOCLIP);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(h, m, w, l);
}

static DWORD WINAPI test_window_thread(LPVOID param) {
    HDESK test = (HDESK)param;
    if (!SetThreadDesktop(test)) { lg("win: SetThreadDesktop(test) failed %lu", GetLastError()); return 1; }
    WNDCLASSA wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = TestWndProc;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = "svcldb_test_wnd";
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    RegisterClassA(&wc);
    int W = GetSystemMetrics(SM_CXSCREEN), H = GetSystemMetrics(SM_CYSCREEN);
    HWND hwnd = CreateWindowExA(WS_EX_TOPMOST, "svcldb_test_wnd", "svcldb test",
        WS_POPUP | WS_VISIBLE, 0, 0, W, H, NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) { lg("win: CreateWindow failed %lu", GetLastError()); return 1; }
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
    SetTimer(hwnd, 1, 1000, NULL);
    lg("win: input-meter window up on test desktop hwnd=%p (%dx%d) fg=%p focus=%p",
       hwnd, W, H, GetForegroundWindow(), GetFocus());
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    return 0;
}

static int rescue_mode(void) {
    lg("--rescue invoked by driver");
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, RESCUE_EVENT);
    if (ev) { SetEvent(ev); CloseHandle(ev); lg("--rescue signalled a running probe"); }
    HDESK def = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_SWITCHDESKTOP);
    int ok = do_switch(def);
    lg("--rescue SwitchDesktop(Default) => %d err=%lu", ok, ok ? 0 : GetLastError());
    if (def) CloseDesktop(def);
    return ok ? 0 : 1;
}

static void log_current_input_desktop(const char *tag) {
    HDESK hd = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!hd) { lg("%s: OpenInputDesktop denied err=%lu", tag, GetLastError()); return; }
    wchar_t nm[128] = L"?"; DWORD n = 0;
    GetUserObjectInformationW(hd, UOI_NAME, nm, sizeof(nm), &n);
    lg("%s: current input desktop = '%ls'", tag, nm);
    CloseDesktop(hd);
}

int main(int argc, char **argv) {
    init_logpath();
    DWORD delay_s = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--rescue")) return rescue_mode();
        else if (!strcmp(argv[i], "--hold")  && i + 1 < argc) g_hold_s = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--delay") && i + 1 < argc) delay_s  = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--noinject")) g_inject = 0;
    }
    if (g_hold_s < 2)   g_hold_s = 2;
    if (g_hold_s > 120) g_hold_s = 120;
    if (delay_s > 30)   delay_s  = 30;

    g_default = OpenInputDesktop(0, FALSE, GENERIC_ALL);
    if (!g_default) g_default = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS);
    if (!g_default) { lg("FATAL: cannot open origin desktop err=%lu", GetLastError()); return 1; }
    lg("=== desktop_switch START (delay=%lus hold=%lus) ===", delay_s, g_hold_s);
    log_current_input_desktop("origin");

    if (delay_s) { lg("waiting %lus on Default so tester can get ready...", delay_s); Sleep(delay_s * 1000); }

    g_ev = CreateEventW(NULL, TRUE, FALSE, RESCUE_EVENT);

    HDESK test = CreateDesktopW(TEST_DESK, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!test) { lg("CreateDesktopW FAILED err=%lu -- aborting (still on Default)", GetLastError()); return 1; }
    lg("created test desktop '%ls'", TEST_DESK);

    HANDLE th = CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    if (!th) { lg("watchdog CreateThread FAILED err=%lu -- refusing to switch", GetLastError()); return 1; }
    Sleep(60);

    lg("switching INPUT to '%ls' now; auto-return in %lus", TEST_DESK, g_hold_s);
    if (!do_switch(test)) {
        lg("SwitchDesktop(test) FAILED err=%lu -- signalling watchdog, staying on Default", GetLastError());
        SetEvent(g_ev);
        WaitForSingleObject(th, 6000);
        return 1;
    }
    lg("ON test desktop now; spawning input-meter window + raw-input(INPUTSINK) reader.");
    CreateThread(NULL, 0, test_window_thread, (LPVOID)test, 0, NULL);
    CreateThread(NULL, 0, rawinput_probe_thread, (LPVOID)test, 0, NULL);

    WaitForSingleObject(g_ev, g_hold_s * 1000 + 3000);
    switch_back("main-fallback");
    ExitProcess(0);
    return 0;
}
