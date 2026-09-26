/* ==========================================================================
 * rawinput_vs_consume_probe.c -- does RIDEV_INPUTSINK raw input still deliver
 * a key when a WH_KEYBOARD_LL hook AHEAD of it CONSUMES that key?
 *
 * This decides svcldb's fix for "hostile hook ahead swallows our hotkey":
 * if raw input (WM_INPUT) is LL-consume-immune on the DEFAULT desktop, we
 * can drive an independent hotkey edge-fire from the raw stream that no
 * competing LL hook can starve -- restoring the true LL-immunity that the
 * GetAsyncKeyState poll was (wrongly) assumed to provide.
 *
 * Setup (single process):
 *   - message-only window + RegisterRawInputDevices(RIDEV_INPUTSINK, kbd)
 *   - WH_KEYBOARD_LL installed LAST (chain HEAD) that CONSUMES 'B'
 *   - SendInput 'B'; count WM_INPUT('B') vs LL head calls
 *
 * async check included for cross-reference with async_consume_probe.
 *
 * Build:  cl /nologo /EHsc rawinput_vs_consume_probe.c /link user32.lib
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>

#ifndef RIDEV_INPUTSINK
#define RIDEV_INPUTSINK 0x00000100
#endif

static volatile LONG g_head_calls   = 0;
static volatile LONG g_wm_input_b    = 0;   /* WM_INPUT deliveries for 'B' */
static volatile LONG g_wm_input_any  = 0;

static LRESULT CALLBACK head_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        InterlockedIncrement(&g_head_calls);
        if (k->vkCode == 'B') return 1;   /* CONSUME at head */
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_INPUT) {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lp, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        if (sz && sz <= 1024) {
            BYTE buf[1024];
            if (GetRawInputData((HRAWINPUT)lp, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) == sz) {
                RAWINPUT *ri = (RAWINPUT *)buf;
                if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                    InterlockedIncrement(&g_wm_input_any);
                    if (ri->data.keyboard.VKey == 'B')
                        InterlockedIncrement(&g_wm_input_b);
                }
            }
        }
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static void pump(int ms) {
    DWORD end = GetTickCount() + ms; MSG m;
    while (GetTickCount() < end) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        Sleep(1);
    }
}

int main(void) {
    printf("=== rawinput_vs_consume_probe ===\n");

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"riprobe_cls";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"riprobe", 0, 0,0,0,0,
                                HWND_MESSAGE, NULL, wc.hInstance, NULL);
    if (!hwnd) { printf("CreateWindow failed %lu\n", GetLastError()); return 1; }

    RAWINPUTDEVICE rid = {0};
    rid.usUsagePage = 0x01; rid.usUsage = 0x06;       /* generic keyboard */
    rid.dwFlags = RIDEV_INPUTSINK; rid.hwndTarget = hwnd;
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        printf("RegisterRawInputDevices failed %lu\n", GetLastError()); return 1;
    }

    /* Chain HEAD hook that consumes 'B'. */
    HHOOK head = SetWindowsHookExW(WH_KEYBOARD_LL, head_proc, GetModuleHandleW(NULL), 0);
    if (!head) { printf("hook failed %lu\n", GetLastError()); return 1; }

    g_head_calls = g_wm_input_b = g_wm_input_any = 0;

    INPUT in[2] = {0};
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = 'B';
    in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = 'B'; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
    pump(120);

    int a = (GetAsyncKeyState('B') & 0x8000) != 0;
    printf("head_calls=%ld  WM_INPUT('B')=%ld  WM_INPUT(any-kbd)=%ld  async('B')=%d\n",
           g_head_calls, g_wm_input_b, g_wm_input_any, a);

    UnhookWindowsHookEx(head);
    RAWINPUTDEVICE unreg = {0};
    unreg.usUsagePage = 0x01; unreg.usUsage = 0x06; unreg.dwFlags = RIDEV_REMOVE;
    RegisterRawInputDevices(&unreg, 1, sizeof(unreg));

    printf("\n=== VERDICT ===\n");
    printf(" LL head consumed 'B'            : %s\n", g_head_calls > 0 ? "YES" : "NO");
    printf(" raw input STILL saw 'B'         : %s\n", g_wm_input_b > 0 ? "YES" : "NO");
    printf(" => raw-input edge-fire fallback  : %s\n",
           g_wm_input_b > 0 ? "VIABLE (LL-consume-immune)" : "NOT viable");
    return 0;
}
