/* ==================================================================
 * deep_hide_stuck_probe.c -- Empirical test of the "deep-hide leaves a
 * modifier stuck" bug (stuck RIGHT-SHIFT incident 2026-09-26).
 *
 * QUESTION: When a WH_KEYBOARD_LL hook CONSUMES (returns 1) both the
 * DOWN and the UP of a modifier (what SVC_OVFLAG_SILENT_MODS deep-hide
 * does), does the OS async key-state (GetAsyncKeyState) end up STUCK
 * "down" after a normal down/up cycle?  And does the teardown case
 * (consume DOWN, remove hook, then physical UP) leave it stuck?
 *
 * We drive the key with SendInput (marked LLKHF_INJECTED); our probe
 * hook processes injected events too (unlike the real deep-hide gate,
 * which filters them) so we can measure the raw consume-vs-async
 * behavior deterministically.
 *
 * Modes tested per run:
 *   A) consume BOTH down+up            (== current deep-hide)
 *   B) consume DOWN, PASS up           (== proposed structural fix)
 *   C) consume DOWN, remove hook, UP   (== teardown race)
 *
 * Build:  cl /O2 deep_hide_stuck_probe.c /link user32.lib
 * Run:    deep_hide_stuck_probe.exe   (no admin needed on Default desk)
 * ================================================================== */
#include <windows.h>
#include <stdio.h>

#define VK_TARGET   VK_RSHIFT
#define SCAN_TARGET 0x36        /* right-shift scancode */

static volatile LONG g_mode = 0;   /* 0=consume both, 1=consume down pass up, 2=passthrough */
static volatile LONG g_fired = 0;

static LRESULT CALLBACK kb(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        if (k->vkCode == VK_RSHIFT || k->vkCode == VK_LSHIFT || k->vkCode == VK_SHIFT) {
            int is_up = (wp == WM_KEYUP || wp == WM_SYSKEYUP);
            InterlockedIncrement(&g_fired);
            if (g_mode == 0) return 1;                     /* consume both */
            if (g_mode == 1) {                             /* consume down, pass up */
                if (is_up) return CallNextHookEx(NULL, code, wp, lp);
                return 1;
            }
            /* mode 2: passthrough */
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static void pump(int ms) {
    DWORD end = GetTickCount() + ms;
    MSG m;
    for (;;) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        if ((int)(GetTickCount() - end) >= 0) break;
        Sleep(5);
    }
}

static void send_rshift(int up) {
    INPUT in; ZeroMemory(&in, sizeof(in));
    in.type       = INPUT_KEYBOARD;
    in.ki.wVk     = VK_TARGET;
    in.ki.wScan   = SCAN_TARGET;
    in.ki.dwFlags = (up ? KEYEVENTF_KEYUP : 0);
    SendInput(1, &in, sizeof(in));
}

static int async_down(void) { return (GetAsyncKeyState(VK_TARGET) & 0x8000) ? 1 : 0; }
static int sync_down(void)   { return (GetKeyState(VK_TARGET)      & 0x8000) ? 1 : 0; }

/* Clean any pre-existing stuck state so each test starts fresh. */
static void force_release(void) {
    INPUT in; ZeroMemory(&in, sizeof(in));
    in.type = INPUT_KEYBOARD; in.ki.wVk = VK_TARGET; in.ki.wScan = SCAN_TARGET;
    in.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &in, sizeof(in));
    Sleep(60);
}

int main(void) {
    printf("== deep_hide_stuck_probe (VK_RSHIFT 0x%02X) ==\n", VK_TARGET);

    /* ---- MODE A: consume BOTH down + up (current deep-hide) ---- */
    force_release();
    InterlockedExchange(&g_mode, 0);
    HHOOK h = SetWindowsHookExW(WH_KEYBOARD_LL, kb, GetModuleHandleW(NULL), 0);
    if (!h) { printf("hook install failed %lu\n", GetLastError()); return 1; }
    printf("\n[A] consume BOTH down+up (== current deep-hide)\n");
    printf("    baseline           async=%d sync=%d\n", async_down(), sync_down());
    send_rshift(0); pump(80);
    printf("    after DOWN (eaten) async=%d sync=%d\n", async_down(), sync_down());
    send_rshift(1); pump(80);
    printf("    after UP   (eaten) async=%d sync=%d  <-- STUCK if async=1\n", async_down(), sync_down());
    UnhookWindowsHookEx(h);
    pump(40);
    printf("    after UNHOOK       async=%d sync=%d\n", async_down(), sync_down());

    /* ---- MODE C: teardown race -- consume DOWN, unhook, then UP ---- */
    force_release();
    InterlockedExchange(&g_mode, 0);
    h = SetWindowsHookExW(WH_KEYBOARD_LL, kb, GetModuleHandleW(NULL), 0);
    printf("\n[C] teardown race: DOWN eaten -> UNHOOK -> UP (no hook)\n");
    printf("    baseline           async=%d sync=%d\n", async_down(), sync_down());
    send_rshift(0); pump(80);
    printf("    after DOWN (eaten) async=%d sync=%d\n", async_down(), sync_down());
    UnhookWindowsHookEx(h); pump(40);
    printf("    after UNHOOK(held) async=%d sync=%d  <-- key still 'down'\n", async_down(), sync_down());
    send_rshift(1); pump(80);
    printf("    after UP (no hook) async=%d sync=%d  <-- STUCK if async=1\n", async_down(), sync_down());

    /* ---- MODE B: consume DOWN, PASS up (proposed structural fix) ---- */
    force_release();
    InterlockedExchange(&g_mode, 1);
    h = SetWindowsHookExW(WH_KEYBOARD_LL, kb, GetModuleHandleW(NULL), 0);
    printf("\n[B] consume DOWN, PASS up (== proposed fix)\n");
    printf("    baseline           async=%d sync=%d\n", async_down(), sync_down());
    send_rshift(0); pump(80);
    printf("    after DOWN (eaten) async=%d sync=%d\n", async_down(), sync_down());
    send_rshift(1); pump(80);
    printf("    after UP (passed)  async=%d sync=%d  <-- STUCK if async=1\n", async_down(), sync_down());
    UnhookWindowsHookEx(h); pump(40);
    printf("    after UNHOOK       async=%d sync=%d\n", async_down(), sync_down());

    force_release();
    printf("\n== done ==\n");
    return 0;
}
