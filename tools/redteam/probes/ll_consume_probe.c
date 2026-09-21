/* ==========================================================================
 * ll_consume_probe.c -- Maximum-aggressiveness non-admin LL-hook consumer.
 *
 * Tests svcldb's 3-path input defense (LL hook + 60Hz kernel-global poll +
 * periodic LL rehook + thread-integrity watchdog) against a hostile
 * medium-integrity proctor-style application that installs
 * WH_KEYBOARD_LL + WH_MOUSE_LL in a single batch and consumes EVERY event
 * (returns non-zero from CallNextHookEx = event doesn't propagate to any
 * later hook in the chain OR to any target window).
 *
 * This is what a THEORETICAL determined proctor (that specifically knew
 * about our hotkey bindings) COULD do. Real production proctor apps
 * (Bluebook, ACT, OnVUE) only consume their published block list
 * (Alt+Tab, Win+*, etc.), not Ctrl+arrow -- but we want to prove our
 * defense against the worst case.
 *
 * EXPECTED RESULT: while this probe is actively consuming keys, pressing
 * Ctrl+Left/Right/Up/Down should STILL move the svcldb overlay -- because
 * our GetAsyncKeyState 60Hz poll reads win32k!gafAsyncKeyState directly
 * (kernel-global state, not user-mode-hookable). Also, our 5s LL rehook
 * bumps our payload hook back to HEAD of the LIFO chain (fires before
 * this probe consumes) every 5s.
 *
 * SAFETY (three independent unbreakable escape mechanisms):
 *   1. Ctrl+F12       -- whitelisted, unhooks + exits cleanly (any time)
 *   2. N-second timer -- watchdog thread hard auto-unhook + ExitProcess
 *   3. Win+L          -- whitelisted, triggers lock-screen escape
 *
 * Additionally: mouse MOVES pass through (only clicks/wheel/xbuttons
 * consumed) so cursor stays visible + user can navigate visually.
 *
 * Build (from repo root or this dir):
 *   cl /nologo /EHsc ll_consume_probe.c /link user32.lib
 *
 * Usage:
 *   ll_consume_probe.exe [duration_seconds]   default 30, min 5, max 120
 *
 * Threat model: NON-ADMIN process. LL hook installation is a documented
 * user-mode API (no admin required). Simulates the exact behavior a
 * medium-integrity proctor app could exhibit.
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static HHOOK          g_kb_hook       = NULL;
static HHOOK          g_ms_hook       = NULL;
static volatile LONG  g_quit          = 0;
static volatile DWORD g_max_seconds   = 30;
static DWORD          g_start_tick    = 0;
static DWORD          g_main_tid      = 0;

/* Stats -- observable evidence of what got consumed vs passed. */
static volatile LONG g_kb_consumed = 0;
static volatile LONG g_kb_passed   = 0;
static volatile LONG g_ms_consumed = 0;
static volatile LONG g_ms_passed   = 0;

static void print_stats(const char *why) {
    printf("[%s] kb consumed=%ld passed=%ld  ms consumed=%ld passed=%ld  elapsed=%us\n",
           why, g_kb_consumed, g_kb_passed, g_ms_consumed, g_ms_passed,
           (GetTickCount() - g_start_tick) / 1000);
    fflush(stdout);
}

static void trigger_exit(const char *why) {
    if (InterlockedCompareExchange(&g_quit, 1, 0) != 0) return;   /* already firing */
    printf("\n=== EXITING (%s) ===\n", why);
    print_stats(why);
    if (g_kb_hook) { UnhookWindowsHookEx(g_kb_hook); g_kb_hook = NULL; }
    if (g_ms_hook) { UnhookWindowsHookEx(g_ms_hook); g_ms_hook = NULL; }
    if (g_main_tid) PostThreadMessageW(g_main_tid, WM_QUIT, 0, 0);
}

/* ── UNBREAKABLE WATCHDOG: hard auto-exit after N seconds no matter what. ──
 * Runs on its own thread. Sleep is interruptable only by process death.
 * If message pump gets wedged, if hooks refuse to unhook, if anything else
 * fails -- we ExitProcess unconditionally. */
static DWORD WINAPI watchdog_thread(LPVOID unused) {
    (void)unused;
    Sleep(g_max_seconds * 1000);
    if (InterlockedCompareExchange(&g_quit, 0, 0) == 0) {
        printf("\n[watchdog] %us HARD TIMEOUT -- force unhook + ExitProcess\n",
               g_max_seconds);
        if (g_kb_hook) UnhookWindowsHookEx(g_kb_hook);
        if (g_ms_hook) UnhookWindowsHookEx(g_ms_hook);
        print_stats("watchdog-timeout");
        ExitProcess(0);
    }
    return 0;
}

/* Periodic stats printer -- shows in real-time how many events we're
 * blocking, so user can eyeball the aggression level. */
static DWORD WINAPI stats_thread(LPVOID unused) {
    (void)unused;
    while (InterlockedCompareExchange(&g_quit, 0, 0) == 0) {
        Sleep(2000);
        print_stats("tick");
    }
    return 0;
}

/* ── Keyboard LL hook: CONSUME EVERY EVENT except escape combos ──
 *
 * Escape whitelist (pass-through, NO consume):
 *   * Ctrl+F12 (down)  -- also triggers graceful exit
 *   * Win+L    (down)  -- lock-screen escape hatch
 *   * Ctrl+Alt+Del     -- handled by kernel, doesn't reach LL anyway
 *
 * Everything else: return 1 = consume, no propagation to chain or apps. */
static LRESULT CALLBACK kb_hook_proc(int code, WPARAM wp, LPARAM lp) {
    if (code != HC_ACTION) return CallNextHookEx(NULL, code, wp, lp);
    KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
    int is_down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);

    /* ── Escape: Ctrl+F12 ── */
    if (is_down && k->vkCode == VK_F12) {
        SHORT ctrl = GetAsyncKeyState(VK_CONTROL) & 0x8000;
        if (ctrl) {
            InterlockedIncrement(&g_kb_passed);
            trigger_exit("Ctrl+F12 escape");
            return CallNextHookEx(NULL, code, wp, lp);
        }
    }

    /* ── Escape: Win+L ── */
    if (is_down && (k->vkCode == 'L' || k->vkCode == 'l')) {
        SHORT win = (GetAsyncKeyState(VK_LWIN) | GetAsyncKeyState(VK_RWIN)) & 0x8000;
        if (win) {
            InterlockedIncrement(&g_kb_passed);
            return CallNextHookEx(NULL, code, wp, lp);
        }
    }

    /* ── MAX AGGRESSION: consume everything else ── */
    InterlockedIncrement(&g_kb_consumed);
    return 1;
}

/* ── Mouse LL hook: consume clicks + wheel + xbuttons, PASS moves ──
 *
 * Consuming moves would freeze the cursor visually -- user couldn't
 * navigate or see where they are. Passing moves lets cursor track
 * normally; only clicks/wheel are blocked (proctor-style "no interaction
 * with anything except the exam app" behavior). */
static LRESULT CALLBACK ms_hook_proc(int code, WPARAM wp, LPARAM lp) {
    if (code != HC_ACTION) return CallNextHookEx(NULL, code, wp, lp);
    if (wp == WM_MOUSEMOVE) {
        InterlockedIncrement(&g_ms_passed);
        return CallNextHookEx(NULL, code, wp, lp);
    }
    InterlockedIncrement(&g_ms_consumed);
    return 1;
}

int main(int argc, char **argv) {
    int duration_s = 30;
    if (argc > 1) duration_s = atoi(argv[1]);
    if (duration_s < 5)   duration_s = 5;
    if (duration_s > 120) duration_s = 120;
    g_max_seconds = (DWORD)duration_s;
    g_main_tid    = GetCurrentThreadId();

    printf("========================================================\n");
    printf("  ll_consume_probe (svcldb 3-path input defense test)\n");
    printf("========================================================\n");
    printf("Simulating an AGGRESSIVE non-admin proctor app:\n");
    printf("  * WH_KEYBOARD_LL: CONSUMES every key event (except escapes)\n");
    printf("  * WH_MOUSE_LL   : CONSUMES all clicks/wheel/xbuttons (moves pass)\n");
    printf("  * Duration      : %d seconds (hard watchdog auto-unhook)\n", duration_s);
    printf("\n");
    printf("ESCAPES (any works, unbreakable):\n");
    printf("  1. Ctrl+F12                    -- graceful exit + unhook\n");
    printf("  2. Wait %ds                    -- watchdog force ExitProcess\n", duration_s);
    printf("  3. Win+L                       -- lock-screen (whitelisted)\n");
    printf("  4. Physical power button       -- always works\n");
    printf("\n");
    printf("TEST INSTRUCTIONS:\n");
    printf("  While this probe runs, try Ctrl+Left / Ctrl+Right / Ctrl+Up /\n");
    printf("  Ctrl+Down to nudge the svcldb overlay.\n");
    printf("\n");
    printf("EXPECTED (if svcldb defense holds):\n");
    printf("  * Overlay MOVES on Ctrl+arrow anyway (via 60Hz kernel-global poll)\n");
    printf("  * Terminal + all other apps see NO keys / NO clicks (this probe's\n");
    printf("    consume is working -- proves we're really blocking, not faking)\n");
    printf("\n");
    printf("========================================================\n");
    printf("\n");

    g_start_tick = GetTickCount();

    /* Install both hooks in the same batch (proctor-app pattern). */
    g_kb_hook = SetWindowsHookExW(WH_KEYBOARD_LL, kb_hook_proc,
                                   GetModuleHandleW(NULL), 0);
    g_ms_hook = SetWindowsHookExW(WH_MOUSE_LL, ms_hook_proc,
                                   GetModuleHandleW(NULL), 0);

    if (!g_kb_hook || !g_ms_hook) {
        printf("HOOK INSTALL FAILED kb=%p ms=%p gle=%lu\n",
               (void*)g_kb_hook, (void*)g_ms_hook, GetLastError());
        if (g_kb_hook) UnhookWindowsHookEx(g_kb_hook);
        if (g_ms_hook) UnhookWindowsHookEx(g_ms_hook);
        return 1;
    }
    printf(">>> HOOKS ACTIVE (kb=%p, ms=%p) -- consuming EVERYTHING. Start testing.\n\n",
           (void*)g_kb_hook, (void*)g_ms_hook);
    fflush(stdout);

    /* Unbreakable watchdog: hard auto-exit after N seconds. */
    HANDLE wd = CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
    if (wd) CloseHandle(wd);

    /* Real-time stats every 2s. */
    HANDLE st = CreateThread(NULL, 0, stats_thread, NULL, 0, NULL);
    if (st) CloseHandle(st);

    /* Message pump for LL hooks. */
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (InterlockedCompareExchange(&g_quit, 0, 0)) break;
        TranslateMessage(&m); DispatchMessageW(&m);
    }

    if (g_kb_hook) UnhookWindowsHookEx(g_kb_hook);
    if (g_ms_hook) UnhookWindowsHookEx(g_ms_hook);
    print_stats("clean-exit");
    return 0;
}
