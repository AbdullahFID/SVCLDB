/* ==========================================================================
 * proctor_detector_probe.c -- the REVERSE-direction test for He's nightmare:
 * "I press Ctrl+B, the proctor ALSO sees Ctrl+B -> instant test termination."
 *
 * Simulates a medium-IL proctor watching for a prohibited combo (default
 * Ctrl+B) via ALL THREE detection mechanisms a real proctor could use,
 * SIMULTANEOUSLY, and reports whether any of them ever saw the combo:
 *
 *   (1) WH_KEYBOARD_LL hook, NON-consuming (CallNextHookEx) -- pure watcher,
 *       like ACT's keyboard-hook-addon. If svcldb holds the LIFO chain head
 *       AND consumes Ctrl+B, this hook is BEHIND svcldb and sees NOTHING.
 *   (2) RegisterHotKey(Ctrl+B) -> WM_HOTKEY. Fires from win32k's global table
 *       UNLESS a hook ahead consumed the key first.
 *   (3) GetAsyncKeyState('B')+Ctrl 60Hz poll. Reads gafAsyncKeyState. If a
 *       hook ahead consumed the key, this reads 0 (proven for injected input
 *       in async_consume_probe; physical TBD).
 *
 * EXPECTED (svcldb defense holding, svcldb at chain head + consuming Ctrl+B):
 *   llHookSaw = 0, hotkeyFired = 0, pollSaw = 0  ->  proctor is BLIND. WIN.
 *
 * If any counter is > 0, that detection path saw your hotkey -> in a real
 * proctor that's a termination event. The timestamps show the window: a few
 * early hits right after this probe installs (before svcldb's next reinstall
 * bumps us back to head) that then STOP = the reinstall race in action.
 *
 * By default installs its LL hook ONCE (realistic: a proctor installs on
 * kiosk entry). Pass -aggressive to also reinstall every 40ms (models a
 * proctor that fights the chain-head war as hard as svcldb does).
 *
 * SAFETY: non-consuming (never blocks input), auto-exit after duration,
 * Ctrl+F12 hard escape. Medium-IL, no admin.
 *
 * Build: cl /nologo /EHsc proctor_detector_probe.c /link user32.lib
 * Run:   proctor_detector_probe.exe [duration_sec] [-aggressive] [-vk 0x42]
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG  g_ll_saw       = 0;
static volatile LONG  g_hotkey_fired = 0;
static volatile LONG  g_poll_saw     = 0;
static volatile LONG  g_quit         = 0;
static HHOOK          g_hook         = NULL;
static int            g_target_vk    = 'B';      /* default Ctrl+B */
static int            g_aggressive   = 0;
static DWORD          g_start        = 0;

static double secs(void) { return (GetTickCount() - g_start) / 1000.0; }

static LRESULT CALLBACK ll_watch(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        int down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        /* Ctrl+F12 escape (always passes). */
        if (down && k->vkCode == VK_F12 && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            InterlockedExchange(&g_quit, 1);
            return CallNextHookEx(NULL, code, wp, lp);
        }
        if (down && (int)k->vkCode == g_target_vk &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            LONG n = InterlockedIncrement(&g_ll_saw);
            printf("[%.2fs] LL-HOOK saw Ctrl+0x%02X  (detection #%ld) -- proctor would TERMINATE\n",
                   secs(), g_target_vk, n);
            fflush(stdout);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);   /* NEVER consume -- pure watcher */
}

static DWORD WINAPI poll_thread(LPVOID u) {
    (void)u;
    int prev = 0;
    while (!InterlockedCompareExchange(&g_quit, 0, 0)) {
        int ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        int vk   = (GetAsyncKeyState(g_target_vk) & 0x8000) != 0;
        int hot  = ctrl && vk;
        if (hot && !prev) {
            LONG n = InterlockedIncrement(&g_poll_saw);
            printf("[%.2fs] POLL saw Ctrl+0x%02X via GetAsyncKeyState (detection #%ld)\n",
                   secs(), g_target_vk, n);
            fflush(stdout);
        }
        prev = hot;
        Sleep(16);
    }
    return 0;
}

static DWORD WINAPI rehook_thread(LPVOID u) {
    (void)u;
    while (!InterlockedCompareExchange(&g_quit, 0, 0)) {
        Sleep(40);
        HHOOK nh = SetWindowsHookExW(WH_KEYBOARD_LL, ll_watch, GetModuleHandleW(NULL), 0);
        if (nh) { HHOOK old = g_hook; g_hook = nh; if (old) UnhookWindowsHookEx(old); }
    }
    return 0;
}

int main(int argc, char **argv) {
    int dur = 30;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-aggressive")) g_aggressive = 1;
        else if (!strcmp(argv[i], "-vk") && i + 1 < argc) g_target_vk = (int)strtol(argv[++i], NULL, 0);
        else { int d = atoi(argv[i]); if (d >= 5 && d <= 300) dur = d; }
    }
    g_start = GetTickCount();

    printf("=== proctor_detector_probe ===\n");
    printf("Watching for Ctrl+0x%02X via LL-hook + RegisterHotKey + GetAsyncKeyState poll\n", g_target_vk);
    printf("Mode: %s | Duration: %ds | Escape: Ctrl+F12\n\n",
           g_aggressive ? "AGGRESSIVE (rehook @40ms)" : "realistic (install once)", dur);
    printf("PRESS Ctrl+0x%02X REPEATEDLY while svcldb is injected.\n", g_target_vk);
    printf("If svcldb holds the chain head + consumes, ALL counters stay 0.\n\n");

    g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, ll_watch, GetModuleHandleW(NULL), 0);
    if (!g_hook) { printf("hook install failed %lu\n", GetLastError()); return 1; }

    /* RegisterHotKey path -- needs a message window; use a thread-message hotkey. */
    RegisterHotKey(NULL, 1, MOD_CONTROL | 0x4000 /*MOD_NOREPEAT*/, g_target_vk);

    CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
    if (g_aggressive) CreateThread(NULL, 0, rehook_thread, NULL, 0, NULL);

    DWORD deadline = GetTickCount() + (DWORD)dur * 1000;
    MSG m;
    while (!InterlockedCompareExchange(&g_quit, 0, 0) && GetTickCount() < deadline) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            if (m.message == WM_HOTKEY) {
                LONG n = InterlockedIncrement(&g_hotkey_fired);
                printf("[%.2fs] RegisterHotKey WM_HOTKEY fired (detection #%ld)\n", secs(), n);
                fflush(stdout);
            }
        }
        Sleep(5);
    }
    InterlockedExchange(&g_quit, 1);
    Sleep(60);

    UnregisterHotKey(NULL, 1);
    if (g_hook) UnhookWindowsHookEx(g_hook);

    printf("\n=== RESULT (Ctrl+0x%02X) ===\n", g_target_vk);
    printf("  LL-hook detections     : %ld\n", g_ll_saw);
    printf("  RegisterHotKey fires   : %ld\n", g_hotkey_fired);
    printf("  GetAsyncKeyState poll  : %ld\n", g_poll_saw);
    int total = g_ll_saw + g_hotkey_fired + g_poll_saw;
    printf("  ---------------------------------\n");
    printf("  VERDICT: %s\n", total == 0
        ? "PROCTOR BLIND -- svcldb hid the hotkey completely. WIN."
        : "LEAK -- proctor saw the hotkey (see timestamps for the window).");
    return 0;
}
