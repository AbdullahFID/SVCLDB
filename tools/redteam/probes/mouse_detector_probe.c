/* ==========================================================================
 * mouse_detector_probe.c -- MOUSE counterpart to proctor_detector_probe.c.
 *
 * Models an ACT/Bluebook-style MOUSE watcher sitting in the WH_MOUSE_LL
 * chain while svcldb is injected, to answer: "if the proctor hooks the mouse,
 * does it break (or see) my triple-click hotkey?"
 *
 * Three detection mechanisms a real proctor could run, SIMULTANEOUSLY:
 *
 *   (1) WH_MOUSE_LL hook, NON-consuming (CallNextHookEx) -- pure watcher, the
 *       exact shape a proctor's mouse-hook addon takes. Counts left-button
 *       DOWN events it observes. If svcldb consumed clicks at the chain head
 *       this would read 0; svcldb does NOT consume clicks (you must click
 *       inside the exam), so this WILL see them -- and that's fine: a leaked
 *       click is benign input, not a prohibited action.
 *   (2) GetAsyncKeyState(VK_LBUTTON) 60Hz poll -- reads kernel-global button
 *       state. A passive LL hook never touches this.
 *   (3) Rising-edge click counter, to show raw click delivery.
 *
 * The POINT is our side: with this hook in the chain, svcldb's MOUSE_MULTI
 * (triple-click) hotkey must still fire cleanly (verify in the payload log).
 * This probe just proves the proctor's hook presence changes nothing.
 *
 * By default installs the hook ONCE (realistic: proctor installs on kiosk
 * entry). Pass -aggressive to reinstall every 40ms (models a proctor that
 * fights the chain-head war -- pathological for a non-consuming watcher, but
 * lets us stress the same churn that broke keyboard multitap).
 *
 * SAFETY: non-consuming (never blocks input), auto-exit after duration,
 * Ctrl+F12 hard escape (polled). Medium-IL, no admin.
 *
 * Build: cl /nologo proctor... ; here:
 *   cl /nologo mouse_detector_probe.c /link user32.lib
 * Run:   mouse_detector_probe.exe [duration_sec] [-aggressive]
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG  g_ll_down_seen = 0;   /* LBUTTON downs the hook observed  */
static volatile LONG  g_poll_edges   = 0;   /* rising edges via GetAsyncKeyState */
static volatile LONG  g_quit         = 0;
static HHOOK          g_hook         = NULL;
static int            g_aggressive   = 0;
static DWORD          g_start        = 0;

static double secs(void) { return (GetTickCount() - g_start) / 1000.0; }

static LRESULT CALLBACK ll_mouse_watch(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        if (wp == WM_LBUTTONDOWN) {
            LONG n = InterlockedIncrement(&g_ll_down_seen);
            printf("[%.2fs] MOUSE-LL saw LBUTTONDOWN (observation #%ld)\n", secs(), n);
            fflush(stdout);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);   /* NEVER consume -- pure watcher */
}

static DWORD WINAPI poll_thread(LPVOID u) {
    (void)u;
    int prev = 0;
    while (!InterlockedCompareExchange(&g_quit, 0, 0)) {
        /* Ctrl+F12 hard escape. */
        if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(VK_F12) & 0x8000)) {
            InterlockedExchange(&g_quit, 1);
            break;
        }
        int down = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
        if (down && !prev) {
            LONG n = InterlockedIncrement(&g_poll_edges);
            printf("[%.2fs] POLL saw LBUTTON down via GetAsyncKeyState (edge #%ld)\n", secs(), n);
            fflush(stdout);
        }
        prev = down;
        Sleep(16);
    }
    return 0;
}

static DWORD WINAPI rehook_thread(LPVOID u) {
    (void)u;
    while (!InterlockedCompareExchange(&g_quit, 0, 0)) {
        Sleep(40);
        HHOOK nh = SetWindowsHookExW(WH_MOUSE_LL, ll_mouse_watch, GetModuleHandleW(NULL), 0);
        if (nh) { HHOOK old = g_hook; g_hook = nh; if (old) UnhookWindowsHookEx(old); }
    }
    return 0;
}

int main(int argc, char **argv) {
    int dur = 30;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-aggressive")) g_aggressive = 1;
        else { int d = atoi(argv[i]); if (d >= 5 && d <= 300) dur = d; }
    }
    g_start = GetTickCount();

    printf("=== mouse_detector_probe ===\n");
    printf("ACT/Bluebook-style WH_MOUSE_LL watcher + GetAsyncKeyState(LBUTTON) poll\n");
    printf("Mode: %s | Duration: %ds | Escape: Ctrl+F12\n\n",
           g_aggressive ? "AGGRESSIVE (rehook @40ms)" : "realistic (install once)", dur);
    printf("TRIPLE-CLICK repeatedly while svcldb is injected; verify the overlay\n");
    printf("toggles in the payload log. This probe just proves the mouse hook's\n");
    printf("presence in the chain does not break svcldb's click detection.\n\n");

    g_hook = SetWindowsHookExW(WH_MOUSE_LL, ll_mouse_watch, GetModuleHandleW(NULL), 0);
    if (!g_hook) { printf("mouse hook install failed %lu\n", GetLastError()); return 1; }

    CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
    if (g_aggressive) CreateThread(NULL, 0, rehook_thread, NULL, 0, NULL);

    DWORD deadline = GetTickCount() + (DWORD)dur * 1000;
    MSG m;
    while (!InterlockedCompareExchange(&g_quit, 0, 0) && GetTickCount() < deadline) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { /* drain */ }
        Sleep(5);
    }
    InterlockedExchange(&g_quit, 1);
    Sleep(60);

    if (g_hook) UnhookWindowsHookEx(g_hook);

    printf("\n=== RESULT (mouse) ===\n");
    printf("  MOUSE-LL LBUTTON downs seen : %ld\n", g_ll_down_seen);
    printf("  GetAsyncKeyState poll edges : %ld\n", g_poll_edges);
    printf("  ---------------------------------\n");
    printf("  NOTE: nonzero here is EXPECTED + benign -- a proctor's mouse hook\n");
    printf("  sees clicks, and clicks are legit exam input. What matters is that\n");
    printf("  svcldb's MOUSE_MULTI hotkey still toggled the overlay (see payload log).\n");
    return 0;
}
