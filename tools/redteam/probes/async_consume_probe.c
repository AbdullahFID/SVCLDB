/* ==========================================================================
 * async_consume_probe.c -- settle the load-bearing Windows-semantics question:
 *
 *   When a WH_KEYBOARD_LL hook CONSUMES a key (returns 1, no CallNextHookEx),
 *   is win32k!gafAsyncKeyState (what GetAsyncKeyState reads) STILL updated?
 *
 * This decides two things at once for svcldb:
 *   (A) Whether a poll-thread GetAsyncKeyState fallback can re-fire our own
 *       hotkeys when a hostile hook AHEAD of us in the LIFO chain swallows
 *       them (our LL hook never runs, so g_consumed_vk is never set).
 *   (B) Whether a hostile POLLING proctor can see OUR hotkey even when our
 *       LL hook consumes it (the reverse-direction "instant termination"
 *       nightmare). If async state is set regardless of consumption, we
 *       cannot hide a raw keypress from a poller in user mode -- kernel
 *       driver only.
 *
 * Also proves LIFO propagation: with two LL hooks in one process, the
 * head (installed last) consuming a key means the tail (installed first)
 * NEVER sees it -> confirms "we consume at head => proctor hook behind us
 * is blind".
 *
 * All input is synthesized via SendInput (marked LLKHF_INJECTED). We read
 * GetAsyncKeyState from the SAME thread right after. No physical keys, no
 * admin, no payload needed. Self-contained.
 *
 * Build:  cl /nologo /EHsc async_consume_probe.c /link user32.lib
 * Run:    async_consume_probe.exe
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>

static volatile LONG g_head_calls = 0;   /* hook installed LAST  = chain head */
static volatile LONG g_tail_calls = 0;   /* hook installed FIRST = chain tail */
static volatile LONG g_consume_b  = 0;   /* when 1, head consumes VK 'B' */

/* HEAD hook: optionally consumes 'B'. Installed LAST so it runs FIRST. */
static LRESULT CALLBACK head_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        InterlockedIncrement(&g_head_calls);
        if (g_consume_b && k->vkCode == 'B')
            return 1;   /* CONSUME -- do not propagate to tail or target */
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

/* TAIL hook: never consumes, just counts. Installed FIRST so it runs LAST.
 * If head consumes 'B', this should NOT be called for 'B'. */
static LRESULT CALLBACK tail_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) InterlockedIncrement(&g_tail_calls);
    return CallNextHookEx(NULL, code, wp, lp);
}

static void tap_b(void) {
    INPUT in[2] = {0};
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = 'B';
    in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = 'B'; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    /* DOWN only first so we can sample async-state while "held". */
    SendInput(1, &in[0], sizeof(INPUT));
}
static void release_b(void) {
    INPUT in = {0};
    in.type = INPUT_KEYBOARD; in.ki.wVk = 'B'; in.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &in, sizeof(INPUT));
}

/* SendInput queues to the RIT asynchronously; the LL hooks fire on this
 * thread's message queue. Pump briefly so the hook chain runs before we
 * sample GetAsyncKeyState. */
static void pump(int ms) {
    DWORD end = GetTickCount() + ms;
    MSG m;
    while (GetTickCount() < end) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
        Sleep(1);
    }
}

static int async_b_down(void) { return (GetAsyncKeyState('B') & 0x8000) != 0; }

int main(void) {
    printf("=== async_consume_probe ===\n");

    /* Baseline: no hooks. Confirm SendInput moves gafAsyncKeyState at all. */
    tap_b(); pump(60);
    printf("[baseline no-hook]   async('B') down = %d (expect 1)\n", async_b_down());
    release_b(); pump(60);
    printf("[baseline released]  async('B') down = %d (expect 0)\n", async_b_down());

    /* Install tail FIRST, head LAST => head is chain HEAD (LIFO). */
    HHOOK tail = SetWindowsHookExW(WH_KEYBOARD_LL, tail_proc, GetModuleHandleW(NULL), 0);
    HHOOK head = SetWindowsHookExW(WH_KEYBOARD_LL, head_proc, GetModuleHandleW(NULL), 0);
    if (!tail || !head) { printf("hook install failed gle=%lu\n", GetLastError()); return 1; }

    /* --- Test 1: head does NOT consume. Both hooks should see 'B'. --- */
    g_consume_b = 0; g_head_calls = g_tail_calls = 0;
    tap_b(); pump(80);
    printf("\n[no-consume] head_calls=%ld tail_calls=%ld  async('B')=%d\n",
           g_head_calls, g_tail_calls, async_b_down());
    printf("            -> expect tail_calls>0 (propagates), async=1\n");
    release_b(); pump(60);

    /* --- Test 2: head CONSUMES 'B'. Tail must NOT see 'B'; async state? --- */
    g_consume_b = 1; g_head_calls = g_tail_calls = 0;
    tap_b(); pump(80);
    int a = async_b_down();
    printf("\n[consume]    head_calls=%ld tail_calls=%ld  async('B')=%d\n",
           g_head_calls, g_tail_calls, a);
    printf("            -> tail_calls should be 0 (consumed at head => hook behind is blind)\n");
    printf("            -> async('B')=%d : 1 = consumption does NOT clear gafAsyncKeyState\n", a);
    release_b(); pump(60);

    UnhookWindowsHookEx(head);
    UnhookWindowsHookEx(tail);

    printf("\n=== VERDICT ===\n");
    printf(" LIFO+consume blinds hook-behind : %s\n", (g_tail_calls == 0) ? "YES" : "NO");
    printf(" poll CAN see consumed key       : %s\n", a ? "YES (async set despite consume)" : "NO");
    printf(" => poll-fallback edge-fire fix   : %s\n", a ? "VIABLE" : "NOT viable");
    printf(" => can hide hotkey from a poller : %s\n", a ? "NO (kernel driver only)" : "YES");
    return 0;
}
