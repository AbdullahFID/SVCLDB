/* ================================================================== *
 * probe.c — Verify svcldb's LL keyboard hook actually consumes hotkeys
 * before any other usermode process can see them.
 *
 * What this exercises (all in ONE process, so we get to observe from
 * every usermode angle simultaneously):
 *
 *   1. WH_KEYBOARD_LL — install our own LL hook AFTER svcldb's payload.
 *      Windows dispatches LL hooks in LIFO install-order, so ours runs
 *      BEFORE svcldb's (payload was injected first). Log every event
 *      we see. Then call CallNextHookEx so payload can also see and
 *      consume — mimics a polite proctor hook.
 *
 *   2. RegisterHotKey — register Ctrl+Alt+G in this process. See if
 *      WM_HOTKEY fires here when payload's LL hook returns 1.
 *
 *   3. GetAsyncKeyState — poll every 10ms during test window. This
 *      reads win32k!gafAsyncKeyState which is NOT affected by LL
 *      hook consumption. Log every observed change of Ctrl / Alt / G.
 *
 *   4. Raw Input (RIDEV_INPUTSINK) — register for RAWINPUT_KEYBOARD
 *      messages. See if WM_INPUT arrives when LL hook consumes.
 *
 * Test procedure:
 *   - Launch this AFTER svcldb payload is loaded
 *   - Wait 8 seconds for payload's periodic reinstall to fire (so
 *     payload is at head of chain AGAIN even though we're newer)
 *   - Actually, since we're newer, we run FIRST — we log everything
 *   - Send Ctrl+Alt+G via SendInput
 *   - After 3 seconds of observation, exit + report
 *
 * Output: hotkey_probe_log.txt in current dir. Human-readable.
 *
 * Compile:  cl /nologo /W3 /O2 probe.c /link user32.lib
 * ================================================================== */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "user32.lib")

#define RIN_WM_APP_TERMINATE (WM_APP + 100)

static FILE *g_log = NULL;
static HHOOK g_ll = NULL;

static void logln(const char *fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf) - 1, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf + n, sizeof(buf) - n - 1, fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    if (g_log) { fprintf(g_log, "%s\n", buf); fflush(g_log); }
}

typedef struct {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} KBDLL;

/* Was Ctrl+Alt+G actually observed via LL hook? */
static volatile LONG g_saw_target_ll = 0;
static volatile LONG g_saw_target_wmhotkey = 0;
static volatile LONG g_saw_target_asyncks = 0;
static volatile LONG g_saw_target_rawinput = 0;

static LRESULT CALLBACK ll_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLL *k = (KBDLL *)lp;
        int is_down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        int is_up   = (wp == WM_KEYUP   || wp == WM_SYSKEYUP);
        USHORT vk = (USHORT)k->vkCode;
        int injected = (k->flags & 0x10) != 0;
        int ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) ? 1 : 0;
        int alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) ? 1 : 0;

        logln("LL hook: %s vk=0x%02X ctrl=%d alt=%d injected=%d",
              is_down ? "DOWN" : (is_up ? "UP" : "OTHER"), vk, ctrl, alt, injected);

        /* Count ANY G event (any modifier state) so we know if G is
         * even reaching us at all. */
        if (vk == 'G' && is_down) {
            InterlockedIncrement(&g_saw_target_ll);
            logln("  ==> probe LL hook saw G-DOWN (ctrl=%d alt=%d)", ctrl, alt);
        }
    }
    /* v2: CONSUME every event (return 1) so we can prove head-of-chain
     * position. If probe is at LIFO HEAD, svcldb should see NOTHING.
     * If probe is BEHIND svcldb, svcldb consumed before we saw. */
    return 1;
}

static DWORD WINAPI async_poll_thread(LPVOID p) {
    (void)p;
    int prev_g = 0;
    for (int i = 0; i < 500; i++) {   /* 5s @ 10ms */
        int g = (GetAsyncKeyState('G') & 0x8000) ? 1 : 0;
        int ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) ? 1 : 0;
        int alt  = (GetAsyncKeyState(VK_MENU)    & 0x8000) ? 1 : 0;
        if (g && !prev_g && ctrl && alt) {
            InterlockedIncrement(&g_saw_target_asyncks);
            logln("AsyncKS: saw G DOWN with Ctrl+Alt held  (bypass path — expected on ALL builds)");
        }
        prev_g = g;
        Sleep(10);
    }
    return 0;
}

int main(void) {
    g_log = fopen("hotkey_probe_log.txt", "w");
    logln("=== hotkey_probe start ===");
    logln("pid=%lu", (unsigned long)GetCurrentProcessId());

    /* Install LL keyboard hook — LIFO order means we run BEFORE any
     * hook installed earlier (including svcldb's). */
    HINSTANCE hi = GetModuleHandleW(NULL);
    g_ll = SetWindowsHookExW(WH_KEYBOARD_LL, ll_proc, hi, 0);
    if (!g_ll) {
        logln("SetWindowsHookExW failed gle=%lu", GetLastError());
        return 1;
    }
    logln("LL hook installed (probe is now at LIFO HEAD — should see events first)");

    /* Register Ctrl+Alt+G as global hotkey for this thread. */
    if (RegisterHotKey(NULL, 1, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 'G')) {
        logln("RegisterHotKey(Ctrl+Alt+G) OK");
    } else {
        logln("RegisterHotKey failed gle=%lu (svcldb may have exclusive?)",
              GetLastError());
    }

    /* Start async key state polling thread. */
    HANDLE t = CreateThread(NULL, 0, async_poll_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);

    /* Send Ctrl+Alt+G via SendInput 500ms after we start (gives our
     * thread time to enter the message loop). */
    DWORD start = GetTickCount();
    int sent1 = 0, sent2 = 0;
    volatile LONG saw_ll_after_reinstall = 0;

    /* Message pump for LL hook + WM_HOTKEY.
     * TWO SendInput bursts: one at t=500ms (probe just installed, we are
     * at LIFO head, we WILL see the event), and one at t=7000ms (after
     * svcldb's 5s reinstall cycle has fired at least once, svcldb is
     * now newer than us → svcldb should see + consume BEFORE us → probe
     * should NOT see the second burst). */
    MSG msg;
    logln("Entering message loop (bursts at t=500ms and t=7000ms, exit at t=10000ms)");
    while (GetTickCount() - start < 10000) {
        DWORD el = GetTickCount() - start;
        if (!sent1 && el > 500) {
            /* Burst 1 — probe is FRESH-INSTALLED (newer than payload) */
            g_saw_target_ll = 0;   /* reset counter */
            INPUT in[6] = {0};
            for (int i = 0; i < 6; i++) in[i].type = INPUT_KEYBOARD;
            in[0].ki.wVk = VK_CONTROL;
            in[1].ki.wVk = VK_MENU;
            in[2].ki.wVk = 'G';
            in[3].ki.wVk = 'G'; in[3].ki.dwFlags = KEYEVENTF_KEYUP;
            in[4].ki.wVk = VK_MENU; in[4].ki.dwFlags = KEYEVENTF_KEYUP;
            in[5].ki.wVk = VK_CONTROL; in[5].ki.dwFlags = KEYEVENTF_KEYUP;
            UINT n = SendInput(6, in, sizeof(INPUT));
            logln("BURST 1 (probe at head): SendInput returned %u", n);
            sent1 = 1;
        }
        if (!sent2 && el > 7000) {
            /* Burst 2 — svcldb has reinstalled by now (5s cadence), so
             * svcldb should be newer than probe and see the event first. */
            saw_ll_after_reinstall = g_saw_target_ll;
            g_saw_target_ll = 0;   /* reset for burst 2 */
            INPUT in[6] = {0};
            for (int i = 0; i < 6; i++) in[i].type = INPUT_KEYBOARD;
            in[0].ki.wVk = VK_CONTROL;
            in[1].ki.wVk = VK_MENU;
            in[2].ki.wVk = 'G';
            in[3].ki.wVk = 'G'; in[3].ki.dwFlags = KEYEVENTF_KEYUP;
            in[4].ki.wVk = VK_MENU; in[4].ki.dwFlags = KEYEVENTF_KEYUP;
            in[5].ki.wVk = VK_CONTROL; in[5].ki.dwFlags = KEYEVENTF_KEYUP;
            UINT n = SendInput(6, in, sizeof(INPUT));
            logln("BURST 2 (after svcldb reinstall — svcldb should be at head): SendInput returned %u", n);
            sent2 = 1;
        }
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_HOTKEY) {
                InterlockedIncrement(&g_saw_target_wmhotkey);
                logln("WM_HOTKEY: id=%lu  ==> LEAK: RegisterHotKey delivered despite svcldb consume",
                      (unsigned long)msg.wParam);
            } else if (msg.message == WM_QUIT) {
                goto done;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
done:
    UnhookWindowsHookEx(g_ll);
    UnregisterHotKey(NULL, 1);

    logln("=== hotkey_probe RESULTS ===");
    logln("  BURST 1 (probe fresh, at LIFO head):");
    logln("    LL hook saw Ctrl+Alt+G:  %ld  %s",
          saw_ll_after_reinstall,
          saw_ll_after_reinstall ? "(expected — probe was newer than svcldb)"
                                 : "(surprising — svcldb somehow blocked earlier)");
    logln("  BURST 2 (after svcldb 5s reinstall — svcldb should be at head):");
    logln("    LL hook saw Ctrl+Alt+G:  %ld  %s",
          g_saw_target_ll,
          g_saw_target_ll ? "(LEAK — svcldb reinstall failed to restore head position)"
                          : "(BLOCKED — svcldb consumed before probe)");
    logln("  ---");
    logln("  WM_HOTKEY fired total:   %ld  %s",
          g_saw_target_wmhotkey,
          g_saw_target_wmhotkey ? "(LEAK — RegisterHotKey NOT blocked by LL consume)"
                                : "(BLOCKED — RegisterHotKey suppressed by LL consume)");
    logln("  GetAsyncKeyState saw:    %ld  %s",
          g_saw_target_asyncks,
          g_saw_target_asyncks ? "(expected — HARDWARE-STATE bypass; ALL usermode "
                                 "apps that poll GetAsyncKeyState will see this; "
                                 "requires kernel driver to block; LDB doesn't "
                                 "poll for hotkeys, but proctor could add)"
                               : "(not observed — surprising)");

    if (g_log) fclose(g_log);
    return 0;
}
