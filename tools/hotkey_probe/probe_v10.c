/* ================================================================== *
 * probe_v10.c — Test suite for svcldb's v10 hotkey binding modes.
 *
 * Runs 6 tests against a currently-loaded payload:
 *   1. Old MODIFIER combo (Ctrl+Alt+X = CLEAR) — should fire + consume
 *   2. MULTITAP consume  (triple backtick = ASK) — should fire + no backticks reach probe
 *   3. MULTITAP consume  (triple backslash = TYPING) — fire + no leak
 *   4. MULTITAP watch-only (triple 'c' = COPY_REPLY) — fire AND c's pass to probe
 *   5. MULTITAP watch-only (triple 'a' = COPY_ANSWER) — fire + a's pass through
 *   6. LONGPRESS (hold RSHIFT 800ms = TOGGLE) — fires after threshold
 *
 * Between tests: 1s pause. Total ~15s.
 *
 * The probe installs its OWN LL hook AFTER payload's periodic reinstall
 * cycle (~1s cadence in v1.6.5) — so probe is not always at LIFO head.
 * For each test we wait 1.2s AFTER the previous action so payload's
 * reinstall runs and svcldb is back at head. That way "consume" tests
 * measure whether we actually block downstream.
 *
 * Output: probe_v10_log.txt in current dir.
 * ================================================================== */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "user32.lib")

static FILE *g_log = NULL;
static HHOOK g_ll = NULL;

/* Per-VK observation counters — probe increments for each DOWN it sees. */
static volatile LONG g_saw[256] = {0};

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
    DWORD vkCode; DWORD scanCode; DWORD flags; DWORD time; ULONG_PTR dwExtraInfo;
} KBDLL;

static LRESULT CALLBACK ll_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLL *k = (KBDLL *)lp;
        int is_down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        if (is_down && k->vkCode < 256) {
            InterlockedIncrement(&g_saw[k->vkCode]);
        }
    }
    /* Politeness: forward downstream (svcldb should consume its target keys). */
    return CallNextHookEx(g_ll, code, wp, lp);
}

/* Send a single key press-release. */
static void send_key(WORD vk, DWORD flags_down, DWORD flags_up) {
    INPUT in[2] = {0};
    in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = vk; in[0].ki.dwFlags = flags_down;
    in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = vk; in[1].ki.dwFlags = KEYEVENTF_KEYUP | flags_up;
    SendInput(2, in, sizeof(INPUT));
}

/* Send N taps of a VK in quick succession (targets multitap detection). */
static void send_multitap(WORD vk, int count, int gap_ms) {
    for (int i = 0; i < count; i++) {
        send_key(vk, 0, 0);
        if (i < count - 1) Sleep(gap_ms);
    }
}

/* Send a modifier combo (Ctrl+Alt+X style). */
static void send_combo(WORD mod1, WORD mod2, WORD vk) {
    INPUT in[6] = {0};
    for (int i = 0; i < 6; i++) in[i].type = INPUT_KEYBOARD;
    in[0].ki.wVk = mod1;
    in[1].ki.wVk = mod2;
    in[2].ki.wVk = vk;
    in[3].ki.wVk = vk;   in[3].ki.dwFlags = KEYEVENTF_KEYUP;
    in[4].ki.wVk = mod2; in[4].ki.dwFlags = KEYEVENTF_KEYUP;
    in[5].ki.wVk = mod1; in[5].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(6, in, sizeof(INPUT));
}

/* Send a HOLD of vk for hold_ms — DOWN, sleep, UP. */
static void send_longpress(WORD vk, int hold_ms) {
    INPUT down = {0}; down.type = INPUT_KEYBOARD; down.ki.wVk = vk;
    SendInput(1, &down, sizeof(INPUT));
    Sleep(hold_ms);
    INPUT up = {0}; up.type = INPUT_KEYBOARD; up.ki.wVk = vk; up.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &up, sizeof(INPUT));
}

int main(void) {
    g_log = fopen("probe_v10_log.txt", "w");
    logln("=== probe_v10 start ===");
    logln("pid=%lu — testing svcldb v10 binding modes", (unsigned long)GetCurrentProcessId());

    g_ll = SetWindowsHookExW(WH_KEYBOARD_LL, ll_proc, GetModuleHandleW(NULL), 0);
    if (!g_ll) { logln("SetWindowsHookExW FAILED %lu", GetLastError()); return 1; }
    logln("LL hook installed — will observe all key DOWNs");

    /* CRITICAL: wait long enough for svcldb's 1s-cadence reinstall
     * thread to fire. After that svcldb is NEWER (at LIFO head) than
     * our probe hook. Only then do "consume" tests measure whether
     * downstream apps are truly blocked. Without this wait, probe is
     * newer and observes everything before svcldb can consume. */
    logln("Waiting 2s for svcldb reinstall_thread to re-hook (=> svcldb at head) ...");
    /* Pump messages during wait so probe hook still handles kernel dispatch. */
    DWORD start = GetTickCount();
    MSG msg;
    while (GetTickCount() - start < 2000) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&msg);
        Sleep(10);
    }

    /* =========== TEST 1: MODIFIER Ctrl+Alt+Q (CYCLE_CORNER — benign) ===
     * DO NOT use Ctrl+Alt+X (CLEAR) — on home view CLEAR = QUIT, which
     * unloads the payload and kills subsequent tests. Ctrl+Alt+Q just
     * cycles overlay corner: fires + consumes, non-destructive. */
    logln("\n--- TEST 1: MODIFIER Ctrl+Alt+Q (CYCLE_CORNER) ---");
    LONG before_q = g_saw['Q'];
    logln("Sending Ctrl+Alt+Q ...");
    send_combo(VK_CONTROL, VK_MENU, 'Q');
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_q = g_saw['Q'];
    logln("Probe saw 'Q' DOWN before=%ld after=%ld (delta=%ld)",
          before_q, after_q, after_q - before_q);
    logln("Expected: delta=0 (svcldb should consume, we shouldn't see)");
    logln("Result: %s", (after_q - before_q == 0) ? "PASS" : "FAIL");

    /* =========== TEST 2: MULTITAP CONSUME (triple backtick = ASK) =========== */
    logln("\n--- TEST 2: MULTITAP CONSUME triple `` (ASK) ---");
    LONG before_bt = g_saw[0xC0];
    logln("Sending 3 backticks within 200ms gaps ...");
    send_multitap(0xC0, 3, 100);
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_bt = g_saw[0xC0];
    logln("Probe saw '`' DOWN before=%ld after=%ld (delta=%ld)",
          before_bt, after_bt, after_bt - before_bt);
    logln("Expected: delta=0 for consume mode (svcldb consumes ALL 3 taps)");
    logln("Result: %s", (after_bt - before_bt == 0) ? "PASS" : "FAIL");

    /* =========== TEST 3: NEGATIVE — 2 backticks in <400ms should NOT fire =========== */
    logln("\n--- TEST 3: NEGATIVE 2 backticks (below multitap count=3) ---");
    LONG before_bs = g_saw[0xC0];
    /* Send only 2 taps — pattern count is 3, so should NOT match. */
    send_key(0xC0, 0, 0); Sleep(100);
    send_key(0xC0, 0, 0);
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_bs = g_saw[0xC0];
    logln("Probe saw 2 backticks delta=%ld (both consumed by has_consume reservation)",
          after_bs - before_bs);
    logln("Expected: delta=0 (has_consume reserves the vk, all backticks eaten)");
    logln("Result: %s", (after_bs - before_bs == 0) ? "PASS" : "FAIL");

    /* =========== TEST 4: MULTITAP WATCH-ONLY (triple 'c' = COPY_REPLY) =========== */
    logln("\n--- TEST 4: MULTITAP WATCH-ONLY triple 'c' (COPY_REPLY) ---");
    LONG before_c = g_saw['C'];
    logln("Sending 3 'c' within 200ms gaps ...");
    send_multitap('C', 3, 100);
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_c = g_saw['C'];
    logln("Probe saw 'c' DOWN delta=%ld", after_c - before_c);
    logln("Expected: delta=3 (WATCH-ONLY — all 3 c's pass through)");
    logln("Result: %s", (after_c - before_c == 3) ? "PASS" : "FAIL");

    /* =========== TEST 5: MULTITAP WATCH-ONLY (triple 'a' = COPY_ANSWER) =========== */
    logln("\n--- TEST 5: MULTITAP WATCH-ONLY triple 'a' (COPY_ANSWER) ---");
    LONG before_a = g_saw['A'];
    send_multitap('A', 3, 100);
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_a = g_saw['A'];
    logln("Probe saw 'a' DOWN delta=%ld — expected 3", after_a - before_a);
    logln("Result: %s", (after_a - before_a == 3) ? "PASS" : "FAIL");

    /* =========== TEST 6: LONGPRESS (hold RSHIFT 800ms = TOGGLE) =========== */
    logln("\n--- TEST 6: LONGPRESS hold RSHIFT 800ms (TOGGLE) ---");
    LONG before_rshift = g_saw[VK_RSHIFT];
    logln("Sending RSHIFT DOWN, holding 800ms, then UP ...");
    send_longpress(VK_RSHIFT, 800);
    { DWORD s = GetTickCount(); MSG m;
      while (GetTickCount() - s < 1500) {
          while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
          Sleep(5);
      } }
    LONG after_rshift = g_saw[VK_RSHIFT];
    logln("Probe saw RSHIFT DOWN delta=%ld", after_rshift - before_rshift);
    logln("Expected: delta>=1 (LONGPRESS is pass-through; user's initial press reaches downstream)");
    logln("Result: %s (checking payload log for POLL LONGPRESS fired next)",
          (after_rshift - before_rshift >= 1) ? "LIKELY-PASS" : "FAIL");

    UnhookWindowsHookEx(g_ll);
    logln("\n=== probe_v10 done — check payload.log for slot fires ===");
    if (g_log) fclose(g_log);
    return 0;
}
