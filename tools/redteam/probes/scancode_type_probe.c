/* ==========================================================================
 * scancode_type_probe.c -- proves the auto-typer's VK_PACKET exposure and
 * that a scancode rewrite evades a Bluebook-style LL-hook detector.
 *
 * Bluebook's WH_KEYBOARD_LL denylist includes VK_PACKET (0xE7) -- the vkCode
 * Windows synthesizes for KEYEVENTF_UNICODE injection (what inj_char does
 * today). This probe installs the SAME kind of non-consuming LL keyboard hook
 * a proctor uses, then auto-types a test string via one of two methods and
 * reports exactly what the hook observed:
 *
 *   -unicode  (default) : KEYEVENTF_UNICODE  -> hook sees VK_PACKET  (BUSTED)
 *   -scancode           : VkKeyScan+scancode -> hook sees real VKs   (CLEAN)
 *
 * The -scancode path here is byte-for-byte the logic that goes into inj_char.
 * "injected" column = LLKHF_INJECTED bit (0x10) -- note it is set for BOTH
 * methods; a proctor that checks that flag broadly is the kernel-driver
 * ceiling. What this probe proves is only the VK_PACKET-specific evasion,
 * which is what Bluebook (per RE) actually checks.
 *
 * Build: cl /nologo scancode_type_probe.c /link user32.lib
 * Run:   scancode_type_probe.exe [-scancode|-unicode]
 * ========================================================================== */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef LLKHF_INJECTED
#define LLKHF_INJECTED 0x00000010
#endif

static volatile LONG g_total_down = 0;
static volatile LONG g_vk_packet  = 0;
static volatile LONG g_real_vk    = 0;
static volatile LONG g_injected   = 0;

static LRESULT CALLBACK ll_watch(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        InterlockedIncrement(&g_total_down);
        if (k->flags & LLKHF_INJECTED) InterlockedIncrement(&g_injected);
        if (k->vkCode == VK_PACKET) {
            InterlockedIncrement(&g_vk_packet);
            printf("  hook saw: VK_PACKET (0x%02X) scan=0x%02X injected=%d  <- BUSTED\n",
                   (unsigned)k->vkCode, (unsigned)k->scanCode,
                   (k->flags & LLKHF_INJECTED) ? 1 : 0);
        } else {
            InterlockedIncrement(&g_real_vk);
            printf("  hook saw: real VK 0x%02X scan=0x%02X injected=%d\n",
                   (unsigned)k->vkCode, (unsigned)k->scanCode,
                   (k->flags & LLKHF_INJECTED) ? 1 : 0);
        }
        fflush(stdout);
    }
    return CallNextHookEx(NULL, code, wp, lp);   /* non-consuming watcher */
}

/* ── UNICODE path (== current inj_char) ─────────────────────────── */
static void emit_unicode(WCHAR ch) {
    INPUT in[2];
    ZeroMemory(in, sizeof(in));
    in[0].type = INPUT_KEYBOARD; in[0].ki.wScan = ch; in[0].ki.dwFlags = KEYEVENTF_UNICODE;
    in[1].type = INPUT_KEYBOARD; in[1].ki.wScan = ch; in[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}

/* ── SCANCODE path (== proposed inj_char). Returns 1 if emitted via
 *    scancode, 0 if the char isn't cleanly mappable (caller falls back
 *    to unicode). Handles the plain + Shift cases only; AltGr/Ctrl or
 *    unmapped chars return 0. ─────────────────────────────────────── */
static int emit_scancode(WCHAR ch) {
    SHORT s = VkKeyScanW(ch);
    if (s == -1) return 0;                     /* no single-key mapping */
    BYTE vk = LOBYTE(s);
    BYTE shift_state = HIBYTE(s);
    if (shift_state & 6) return 0;             /* needs Ctrl/Alt(AltGr) -> fall back */
    WORD scan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    if (scan == 0) return 0;                   /* no scancode -> fall back */
    int need_shift = (shift_state & 1) != 0;
    WORD shift_scan = (WORD)MapVirtualKeyW(VK_SHIFT, MAPVK_VK_TO_VSC);
    INPUT in[4]; int n = 0;
    if (need_shift) {
        ZeroMemory(&in[n], sizeof(INPUT)); in[n].type = INPUT_KEYBOARD;
        in[n].ki.wScan = shift_scan; in[n].ki.dwFlags = KEYEVENTF_SCANCODE; n++;
    }
    ZeroMemory(&in[n], sizeof(INPUT)); in[n].type = INPUT_KEYBOARD;
    in[n].ki.wScan = scan; in[n].ki.dwFlags = KEYEVENTF_SCANCODE; n++;
    ZeroMemory(&in[n], sizeof(INPUT)); in[n].type = INPUT_KEYBOARD;
    in[n].ki.wScan = scan; in[n].ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP; n++;
    if (need_shift) {
        ZeroMemory(&in[n], sizeof(INPUT)); in[n].type = INPUT_KEYBOARD;
        in[n].ki.wScan = shift_scan; in[n].ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP; n++;
    }
    SendInput(n, in, sizeof(INPUT));
    return 1;
}

int main(int argc, char **argv) {
    int scancode = 0;
    int watch_sec = 0;   /* -watch N : observe the PAYLOAD's typing, no self-type */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-scancode")) scancode = 1;
        else if (!strcmp(argv[i], "-unicode")) scancode = 0;
        else if (!strcmp(argv[i], "-watch") && i + 1 < argc) watch_sec = atoi(argv[++i]);
    }

    if (watch_sec > 0) {
        printf("=== scancode_type_probe (WATCH mode) ===\n");
        printf("Bluebook-style LL keyboard watcher for %ds. Trigger the svcldb\n", watch_sec);
        printf("autotyper now (copy text, focus Notepad, press the autotype hotkey).\n\n");
        HHOOK hw = SetWindowsHookExW(WH_KEYBOARD_LL, ll_watch, GetModuleHandleW(NULL), 0);
        if (!hw) { printf("hook install failed %lu\n", GetLastError()); return 1; }
        DWORD deadline = GetTickCount() + (DWORD)watch_sec * 1000;
        MSG m;
        while (GetTickCount() < deadline) {
            while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {}
            Sleep(5);
        }
        UnhookWindowsHookEx(hw);
        printf("\n=== RESULT (watched svcldb autotyper) ===\n");
        printf("  total key-downs observed : %ld\n", g_total_down);
        printf("  VK_PACKET (Bluebook trip): %ld\n", g_vk_packet);
        printf("  real VK codes            : %ld\n", g_real_vk);
        printf("  LLKHF_INJECTED flagged   : %ld\n", g_injected);
        printf("  ---------------------------------\n");
        printf("  VERDICT: %s\n", g_vk_packet == 0
            ? "CLEAN -- svcldb autotyper emitted no VK_PACKET; Bluebook would not trip."
            : "BUSTED -- svcldb autotyper emitted VK_PACKET; Bluebook would flag it.");
        return 0;
    }
    const WCHAR *test = L"The quick Brown Fox 42!";   /* mixed case + digit + punct */
    int fell_back = 0;

    printf("=== scancode_type_probe ===\n");
    printf("Method: %s | Test string: \"The quick Brown Fox 42!\"\n\n",
           scancode ? "SCANCODE (proposed inj_char)" : "UNICODE (current inj_char)");

    HHOOK h = SetWindowsHookExW(WH_KEYBOARD_LL, ll_watch, GetModuleHandleW(NULL), 0);
    if (!h) { printf("hook install failed %lu\n", GetLastError()); return 1; }
    Sleep(300);

    for (const WCHAR *p = test; *p; ++p) {
        if (scancode) {
            if (!emit_scancode(*p)) { fell_back++; emit_unicode(*p); }
        } else {
            emit_unicode(*p);
        }
        Sleep(12);
        MSG m; while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {}
    }
    Sleep(300);
    { MSG m; while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {} }
    UnhookWindowsHookEx(h);

    printf("\n=== RESULT ===\n");
    printf("  total key-downs observed : %ld\n", g_total_down);
    printf("  VK_PACKET (Bluebook trip): %ld\n", g_vk_packet);
    printf("  real VK codes            : %ld\n", g_real_vk);
    printf("  LLKHF_INJECTED flagged   : %ld\n", g_injected);
    if (scancode) printf("  scancode->unicode fallbacks: %d\n", fell_back);
    printf("  ---------------------------------\n");
    printf("  VERDICT: %s\n", g_vk_packet == 0
        ? "CLEAN -- no VK_PACKET; Bluebook's denylist would not trip."
        : "BUSTED -- VK_PACKET emitted; Bluebook would flag the auto-typer.");
    return 0;
}
