/* ================================================================== *
 * keylogger_probe.c — verification harness for svcldb hotkey stealth.  *
 *                                                                    *
 * Runs THREE parallel key-observation techniques in a single process *
 * — exactly what a hostile keylogger would combine:                  *
 *                                                                    *
 *   1. WH_KEYBOARD_LL       (SetWindowsHookExW)                      *
 *   2. GetAsyncKeyState polling @ ~250 Hz  (win32k gafAsyncKeyState) *
 *   3. RegisterRawInputDevices + WM_INPUT  (RIDEV_INPUTSINK)         *
 *                                                                    *
 * Logs every observed press of the classic svcldb hotkey combos      *
 * (Ctrl+Alt+G / T / X / N / A / etc.) with source-of-observation.    *
 * Also prints a header showing which combos are being watched.       *
 *                                                                    *
 * Ground truth:                                                      *
 *   - If svcldb LL hook is at the head of the chain and consumes DOWN*
 *     / UP / auto-repeat correctly, the WH_KEYBOARD_LL column below  *
 *     should be EMPTY for every consumed hotkey.                     *
 *   - GetAsyncKeyState reads a kernel structure that is updated      *
 *     BEFORE any LL hook fires (documented; see write-up). It should *
 *     still see the key transition, exposing that LL-hook consumption*
 *     is NOT a full defense against determined keyloggers.           *
 *   - Raw Input / WM_INPUT is delivered from an independent pipeline *
 *     that does not respect LL-hook consumption. Should see events   *
 *     independently.                                                 *
 *                                                                    *
 * Build:                                                             *
 *   cl /nologo /W3 /O2 keylogger_probe.c user32.lib                  *
 *                                                                    *
 * Run:                                                               *
 *   .\keylogger_probe.exe                     (baseline / probe only)*
 *   [inject svcldb payload]                                          *
 *   .\keylogger_probe.exe                     (with payload injected)*
 *                                                                    *
 * Exit with Ctrl+C (from the probe's console — svcldb doesn't hook   *
 * that combo).                                                       *
 * ================================================================== */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------- */
/*   Hotkey table — mirrors svcldb defaults from launcher/main.c.   */
/* ---------------------------------------------------------------- */
typedef struct {
    const char *label;
    unsigned    mods;    /* bit 0 ctrl, 1 shift, 2 alt (same as svcldb) */
    unsigned    vk;
} probe_hk_t;
static const probe_hk_t g_probe_hks[] = {
    { "Ctrl+Shift+Space  ASK        ",  1 | 2,     VK_SPACE },
    { "Ctrl+Alt+G        TOGGLE     ",  1 | 4,     'G'      },
    { "Ctrl+Alt+T        TYPING     ",  1 | 4,     'T'      },
    { "Ctrl+Alt+C        COPY_REPLY ",  1 | 4,     'C'      },
    { "Ctrl+Alt+X        CLEAR/QUIT ",  1 | 4,     'X'      },
    { "Ctrl+Alt+N        NEW_CHAT   ",  1 | 4,     'N'      },
    { "Ctrl+Alt+A        COPY_ANSWR ",  1 | 4,     'A'      },
    { "Ctrl+Alt+M        CYCLE_TIER ",  1 | 4,     'M'      },
    { "Ctrl+Alt+S        STOP_GEN   ",  1 | 4,     'S'      },
    { "Ctrl+Shift+Alt+K  KILL_ALL   ",  1 | 2 | 4, 'K'      },
    { "Ctrl+Shift+Alt+L  LATEX      ",  1 | 2 | 4, 'L'      },
    { "Ctrl+Shift+Alt+D  DIRECT     ",  1 | 2 | 4, 'D'      },
    { "Ctrl+Alt+J        SCROLL_DN  ",  1 | 4,     'J'      },
    { "Ctrl+Alt+K        SCROLL_UP  ",  1 | 4,     'K'      },
    { "Ctrl+Alt+Left     NUDGE_LEFT ",  1 | 4,     VK_LEFT  },
    { "Ctrl+Alt+Right    NUDGE_RGHT ",  1 | 4,     VK_RIGHT },
    { "Ctrl+Alt+Up       NUDGE_UP   ",  1 | 4,     VK_UP    },
    { "Ctrl+Alt+Down     NUDGE_DOWN ",  1 | 4,     VK_DOWN  },
};
#define NUM_HKS ((int)(sizeof(g_probe_hks) / sizeof(g_probe_hks[0])))

/* Counters — one column per observation channel. */
static volatile LONG g_ll_seen[NUM_HKS];
static volatile LONG g_poll_seen[NUM_HKS];
static volatile LONG g_wminput_seen[NUM_HKS];
/* Raw counts of ANY observed key event on each channel (used to
 * distinguish "channel is completely silent" vs "channel is active
 * but this specific combo wasn't matched"). */
static volatile LONG g_ll_total_events = 0;
static volatile LONG g_ll_total_downs  = 0;
static volatile LONG g_ri_total_events = 0;

/* Timestamped console log — nicer than printf races. */
static CRITICAL_SECTION g_log_cs;
static void plog(const char *fmt, ...) {
    SYSTEMTIME t; GetSystemTime(&t);
    EnterCriticalSection(&g_log_cs);
    printf("[%02u:%02u:%02u.%03u] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
    LeaveCriticalSection(&g_log_cs);
}

/* Try to match against a hotkey slot given current key + mod state. */
static int match_slot(unsigned vk, int ctrl, int shift, int alt) {
    for (int i = 0; i < NUM_HKS; i++) {
        const probe_hk_t *h = &g_probe_hks[i];
        if (h->vk != vk) continue;
        int want_ctrl  = (h->mods & 1) != 0;
        int want_shift = (h->mods & 2) != 0;
        int want_alt   = (h->mods & 4) != 0;
        if (want_ctrl == ctrl && want_shift == shift && want_alt == alt)
            return i;
    }
    return -1;
}

/* ---------------------------------------------------------------- */
/*   Channel 1 — WH_KEYBOARD_LL                                     */
/* ---------------------------------------------------------------- */
static HHOOK g_ll = NULL;
static LRESULT CALLBACK ll_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        int is_down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        InterlockedIncrement(&g_ll_total_events);
        if (is_down) {
            InterlockedIncrement(&g_ll_total_downs);
            int ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            int shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
            int alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
            int slot  = match_slot(k->vkCode, ctrl, shift, alt);
            if (slot >= 0) {
                InterlockedIncrement(&g_ll_seen[slot]);
                plog("  LL   seen: [%s]  vk=0x%02X  (ll can keylog: YES)",
                     g_probe_hks[slot].label, (unsigned)k->vkCode);
            }
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static DWORD WINAPI ll_thread_proc(LPVOID p) {
    (void)p;
    g_ll = SetWindowsHookExW(WH_KEYBOARD_LL, ll_proc,
                             GetModuleHandleW(NULL), 0);
    if (!g_ll) {
        plog("  LL   install FAILED err=%lu — channel disabled", GetLastError());
        return 1;
    }
    plog("  LL   hook installed (channel active)");
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    UnhookWindowsHookEx(g_ll);
    return 0;
}

/* ---------------------------------------------------------------- */
/*   Channel 2 — GetAsyncKeyState polling                           */
/* ---------------------------------------------------------------- */
static volatile LONG g_poll_running = 1;
static DWORD WINAPI poll_thread_proc(LPVOID p) {
    (void)p;
    int prev_down[NUM_HKS] = {0};
    plog("  POLL thread up (250 Hz gafAsyncKeyState sampling)");
    while (g_poll_running) {
        int ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        int shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
        int alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
        for (int i = 0; i < NUM_HKS; i++) {
            int key_down = (GetAsyncKeyState(g_probe_hks[i].vk) & 0x8000) != 0;
            int want_ctrl  = (g_probe_hks[i].mods & 1) != 0;
            int want_shift = (g_probe_hks[i].mods & 2) != 0;
            int want_alt   = (g_probe_hks[i].mods & 4) != 0;
            int match = key_down
                && (want_ctrl  == ctrl)
                && (want_shift == shift)
                && (want_alt   == alt);
            if (match && !prev_down[i]) {
                InterlockedIncrement(&g_poll_seen[i]);
                plog("  POLL seen: [%s]  vk=0x%02X  (async-poll can keylog: YES)",
                     g_probe_hks[i].label, g_probe_hks[i].vk);
            }
            prev_down[i] = match;
        }
        Sleep(4);   /* ~250 Hz */
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/*   Channel 3 — Raw Input WM_INPUT (RIDEV_INPUTSINK)               */
/* ---------------------------------------------------------------- */
static LRESULT CALLBACK ri_wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_INPUT) {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)l, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        if (sz > 0 && sz <= 128) {
            BYTE buf[128];
            if (GetRawInputData((HRAWINPUT)l, RID_INPUT, buf, &sz,
                                sizeof(RAWINPUTHEADER)) == sz) {
                RAWINPUT *ri = (RAWINPUT *)buf;
                if (ri->header.dwType == RIM_TYPEKEYBOARD &&
                    (ri->data.keyboard.Flags & RI_KEY_BREAK) == 0) {
                    USHORT vk = ri->data.keyboard.VKey;
                    InterlockedIncrement(&g_ri_total_events);
                    int ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                    int shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
                    int alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
                    int slot  = match_slot(vk, ctrl, shift, alt);
                    if (slot >= 0) {
                        InterlockedIncrement(&g_wminput_seen[slot]);
                        plog("  RI   seen: [%s]  vk=0x%02X  (raw-input can keylog: YES)",
                             g_probe_hks[slot].label, vk);
                    }
                }
            }
        }
        return DefWindowProcW(h, msg, w, l);
    }
    return DefWindowProcW(h, msg, w, l);
}

static DWORD WINAPI ri_thread_proc(LPVOID p) {
    (void)p;
    HINSTANCE hi = GetModuleHandleW(NULL);
    WNDCLASSEXW wc = { sizeof(wc), 0, ri_wnd_proc, 0, 0, hi,
                       NULL, NULL, NULL, NULL,
                       L"KeyloggerProbeSink", NULL };
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        plog("  RI   RegisterClassExW FAILED err=%lu", GetLastError());
        return 1;
    }
    HWND w = CreateWindowExW(0, L"KeyloggerProbeSink", L"probe", 0,
                             0, 0, 0, 0, HWND_MESSAGE, NULL, hi, NULL);
    if (!w) {
        plog("  RI   CreateWindowExW FAILED err=%lu", GetLastError());
        return 2;
    }
    RAWINPUTDEVICE rid = { 0x01, 0x06, RIDEV_INPUTSINK, w };
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        plog("  RI   RegisterRawInputDevices FAILED err=%lu", GetLastError());
    } else {
        plog("  RI   raw-input sink registered (channel active)");
    }
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/*   main                                                            */
/* ---------------------------------------------------------------- */
static BOOL WINAPI ctrl_c(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\n\n=== Summary ===\n");
        printf("  %-32s  %5s  %5s  %5s\n", "hotkey", "LL", "POLL", "RI");
        int any_ll = 0, any_poll = 0, any_ri = 0;
        for (int i = 0; i < NUM_HKS; i++) {
            printf("  %-32s  %5ld  %5ld  %5ld\n",
                   g_probe_hks[i].label,
                   g_ll_seen[i], g_poll_seen[i], g_wminput_seen[i]);
            if (g_ll_seen[i])      any_ll   = 1;
            if (g_poll_seen[i])    any_poll = 1;
            if (g_wminput_seen[i]) any_ri   = 1;
        }
        printf("\n  LL   total events observed: %ld  (downs: %ld)\n",
               g_ll_total_events, g_ll_total_downs);
        printf("\n=== Verdict ===\n");
        printf("  LL   channel captured hotkey combos: %s\n",
               any_ll ? "YES (svcldb NOT consuming for this channel)" : "NO  (svcldb consumed on LL chain)");
        printf("  POLL channel captured hotkey combos: %s\n",
               any_poll ? "YES (svcldb CANNOT stop polling keyloggers)" : "NO  (unusual — probably no test presses)");
        printf("  RI   channel captured hotkey combos: %s\n",
               any_ri ? "YES (svcldb CANNOT stop raw-input keyloggers)" : "NO  (unusual — probably no test presses)");
        InterlockedExchange(&g_poll_running, 0);
        Sleep(200);
        ExitProcess(0);
    }
    return FALSE;
}

/* Every second, print total raw event counts on each channel so we
 * can distinguish "the LL hook chain is completely silent for us"
 * (svcldb prevented delivery) from "LL sees traffic but no combo
 * matched" (letter-only test). Runs until g_poll_running == 0. */
static DWORD WINAPI beacon_thread_proc(LPVOID p) {
    (void)p;
    LONG last_ll = 0, last_ri = 0;
    while (g_poll_running) {
        Sleep(1000);
        LONG ll = g_ll_total_events;
        LONG ri = g_ri_total_events;
        LONG dll = ll - last_ll;
        LONG dri = ri - last_ri;
        plog("  BEACON  LL_events=%ld (+%ld/s)  RI_events=%ld (+%ld/s)",
             ll, dll, ri, dri);
        last_ll = ll;
        last_ri = ri;
    }
    return 0;
}

int main(void) {
    InitializeCriticalSection(&g_log_cs);
    SetConsoleCtrlHandler(ctrl_c, TRUE);

    printf("=========================================================\n");
    printf(" svcldb hotkey stealth verifier\n");
    printf("=========================================================\n");
    printf(" Watching %d hotkey combos on THREE parallel channels:\n\n", NUM_HKS);
    for (int i = 0; i < NUM_HKS; i++) {
        printf("   %s  (vk=0x%02X)\n",
               g_probe_hks[i].label, g_probe_hks[i].vk);
    }
    printf("\n Instructions:\n");
    printf("   1. Press each combo a few times.\n");
    printf("   2. Watch which channel(s) log the event.\n");
    printf("   3. Ctrl+C in THIS console to see the summary.\n\n");
    printf(" Interpreting output:\n");
    printf("   [LL   seen: ...]  -> WH_KEYBOARD_LL chain caught it\n");
    printf("                       -> a real keylogger using WH_KEYBOARD_LL would too\n");
    printf("   [POLL seen: ...]  -> GetAsyncKeyState/gafAsyncKeyState caught it\n");
    printf("                       -> a polling keylogger would too\n");
    printf("   [RI   seen: ...]  -> WM_INPUT / raw input caught it\n");
    printf("                       -> a raw-input keylogger would too\n\n");
    printf("---------------------------------------------------------\n");

    HANDLE h1 = CreateThread(NULL, 0, ll_thread_proc,     NULL, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, poll_thread_proc,   NULL, 0, NULL);
    HANDLE h3 = CreateThread(NULL, 0, ri_thread_proc,     NULL, 0, NULL);
    HANDLE h4 = CreateThread(NULL, 0, beacon_thread_proc, NULL, 0, NULL);
    (void)h1; (void)h2; (void)h3; (void)h4;

    /* Idle in main — worker threads carry the observation load. */
    while (g_poll_running) Sleep(1000);
    return 0;
}
