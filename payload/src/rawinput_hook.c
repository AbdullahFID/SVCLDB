/* ================================================================== *
 * rawinput_hook.c — Global hotkey delivery from inside dwm.exe.       *
 *                                                                    *
 * Two parallel delivery paths (whichever fires first wins; per-hotkey*
 * 250 ms debounce prevents duplicates):                              *
 *                                                                    *
 *   1. WM_INPUT via RIDEV_INPUTSINK on a HWND_MESSAGE window with a  *
 *      plausibly-legitimate class name (MSDiagEventSink). Not always *
 *      delivered when DWM's window station is restricted (some Win11 *
 *      builds and PPL contexts drop these). Kept as best-effort.     *
 *                                                                    *
 *   2. GetAsyncKeyState polling @ 60 Hz. Reads kernel-global key     *
 *      state (win32k!gafAsyncKeyState) which is NOT session-gated,   *
 *      NOT desktop-gated, NOT process-protection-gated. Confirmed    *
 *      working from DWM 2026-07-05. This is the reliable path.      *
 *                                                                    *
 * Hotkey table is svc_config_t::hotkeys[SVC_HK_COUNT] — one packed   *
 * (mod<<16)|vk per slot. Slot index equals svc_hotkey_action_t enum  *
 * (0=ASK, 1=TOGGLE, ..., 18=RESET). Zero slots ignored.              *
 * ================================================================== */

#include "../../shared/common.h"
#include "../../shared/config_types.h"
#include "rawinput_hook.h"

#include <stdio.h>
#include <stdarg.h>

/* ── Constants (avoid pulling in whole winuser structs) ─────────── */
#define WORKER_CLASS_NAME  L"MSDiagEventSink"
#define RIDEV_INPUTSINK    0x00000100
#define RIDEV_REMOVE       0x00000001
#define RID_INPUT          0x10000003
#define RIM_TYPEKEYBOARD   1
#define RI_KEY_BREAK       1

typedef struct {
    ULONG dwSize;
    UINT  style;
    WNDPROC lpfnWndProc;
    int   cbClsExtra;
    int   cbWndExtra;
    HINSTANCE hInstance;
    HICON  hIcon;
    HCURSOR hCursor;
    HBRUSH  hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
    HICON  hIconSm;
} RIN_WNDCLASSEX;

typedef struct { USHORT UsagePage; USHORT Usage; DWORD Flags; HWND hwndTarget; } RIN_RAWINPUTDEVICE;

typedef struct {
    DWORD dwType;
    DWORD dwSize;
    HANDLE hDevice;
    WPARAM wParam;
    /* + RAWKEYBOARD */
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    USHORT VKey;
    UINT   Message;
    ULONG  ExtraInformation;
} RIN_RAWINPUT_KEYBOARD;

/* ── State ──────────────────────────────────────────────────────── */
static HANDLE      g_wm_thread   = NULL;
static HANDLE      g_poll_thread = NULL;
static HANDLE      g_ll_thread   = NULL;
static volatile LONG g_poll_running = 0;
static DWORD       g_wm_tid      = 0;
static DWORD       g_ll_tid      = 0;
static HWND        g_wnd         = NULL;
static HHOOK       g_ll_hook     = NULL;
static hotkey_cb_t g_cb          = NULL;

/* Modifier state tracked via LL hook events — REQUIRED because
 * GetAsyncKeyState(VK_CONTROL) from DWM's process context unreliably
 * returns 0 even when Ctrl is physically held (confirmed empirically
 * 2026-07-05: `EDGE: G pressed (ctrl=0 shift=0 alt=0)` even during
 * user's Ctrl+G spam). The LL hook DOES see every keyboard transition
 * regardless of desktop/session, so we build our own modifier state
 * from those events. */
static volatile LONG g_ctrl_down  = 0;
static volatile LONG g_shift_down = 0;
static volatile LONG g_alt_down   = 0;

/* Per-action hotkey config + debounce timestamp. Sized to SVC_HK_COUNT. */
static unsigned g_hk[SVC_HK_COUNT]        = {0};
static DWORD    g_last_fire[SVC_HK_COUNT] = {0};

/* Forward decl — g_repeat_allowed defined below (near LL hook block)
 * but used by fire() which is defined above it. */
static int g_repeat_allowed[SVC_HK_COUNT];

/* Critical / high-priority hotkeys — user-facing "these ALWAYS work
 * instantly" set. Debounce is much shorter than one-shots so rapid
 * presses aren't dropped and the wake path fires each time.
 *
 * The user's mental model: Ctrl+Alt+G (toggle) and Ctrl+Alt+X (quit)
 * are the "give me control back NOW" hotkeys — if they're bounced by
 * a 250ms guard the user perceives it as broken. KILL_ALL is the
 * emergency stop — same treatment. */
static int hotkey_is_critical(int slot) {
    return slot == SVC_HK_TOGGLE
        || slot == SVC_HK_CLEAR
        || slot == SVC_HK_KILL_ALL
        || slot == SVC_HK_ASK
        || slot == SVC_HK_TYPING;
}

/* KBDLLHOOKSTRUCT — declared inline to avoid dragging in extra winuser stuff. */
typedef struct {
    DWORD     vkCode;
    DWORD     scanCode;
    DWORD     flags;
    DWORD     time;
    ULONG_PTR dwExtraInfo;
} RIN_KBDLLHOOKSTRUCT;
#define RIN_WH_KEYBOARD_LL  13
#define RIN_HC_ACTION       0
#define RIN_WM_KEYDOWN      0x0100
#define RIN_WM_SYSKEYDOWN   0x0104

/* ── Local plaintext diagnostic (bypasses slog TLS-in-manual-map).
 * Everything critical also logs here so the plaintext file always tells the
 * full story even when the encrypted logger silently fails. */
/* Route rawinput diag through encrypted slog. Set DWM_EXT_TRACE=1
 * env var to also mirror to payload_early.txt for iteration. See
 * dllmain.c early_log + dwm_hooks.c hook_diag_raw for the same
 * anti-strings-scan pattern. */
static int g_rin_plaintext = -1;
static void rin_diag(const char *fmt, ...) {
    char body[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    body[sizeof(body) - 1] = 0;
    slog_writef("payload.log", "rin: %s", body);
    if (g_rin_plaintext < 0) {
#if SVCLDB_PRODUCTION_BUILD
        g_rin_plaintext = 0;
#else
        char buf[8];
        DWORD n = GetEnvironmentVariableA("DWM_EXT_TRACE",
                                          buf, sizeof(buf));
        g_rin_plaintext = (n > 0 && buf[0] != '0') ? 1 : 0;
#endif
    }
    if (g_rin_plaintext) {
        HANDLE h = CreateFileA(SVC_INSTALL_DIR "\\payload_early.txt",
                               FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        char line[600];
        SYSTEMTIME t; GetSystemTime(&t);
        int n = _snprintf(line, sizeof(line) - 1,
            "[%02d:%02d:%02d.%03d] rin: %s\r\n",
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, body);
        if (n > 0) { DWORD w = 0; WriteFile(h, line, (DWORD)n, &w, NULL); }
        CloseHandle(h);
    }
}

/* Match current key event against a specific hotkey slot's requirements. */
static int match_hk(unsigned hkcode, USHORT vk,
                    int is_ctrl, int is_shift, int is_alt) {
    unsigned target_vk  = hkcode & 0xFFFF;
    unsigned target_mod = (hkcode >> 16) & 0xFF;
    if (target_vk == 0 || vk != target_vk) return 0;
    int want_ctrl  = (target_mod & SVC_HK_MOD_CTRL)  != 0;
    int want_shift = (target_mod & SVC_HK_MOD_SHIFT) != 0;
    int want_alt   = (target_mod & SVC_HK_MOD_ALT)   != 0;
    return want_ctrl == is_ctrl && want_shift == is_shift && want_alt == is_alt;
}

/* Fire the callback for a matched hotkey slot. Returns 1 if actually fired
 * (else debounced). Debounce is per-slot at 250 ms. */
/* Per-slot debounce. Repeat-friendly slots (nudge/resize/etc) use a
 * shorter window so hold-to-repeat feels responsive (~20 fires/sec).
 * Others use 250ms so accidental double-tap doesn't fire twice. */
static int fire(int slot) {
    if (slot < 0 || slot >= SVC_HK_COUNT || !g_hk[slot] || !g_cb) return 0;
    DWORD now = GetTickCount();
    /* Priority tiers:
     *   - repeat-allowed (nudge/resize/scroll/etc): 50ms → 20Hz continuous
     *   - critical (toggle/quit/ask/chat/kill): 80ms → rapid press works
     *   - other one-shots (cycle-corner, reset, debug-cap): 250ms → no dupes
     */
    DWORD min_gap;
    if (g_repeat_allowed[slot])       min_gap = 50;
    else if (hotkey_is_critical(slot)) min_gap = 80;
    else                               min_gap = 250;
    if (now - g_last_fire[slot] <= min_gap) return 0;
    g_last_fire[slot] = now;
    g_cb(slot);
    return 1;
}

/* ── Window proc — handles both WM_HOTKEY (RegisterHotKey) and WM_INPUT ── *
 * RegisterHotKey is the reliable path. Uses win32k's per-session global
 * hotkey table (independent of thread input queue or desktop). WM_HOTKEY
 * with wParam == registered id fires whenever the combo is pressed
 * anywhere in the session — including inside a kiosk app like LDB. */
static LRESULT CALLBACK wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_HOTKEY) {
        int slot = (int)w;   /* We register with id == slot */
        if (slot >= 0 && slot < SVC_HK_COUNT) {
            if (fire(slot))
                rin_diag("WM_HOTKEY fired slot=%d", slot);
        }
        return 0;
    }
    if (msg == WM_INPUT) {
        UINT sz = 0;
        UINT hdr_size = sizeof(RIN_RAWINPUT_KEYBOARD) - sizeof(HANDLE) - sizeof(WPARAM);
        GetRawInputData((HRAWINPUT)l, RID_INPUT, NULL, &sz, hdr_size);
        if (sz > 0 && sz <= 128) {
            BYTE buf[128];
            if (GetRawInputData((HRAWINPUT)l, RID_INPUT, buf, &sz, hdr_size) == sz) {
                RIN_RAWINPUT_KEYBOARD *ri = (RIN_RAWINPUT_KEYBOARD *)buf;
                if (ri->dwType == RIM_TYPEKEYBOARD && (ri->Flags & RI_KEY_BREAK) == 0) {
                    USHORT vk = ri->VKey;
                    int is_ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                    int is_shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
                    int is_alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
                    for (int i = 0; i < SVC_HK_COUNT; i++) {
                        if (match_hk(g_hk[i], vk, is_ctrl, is_shift, is_alt)) {
                            if (fire(i))
                                rin_diag("WM_INPUT fired slot=%d vk=0x%02X", i, vk);
                            break;
                        }
                    }
                }
            }
        }
        return DefWindowProcW(h, msg, w, l);
    }
    if (msg == WM_CLOSE)   { DestroyWindow(h); return 0; }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, msg, w, l);
}

/* Convert our packed mod bits to Win32 MOD_* flags for RegisterHotKey.
 * MOD_ALT=1, MOD_CONTROL=2, MOD_SHIFT=4, MOD_NOREPEAT=0x4000. */
static UINT hk_to_win32_mod(unsigned target_mod) {
    UINT m = 0;
    if (target_mod & SVC_HK_MOD_CTRL)  m |= 2;
    if (target_mod & SVC_HK_MOD_SHIFT) m |= 4;
    if (target_mod & SVC_HK_MOD_ALT)   m |= 1;
    m |= 0x4000;   /* MOD_NOREPEAT — one fire per press, we debounce anyway */
    return m;
}

static void register_win32_hotkeys(HWND target) {
    if (!target) return;
    int ok_count = 0, fail_count = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        if (!g_hk[i]) continue;
        UINT vk  = g_hk[i] & 0xFFFF;
        UINT mod = hk_to_win32_mod((g_hk[i] >> 16) & 0xFF);
        if (RegisterHotKey(target, i /* id == slot */, mod, vk)) {
            ok_count++;
        } else {
            fail_count++;
            rin_diag("RegisterHotKey slot=%d vk=0x%02X mod=0x%X FAILED %lu",
                     i, vk, mod, GetLastError());
        }
    }
    rin_diag("RegisterHotKey summary: %d ok, %d failed", ok_count, fail_count);
}

static void unregister_win32_hotkeys(HWND target) {
    if (!target) return;
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        if (g_hk[i]) UnregisterHotKey(target, i);
    }
}

/* Attach the current thread to the user's default desktop.
 *
 * DWM runs as a special user (DWM-1 etc.) on a session-specific desktop
 * OTHER than "Default" — typically its own hidden "SI-N" desktop. Threads
 * attached there DO NOT receive interactive keyboard input via WM_INPUT
 * NOR see it via GetAsyncKeyState (which is per-desktop-input-desktop).
 *
 * The fix: open winsta0\Default (or whatever the input desktop is) and
 * SetThreadDesktop the poll/WM_INPUT thread there. Now GetAsyncKeyState
 * reads from win32k!gafAsyncKeyState which IS shared across desktops in
 * the same session, and WM_INPUT delivery via RIDEV_INPUTSINK works. */
static void attach_to_input_desktop(void) {
    /* Try OpenInputDesktop first — always the currently-active desktop.
     * DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | GENERIC_ALL are broad;
     * we don't strictly need them but they cover any handle-type use. */
    HDESK hd = OpenInputDesktop(0, TRUE, GENERIC_ALL);
    if (!hd) {
        DWORD e1 = GetLastError();
        hd = OpenDesktopA("Default", 0, TRUE, GENERIC_ALL);
        if (!hd) {
            rin_diag("desk: OpenInputDesktop=%lu OpenDesktopA(Default)=%lu — polling from DWM desk",
                     e1, GetLastError());
            return;
        }
    }
    if (SetThreadDesktop(hd)) {
        rin_diag("desk: SetThreadDesktop OK (hd=%p)", hd);
    } else {
        rin_diag("desk: SetThreadDesktop failed %lu (hd=%p)", GetLastError(), hd);
        CloseDesktop(hd);
    }
    /* Intentionally leak hd — thread lifetime == process lifetime. */
}

/* ── Poll thread (reliable delivery path) ──────────────────────── *
 * Polls every 16 ms. For each configured hotkey, tracks "was matched last
 * poll" so we edge-trigger on the down-transition. Also emits a periodic
 * health beacon so we can confirm the thread is alive and observing state
 * even when no hotkey has fired yet. */
static DWORD WINAPI poll_thread(LPVOID param) {
    (void)param;
    attach_to_input_desktop();
    rin_diag("poll_thread started; slots=%d", SVC_HK_COUNT);
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        if (g_hk[i]) {
            rin_diag("  slot[%d]=0x%X (vk=0x%02X mod=0x%X)",
                     i, g_hk[i], g_hk[i] & 0xFFFF, (g_hk[i] >> 16) & 0xFF);
        }
    }
    /* Smoke test: after 200 ms, log whether GetAsyncKeyState reports anything. */
    Sleep(200);
    SHORT a = GetAsyncKeyState('A');
    SHORT c = GetAsyncKeyState(VK_CONTROL);
    rin_diag("GetAsyncKeyState smoke: A=0x%04hX CTRL=0x%04hX", a, c);

    int prev_down[SVC_HK_COUNT] = {0};
    DWORD last_beacon = GetTickCount();
    unsigned poll_count = 0;
    unsigned any_key_events = 0;
    unsigned any_target_vk_events = 0;
    unsigned any_near_matches = 0;
    /* Extra diag: track G key specifically since user tests Ctrl+G. */
    int prev_g = 0;

    while (g_poll_running) {
        int is_ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        int is_shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
        int is_alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
        if (is_ctrl || is_shift || is_alt) any_key_events++;

        /* Track 'G' specifically. */
        int is_g = (GetAsyncKeyState('G') & 0x8000) != 0;
        if (is_g && !prev_g) {
            rin_diag("EDGE: G pressed (ctrl=%d shift=%d alt=%d)",
                     is_ctrl, is_shift, is_alt);
        }
        prev_g = is_g;

        for (int i = 0; i < SVC_HK_COUNT; i++) {
            if (!g_hk[i]) continue;
            unsigned target_vk  = g_hk[i] & 0xFFFF;
            unsigned target_mod = (g_hk[i] >> 16) & 0xFF;
            if (target_vk == 0) { prev_down[i] = 0; continue; }
            int is_key = (GetAsyncKeyState(target_vk) & 0x8000) != 0;
            if (is_key) any_target_vk_events++;
            int want_ctrl  = (target_mod & SVC_HK_MOD_CTRL)  != 0;
            int want_shift = (target_mod & SVC_HK_MOD_SHIFT) != 0;
            int want_alt   = (target_mod & SVC_HK_MOD_ALT)   != 0;
            int match = is_key
                && (want_ctrl  == is_ctrl)
                && (want_shift == is_shift)
                && (want_alt   == is_alt);
            /* Near-match: target vk down but mods wrong. Great for diag. */
            if (is_key && !match) {
                any_near_matches++;
            }
            if (match && !prev_down[i]) {
                if (fire(i))
                    rin_diag("POLL fired slot=%d vk=0x%02X mod=0x%X",
                             i, target_vk, target_mod);
            }
            prev_down[i] = match;
        }
        poll_count++;
        DWORD now = GetTickCount();
        if (now - last_beacon > 5000) {
            rin_diag("poll alive polls=%u mods=%u targetVKs=%u nearMatches=%u",
                     poll_count, any_key_events, any_target_vk_events, any_near_matches);
            last_beacon = now;
            poll_count = 0;
            any_key_events = 0;
            any_target_vk_events = 0;
            any_near_matches = 0;
        }
        Sleep(16);
    }
    rin_diag("poll_thread exit");
    return 0;
}

/* ── WM_INPUT worker thread ────────────────────────────────────── */
static DWORD WINAPI wm_worker(LPVOID param) {
    (void)param;
    attach_to_input_desktop();
    g_wm_tid = GetCurrentThreadId();

    HINSTANCE hInst = GetModuleHandleW(NULL);
    RIN_WNDCLASSEX wc = { sizeof(wc), 0, wnd_proc, 0, 0, hInst, NULL, NULL,
                          NULL, NULL, WORKER_CLASS_NAME, NULL };
    if (!RegisterClassExW((const WNDCLASSEXW *)&wc)
        && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        rin_diag("RegisterClassExW failed %lu", GetLastError());
        return 1;
    }

    g_wnd = CreateWindowExW(0, WORKER_CLASS_NAME, WORKER_CLASS_NAME, 0,
                            0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    if (!g_wnd) {
        rin_diag("CreateWindowExW failed %lu", GetLastError());
        return 2;
    }

    RIN_RAWINPUTDEVICE rid = { 0x01, 0x06, RIDEV_INPUTSINK, g_wnd };
    if (!RegisterRawInputDevices((PCRAWINPUTDEVICE)&rid, 1, sizeof(rid))) {
        rin_diag("RegisterRawInputDevices failed %lu (poll thread carries)",
                 GetLastError());
    } else {
        rin_diag("RIDEV_INPUTSINK registered hwnd=%p tid=%lu", g_wnd, g_wm_tid);
    }

    /* Register global hotkeys — most reliable delivery in kiosk. */
    register_win32_hotkeys(g_wnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    unregister_win32_hotkeys(g_wnd);
    RIN_RAWINPUTDEVICE rid_rm = { 0x01, 0x06, RIDEV_REMOVE, NULL };
    RegisterRawInputDevices((PCRAWINPUTDEVICE)&rid_rm, 1, sizeof(rid_rm));
    if (g_wnd) { DestroyWindow(g_wnd); g_wnd = NULL; }
    rin_diag("wm_worker exit");
    return 0;
}

/* ── Low-level keyboard hook thread ──────────────────────────────
 * WH_KEYBOARD_LL fires BEFORE any window's WndProc gets the message, so
 * we intercept hotkeys before Cursor/Chrome/LDB accelerators consume them.
 * Runs on a dedicated thread with its own message pump because the hook
 * callback is dispatched via the thread's message queue.
 *
 * Note: LL hooks require the calling process to have DPI awareness at
 * the correct level AND be UIAccess-enabled OR have SeTcbPrivilege.
 * DWM.exe runs with SYSTEM privileges so it satisfies this. */
#define RIN_WM_KEYUP        0x0101
#define RIN_WM_SYSKEYUP     0x0105

/* Per-second event counter for diag beacon. */
static volatile LONG g_ll_events_seen = 0;
static volatile LONG g_ll_down_events = 0;

/* Per-VK "was the last DOWN a consumed hotkey" flag. Used to consume
 * auto-repeat DOWN events AND the corresponding UP event, so LDB (or
 * any other app in the LL hook chain / message queue downstream of us)
 * NEVER sees any part of our hotkey sequence — not the initial DOWN,
 * not the auto-repeats, not the UP.
 *
 * Without this, a hotkey held for ~500 ms would leak ~20 auto-repeat
 * DOWNs to LDB + one UP. Even though LDB doesn't specifically watch
 * for these VK codes, a competent anti-cheat could flag "orphan UP
 * events" or "burst of same-VK downs" as suspicious. */
static volatile LONG g_consumed_vk[256] = {0};

/* Which slot claimed each VK. Used for auto-repeat routing —
 * subsequent DOWNs while g_consumed_vk[vk]==1 look up the slot
 * and check g_repeat_allowed[slot] to decide whether to re-fire.
 * -1 = never claimed. Written under g_consumed_vk[vk] transition. */
static volatile LONG g_consumed_vk_slot[256] = {0};

/* Per-hotkey allow-auto-repeat. Definition — forward decl in top-of-file.
 * Anything positional/scaling should repeat (movement, resize, opacity,
 * font, scroll). Toggles and one-shots should NOT repeat.
 * Read-only after init in rin_start. */
static void init_repeat_allowlist(void) {
    for (int i = 0; i < SVC_HK_COUNT; i++) g_repeat_allowed[i] = 0;
    /* Default 0 (no repeat). Toggle these to 1 for repeat-friendly. */
    g_repeat_allowed[SVC_HK_MOVE_LEFT]    = 1;
    g_repeat_allowed[SVC_HK_MOVE_RIGHT]   = 1;
    g_repeat_allowed[SVC_HK_MOVE_UP]      = 1;
    g_repeat_allowed[SVC_HK_MOVE_DOWN]    = 1;
    g_repeat_allowed[SVC_HK_RESIZE_WIDER] = 1;
    g_repeat_allowed[SVC_HK_RESIZE_NARROW]= 1;
    g_repeat_allowed[SVC_HK_RESIZE_TALLER]= 1;
    g_repeat_allowed[SVC_HK_RESIZE_SHORT] = 1;
    g_repeat_allowed[SVC_HK_ALPHA_UP]     = 1;
    g_repeat_allowed[SVC_HK_ALPHA_DOWN]   = 1;
    g_repeat_allowed[SVC_HK_FONT_UP]      = 1;
    g_repeat_allowed[SVC_HK_FONT_DOWN]    = 1;
    g_repeat_allowed[SVC_HK_SCROLL_UP]    = 1;
    g_repeat_allowed[SVC_HK_SCROLL_DOWN]  = 1;
}

/* Forward decl — chat-input helpers live in imgui_layer.cpp. */
extern int  ui_chat_is_active(void);
extern void ui_chat_feed_char(unsigned int cp);
extern void ui_chat_feed_backspace(void);
extern void ui_chat_feed_delete(void);
extern void ui_chat_cursor_left(void);
extern void ui_chat_cursor_right(void);
extern void ui_chat_cursor_home(void);
extern void ui_chat_cursor_end(void);
extern void ui_chat_cancel(void);
/* Callback into dllmain to submit typed text (spawns AI worker). */
extern void chat_submit_typed_text(void);

static LRESULT CALLBACK ll_kbd_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == RIN_HC_ACTION) {
        RIN_KBDLLHOOKSTRUCT *k = (RIN_KBDLLHOOKSTRUCT *)lp;
        USHORT vk = (USHORT)k->vkCode;
        int is_down = (wp == RIN_WM_KEYDOWN || wp == RIN_WM_SYSKEYDOWN);
        int is_up   = (wp == RIN_WM_KEYUP   || wp == RIN_WM_SYSKEYUP);

        InterlockedIncrement(&g_ll_events_seen);
        if (is_down) InterlockedIncrement(&g_ll_down_events);

        /* Log first 40 events for diag. */
        static volatile LONG s_ev_logged = 0;
        LONG n = InterlockedIncrement(&s_ev_logged);
        if (n <= 40) {
            rin_diag("LL ev%ld: wp=0x%02X vk=0x%02X",
                     n, (unsigned)wp, vk);
        }

        /* Track modifier state (GetAsyncKeyState lies for DWM's process). */
        int mod_released = 0;
        if (is_down || is_up) {
            int v = is_down ? 1 : 0;
            if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) {
                InterlockedExchange(&g_ctrl_down, v);
                if (is_up) mod_released = 1;
            } else if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT) {
                InterlockedExchange(&g_shift_down, v);
                if (is_up) mod_released = 1;
            } else if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) {
                InterlockedExchange(&g_alt_down, v);
                if (is_up) mod_released = 1;
            }
        }

        /* Modifier release sweep — the moment ANY modifier goes up,
         * clear every consumed_vk whose slot required a modifier that's
         * no longer held. Stops auto-repeat continuous nudge the
         * INSTANT the user lifts Ctrl/Shift/Alt, even if they still
         * hold the arrow/letter key. Belt-and-suspenders on top of the
         * per-fire mods_match check below. */
        if (mod_released) {
            for (int vki = 0; vki < 256; vki++) {
                if (!g_consumed_vk[vki]) continue;
                LONG slot = g_consumed_vk_slot[vki];
                if (slot < 0 || slot >= SVC_HK_COUNT) continue;
                unsigned req = (g_hk[slot] >> 16) & 0xFF;
                int want_ctrl  = (req & SVC_HK_MOD_CTRL)  != 0;
                int want_shift = (req & SVC_HK_MOD_SHIFT) != 0;
                int want_alt   = (req & SVC_HK_MOD_ALT)   != 0;
                if ((want_ctrl  && !g_ctrl_down)  ||
                    (want_shift && !g_shift_down) ||
                    (want_alt   && !g_alt_down)) {
                    InterlockedExchange(&g_consumed_vk[vki], 0);
                    InterlockedExchange(&g_consumed_vk_slot[vki], -1);
                }
            }
        }

        /* UP handling: if this VK's last DOWN was consumed by us, consume
         * the UP too — no orphan UP events for LDB to see. */
        if (is_up && vk < 256 && g_consumed_vk[vk]) {
            InterlockedExchange(&g_consumed_vk[vk], 0);
            return 1;   /* consume UP */
        }

        if (is_down) {
            /* Auto-repeat handling: if we consumed the initial DOWN for
             * this VK, the OS keeps sending DOWN events as auto-repeats
             * (~30/sec at Windows default). Two options per hotkey:
             *   - Repeat NOT allowed → eat every repeat (default: toggles
             *     don't want to fire N times when held).
             *   - Repeat ALLOWED → re-fire the same slot each repeat
             *     (nudge/resize/opacity/font/scroll should be hold-able).
             * Either way we ALWAYS return 1 so LDB / other apps NEVER
             * see repeats of hotkey scancodes. */
            if (vk < 256 && g_consumed_vk[vk]) {
                /* Auto-repeat validation gauntlet — must ALL pass or we
                 * clear state + drop the fire. Fixes "nudge continues
                 * after release" caused by a race where OS auto-repeat
                 * emits one extra DOWN after the UP was already
                 * processed, or by a modifier release while the arrow
                 * is still held. */
                LONG slot = g_consumed_vk_slot[vk];
                int mods_match = (slot >= 0 && slot < SVC_HK_COUNT) &&
                    match_hk(g_hk[slot], vk,
                             g_ctrl_down, g_shift_down, g_alt_down);
                /* Hardware key state — bypasses our LL hook consumption.
                 * If the physical key isn't down, this is a phantom
                 * event; do not fire. */
                int key_phys_down = (GetAsyncKeyState(vk) & 0x8000) != 0;

                if (!mods_match || !key_phys_down) {
                    InterlockedExchange(&g_consumed_vk[vk], 0);
                    InterlockedExchange(&g_consumed_vk_slot[vk], -1);
                    return 1;   /* still consume — no leak to LDB */
                }

                if (slot >= 0 && slot < SVC_HK_COUNT &&
                    g_repeat_allowed[slot]) {
                    fire((int)slot);   /* 50ms debounce inside */
                }
                return 1;
            }

            int is_ctrl  = g_ctrl_down;
            int is_shift = g_shift_down;
            int is_alt   = g_alt_down;

            /* Hotkey matching runs FIRST (before chat capture) so
             * Ctrl+Alt+T can toggle chat mode + Ctrl+Shift+Alt+K
             * emergency-stops even mid-type. */
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (match_hk(g_hk[i], vk, is_ctrl, is_shift, is_alt)) {
                    if (vk < 256) {
                        InterlockedExchange(&g_consumed_vk[vk], 1);
                        InterlockedExchange(&g_consumed_vk_slot[vk], i);
                    }
                    if (fire(i)) {
                        rin_diag("LL_HOOK fired slot=%d vk=0x%02X mods=(c%d s%d a%d) [consumed, repeat=%d]",
                                 i, vk, is_ctrl, is_shift, is_alt, g_repeat_allowed[i]);
                    }
                    return 1;   /* consume DOWN */
                }
            }

            /* ── Chat input capture ────────────────────────────────
             * If chat mode is active AND no hotkey matched, treat this
             * key as input for the AI prompt. LDB never sees any of
             * these keystrokes (all consumed). */
            if (ui_chat_is_active()) {
                /* Modifier / lock / super keys — mod tracking above
                 * already captured the transition. Consume the event
                 * so nothing downstream (Cursor, Chrome, LDB, Windows
                 * Start menu, etc.) sees the raw modifier press. In
                 * chat mode NOTHING escapes to any other app. */
                if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
                    vk == VK_SHIFT   || vk == VK_LSHIFT   || vk == VK_RSHIFT   ||
                    vk == VK_MENU    || vk == VK_LMENU    || vk == VK_RMENU    ||
                    vk == VK_CAPITAL || vk == VK_NUMLOCK  || vk == VK_SCROLL   ||
                    vk == VK_LWIN    || vk == VK_RWIN) {
                    /* Also mark the vk as consumed so its UP gets
                     * eaten too (see top-of-function up-consume block). */
                    if (vk < 256) InterlockedExchange(&g_consumed_vk[vk], 1);
                    return 1;
                }

                if (vk < 256) InterlockedExchange(&g_consumed_vk[vk], 1);

                if (vk == VK_RETURN) {
                    /* Submit + close chat. Spawned in a helper thread
                     * because ll_kbd_proc runs on the LL hook thread
                     * and MUST return quickly. */
                    chat_submit_typed_text();
                    return 1;
                }
                if (vk == VK_ESCAPE) {
                    ui_chat_cancel();
                    return 1;
                }
                if (vk == VK_BACK)   { ui_chat_feed_backspace(); return 1; }
                if (vk == VK_DELETE) { ui_chat_feed_delete();    return 1; }
                if (vk == VK_LEFT)   { ui_chat_cursor_left();    return 1; }
                if (vk == VK_RIGHT)  { ui_chat_cursor_right();   return 1; }
                if (vk == VK_HOME)   { ui_chat_cursor_home();    return 1; }
                if (vk == VK_END)    { ui_chat_cursor_end();     return 1; }
                /* PageUp/PageDown/Tab/etc. — consume to prevent leak,
                 * ignore semantically. */
                if (vk == VK_PRIOR || vk == VK_NEXT || vk == VK_TAB ||
                    vk == VK_UP    || vk == VK_DOWN) {
                    return 1;
                }

                /* Regular printable key — translate VK+scan+modifiers
                 * to Unicode via ToUnicode(). Result depends on the
                 * user's keyboard layout, so a French layout gets `é`
                 * from AltGr+e etc. */
                BYTE kbstate[256] = {0};
                if (is_ctrl)  kbstate[VK_CONTROL] = 0x80;
                if (is_shift) kbstate[VK_SHIFT]   = 0x80;
                if (is_alt)   kbstate[VK_MENU]    = 0x80;
                if ((GetKeyState(VK_CAPITAL) & 1)) kbstate[VK_CAPITAL] = 0x01;
                WCHAR wbuf[8] = {0};
                HKL hkl = GetKeyboardLayout(0);
                int r = ToUnicodeEx((UINT)vk, (UINT)k->scanCode, kbstate,
                                    wbuf, 8, 0, hkl);
                if (r > 0) {
                    /* Handle surrogate pair (rare for input). */
                    if (r >= 2 && wbuf[0] >= 0xD800 && wbuf[0] <= 0xDBFF &&
                        wbuf[1] >= 0xDC00 && wbuf[1] <= 0xDFFF) {
                        unsigned int cp = 0x10000 +
                            ((wbuf[0] - 0xD800) << 10) + (wbuf[1] - 0xDC00);
                        ui_chat_feed_char(cp);
                    } else {
                        for (int wi = 0; wi < r; wi++) {
                            if (wbuf[wi] >= 0x20 || wbuf[wi] == '\t') {
                                ui_chat_feed_char((unsigned int)wbuf[wi]);
                            }
                        }
                    }
                }
                return 1;   /* consume ALL keys while typing */
            }
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static DWORD WINAPI ll_thread(LPVOID param) {
    (void)param;
    attach_to_input_desktop();
    g_ll_tid = GetCurrentThreadId();

    /* SetWindowsHookExW with WH_KEYBOARD_LL — hModule can be NULL for
     * thread-scoped, but we want SYSTEM-wide so pass our HINSTANCE.
     * Actually LL hooks are ALWAYS system-wide regardless of hMod; the
     * hMod arg is essentially ignored per MSDN docs since Vista. */
    g_ll_hook = SetWindowsHookExW(RIN_WH_KEYBOARD_LL, ll_kbd_proc,
                                  GetModuleHandleW(NULL), 0);
    if (!g_ll_hook) {
        rin_diag("SetWindowsHookExW(WH_KEYBOARD_LL) FAILED %lu", GetLastError());
        return 0;
    }
    rin_diag("WH_KEYBOARD_LL installed hook=%p tid=%lu", g_ll_hook, g_ll_tid);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_ll_hook) {
        UnhookWindowsHookEx(g_ll_hook);
        g_ll_hook = NULL;
    }
    rin_diag("ll_thread exit");
    return 0;
}

/* ── Public API ────────────────────────────────────────────────── */
int rawin_start(const unsigned *hotkeys, hotkey_cb_t cb) {
    if (g_poll_thread || g_wm_thread) return 1;   /* already running */
    if (!hotkeys || !cb) return 0;

    for (int i = 0; i < SVC_HK_COUNT; i++) g_hk[i] = hotkeys[i];
    g_cb = cb;

    /* Initialize per-slot consume-slot tracking (default -1). */
    for (int i = 0; i < 256; i++) g_consumed_vk_slot[i] = -1;
    init_repeat_allowlist();

    int configured = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) if (g_hk[i]) configured++;
    rin_diag("rawin_start: %d/%d slots configured", configured, SVC_HK_COUNT);

    /* Poll thread is the reliable path — start it FIRST. */
    InterlockedExchange(&g_poll_running, 1);
    g_poll_thread = CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
    if (!g_poll_thread) {
        rin_diag("CreateThread(poll) FAILED %lu", GetLastError());
        InterlockedExchange(&g_poll_running, 0);
        return 0;
    }

    /* WM_INPUT + RegisterHotKey path. */
    g_wm_thread = CreateThread(NULL, 0, wm_worker, NULL, 0, NULL);
    if (!g_wm_thread) {
        rin_diag("CreateThread(wm) FAILED %lu (poll path still active)",
                 GetLastError());
    }

    /* WH_KEYBOARD_LL path — highest priority, consumes keys before apps. */
    g_ll_thread = CreateThread(NULL, 0, ll_thread, NULL, 0, NULL);
    if (!g_ll_thread) {
        rin_diag("CreateThread(ll) FAILED %lu (RegisterHotKey path still active)",
                 GetLastError());
    }
    return 1;
}

void rawin_stop(void) {
    InterlockedExchange(&g_poll_running, 0);
    if (g_poll_thread) {
        WaitForSingleObject(g_poll_thread, 3000);
        CloseHandle(g_poll_thread);
        g_poll_thread = NULL;
    }
    if (g_wm_thread) {
        if (g_wm_tid) PostThreadMessageW(g_wm_tid, WM_QUIT, 0, 0);
        WaitForSingleObject(g_wm_thread, 3000);
        CloseHandle(g_wm_thread);
        g_wm_thread = NULL;
        g_wm_tid = 0;
    }
    if (g_ll_thread) {
        if (g_ll_tid) PostThreadMessageW(g_ll_tid, WM_QUIT, 0, 0);
        WaitForSingleObject(g_ll_thread, 3000);
        CloseHandle(g_ll_thread);
        g_ll_thread = NULL;
        g_ll_tid = 0;
    }
    g_cb = NULL;
    for (int i = 0; i < SVC_HK_COUNT; i++) g_hk[i] = 0;
}
