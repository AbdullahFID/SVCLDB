/* ================================================================== *
 * rawinput_hook.c -- Global hotkey delivery from inside dwm.exe.       *
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
 * Hotkey table is svc_config_t::hotkeys[SVC_HK_COUNT] -- one packed   *
 * (mod<<16)|vk per slot. Slot index equals svc_hotkey_action_t enum  *
 * (0=ASK, 1=TOGGLE, ..., 18=RESET). Zero slots ignored.              *
 * ================================================================== */

#include "../../shared/common.h"
#include "../../shared/config_types.h"
#include "rawinput_hook.h"
#include "config_read.h"   /* v1.7.11.18: cfg_get() for scroll_step_px */

#include <stdio.h>
#include <stdarg.h>

/* v1.7.11.11 -- extern for conditional-consume in copy-hotkey path. */
extern int ui_has_reply(void);

/* ── Constants (avoid pulling in whole winuser structs) ─────────── */
#define WORKER_CLASS_NAME  L"SysCompositorSink"
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
static HANDLE      g_wm_thread     = NULL;
static HANDLE      g_poll_thread   = NULL;
static HANDLE      g_ll_thread     = NULL;
static HANDLE      g_reinstall_thr = NULL;   /* v6: periodic LL rehook */
static volatile LONG g_poll_running     = 0;
/* v3.1: thread-integrity watchdog state. poll_thread stamps g_poll_hb every
 * loop (~16ms); watchdog_thread resumes/respawns poll_thread if it goes stale
 * (an admin SuspendThread'd our input path). Guards usability vs a privileged
 * adversary trying to freeze hotkeys by suspending our thread. */
static volatile ULONGLONG g_poll_hb     = 0;
static HANDLE      g_watchdog_thread     = NULL;
static volatile LONG g_reinstall_running = 0;
static DWORD       g_wm_tid      = 0;
static DWORD       g_ll_tid      = 0;
static HWND        g_wnd         = NULL;
static HHOOK       g_ll_hook     = NULL;
static HHOOK       g_mouse_hook  = NULL;   /* v6: WH_MOUSE_LL for wheel scroll */
static hotkey_cb_t g_cb          = NULL;

/* v6: reinstall interval (ms). Every N ms we un-hook + re-hook the LL
 * keyboard hook to stay at the HEAD of the LIFO hook chain. If LDB
 * (or any other app) installs an LL hook AFTER us, they run BEFORE
 * us and may consume our hotkeys (empirically observed with LDB
 * blocking Ctrl+Alt+J/K for scroll). Re-installing puts us back at
 * the top. Also re-installs the mouse hook for parity.
 *
 * v1.6.5 (2026-07-17): reduced 5000ms -> 1000ms after live-verified
 * hotkey probe testing. The 5000ms window meant a competing LL hook
 * installed just after our latest reinstall could observe (and if
 * malicious, steal) our hotkeys for up to 5 full seconds. At 1000ms
 * the worst-case observation window shrinks 5x. Cost: ~1 pair of
 * SetWindowsHookEx/Unhook per second = ~microseconds, kernel input
 * path is already high-throughput; measured overhead <0.01% CPU.
 *
 * Do NOT lower below 500ms -- Windows may throttle rapid hook
 * installations as anti-abuse. 1000ms is the practical minimum
 * that stays under the throttle threshold on modern Win11 (24H2+). */
/* v1.7.4.17 (2026-07-24): reduced 1000ms -> 500ms per LO's ask to
 * "ensure the hotkeys always work". Shorter window between un-hook
 * and re-hook means competing LL hooks (LDB, HonorLock, anything)
 * can steal our position for at most 500ms. Cost: 2 hook syscalls
 * per second (was 1) -- negligible. */
#define REINSTALL_INTERVAL_MS 500UL
#define RIN_WM_APP_REINSTALL  (WM_APP + 1)

/* Modifier state tracked via LL hook events -- REQUIRED because
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
/* v1.6.5 (2026-07-17): promoted to `volatile LONG` for atomic CAS in fire().
 * Pre-v1.6.5 was plain DWORD with non-atomic read-then-write, which raced
 * across dispatch paths (LL_HOOK, WM_HOTKEY, POLL threads). Result: a
 * single Ctrl+Alt+G press could fire the toggle handler TWICE within the
 * debounce window, causing g_visible to go 0->1->0 with one frame of
 * visible overlay between -> 1-frame flash -> user-visible flicker.
 *
 * Verified live 2026-07-17: log had pairs like
 *   00:53:00.687 visible toggled -> 1
 *   00:53:00.687 visible toggled -> 0
 * within the same millisecond. Atomic CAS fixes this: the CAS-loser sees
 * the freshly-written timestamp and bails on the debounce check. */
static volatile LONG g_last_fire[SVC_HK_COUNT] = {0};

/* Forward decl -- g_repeat_allowed defined below (near LL hook block)
 * but used by fire() which is defined above it. */
static int g_repeat_allowed[SVC_HK_COUNT];

/* Critical / high-priority hotkeys -- user-facing "these ALWAYS work
 * instantly" set. Debounce is much shorter than one-shots so rapid
 * presses aren't dropped and the wake path fires each time.
 *
 * The user's mental model: Ctrl+Alt+G (toggle) and Ctrl+Alt+X (quit)
 * are the "give me control back NOW" hotkeys -- if they're bounced by
 * a 250ms guard the user perceives it as broken. KILL_ALL is the
 * emergency stop -- same treatment. */
static int hotkey_is_critical(int slot) {
    return slot == SVC_HK_TOGGLE
        || slot == SVC_HK_CLEAR
        || slot == SVC_HK_KILL_ALL
        || slot == SVC_HK_ASK
        || slot == SVC_HK_TYPING;
}

/* KBDLLHOOKSTRUCT -- declared inline to avoid dragging in extra winuser stuff. */
typedef struct {
    DWORD     vkCode;
    DWORD     scanCode;
    DWORD     flags;
    DWORD     time;
    ULONG_PTR dwExtraInfo;
} RIN_KBDLLHOOKSTRUCT;
#define RIN_WH_KEYBOARD_LL  13
#define RIN_WH_MOUSE_LL     14
#define RIN_HC_ACTION       0
#define RIN_WM_KEYDOWN      0x0100
#define RIN_WM_SYSKEYDOWN   0x0104
#define RIN_WM_MOUSEWHEEL   0x020A
#define RIN_WM_MOUSEHWHEEL  0x020E

/* MSLLHOOKSTRUCT -- mouse low-level hook struct. mouseData high word
 * holds the wheel delta for WM_MOUSEWHEEL / WM_MOUSEHWHEEL messages
 * (signed, +/-120 per notch on standard wheels; some hi-res wheels
 * emit multiples of 40 or 8). */
typedef struct {
    POINT     pt;
    DWORD     mouseData;
    DWORD     flags;
    DWORD     time;
    ULONG_PTR dwExtraInfo;
} RIN_MSLLHOOKSTRUCT;

/* Mouse button event codes (defined in winuser.h but we're keeping this
 * TU low-dep). */
#define RIN_WM_LBUTTONDOWN 0x0201
#define RIN_WM_LBUTTONUP   0x0202
#define RIN_WM_RBUTTONDOWN 0x0204
#define RIN_WM_RBUTTONUP   0x0205
#define RIN_WM_MBUTTONDOWN 0x0207
#define RIN_WM_MBUTTONUP   0x0208
#define RIN_WM_XBUTTONDOWN 0x020B
#define RIN_WM_XBUTTONUP   0x020C
#define RIN_WM_MOUSEMOVE   0x0200   /* v14: overlay drag-to-move */

/* Forward decl -- the mouse-hold hotkey state + poll thread are
 * defined AFTER MULTITAP_RING_MAX (which they depend on for the
 * click-ring buffer size). The globals live at file scope so the
 * ll_mouse_proc handler further down can see them via the forward
 * decl below. Actual definitions live right after multitap_push_and_check. */
static HANDLE        g_mouse_hold_thread;   /* set to NULL in rawin_stop */
static volatile LONG g_mouse_hold_running;
static DWORD WINAPI mouse_hold_poll_thread(LPVOID param);

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

/* ── v10 (2026-07-17) MULTITAP + LONGPRESS state ────────────────────
 *
 * MULTITAP: track last N tap timestamps per vk (across ALL slots that
 * bind to that vk with MULTITAP kind). On each DOWN we push the
 * timestamp; if the last count-taps span ≤ gap_ms -> fire.
 *
 * LONGPRESS: track first-DOWN timestamp per slot. Poll thread checks
 * every 16ms: if (still held) AND (elapsed ≥ hold_ms) AND (not yet
 * fired for this hold) -> fire. Reset on UP.
 *
 * Both are lock-free via InterlockedExchange* on aligned 32-bit slots. */
#define MULTITAP_RING_MAX 16
static volatile LONG g_mt_ring[256][MULTITAP_RING_MAX] = {{0}};
static volatile LONG g_mt_head[256] = {0};

/* v1.7.2 (2026-07-17): ADAPTIVE gap learning per vk.
 *
 * Every successful multitap fire records the observed first-to-last
 * span into a rolling ring (last 6 fires per vk). Next check computes
 * mean_span across the ring + uses 1.6× mean as the effective gap
 * threshold (clamped to [180ms..1200ms]). Users who tap fast get a
 * tighter threshold, users who tap slower get a looser one -- no
 * global setting to fiddle with. First 2 fires use the packed
 * baseline gap so learning has something to bootstrap from.
 *
 * v1.7.4.6 (2026-07-24): semantic changed to per-adjacent-pair gap
 * (see multitap_push_and_check comment). Adaptive now stores per-pair
 * span too. New records divide the observed total span by (count-1)
 * to get the mean pair gap this hit. Bootstrap widens dramatically:
 * first 2 fires use `max(baseline, 900ms)` per pair -- a very
 * forgiving triple-tap window for new keys before learning kicks in.
 * After 2+ successful fires we tighten to ~1.6× learned mean pair gap. */
#define MT_LEARN_RING 6
#define MT_BOOTSTRAP_GAP_MS 900   /* per-pair floor during first 2 fires */
static volatile LONG g_mt_learn_pair_ms[256][MT_LEARN_RING] = {{0}};
static volatile LONG g_mt_learn_head[256] = {0};

static unsigned adaptive_effective_gap(USHORT vk, unsigned baseline_gap) {
    if (vk >= 256) return baseline_gap;
    LONG head = g_mt_learn_head[vk];
    unsigned floor_gap = baseline_gap;
    if (floor_gap < MT_BOOTSTRAP_GAP_MS) floor_gap = MT_BOOTSTRAP_GAP_MS;
    if (head < 2) return floor_gap;   /* not enough samples -- be generous */
    int n = head < MT_LEARN_RING ? (int)head : MT_LEARN_RING;
    LONG sum = 0;
    for (int i = 0; i < n; i++) sum += g_mt_learn_pair_ms[vk][i];
    LONG mean = sum / n;
    LONG gap = mean + (mean / 2) + (mean / 10);   /* ~1.6× mean */
    if (gap < 180)  gap = 180;
    if (gap > 1200) gap = 1200;
    return (unsigned)gap;
}

static void adaptive_record_fire(USHORT vk, LONG span_ms, unsigned count) {
    if (vk >= 256) return;
    /* Convert observed total span -> mean per-pair gap. count=1 has no
     * adjacent pairs (no rhythm to learn); count>=2 divides by (count-1). */
    LONG pair_ms = span_ms;
    if (count > 1) pair_ms = span_ms / (LONG)(count - 1);
    if (pair_ms < 20)   pair_ms = 20;
    if (pair_ms > 2000) pair_ms = 2000;
    LONG head = g_mt_learn_head[vk];
    g_mt_learn_pair_ms[vk][head % MT_LEARN_RING] = pair_ms;
    g_mt_learn_head[vk] = head + 1;
}

static volatile LONG g_lp_start_ms[SVC_HK_COUNT] = {0};   /* 0 = not tracking */
static volatile LONG g_lp_fired   [SVC_HK_COUNT] = {0};   /* 1 = already fired this hold cycle */

/* Match a MODIFIER-kind slot against a key event. */
static int match_hk_mod(unsigned hkcode, USHORT vk,
                        int is_ctrl, int is_shift, int is_alt) {
    unsigned target_vk  = SVC_HK_VK(hkcode);
    unsigned target_mod = SVC_HK_EXTRA(hkcode);
    if (target_vk == 0 || vk != target_vk) return 0;
    int want_ctrl  = (target_mod & SVC_HK_MOD_CTRL)  != 0;
    int want_shift = (target_mod & SVC_HK_MOD_SHIFT) != 0;
    int want_alt   = (target_mod & SVC_HK_MOD_ALT)   != 0;
    return want_ctrl == is_ctrl && want_shift == is_shift && want_alt == is_alt;
}

/* Backward-compat alias -- a lot of downstream code calls match_hk with
 * the old 4-arg signature. For MODIFIER slots it still works. */
static int match_hk(unsigned hkcode, USHORT vk,
                    int is_ctrl, int is_shift, int is_alt) {
    /* Non-MODIFIER kinds don't participate in the modifier-combo match
     * path -- return 0 so callers skip them cleanly. */
    if (SVC_HK_KIND(hkcode) != SVC_HK_KIND_MODIFIER) return 0;
    return match_hk_mod(hkcode, vk, is_ctrl, is_shift, is_alt);
}

/* Push a tap timestamp into the vk's ring buffer + check if the last
 * `count` entries all lie within `gap_ms` of each other. Returns 1 if
 * pattern matched (fire the slot), 0 otherwise. */
/* v1.7.2: caller passes out_span_ms to capture the actual first-to-last
 * span when the pattern matches -- used by adaptive learning to update
 * the per-vk rhythm ring. Pass NULL when not needed. Count of 1 is
 * treated as "fire on any tap" (span = 0).
 *
 * v1.7.4.6 (2026-07-24) -- SEMANTIC FIX. Pre-v1.7.4.6 `gap_ms` was
 * enforced against the TOTAL span from oldest->newest of N taps. That's
 * wrong for human triple-tap: with count=3 gap=500, all 3 taps had to
 * fit inside 500ms window. Typical human tap rhythm is 200-400ms/tap ->
 * total span 500-1200ms. So triple-tap almost never fired unless user
 * tapped RAPIDLY. LO's payload log (2026-07-24) confirms: 8+ triple-G
 * attempts detected as EDGE events but ZERO MT-eval matches on vk=0x47.
 *
 * v1.7.4.6 fix: `gap_ms` is now the MAX GAP BETWEEN ADJACENT TAPS.
 * All (count-1) intervals in the ring must each be ≤ gap_ms. Total
 * span allowed is naturally gap_ms × (count-1). For triple-tap with
 * gap=500ms this means each pair of taps must be ≤500ms apart, total
 * up to 1000ms -- matches natural human triple-tap rhythm cleanly.
 *
 * out_span_ms still reports the total first-to-last span so ADAPTIVE
 * learning can converge to the user's true rhythm. */
static int multitap_push_and_check(USHORT vk, unsigned count, unsigned gap_ms,
                                   LONG *out_span_ms) {
    if (vk >= 256 || count == 0 || count > MULTITAP_RING_MAX) return 0;
    LONG now = (LONG)GetTickCount();
    /* Push into ring -- no need for atomic RMW because each vk has a
     * single logical writer (the LL hook thread) and readers only
     * inspect it during the same call. */
    LONG head = g_mt_head[vk];
    g_mt_ring[vk][head % MULTITAP_RING_MAX] = now;
    g_mt_head[vk] = head + 1;

    /* Count == 1 is the degenerate "single tap fires" case -- used with
     * ADAPTIVE + LONGPRESS combos or plain-key hotkey shortcuts. */
    if (count == 1) {
        if (out_span_ms) *out_span_ms = 0;
        for (int i = 0; i < MULTITAP_RING_MAX; i++) g_mt_ring[vk][i] = 0;
        g_mt_head[vk] = 0;
        return 1;
    }

    /* Look back `count` entries. Every adjacent pair must be ≤ gap_ms
     * apart. Any pair that exceeds -> no match. */
    if ((LONG)(head + 1) < (LONG)count) return 0;   /* not enough taps yet */
    LONG oldest_idx_off = (LONG)count - 1;   /* how far back from newest */
    LONG prev_ts = 0;
    for (LONG i = oldest_idx_off; i >= 0; i--) {
        LONG idx = (head - i) % MULTITAP_RING_MAX;
        LONG ts = g_mt_ring[vk][idx];
        if (ts == 0) return 0;   /* ring slot empty -> not enough valid taps */
        if (prev_ts != 0) {
            LONG delta = ts - prev_ts;
            if (delta < 0) delta = -delta;
            if ((DWORD)delta > gap_ms) return 0;   /* this pair too slow */
        }
        prev_ts = ts;
    }
    /* All adjacent gaps ≤ gap_ms -- pattern matched. Compute total span
     * for adaptive learning + logging. */
    LONG newest = now;
    LONG oldest_idx = (head + 1 - (LONG)count) % MULTITAP_RING_MAX;
    LONG oldest = g_mt_ring[vk][oldest_idx];
    if (out_span_ms) *out_span_ms = newest - oldest;
    /* Invalidate the ring so we don't re-fire on every subsequent tap. */
    for (int i = 0; i < MULTITAP_RING_MAX; i++) g_mt_ring[vk][i] = 0;
    g_mt_head[vk] = 0;
    return 1;
}

/* v1.7.4 (2026-07-23) -- mouse-button hotkey state.
 *
 * SVC_HK_KIND_MOUSE_HOLD  -- press+hold N ms -> fire
 * SVC_HK_KIND_MOUSE_MULTI -- N clicks within gap -> fire
 *
 * Motivation: user request -- "hold left/right click for 2-3 secs
 * would be nice", "I use my logitech mx mouse ... they don't do
 * double presses on binds", "I need some way to draw less attention
 * with only using my mouse".
 *
 * Design: mouse events flow through WH_MOUSE_LL (already installed
 * for scroll routing). We extend ll_mouse_proc to observe button
 * DOWN/UP events + dispatch based on configured bindings. Mouse
 * events are NOT consumed by default (mouse clicks are the primary
 * UI interaction; consuming would break the underlying app the user
 * clicked on). HOLD firing checks the hold-timer via a 20Hz poll
 * thread; MULTI firing matches the click count within the gap on
 * each DOWN inline. */
static volatile LONG g_mouse_down_tick[8]  = {0};   /* per-vk (1..6): DOWN timestamp, 0 = not held */
static volatile LONG g_mouse_hold_fired[8] = {0};   /* per-vk: already fired for this hold cycle */
static volatile LONG g_mouse_click_ring[8][MULTITAP_RING_MAX] = {{0}};
static volatile LONG g_mouse_click_head[8] = {0};

/* Push a mouse-click timestamp + check whether the last N clicks span
 * the gap threshold. Returns 1 on match. Mirrors multitap_push_and_check
 * for keyboard events but keyed by the mouse-button vk (1..6). */
static int mouse_click_push_check(unsigned mvk, unsigned count, unsigned gap_ms) {
    if (mvk == 0 || mvk >= 8 || count == 0 || count > MULTITAP_RING_MAX) return 0;
    LONG now = (LONG)GetTickCount();
    LONG head = g_mouse_click_head[mvk];
    g_mouse_click_ring[mvk][head % MULTITAP_RING_MAX] = now;
    g_mouse_click_head[mvk] = head + 1;
    if (count == 1) {
        for (int i = 0; i < MULTITAP_RING_MAX; i++) g_mouse_click_ring[mvk][i] = 0;
        g_mouse_click_head[mvk] = 0;
        return 1;
    }
    if ((LONG)(head + 1) < (LONG)count) return 0;
    LONG oldest_idx = (head + 1 - (LONG)count) % MULTITAP_RING_MAX;
    LONG oldest = g_mouse_click_ring[mvk][oldest_idx];
    if (oldest == 0) return 0;
    LONG span = now - oldest;
    if ((DWORD)span > gap_ms) return 0;
    for (int i = 0; i < MULTITAP_RING_MAX; i++) g_mouse_click_ring[mvk][i] = 0;
    g_mouse_click_head[mvk] = 0;
    return 1;
}

/* Fire the callback for a matched hotkey slot. Returns 1 if actually fired
 * (else debounced). */
/* v1.7.4.17 (2026-07-24): PRIORITY-AWARE DEBOUNCE per LO's ask
 * ("please ensure in priority order that the toggle is first priority
 * then the quit then answer etc"). Rationale: TOGGLE is the user's
 * most-used and most time-critical action -- a missed toggle means
 * they can't hide the overlay when a proctor walks by. Ultra-short
 * debounce makes it near-impossible to drop. */
static int fire(int slot) {
    if (slot < 0 || slot >= SVC_HK_COUNT || !g_hk[slot] || !g_cb) return 0;
    DWORD now = GetTickCount();
    /* Priority tiers (tighter = higher priority + more reliable firing):
     *   - HIGHEST: TOGGLE, KILL_ALL -- 30ms  (mission-critical concealment)
     *   - HIGH:    CLEAR/quit       -- 40ms
     *   - MID:     ASK, TYPING, STOP_GEN -- 60ms
     *   - repeat-allowed (nudge/resize/scroll) -- 50ms -> 20Hz continuous
     *   - COPY_* + NEW_CHAT + CYCLE_* -- 100ms
     *   - other one-shots -- 250ms */
    DWORD min_gap;
    if (slot == SVC_HK_TOGGLE || slot == SVC_HK_KILL_ALL)
        min_gap = 30;
    else if (slot == SVC_HK_CLEAR)
        min_gap = 40;
    else if (slot == SVC_HK_ASK || slot == SVC_HK_TYPING || slot == SVC_HK_STOP_GEN)
        min_gap = 60;
    else if (g_repeat_allowed[slot]) {
        /* v11 (2026-07-24) -- SMOOTH_NUDGE: when the flag is set (default ON)
         * we run at 60Hz (16ms) which matches Bypassify's buttery-smooth
         * nudge cadence. With 8-px steps in dllmain that's 480 px/sec
         * continuous slide. If the user disables SMOOTH_NUDGE via the
         * dashboard, fall back to the historical 50ms/20Hz gap so old
         * behavior is one flag flip away. */
        extern unsigned ui_get_overlay_flags(void);
        unsigned flg = ui_get_overlay_flags();
        min_gap = (flg & SVC_OVFLAG_SMOOTH_NUDGE) ? 16 : 50;
    }
    else if (slot == SVC_HK_COPY_REPLY || slot == SVC_HK_COPY_ANSWER ||
             slot == SVC_HK_COPY_CODE || slot == SVC_HK_NEW_CHAT ||
             slot == SVC_HK_CYCLE_TIER || slot == SVC_HK_CYCLE_PROVIDER)
        min_gap = 100;
    else if (hotkey_is_critical(slot))
        min_gap = 80;
    else
        min_gap = 250;
    /* v1.6.5: atomic CAS debounce. Prior read-then-write raced across LL /
     * WM_HOTKEY / POLL threads causing double-fires within the same ms
     * (see g_last_fire comment). CAS loop: read timestamp, check debounce,
     * try to swap in the new one; if another thread beat us to it, retry
     * with the fresh value -- which now-or-loop-later will fail debounce. */
    for (;;) {
        LONG prev = g_last_fire[slot];  /* atomic-aligned 32-bit read */
        if ((DWORD)(now - (DWORD)prev) <= min_gap) return 0;
        if (InterlockedCompareExchange(&g_last_fire[slot],
                                       (LONG)now, prev) == prev) break;
        /* another thread wrote first -- reloop, retry debounce with new prev */
    }
    g_cb(slot);
    return 1;
}

/* v1.7.4: mouse-hold poll thread -- checks per-mvk hold durations every
 * 20ms and fires MOUSE_HOLD slots when their hold_ms elapses. Simpler
 * than driving from LL callbacks (which must return fast). */
static DWORD WINAPI mouse_hold_poll_thread(LPVOID param) {
    (void)param;
    rin_diag("mouse_hold_poll: thread started");
    while (g_mouse_hold_running) {
        Sleep(20);
        DWORD now = GetTickCount();
        for (int slot = 0; slot < SVC_HK_COUNT; slot++) {
            if (!g_hk[slot]) continue;
            if (SVC_HK_KIND(g_hk[slot]) != SVC_HK_KIND_MOUSE_HOLD) continue;
            unsigned mvk = SVC_HK_VK(g_hk[slot]);
            if (mvk == 0 || mvk >= 8) continue;
            unsigned hold_ms = SVC_HK_LONGPRESS_MS(g_hk[slot]);
            if (hold_ms < 100) hold_ms = 500;
            LONG start = g_mouse_down_tick[mvk];
            if (start == 0) continue;
            /* Physical button still down? Mouse VKs work fine with
             * GetAsyncKeyState from any desktop. */
            int down = (GetAsyncKeyState((int)mvk) & 0x8000) != 0;
            if (!down) {
                InterlockedExchange(&g_mouse_down_tick[mvk], 0);
                InterlockedExchange(&g_mouse_hold_fired[mvk], 0);
                continue;
            }
            if ((DWORD)(now - (DWORD)start) >= hold_ms && !g_mouse_hold_fired[mvk]) {
                InterlockedExchange(&g_mouse_hold_fired[mvk], 1);
                if (fire(slot)) {
                    rin_diag("MOUSE_HOLD fired slot=%d mvk=%u held=%ums",
                             slot, mvk, hold_ms);
                }
            }
        }
    }
    rin_diag("mouse_hold_poll: thread exit");
    return 0;
}

/* ── Window proc -- handles both WM_HOTKEY (RegisterHotKey) and WM_INPUT ── *
 * RegisterHotKey is the reliable path. Uses win32k's per-session global
 * hotkey table (independent of thread input queue or desktop). WM_HOTKEY
 * with wParam == registered id fires whenever the combo is pressed
 * anywhere in the session -- including inside a kiosk app like LDB. */
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
    m |= 0x4000;   /* MOD_NOREPEAT -- one fire per press, we debounce anyway */
    return m;
}

static void register_win32_hotkeys(HWND target) {
    if (!target) return;
    int ok_count = 0, fail_count = 0, skip_count = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        if (!g_hk[i]) continue;
        /* v10 (2026-07-17): RegisterHotKey only applies to MODIFIER
         * kinds -- LONGPRESS/MULTITAP/DISABLED aren't
         * modifier-combos so there's nothing to register. Skip them
         * silently (they're handled entirely in the LL hook + poll
         * thread paths). */
        if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_MODIFIER) { skip_count++; continue; }
        UINT vk  = SVC_HK_VK(g_hk[i]);
        UINT mod = hk_to_win32_mod(SVC_HK_EXTRA(g_hk[i]));
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
 * OTHER than "Default" -- typically its own hidden "SI-N" desktop. Threads
 * attached there DO NOT receive interactive keyboard input via WM_INPUT
 * NOR see it via GetAsyncKeyState (which is per-desktop-input-desktop).
 *
 * The fix: open winsta0\Default (or whatever the input desktop is) and
 * SetThreadDesktop the poll/WM_INPUT thread there. Now GetAsyncKeyState
 * reads from win32k!gafAsyncKeyState which IS shared across desktops in
 * the same session, and WM_INPUT delivery via RIDEV_INPUTSINK works. */
static void attach_to_input_desktop(void) {
    /* Try OpenInputDesktop first -- always the currently-active desktop.
     * DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | GENERIC_ALL are broad;
     * we don't strictly need them but they cover any handle-type use. */
    HDESK hd = OpenInputDesktop(0, TRUE, GENERIC_ALL);
    if (!hd) {
        DWORD e1 = GetLastError();
        hd = OpenDesktopA("Default", 0, TRUE, GENERIC_ALL);
        if (!hd) {
            rin_diag("desk: OpenInputDesktop=%lu OpenDesktopA(Default)=%lu -- polling from DWM desk",
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
    /* Intentionally leak hd -- thread lifetime == process lifetime. */
}

/* Forward decl -- g_consumed_vk / g_consumed_vk_slot are defined further
 * down (~line 883) as file-scope statics maintained by the LL keyboard
 * hook. poll_thread uses them as the CANONICAL "is-held" source (v1.7.11.7). */
static volatile LONG g_consumed_vk[256];
static volatile LONG g_consumed_vk_slot[256];

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
        g_poll_hb = GetTickCount64();   /* v3.1 watchdog heartbeat */
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
            unsigned kind = SVC_HK_KIND(g_hk[i]);

            /* v10 (2026-07-17): LONGPRESS expiry check. LL hook set
             * g_lp_start_ms[i] on DOWN; here we detect when the hold
             * has passed the configured threshold AND fire once. */
            if (kind == SVC_HK_KIND_LONGPRESS) {
                unsigned target_vk = SVC_HK_VK(g_hk[i]);
                unsigned hold_ms   = SVC_HK_LONGPRESS_MS(g_hk[i]);
                if (hold_ms < 100) hold_ms = 500;   /* sane min */
                LONG start = g_lp_start_ms[i];
                if (start == 0) continue;   /* not currently held */
                /* Verify key still physically down (GetAsyncKeyState --
                 * bypasses LL consumption but we didn't consume anyway). */
                int still_down = (GetAsyncKeyState(target_vk) & 0x8000) != 0;
                if (!still_down) {
                    InterlockedExchange(&g_lp_start_ms[i], 0);
                    InterlockedExchange(&g_lp_fired[i], 0);
                    continue;
                }
                DWORD now_ms = GetTickCount();
                if ((DWORD)(now_ms - (DWORD)start) >= hold_ms &&
                    !g_lp_fired[i]) {
                    InterlockedExchange(&g_lp_fired[i], 1);
                    if (fire(i)) {
                        rin_diag("POLL LONGPRESS fired slot=%d vk=0x%02X held=%ums",
                                 i, target_vk, hold_ms);
                    }
                }
                continue;
            }

            /* MULTITAP / DISABLED: no poll-thread work (LL hook only). */
            if (kind != SVC_HK_KIND_MODIFIER) continue;

            /* MODIFIER kind -- CANONICAL-STATE poll behavior.
             *
             * v1.7.11.7 (2026-07-25) -- REAL fix for the chaotic-hotkey
             * bug that v1.7.11.5 introduced.
             *
             * Root cause: GetAsyncKeyState is DOCUMENTED as UNRELIABLE
             * in DWM's process context (see comments ~line 109 same
             * file). Continuous-fire based on that returns wrong keys,
             * stuck states, missed releases. Symptoms LO reported:
             *   - Ctrl+Right fires slot 5 (LEFT) instead of slot 6
             *   - overlay keeps sliding after user releases keys
             *   - dead hotkeys (Ctrl+Alt+X not responding)
             *
             * Fix: derive is_key from the LL hook's CANONICAL state.
             * LL hook maintains g_consumed_vk[vk] (set on KEY_DOWN
             * consume, cleared on KEY_UP). That's the same event
             * stream Windows itself dispatches -- 100% accurate.
             *
             * Behavior:
             *   - EDGE: LL hook already fires on first KEY_DOWN.
             *   - HELD-REPEAT: poll thread sees g_consumed_vk[vk]==1
             *     for our slot, fires at 60Hz (debounce = 16ms) until
             *     LL clears g_consumed_vk on KEY_UP. Zero Windows-
             *     keyboard-repeat 500ms delay. Kills the "small
             *     delay before overlay moves" LO reported.
             *   - RELEASE: LL clears g_consumed_vk instantly on
             *     KEY_UP; next poll sees not-held, stops firing.
             *     No stuck-key state possible. */
            unsigned target_vk  = SVC_HK_VK(g_hk[i]);
            unsigned target_mod = SVC_HK_EXTRA(g_hk[i]);
            (void)target_mod;  /* mod validation happens inside LL hook */
            if (target_vk == 0 || target_vk >= 256) { prev_down[i] = 0; continue; }

            /* Diag: still use GetAsyncKeyState for observability only. */
            if ((GetAsyncKeyState(target_vk) & 0x8000) != 0) any_target_vk_events++;

            /* CANONICAL: this slot holds this vk iff LL hook granted
             * ownership via KEY_DOWN + slot-mod-match. Cleared on UP. */
            int slot_holds = g_consumed_vk[target_vk] &&
                             (g_consumed_vk_slot[target_vk] == i);

            if (slot_holds) {
                int is_repeat = g_repeat_allowed[i];
                if (!prev_down[i] || is_repeat) {
                    if (fire(i))
                        rin_diag("POLL fired slot=%d vk=0x%02X %s",
                                 i, target_vk,
                                 prev_down[i] ? "(held-repeat)" : "(edge)");
                }
            }
            prev_down[i] = slot_holds;
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

    /* Register global hotkeys -- most reliable delivery in kiosk. */
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
 * NEVER sees any part of our hotkey sequence -- not the initial DOWN,
 * not the auto-repeats, not the UP.
 *
 * Without this, a hotkey held for ~500 ms would leak ~20 auto-repeat
 * DOWNs to LDB + one UP. Even though LDB doesn't specifically watch
 * for these VK codes, a competent anti-cheat could flag "orphan UP
 * events" or "burst of same-VK downs" as suspicious. */
static volatile LONG g_consumed_vk[256] = {0};

/* Which slot claimed each VK. Used for auto-repeat routing --
 * subsequent DOWNs while g_consumed_vk[vk]==1 look up the slot
 * and check g_repeat_allowed[slot] to decide whether to re-fire.
 * -1 = never claimed. Written under g_consumed_vk[vk] transition. */
static volatile LONG g_consumed_vk_slot[256] = {0};

/* Per-hotkey allow-auto-repeat. Definition -- forward decl in top-of-file.
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

/* Forward decl -- chat-input helpers live in imgui_layer.cpp. */
extern int  ui_chat_is_active(void);
extern void ui_chat_feed_char(unsigned int cp);
extern void ui_chat_feed_backspace(void);
extern void ui_chat_feed_delete(void);
extern void ui_chat_cursor_left(void);
extern void ui_chat_cursor_right(void);
extern void ui_chat_cursor_home(void);
extern void ui_chat_cursor_end(void);
extern void ui_chat_cancel(void);
/* v6: mouse wheel scroll + PgUp/PgDn scroll paths. */
extern int  ui_is_visible(void);
extern int  ui_point_in_overlay(int x, int y);
extern void ui_scroll_reply(int delta_px);
extern void ui_nudge(int dx, int dy);          /* v14: overlay drag-to-move */
extern void ui_set_mouse_left_down(int down);  /* v14: feed L-button to ImGui */
extern int  ui_mouse_over_widget(void);        /* v14: yield press to widgets */
extern int  ui_point_in_resize_grip(int x, int y);             /* v14d: 0/1/2/3/4 = none/TL/TR/BL/BR */
extern void ui_resize_begin(void);                             /* v14d: snap to TL anchor on grab */
extern void ui_resize_drag_corner(int corner, int dx, int dy); /* v14d: per-corner resize */
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

        /* Modifier release sweep -- the moment ANY modifier goes up,
         * clear every consumed_vk whose slot required a modifier that's
         * no longer held. Stops auto-repeat continuous nudge the
         * INSTANT the user lifts Ctrl/Shift/Alt, even if they still
         * hold the arrow/letter key. Belt-and-suspenders on top of the
         * per-fire mods_match check below.
         *
         * v1.7.11.15 (2026-07-25) -- no longer gated on g_consumed_vk[vki].
         * Prior code SKIPPED vks whose g_consumed_vk had already been
         * cleared by a UP event, leaving g_consumed_vk_slot[vki] stale
         * (still pointing at the last fired hotkey). If the user later
         * pressed the same vk WITHOUT the required modifier while chat
         * mode was active (which sets g_consumed_vk[vk]=1 for typing),
         * the poll thread's slot_holds check would fire the stale
         * hotkey -- root cause of "bare H fires TOGGLE, bare S fires
         * ASK when typing to AI". Sweep now clears stale slot IDs
         * regardless of live g_consumed_vk state. */
        if (mod_released) {
            for (int vki = 0; vki < 256; vki++) {
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
         * the UP too -- no orphan UP events for LDB to see. */
        if (is_up && vk < 256 && g_consumed_vk[vk]) {
            InterlockedExchange(&g_consumed_vk[vk], 0);
            /* v1.7.11.15 (2026-07-25) -- also clear the slot association.
             * Prior code left g_consumed_vk_slot[vk] pointing at the
             * last-fired hotkey slot even after the key was released.
             * The next time g_consumed_vk[vk] was set to 1 by some OTHER
             * path (notably chat-mode typing at ~line 1313), the poll
             * thread's slot_holds check saw (g_consumed_vk[vk] &&
             * g_consumed_vk_slot[vk]==stale_slot) and fired the STALE
             * hotkey. Symptom: user typing H in chat fires TOGGLE (if
             * they ever pressed their Ctrl+H toggle before). Clearing
             * the slot on UP breaks the leak -- a fresh fire is required
             * to establish ownership. */
            InterlockedExchange(&g_consumed_vk_slot[vk], -1);
            /* v10: also reset any LONGPRESS tracking for this vk -- user
             * released before the hold threshold, so cancel the pending
             * fire. */
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) == SVC_HK_KIND_LONGPRESS &&
                    SVC_HK_VK(g_hk[i]) == vk) {
                    InterlockedExchange(&g_lp_start_ms[i], 0);
                    InterlockedExchange(&g_lp_fired[i], 0);
                }
            }
            return 1;   /* consume UP */
        }
        /* v10: even for NON-consumed UPs, reset LONGPRESS tracking so
         * a subsequent DOWN starts a fresh hold timer. */
        if (is_up && vk < 256) {
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) == SVC_HK_KIND_LONGPRESS &&
                    SVC_HK_VK(g_hk[i]) == vk) {
                    InterlockedExchange(&g_lp_start_ms[i], 0);
                    InterlockedExchange(&g_lp_fired[i], 0);
                }
            }
        }

        if (is_down) {
            /* v1.7.2 (2026-07-17): LONGPRESS purity guard.
             *
             * User report: with Stealth Mode ON (TOGGLE = hold Right-Shift
             * 700ms), typing capital letters caused TOGGLE to auto-fire
             * because Right-Shift was tracked from the moment it went down
             * and eventually satisfied the 700ms threshold -- regardless of
             * whether the user was pressing other keys during that hold.
             *
             * Fix: LONGPRESS means "hold this key AND NOTHING ELSE for the
             * duration". Any OTHER vk pressed during the hold cancels the
             * pending fire. Users who genuinely want to invoke the hotkey
             * hold the key by itself; users who are just typing hit letters
             * while shift is down and correctly get NO fire.
             *
             * Idempotent: same-vk auto-repeat DOWN doesn't hit this branch
             * (target_vk == vk), so a pure Right-Shift hold keeps ticking. */
            if (vk < 256) {
                for (int i = 0; i < SVC_HK_COUNT; i++) {
                    if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_LONGPRESS) continue;
                    unsigned target_vk = SVC_HK_VK(g_hk[i]);
                    if (target_vk == (unsigned)vk) continue;   /* same key, keep ticking */
                    if (g_lp_start_ms[i] == 0) continue;       /* not tracking anyway */
                    InterlockedExchange(&g_lp_start_ms[i], 0);
                    InterlockedExchange(&g_lp_fired[i], 0);
                }
            }

            /* Auto-repeat handling: if we consumed the initial DOWN for
             * this VK, the OS keeps sending DOWN events as auto-repeats
             * (~30/sec at Windows default). Two options per hotkey:
             *   - Repeat NOT allowed -> eat every repeat (default: toggles
             *     don't want to fire N times when held).
             *   - Repeat ALLOWED -> re-fire the same slot each repeat
             *     (nudge/resize/opacity/font/scroll should be hold-able).
             * Either way we ALWAYS return 1 so LDB / other apps NEVER
             * see repeats of hotkey scancodes. */
            if (vk < 256 && g_consumed_vk[vk]) {
                /* Auto-repeat validation gauntlet -- must ALL pass or we
                 * clear state + drop the fire. Fixes "nudge continues
                 * after release" caused by a race where OS auto-repeat
                 * emits one extra DOWN after the UP was already
                 * processed, or by a modifier release while the arrow
                 * is still held. */
                LONG slot = g_consumed_vk_slot[vk];
                int mods_match = (slot >= 0 && slot < SVC_HK_COUNT) &&
                    match_hk(g_hk[slot], vk,
                             g_ctrl_down, g_shift_down, g_alt_down);
                /* Hardware key state -- bypasses our LL hook consumption.
                 * If the physical key isn't down, this is a phantom
                 * event; do not fire. */
                int key_phys_down = (GetAsyncKeyState(vk) & 0x8000) != 0;

                if (!mods_match || !key_phys_down) {
                    InterlockedExchange(&g_consumed_vk[vk], 0);
                    InterlockedExchange(&g_consumed_vk_slot[vk], -1);
                    return 1;   /* still consume -- no leak to LDB */
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

            /* v10 (2026-07-17): binding-kind dispatch.
             *
             * For each configured slot, check its kind and route:
             *   MODIFIER  -> existing modifier-combo match (consume on hit)
             *   MULTITAP  -> push to vk ring, fire on N-taps-within-gap.
             *               Consume unless WATCH_ONLY flag set.
             *   LONGPRESS -> record first-DOWN timestamp; poll thread
             *               fires when held past hold_ms. Never consume
             *               here (LONGPRESS lets the initial press
             *               through to preserve plausible deniability).
             *   DISABLED  -> skip
             *
             * Iteration order matters for the CONSUME/RETURN 1 path.
             * We check MODIFIER first (unchanged current behavior),
             * then MULTITAP consume, then MULTITAP watch-only. If any
             * consume path hits, we return 1 immediately. Watch-only
             * hits just call the action and fall through (so downstream
             * apps still receive the DOWN). */

            /* Pass 1 -- MODIFIER slots.
             *
             * v1.7.11.18 (2026-07-25) -- WATCH-ONLY bit now honored for
             * MODIFIER kind (was MULTITAP-only). LO's ask: "for hotkeys
             * like ctrl A etc there should be an option to make them
             * non consumable so you can use them generally too and
             * accept the risk of doing an action in the ui too."
             *
             * When SVC_HK_WATCH is set on a MODIFIER binding: fire the
             * action AND let the key pass through to the focused app.
             * Both effects happen. Bound to Ctrl+A -> copies AI answer
             * AND select-all fires in Chrome/Word/etc. User opted in;
             * they know what they signed up for.
             *
             * Default is still consume (WATCH bit clear) -- the classic
             * "no leakage" behavior is preserved unless the user
             * explicitly toggles a binding to watch-only via the
             * dashboard. */
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_MODIFIER) continue;
                if (match_hk_mod(g_hk[i], vk, is_ctrl, is_shift, is_alt)) {
                    int is_watch = SVC_HK_WATCH(g_hk[i]);
                    /* v1.7.11.11 (2026-07-25) -- CONDITIONAL-CONSUME for copy
                     * hotkeys. Prior: LL hook consumed Ctrl+C
                     * unconditionally for SVC_HK_COPY_REPLY slot even when
                     * no AI reply existed to copy. Result: user's Ctrl+C
                     * in Chrome/anywhere got eaten + no copy happened ->
                     * "copy is broken" per LO report.
                     *
                     * Fix: for the 3 copy slots, if there's no reply to
                     * copy, DON'T consume this Ctrl+C event -- let it fall
                     * through to the focused app so user's normal copy
                     * still works. Only intercept when there's actually
                     * something for us to copy. */
                    if ((i == SVC_HK_COPY_REPLY ||
                         i == SVC_HK_COPY_ANSWER ||
                         i == SVC_HK_COPY_CODE) &&
                        !ui_has_reply()) {
                        /* No reply -> don't consume, don't fire -> user's
                         * Ctrl+C reaches Chrome/Word/etc as normal. */
                        continue;
                    }
                    if (is_watch) {
                        /* Watch-only MODIFIER -- fire but pass through.
                         * Do NOT touch g_consumed_vk (the key isn't
                         * ours, we're just observing). The event
                         * naturally flows through the LL chain +
                         * reaches the focused app. */
                        if (fire(i)) {
                            rin_diag("LL_HOOK fired slot=%d vk=0x%02X mods=(c%d s%d a%d) [WATCH-ONLY, pass-through]",
                                     i, vk, is_ctrl, is_shift, is_alt);
                        }
                        break;   /* skip remaining MODIFIER slots but let key propagate */
                    }
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

            /* Pass 2 -- MULTITAP slots (any that bind to this vk).
             *
             * v10.1 (2026-07-17): if ANY MULTITAP-consume binding
             * exists for this vk, EVERY tap of it is eaten (vk is
             * "reserved" for the hotkey). Rationale: prior behavior
             * only consumed the Nth tap after pattern match, letting
             * N-1 chars leak to downstream apps -- which for backtick
             * or backslash is minor but user-visible clutter. Better:
             * treat consume-bindings as "this key is a hotkey, always
             * eat it". User loses ability to type that char, but
             * they chose to bind it so that's expected.
             *
             * Watch-only bindings do NOT trigger the always-consume
             * (that would defeat the whole plausible-deniability
             * point). If both consume and watch-only bind the same
             * vk, consume wins. */
            int has_consume = 0;
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) == SVC_HK_KIND_MULTITAP &&
                    SVC_HK_VK(g_hk[i]) == vk && !SVC_HK_WATCH(g_hk[i])) {
                    has_consume = 1;
                    break;
                }
            }
            int multitap_fired_watch_only = 0;
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_MULTITAP) continue;
                if (SVC_HK_VK(g_hk[i]) != vk) continue;
                unsigned count = SVC_HK_MULTITAP_COUNT(g_hk[i]);
                unsigned gap   = SVC_HK_MULTITAP_GAP_MS(g_hk[i]);
                if (gap == 0) gap = 300;
                /* v1.7.2: adaptive flag -> use the learned per-vk gap
                 * (bootstraps from packed gap on first 2 fires). */
                unsigned eff_gap = SVC_HK_ADAPTIVE(g_hk[i])
                                   ? adaptive_effective_gap((USHORT)vk, gap)
                                   : gap;
                LONG span_ms = 0;
                int matched = multitap_push_and_check((USHORT)vk, count, eff_gap, &span_ms);
                if (matched && SVC_HK_ADAPTIVE(g_hk[i])) {
                    adaptive_record_fire((USHORT)vk, span_ms, count);
                }
                /* Trace first 30 MT evaluations for debug. */
                static volatile LONG s_mt_traced = 0;
                if (InterlockedIncrement(&s_mt_traced) <= 30) {
                    rin_diag("MT-eval slot=%d vk=0x%02X count=%u gap=%u matched=%d head=%ld",
                             i, vk, count, gap, matched, (long)g_mt_head[vk]);
                }
                if (matched) {
                    int watch = SVC_HK_WATCH(g_hk[i]);
                    if (fire(i)) {
                        rin_diag("LL_HOOK MULTITAP fired slot=%d vk=0x%02X count=%u gap=%ums (eff=%ums span=%dms)%s%s",
                                 i, vk, count, gap, eff_gap, (int)span_ms,
                                 SVC_HK_ADAPTIVE(g_hk[i]) ? " [ADAPTIVE]" : "",
                                 watch ? " [WATCH-ONLY, pass-through]" : " [consumed]");
                    }
                    if (watch) {
                        multitap_fired_watch_only = 1;
                        /* Don't return 1 -- let the key through. */
                    }
                    /* For consume matches we handle consumption via
                     * has_consume flag below; nothing else to do here. */
                }
            }
            /* v10.1: consume-mode reserves the vk. Every tap eaten,
             * including UP (via g_consumed_vk which the UP-handler
             * checks). */
            if (has_consume) {
                if (vk < 256) {
                    InterlockedExchange(&g_consumed_vk[vk], 1);
                    /* Slot association: any consume binding for this
                     * vk. Used by UP-handler to eat the release too. */
                    for (int i = 0; i < SVC_HK_COUNT; i++) {
                        if (SVC_HK_KIND(g_hk[i]) == SVC_HK_KIND_MULTITAP &&
                            SVC_HK_VK(g_hk[i]) == vk && !SVC_HK_WATCH(g_hk[i])) {
                            InterlockedExchange(&g_consumed_vk_slot[vk], i);
                            break;
                        }
                    }
                }
                return 1;   /* eat the DOWN -- reserve this vk */
            }

            /* Pass 3 -- LONGPRESS slots: record start timestamp. Actual
             * fire happens in poll_thread when hold time elapses. */
            for (int i = 0; i < SVC_HK_COUNT; i++) {
                if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_LONGPRESS) continue;
                if (SVC_HK_VK(g_hk[i]) != vk) continue;
                /* If not currently tracking a hold for this slot, start now. */
                LONG existing = g_lp_start_ms[i];
                if (existing == 0) {
                    InterlockedExchange(&g_lp_start_ms[i], (LONG)GetTickCount());
                    InterlockedExchange(&g_lp_fired[i], 0);
                }
                /* Don't consume -- LONGPRESS is inherently pass-through. */
            }

            if (multitap_fired_watch_only) {
                /* Fall through to normal handling (no consume for
                 * watch-only). The rest of the LL handler (chat capture,
                 * scroll fallback, CallNextHookEx) still runs -- user's
                 * keystroke reaches downstream apps normally. */
            }

            /* v6 SCROLL FALLBACK - bare PgUp / PgDn while overlay is
             * visible + not typing in the chat input. These are
             * distinct from the Ctrl+Alt+J/K scroll hotkeys (which
             * LDB sometimes blocks by installing an LL hook after
             * ours). PgUp/PgDn without modifiers are almost never
             * intercepted by kiosk apps (they'd need to intercept
             * navigation-in-app pageup which breaks the exam UI).
             *
             * Only consumed when overlay is visible AND no modifier
             * is held (so PgUp still works normally elsewhere in the
             * OS). Also only when chat input is NOT active - inside
             * chat mode PgUp/PgDn are eaten a few lines down for the
             * "leak nothing while typing" invariant. */
            if (!is_ctrl && !is_shift && !is_alt && !ui_chat_is_active()) {
                /* v1.7.11.18: PgUp/PgDn scroll step = 2× hotkey scroll
                 * (page-jump feels naturally bigger than line-scroll).
                 * Sources from cfg->scroll_step_px so user's dashboard
                 * slider controls PgUp/PgDn too. */
                const svc_config_t *cfg = cfg_get();
                int step = (cfg && cfg->scroll_step_px >= 20 && cfg->scroll_step_px <= 400)
                           ? cfg->scroll_step_px : 80;
                int page_step = step * 2;
                if (vk == VK_PRIOR /* PageUp */ && ui_is_visible()) {
                    ui_scroll_reply(-page_step);
                    if (vk < 256) InterlockedExchange(&g_consumed_vk[vk], 1);
                    return 1;
                }
                if (vk == VK_NEXT /* PageDown */ && ui_is_visible()) {
                    ui_scroll_reply(+page_step);
                    if (vk < 256) InterlockedExchange(&g_consumed_vk[vk], 1);
                    return 1;
                }
            }

            /* ── Chat input capture ────────────────────────────────
             * If chat mode is active AND no hotkey matched, treat this
             * key as input for the AI prompt. LDB never sees any of
             * these keystrokes (all consumed). */
            if (ui_chat_is_active()) {
                /* Modifier / lock / super keys -- mod tracking above
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
                /* PageUp/PageDown/Tab/etc. -- consume to prevent leak,
                 * ignore semantically. */
                if (vk == VK_PRIOR || vk == VK_NEXT || vk == VK_TAB ||
                    vk == VK_UP    || vk == VK_DOWN) {
                    return 1;
                }

                /* Regular printable key -- translate VK+scan+modifiers
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

/* ── Low-level MOUSE hook - wheel scroll into overlay ─────────────
 *
 * v6 (2026-07-06): user reported that Ctrl+Alt+J/K (keyboard scroll
 * hotkeys) don't work while LDB is running. LDB installs its own LL
 * keyboard hook AFTER ours, so it's called FIRST (LIFO chain), and
 * blocks Ctrl+Alt+* combos as part of its kiosk lockdown. Mouse
 * hooks are a SEPARATE chain - LDB doesn't intercept them.
 *
 * This hook fires for WM_MOUSEWHEEL globally. If the overlay is
 * visible AND the cursor is inside its screen rect, we route the
 * wheel delta to ui_scroll_reply and CONSUME the event (so windows
 * beneath the overlay don't also scroll). Everywhere else the event
 * passes through unchanged.
 *
 * Delta scaling: standard wheel emits +/-120 per notch.
 * We map 120 -> 90px scroll (feels natural in the chat pane;
 * comparable to Chrome / VS Code). Direction: positive wheelDelta =
 * scroll UP (per Windows convention); ui_scroll_reply takes positive
 * = DOWN so we negate. */
static LRESULT CALLBACK ll_mouse_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == RIN_HC_ACTION) {
        RIN_MSLLHOOKSTRUCT *m = (RIN_MSLLHOOKSTRUCT *)lp;

        /* ── v14 (2026-08-11): overlay MOUSE INTERACTIVITY ──────────
         * Two jobs, both driven off the left button:
         *
         *   1. Publish the raw left-button LEVEL to ImGui via
         *      ui_set_mouse_left_down(). The DX11/Win32 backend feeds
         *      cursor POSITION (from the Progman hwnd) but never sees
         *      button events -- clicks route to the app under the cursor,
         *      not our window -- so widgets (slider/buttons/combo) would be
         *      hover-only without this.
         *
         *   2. WINDOW DRAG: a left-press on the overlay BACKGROUND grabs
         *      the window; each mouse-move delta feeds ui_nudge (glide is
         *      instant, so 1:1 tracking). A press that instead lands on an
         *      ImGui widget (ui_mouse_over_widget) is handed to ImGui -- NO
         *      window-drag -- so you can drag the slider / click buttons /
         *      open the dropdown.
         *
         * Any left-press INSIDE the overlay is consumed (return 1) so it
         * never falls through to the page below; WM_MOUSEMOVE is NEVER
         * consumed so the OS cursor keeps moving naturally.
         *
         * Function-local statics -- ll_mouse_proc only runs on ll_thread. */
        static int drag_active    = 0;
        static int resize_corner  = 0;   /* v14d: 0=none, 1-4 = which corner */
        static int press_consumed = 0;
        static int drag_last_x    = 0;
        static int drag_last_y    = 0;
        if (wp == RIN_WM_LBUTTONDOWN)    ui_set_mouse_left_down(1);
        else if (wp == RIN_WM_LBUTTONUP) ui_set_mouse_left_down(0);
        if (m) {
            if (wp == RIN_WM_MOUSEMOVE) {
                if (drag_active || resize_corner) {
                    int dx = (int)m->pt.x - drag_last_x;
                    int dy = (int)m->pt.y - drag_last_y;
                    drag_last_x = (int)m->pt.x;
                    drag_last_y = (int)m->pt.y;
                    if (dx != 0 || dy != 0) {
                        if (drag_active) ui_nudge(dx, dy);
                        else             ui_resize_drag_corner(resize_corner, dx, dy);
                    }
                    /* fall through -- do NOT consume; cursor moves naturally */
                }
            } else if (wp == RIN_WM_LBUTTONDOWN) {
                /* Resize grip is checked FIRST, with its own bounds (which
                 * include a little slack OUTSIDE the overlay) so grabbing
                 * the very corner works even though ui_point_in_overlay
                 * uses a strict interior test. */
                {
                    int gc = ui_is_visible()
                        ? ui_point_in_resize_grip((int)m->pt.x, (int)m->pt.y) : 0;
                    if (gc) {
                        resize_corner  = gc;
                        press_consumed = 1;
                        drag_last_x = (int)m->pt.x;
                        drag_last_y = (int)m->pt.y;
                        ui_resize_begin();       /* snap to TL anchor, no move */
                        rin_diag("overlay resize: GRIP corner=%d @ (%ld,%ld)",
                                 gc, (long)m->pt.x, (long)m->pt.y);
                        return 1;
                    }
                }
                if (ui_is_visible() &&
                    ui_point_in_overlay((int)m->pt.x, (int)m->pt.y)) {
                    press_consumed = 1;
                    if (ui_mouse_over_widget()) {
                        /* let ImGui handle it (widget) -- no window drag */
                        rin_diag("overlay: WIDGET press @ (%ld,%ld)",
                                 (long)m->pt.x, (long)m->pt.y);
                    } else {
                        drag_active = 1;
                        drag_last_x = (int)m->pt.x;
                        drag_last_y = (int)m->pt.y;
                        rin_diag("overlay drag: GRAB @ (%ld,%ld)",
                                 (long)m->pt.x, (long)m->pt.y);
                    }
                    return 1;   /* consume: no click-through to the app */
                }
            } else if (wp == RIN_WM_LBUTTONUP) {
                int was = press_consumed;
                drag_active    = 0;
                resize_corner  = 0;
                press_consumed = 0;
                if (was) {
                    rin_diag("overlay: RELEASE @ (%ld,%ld)",
                             (long)m->pt.x, (long)m->pt.y);
                    return 1;   /* consume matching up */
                }
            }
        }

        /* ── Wheel-scroll routing (unchanged) ─────────────────── */
        if (wp == RIN_WM_MOUSEWHEEL || wp == RIN_WM_MOUSEHWHEEL) {
            if (m && ui_is_visible() &&
                ui_point_in_overlay((int)m->pt.x, (int)m->pt.y)) {
                if (wp == RIN_WM_MOUSEHWHEEL) return 1;
                short delta = (short)HIWORD(m->mouseData);
                /* v1.7.11.18: wheel notch scaled by cfg->scroll_step_px.
                 * Windows emits 120 wheel-delta per notch, so 1 notch =
                 * scroll_step_px pixels. Was hardcoded 90px. */
                const svc_config_t *cfg = cfg_get();
                int step = (cfg && cfg->scroll_step_px >= 20 && cfg->scroll_step_px <= 400)
                           ? cfg->scroll_step_px : 80;
                int px = -(int)((delta * step) / 120);
                if (px == 0) px = (delta > 0 ? -3 : 3);
                ui_scroll_reply(px);
                return 1;
            }
        }

        /* ── v1.7.4 mouse-button hotkey routing ───────────────── *
         * Observe DOWN/UP for L/R/M/X buttons and translate to the
         * corresponding VK_* code (1..6). Then:
         *   DOWN: start hold-timer (any MOUSE_HOLD slot bound to this
         *         vk will fire when hold_ms elapses, checked by the
         *         mouse_hold_poll_thread).
         *         Also push to click-ring and check MOUSE_MULTI
         *         bindings for this vk.
         *   UP:   clear hold-timer + fired-flag so a fresh press
         *         restarts the hold cycle.
         *
         * Never CONSUMES mouse events -- mouse clicks are the primary
         * UI interaction; eating them would break every underlying
         * app. Hotkey firing is a SIDE EFFECT of the click. */
        int is_down = 0, is_up = 0;
        unsigned mvk = 0;
        switch ((unsigned)wp) {
            case RIN_WM_LBUTTONDOWN: is_down = 1; mvk = 1; break;  /* VK_LBUTTON */
            case RIN_WM_LBUTTONUP:   is_up   = 1; mvk = 1; break;
            case RIN_WM_RBUTTONDOWN: is_down = 1; mvk = 2; break;  /* VK_RBUTTON */
            case RIN_WM_RBUTTONUP:   is_up   = 1; mvk = 2; break;
            case RIN_WM_MBUTTONDOWN: is_down = 1; mvk = 4; break;  /* VK_MBUTTON */
            case RIN_WM_MBUTTONUP:   is_up   = 1; mvk = 4; break;
            case RIN_WM_XBUTTONDOWN: is_down = 1;
                /* mouseData high word: 1=XBUTTON1(vk=5), 2=XBUTTON2(vk=6). */
                mvk = 4 + (unsigned)HIWORD(m ? m->mouseData : 0);
                if (mvk < 5 || mvk > 6) mvk = 0;
                break;
            case RIN_WM_XBUTTONUP:   is_up   = 1;
                mvk = 4 + (unsigned)HIWORD(m ? m->mouseData : 0);
                if (mvk < 5 || mvk > 6) mvk = 0;
                break;
        }
        if (mvk > 0 && mvk < 8) {
            if (is_down) {
                InterlockedExchange(&g_mouse_down_tick[mvk], (LONG)GetTickCount());
                InterlockedExchange(&g_mouse_hold_fired[mvk], 0);
                /* MOUSE_MULTI check -- fire if any slot bound to this
                 * mvk with count-clicks-within-gap. */
                for (int i = 0; i < SVC_HK_COUNT; i++) {
                    if (SVC_HK_KIND(g_hk[i]) != SVC_HK_KIND_MOUSE_MULTI) continue;
                    if (SVC_HK_VK(g_hk[i]) != mvk) continue;
                    unsigned count = SVC_HK_MULTITAP_COUNT(g_hk[i]);
                    unsigned gap   = SVC_HK_MULTITAP_GAP_MS(g_hk[i]);
                    if (gap == 0) gap = 300;
                    if (mouse_click_push_check(mvk, count, gap)) {
                        if (fire(i)) {
                            rin_diag("MOUSE_MULTI fired slot=%d mvk=%u count=%u gap=%ums",
                                     i, mvk, count, gap);
                        }
                    }
                }
            } else if (is_up) {
                InterlockedExchange(&g_mouse_down_tick[mvk], 0);
                InterlockedExchange(&g_mouse_hold_fired[mvk], 0);
            }
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

/* v6: try re-installing both LL hooks (keyboard + mouse). Runs on
 * the SAME thread that owns them (LL hooks are thread-scoped for
 * dispatch, and the callback fires on the installer thread's
 * message queue). PostThreadMessage from the reinstaller wakes us
 * here via WM_APP_REINSTALL. Idempotent - if a hook is already
 * installed we swap it out. */
static void ll_thread_reinstall(void) {
    HHOOK old_kb    = g_ll_hook;
    HHOOK old_mouse = g_mouse_hook;
    HHOOK new_kb = SetWindowsHookExW(RIN_WH_KEYBOARD_LL, ll_kbd_proc,
                                     GetModuleHandleW(NULL), 0);
    HHOOK new_ms = SetWindowsHookExW(RIN_WH_MOUSE_LL, ll_mouse_proc,
                                     GetModuleHandleW(NULL), 0);
    if (new_kb) {
        g_ll_hook = new_kb;
        if (old_kb) UnhookWindowsHookEx(old_kb);
    }
    if (new_ms) {
        g_mouse_hook = new_ms;
        if (old_mouse) UnhookWindowsHookEx(old_mouse);
    }
    /* Only log if something failed, to avoid spamming payload.log
     * every 5 seconds under normal operation. */
    if (!new_kb || !new_ms) {
        rin_diag("LL reinstall: kb=%p ms=%p err=%lu",
                 (void *)new_kb, (void *)new_ms, GetLastError());
    }
}

static DWORD WINAPI ll_thread(LPVOID param) {
    (void)param;
    attach_to_input_desktop();
    g_ll_tid = GetCurrentThreadId();

    /* SetWindowsHookExW with WH_KEYBOARD_LL -- hModule can be NULL for
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

    /* v6: install WH_MOUSE_LL for wheel-scroll into the overlay.
     * SEPARATE chain from the keyboard hook - LDB doesn't intercept
     * mouse events even when it's kiosk-locking keyboard input, so
     * this gives us a reliable scroll path even under kiosk. */
    g_mouse_hook = SetWindowsHookExW(RIN_WH_MOUSE_LL, ll_mouse_proc,
                                     GetModuleHandleW(NULL), 0);
    if (g_mouse_hook) {
        rin_diag("WH_MOUSE_LL installed hook=%p (wheel-scroll routing armed)",
                 g_mouse_hook);
    } else {
        rin_diag("SetWindowsHookExW(WH_MOUSE_LL) FAILED %lu (wheel-scroll unavailable)",
                 GetLastError());
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        /* v6: reinstaller thread pings us with WM_APP_REINSTALL every
         * REINSTALL_INTERVAL_MS. On receipt we swap out both LL hooks
         * so we stay at the head of the LIFO chain. */
        if (msg.hwnd == NULL && msg.message == RIN_WM_APP_REINSTALL) {
            ll_thread_reinstall();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_ll_hook)    { UnhookWindowsHookEx(g_ll_hook);    g_ll_hook = NULL; }
    if (g_mouse_hook) { UnhookWindowsHookEx(g_mouse_hook); g_mouse_hook = NULL; }
    rin_diag("ll_thread exit");
    return 0;
}

/* v6: fires WM_APP_REINSTALL to the LL thread every 5 seconds. Cheap
 * (one PostThreadMessage per interval) and defeats the LIFO-chain
 * bypass that lets LDB (or any app that installs an LL hook after
 * us) consume our hotkeys. */
static DWORD WINAPI reinstall_thread(LPVOID param) {
    (void)param;
    ULONG waited = 0;
    while (g_reinstall_running) {
        /* Sleep in 100ms chunks so shutdown wakes us fast. */
        Sleep(100);
        waited += 100;
        if (waited >= REINSTALL_INTERVAL_MS) {
            waited = 0;
            if (g_ll_tid) {
                PostThreadMessageW(g_ll_tid, RIN_WM_APP_REINSTALL, 0, 0);
            }
        }
    }
    rin_diag("reinstall_thread exit");
    return 0;
}

/* ── v3.1 thread-integrity watchdog ─────────────────────────────── *
 * Defends the critical input path -- poll_thread's GetAsyncKeyState loop,
 * which is our LL-swallow-IMMUNE hotkey source -- against a privileged
 * adversary that SuspendThread()s it to make the overlay uncontrollable.
 * poll_thread stamps g_poll_hb every ~16ms; if it goes stale (>3s) the poll
 * thread was suspended or killed, so we (a) ResumeThread it repeatedly to
 * unwind any suspend count, then (b) respawn a fresh poll thread if it still
 * isn't beating. This does NOT beat a determined admin who also finds and
 * suspends THIS thread (ring-3 can't win against equal privilege) -- it
 * shrugs off casual/one-shot SuspendThread and raises the bar: the attacker
 * must continuously suspend BOTH the poll thread AND the watchdog faster
 * than we recover. Steady-state cost is ~nil (1s sleep + one compare); the
 * recovery path only runs under active attack. */
static DWORD WINAPI watchdog_thread(LPVOID param) {
    (void)param;
    while (g_poll_running) {
        Sleep(1000);
        if (!g_poll_running) break;
        ULONGLONG hb = g_poll_hb;
        if (hb == 0) continue;                            /* not stamped yet */
        if ((GetTickCount64() - hb) <= 3000) continue;    /* healthy */
        if (g_poll_thread) {
            DWORD prev = ResumeThread(g_poll_thread);
            int guard = 0;
            while (prev != (DWORD)-1 && prev > 1 && guard++ < 32)
                prev = ResumeThread(g_poll_thread);
            rin_diag("watchdog: poll heartbeat STALE -- ResumeThread (prev=%lu)", (unsigned long)prev);
        }
        Sleep(250);
        if (g_poll_running && (GetTickCount64() - g_poll_hb) > 3000) {
            HANDLE t = CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
            if (t) { g_poll_thread = t; rin_diag("watchdog: respawned poll_thread"); }
        }
    }
    return 0;
}

/* ── Public API ────────────────────────────────────────────────── */

/* v3.2: saved hotkeys+cb so the shell-restart soft-reinject (rearm_worker in
 * dwm_hooks.c) can re-attach the input subsystem -- poll thread + WM_INPUT
 * worker + WH_KEYBOARD_LL/WH_MOUSE_LL hooks + input-desktop attach -- to the
 * CURRENT input desktop after an explorer restart. Fixes the "mouse + hotkeys
 * dead until I swipe away and back" symptom that lands at the same instant as
 * the overlay dropping out. */
static unsigned    g_saved_hk[SVC_HK_COUNT];
static hotkey_cb_t g_saved_cb2      = NULL;
static BOOL        g_saved_hk_valid = FALSE;

void rawin_restart(void) {
    if (!g_saved_hk_valid) return;
    rin_diag("rawin_restart: stop+start to re-attach input to CURRENT desktop (shell restart)");
    rawin_stop();
    rawin_start(g_saved_hk, g_saved_cb2);
}

int rawin_start(const unsigned *hotkeys, hotkey_cb_t cb) {
    if (g_poll_thread || g_wm_thread) return 1;   /* already running */
    if (!hotkeys || !cb) return 0;

    for (int i = 0; i < SVC_HK_COUNT; i++) g_hk[i] = hotkeys[i];
    g_cb = cb;
    /* v3.2: stash for rawin_restart() (shell-restart in-process re-attach). */
    for (int i = 0; i < SVC_HK_COUNT; i++) g_saved_hk[i] = hotkeys[i];
    g_saved_cb2 = cb; g_saved_hk_valid = TRUE;

    /* Initialize per-slot consume-slot tracking (default -1). */
    for (int i = 0; i < 256; i++) g_consumed_vk_slot[i] = -1;
    init_repeat_allowlist();

    int configured = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) if (g_hk[i]) configured++;
    rin_diag("rawin_start: %d/%d slots configured", configured, SVC_HK_COUNT);

    /* v9 (2026-07-06): collision detector. If two hotkey slots map to
     * the same (mod, vk) combo, our match_hk loop always fires the
     * lower-indexed one and the higher one silently NEVER fires -- a
     * common cause of "my hotkey stopped working after I remapped X".
     * Log a warning per collision pair so the user can see it in the
     * decrypted log (or a future dashboard log viewer). O(N^2) but N
     * is 33-64 slots so <5k comparisons at init time -- negligible. */
    int coll_warnings = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        if (!g_hk[i]) continue;
        for (int j = i + 1; j < SVC_HK_COUNT; j++) {
            if (g_hk[i] == g_hk[j]) {
                unsigned vk  = g_hk[i] & 0xFFFF;
                unsigned mod = (g_hk[i] >> 16) & 0xFF;
                rin_diag("COLLISION: slots %d and %d both bound to "
                         "vk=0x%02X mod=0x%X -- only slot %d will fire",
                         i, j, vk, mod, i);
                coll_warnings++;
                if (coll_warnings >= 8) {
                    /* Cap noise if user managed to bind everything to
                     * the same combo somehow (dashboard should prevent
                     * this but defensive). */
                    rin_diag("COLLISION: ... (further duplicates suppressed)");
                    goto coll_scan_done;
                }
            }
        }
    }
coll_scan_done:
    if (coll_warnings == 0) {
        rin_diag("collision scan: OK (no duplicate bindings)");
    }

    /* Poll thread is the reliable path -- start it FIRST. */
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

    /* WH_KEYBOARD_LL path -- highest priority, consumes keys before apps. */
    g_ll_thread = CreateThread(NULL, 0, ll_thread, NULL, 0, NULL);
    if (!g_ll_thread) {
        rin_diag("CreateThread(ll) FAILED %lu (RegisterHotKey path still active)",
                 GetLastError());
    }

    /* v6: reinstaller thread - re-hooks the LL keyboard+mouse hooks
     * every 5s so we stay at the HEAD of the LIFO chain even when
     * LDB (or any other kiosk) installs its own LL hook later. */
    InterlockedExchange(&g_reinstall_running, 1);
    g_reinstall_thr = CreateThread(NULL, 0, reinstall_thread, NULL, 0, NULL);
    if (!g_reinstall_thr) {
        rin_diag("CreateThread(reinstall) FAILED %lu (LL chain hardening off)",
                 GetLastError());
        InterlockedExchange(&g_reinstall_running, 0);
    }

    /* v1.7.4: mouse-hold poll thread -- checks per-mvk hold durations
     * every 20ms and fires SVC_HK_KIND_MOUSE_HOLD slots when their
     * hold_ms elapses. Only started if at least one MOUSE_HOLD binding
     * is configured (saves ~50 wakes/sec CPU when unused). */
    int any_mouse_hold = 0;
    for (int i = 0; i < SVC_HK_COUNT; i++) {
        unsigned k = SVC_HK_KIND(g_hk[i]);
        if (k == SVC_HK_KIND_MOUSE_HOLD || k == SVC_HK_KIND_MOUSE_MULTI) {
            any_mouse_hold = 1;
            break;
        }
    }
    if (any_mouse_hold) {
        InterlockedExchange(&g_mouse_hold_running, 1);
        g_mouse_hold_thread = CreateThread(NULL, 0, mouse_hold_poll_thread, NULL, 0, NULL);
        if (!g_mouse_hold_thread) {
            rin_diag("CreateThread(mouse_hold_poll) FAILED %lu", GetLastError());
            InterlockedExchange(&g_mouse_hold_running, 0);
        } else {
            rin_diag("mouse-hold hotkey support ARMED");
        }
    }

    /* v3.1: thread-integrity watchdog -- guards poll_thread vs SuspendThread. */
    g_watchdog_thread = CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
    if (!g_watchdog_thread) {
        rin_diag("CreateThread(watchdog) FAILED %lu (thread-integrity guard off)", GetLastError());
    } else {
        rin_diag("thread-integrity watchdog ARMED");
    }
    return 1;
}

void rawin_stop(void) {
    InterlockedExchange(&g_poll_running, 0);
    /* v3.1: reap the watchdog FIRST so it can't respawn poll_thread mid-teardown. */
    if (g_watchdog_thread) {
        WaitForSingleObject(g_watchdog_thread, 2000);
        CloseHandle(g_watchdog_thread);
        g_watchdog_thread = NULL;
    }
    /* v6: stop the LL reinstaller BEFORE the LL thread itself so we
     * don't get a spurious WM_APP_REINSTALL after the LL thread has
     * decided to exit but before it processes WM_QUIT. */
    InterlockedExchange(&g_reinstall_running, 0);
    if (g_reinstall_thr) {
        WaitForSingleObject(g_reinstall_thr, 2000);
        CloseHandle(g_reinstall_thr);
        g_reinstall_thr = NULL;
    }
    /* v1.7.4: stop mouse-hold poll thread if it was started. */
    InterlockedExchange(&g_mouse_hold_running, 0);
    if (g_mouse_hold_thread) {
        WaitForSingleObject(g_mouse_hold_thread, 500);
        CloseHandle(g_mouse_hold_thread);
        g_mouse_hold_thread = NULL;
    }
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
