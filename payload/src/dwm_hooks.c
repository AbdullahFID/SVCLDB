/* ================================================================== *
 * dwm_hooks.c — dwmcore hook implementation.                          *
 *                                                                    *
 * Ported 1:1 from Bypassify v1.3.0 payload (RE'd 2026-07-04, see     *
 * docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md) plus the production            *
 * hooksdll/dwm/dwm_payload.c pattern (25/25 audit pass, 800+ users). *
 *                                                                    *
 * The core anti-lazy-compose trick: hook                             *
 * CDDisplayRenderTarget::PresentNeeded (+ Legacy) and return TRUE    *
 * unconditionally while our overlay is "wake-active". This forces    *
 * DWM to composite every vsync tick, so state changes in our overlay *
 * (hotkey toggles, nudges, opacity bumps) are visible on the very    *
 * next frame with ZERO user interaction — solving the exact bug the  *
 * user reported: "if i press ctrl alt g it wont work but if i press  *
 * it then interact with the ui bam its gone".                        *
 * ================================================================== */

#include "../../shared/common.h"
#include "dwm_hooks.h"
#include "../../shared/log_secure.h"
#include "../../shared/crypto_util.h"
#include "../../shared/str_enc.h"

#include "../../shared/minhook/MinHook.h"

#include <stdio.h>
#include <stdarg.h>

/* ── Detour signatures ── */
/* Present: 6-arg __fastcall (confirmed via Bypassify RE + production audit). */
typedef LONG (__fastcall *pfnCOverlayPresent_t)(
    void *pCtx, void *pLayer, UINT flags, void *a3, DWORD a4, void *a5);

/* PresentNeeded: 1-arg __fastcall taking pThis, returns BOOL. */
typedef BOOL (__fastcall *pfnPresentNeeded_t)(void *pThis);

/* ForceFullDirtyRendering: no args, no return. DANGEROUS to call from
 * arbitrary threads (crashed DWM in our earlier attempt — see git log).
 * Kept as a resolved pointer for future experimentation, never called. */
typedef void (__cdecl *pfnForceFullDirty_t)(void);

/* AddDirtyRect: thin trampoline that adjusts `this` by +0x7790 (Legacy) or
 * +0x7798 (Display) and jumps to the real impl at dwmcore!0xbed84. Real
 * impl signature: `void __thiscall(void *dirty_tracker_this, const float rect[4])`.
 * RECT layout confirmed via RE (dwmcore.dll RVA 0xbed84):
 *   rect[0] = left,  rect[1] = top,  rect[2] = right,  rect[3] = bottom
 * All floats. Real impl UNIONs the new rect with existing tracked rect
 * (min-of-left/top, max-of-right/bottom), so passing a fullscreen rect
 * grows the tracked region to fullscreen.
 *
 * WHY WE CALL THIS: DWM's compositor only re-samples layer regions that
 * are marked "dirty". Without this call, DWM's dirty tracking is driven
 * by user input events (mouse move → tiny dirty rect at cursor). Our
 * overlay pixels outside that dirty rect never get sampled → user sees
 * partial ("quadrant") updates. Calling AddDirtyRect with a fullscreen
 * rect on every PN fire ensures DWM always samples the ENTIRE layer. */
typedef void (__fastcall *pfnAddDirtyRect_t)(void *this_ptr, const float *rect);

/* ScheduleCompositionPass: `void (int arg0, int arg1)` — RE'd 2026-07-05
 * from dwmcore.dll @ RVA 0x12be7c. Global (non-member) function that
 * requests DWM's compositor to schedule the next composition pass.
 * Args verified from disasm:
 *   sub rsp, 0x28
 *   mov eax, ecx                    ; arg0 (int)
 *   mov rcx, [rip+singleton_ptr]    ; global singleton
 *   test rcx, rcx; je .ret          ; if singleton null, no-op
 *   cmp byte [rcx+0x1971], 0        ; if scheduler-enabled flag clear, no-op
 *   je .ret
 *   mov r8d, edx                    ; arg1 (int)
 *   mov edx, eax
 *   call inner_scheduler            ; inner(rcx=singleton, edx=arg0, r8d=arg1)
 *   ret
 *
 * BYPASSIFY EXACT USAGE (RE'd from their payload.dll):
 *   Their PN detour after calling orig fires:
 *     mov edx, 0xffffffff              ; edx = -1
 *     xor ecx, ecx                     ; rcx = 0
 *     call qword ptr [dwmcore+0x10e3fc]
 *   That's `ScheduleCompositionPass(arg0=0, arg1=-1)` — RE-CONFIRMED.
 *   Bypassify's slot [7] @ 0x10e3fc on their build = ScheduleCompositionPass.
 *
 * Effect: every PN fire schedules the NEXT composition immediately →
 * DWM never enters idle → composition stays at native vsync rate.
 * This is the missing piece that keeps DWM at 60Hz continuously. */
typedef void (__stdcall *pfnScheduleCompositionPass_t)(int arg0, int arg1);

/* Extern from imgui_layer.cpp — used by the PN detours + keepalive
 * to gate SCP/ghost activity on overlay visibility (v6.3 flicker fix). */
extern int ui_is_visible(void);

/* ── Originals + state ── */
static pfnCOverlayPresent_t g_orig_present    = NULL;
static pfnPresentNeeded_t   g_orig_pn1        = NULL;   /* CDDisplayRenderTarget */
static pfnPresentNeeded_t   g_orig_pn2        = NULL;   /* CLegacyRenderTarget   */
static pfnForceFullDirty_t  g_force_full_dirty = NULL;  /* NOT hooked, just resolved */
static pfnScheduleCompositionPass_t g_schedule_composition = NULL;  /* the KEY wake fn */
static pfnAddDirtyRect_t    g_add_dirty_display = NULL;   /* CDDisplayRenderTarget::AddDirtyRect */
static pfnAddDirtyRect_t    g_add_dirty_legacy  = NULL;   /* CLegacyRenderTarget::AddDirtyRect  */

/* Hook TARGET addresses (what we passed to MH_CreateHook) — cached at
 * install time so per-detour SEH __except blocks can pass them into
 * hook_crash_bump() for the 3-strike auto-disable. NULL if that hook
 * wasn't installed. */
static void *g_ht_present         = NULL;
static void *g_ht_pn1             = NULL;
static void *g_ht_pn2             = NULL;
static void *g_ht_present_display = NULL;
static void *g_ht_present_legacy  = NULL;
static void *g_ht_rc_window       = NULL;
static void *g_ht_rc_visual       = NULL;
/* g_ht_adr_display / g_ht_adr_legacy REMOVED 2026-07-06 v4.2 —
 * ADR[Display] + ADR[Legacy] hooks were passive RE-mode loggers that
 * observed AddDirtyRect calls without doing functional work. Now
 * uninstalled entirely (9 → 7 hooks, smaller registry footprint,
 * fewer entries the hook integrity monitor needs to keep alive).
 * The trampoline pointers g_add_dirty_{display,legacy} are still
 * resolved (below) because they're a documented no-op fallback for
 * the quadrant fix — leaving them keeps the offsets.blob layout
 * stable without touching the resolver. */

/* Present1/2: hooked to capture the TRUE `this` from DWM's own context.
 * PN's `this` might be virtual-base-adjusted (crashes AddDirtyRect); the
 * `this` inside Present is the top-level object with complete layout,
 * making AddDirtyRect safe to call from inside our Present detour. */
typedef LONG (__fastcall *pfnRTPresent_t)(void *pThis);
static pfnRTPresent_t       g_orig_present_display = NULL;
static pfnRTPresent_t       g_orig_present_legacy  = NULL;

/* RenderContent hooks — CROWN JEWEL from hooksdll (dwm_payload.c line 2524):
 *   CWindowNode::RenderContent(this, pDrawCtx, pResult) is called for each
 *   window's node during composition. pDrawCtx has a field at +0x30 that's
 *   NULL when this render is targeting a CAPTURE buffer (LDB Monitor
 *   continuous screenshot, BitBlt, DXGI Duplication) vs the screen.
 *
 * Using this detection, we set g_in_capture_render while a capture-context
 * RenderContent is in progress. Our Detour_COverlayContextPresent checks
 * this flag and SKIPS drawing our overlay for capture renders — the
 * overlay stays visible on the user's actual monitor but is INVISIBLE in
 * any capture LDB uploads to their server. */
typedef LONG (__fastcall *pfnRenderContent_t)(void *pThis, void *pDrawCtx, BOOL *pResult);
static pfnRenderContent_t   g_orig_rc_window  = NULL;   /* CWindowNode::RenderContent */
static pfnRenderContent_t   g_orig_rc_visual  = NULL;   /* CVisual::RenderContent     */

/* Offset inside CDrawingContext where the "screen render target" pointer
 * lives. If [pDrawCtx + 0x30] == NULL, this render is a CAPTURE pass
 * (verified via hooksdll RE — dwm_payload.c line 2508). */
#define DRAWCTX_CAPTURE_FLAG_OFFSET 0x30

/* Capture-stealth latch — set every time a RenderContent detour observes
 * a capture-context draw. Present detour (fires AFTER RenderContent in
 * the same compose cycle — sometimes SIGNIFICANTLY after) checks if the
 * timestamp is within CAPTURE_LATCH_MS and skips draw if so.
 *
 * CAPTURE_LATCH_MS = 15ms — narrow enough that a missed screen frame
 * is imperceptible (~1 frame at 60fps) but wide enough to cover the
 * gap between RC's decrement and Present's fire during a real capture
 * cycle. Combined with the live counter check (g_in_capture_render > 0)
 * we get most captures via zero-latency detection + this handles the
 * gap where RC returned but Present is still coming. */
#define CAPTURE_LATCH_MS 15
static volatile LONG      g_in_capture_render     = 0;    /* live counter */
static volatile ULONGLONG g_capture_seen_tick     = 0;    /* GetTickCount64() */
static volatile LONG      g_capture_render_hits   = 0;
static volatile LONG      g_present_skips_capture = 0;

/* Hook target registry — cached in hooks_install so the integrity
 * monitor can verify each hook is still armed. Max 16 (we currently
 * install 9). */
#define HOOK_INTEGRITY_MAX 16
/* Per-hook 3-strike auto-disable. Every SEH __except in a detour body
 * bumps its slot's crash_count via hook_crash_bump(). If a hook reaches
 * HOOK_CRASH_THRESHOLD crashes within HOOK_CRASH_WINDOW_MS, we call
 * MH_DisableHook so the detour body stops firing (dwmcore's original
 * function runs directly). Lost feature is preferable to a spiral of
 * compounded exception logs starving the compositor thread. */
#define HOOK_CRASH_THRESHOLD    3
#define HOOK_CRASH_WINDOW_MS    60000
typedef struct {
    void       *target;           /* function address (with JMP prologue) */
    unsigned char orig_first_bytes[16]; /* pre-hook bytes (for diff logging) */
    const char *name;             /* short label for diag */
    volatile LONG      crash_count;    /* consecutive crashes inside window */
    volatile ULONGLONG first_crash_ms; /* GetTickCount64() of oldest counted */
    volatile LONG      auto_disabled;  /* 1 once MH_DisableHook was called  */
} hook_reg_t;
static hook_reg_t g_hook_registry[HOOK_INTEGRITY_MAX] = {0};
static volatile LONG g_hook_reg_count = 0;
static HANDLE g_integrity_thread = NULL;
static volatile LONG g_integrity_running = 0;
static volatile LONG g_integrity_tamper_hits = 0;

static void hook_registry_add(void *target, const char *name) {
    LONG idx = InterlockedIncrement(&g_hook_reg_count) - 1;
    if (idx >= HOOK_INTEGRITY_MAX) return;
    g_hook_registry[idx].target = target;
    g_hook_registry[idx].name   = name;
    g_hook_registry[idx].crash_count = 0;
    g_hook_registry[idx].first_crash_ms = 0;
    g_hook_registry[idx].auto_disabled  = 0;
    __try {
        memcpy(g_hook_registry[idx].orig_first_bytes, target, 16);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

/* Find the registry index whose target equals `key`. Returns -1 if
 * unknown. Only used by the crash bumper; not perf-critical. */
static int hook_registry_index(void *key) {
    if (!key) return -1;
    LONG cnt = g_hook_reg_count;
    if (cnt > HOOK_INTEGRITY_MAX) cnt = HOOK_INTEGRITY_MAX;
    for (LONG i = 0; i < cnt; i++) {
        if (g_hook_registry[i].target == key) return (int)i;
    }
    return -1;
}

/* Forward decl — hook_diag is defined further down; hook_crash_bump
 * below emits diag on threshold trip. */
static void hook_diag(const char *fmt, ...);

/* Called from every detour's __except block. Increments the crash
 * counter for the matching hook, rolls the window if the oldest
 * counted crash is > HOOK_CRASH_WINDOW_MS old, and if the count
 * reaches HOOK_CRASH_THRESHOLD within the window, calls
 * MH_DisableHook on the target. Safe to call with any target
 * pointer (unknown targets are no-op). */
static void hook_crash_bump(void *target, const char *label) {
    int idx = hook_registry_index(target);
    if (idx < 0) return;
    hook_reg_t *r = &g_hook_registry[idx];
    if (r->auto_disabled) return;   /* already disabled — nothing to do */
    ULONGLONG now = GetTickCount64();
    /* Roll window if oldest counted crash is stale. */
    ULONGLONG first = r->first_crash_ms;
    if (first == 0 || (now - first) > HOOK_CRASH_WINDOW_MS) {
        InterlockedExchange64((volatile LONG64 *)&r->first_crash_ms,
                              (LONG64)now);
        InterlockedExchange(&r->crash_count, 1);
        return;
    }
    LONG c = InterlockedIncrement(&r->crash_count);
    if (c >= HOOK_CRASH_THRESHOLD) {
        /* Trip: attempt to disable this specific hook. Race-safe via
         * auto_disabled compare-and-set — only ONE thread should call
         * MH_DisableHook. */
        if (InterlockedCompareExchange(&r->auto_disabled, 1, 0) == 0) {
            MH_STATUS s = MH_DisableHook(target);
            hook_diag("hook AUTO-DISABLED %s (%s) after %ld crashes/60s -> MH_STATUS=%d",
                      r->name ? r->name : "?",
                      label ? label : "?",
                      (long)c, (int)s);
        }
    }
}

/* Early forward decl — hook_diag is defined further down (its body
 * writes to encrypted slog) but hook_integrity_thread below calls it. */
static void hook_diag(const char *fmt, ...);

/* Hook integrity monitor. Every 10s, walk the registry and verify the
 * first byte at each target is `0xE9` (MinHook's JMP rel32 trampoline
 * head). If any hook shows a non-`0xE9` first byte, an anti-cheat has
 * likely restored the original bytes to detect / disable us. Attempt
 * to re-enable via MinHook (MH_EnableHook is idempotent-safe).
 *
 * Never crashes DWM — memcmp is wrapped in SEH, MH_EnableHook is
 * checked for success. Tamper hits logged for post-mortem analysis.
 *
 * CRITICAL — INTERRUPTIBLE SLEEP:
 *   The old code used `Sleep(10000)` which is NOT cancellable. When
 *   the payload's shutdown_watcher fired hooks_uninstall (which sets
 *   g_integrity_running=0 + waits 500ms for this thread), the wait
 *   TIMED OUT because we were mid-Sleep. hooks_uninstall proceeded
 *   without us actually exiting, shutdown_watcher then called
 *   FreeLibraryAndExitThread, launcher's next inject-cycle sweep
 *   VirtualFreeEx'd the payload's code memory. When our Sleep
 *   returned, the CPU tried to execute the next instruction —
 *   which was in decommitted memory. HARD DWM CRASH.
 *
 *   Verified live 2026-07-06 13:10-13:17 EDT: multiple back-to-back
 *   DWM crashes with fault RIP at RVA 0x5462C / 0x54CC0 (inside this
 *   thread's post-Sleep return path).
 *
 *   Fix: chunk the 10s wait into 50ms Sleeps that re-check the flag
 *   on each iteration. Total wall-clock is still ~10s under normal
 *   operation, but shutdown drains within 50ms max. Cost is 200
 *   syscalls per 10s cycle — negligible. No new globals/handles
 *   required, works in a purely user-mode/manual-mapped context. */
static DWORD WINAPI hook_integrity_thread(LPVOID param) {
    (void)param;
    while (g_integrity_running) {
        /* Sleep 10s in 50ms chunks so shutdown wakes us fast. */
        for (int slice = 0; slice < 200 && g_integrity_running; slice++) {
            Sleep(50);
        }
        if (!g_integrity_running) break;
        LONG cnt = g_hook_reg_count;
        if (cnt > HOOK_INTEGRITY_MAX) cnt = HOOK_INTEGRITY_MAX;
        for (LONG i = 0; i < cnt; i++) {
            hook_reg_t *r = &g_hook_registry[i];
            if (!r->target) continue;
            unsigned char first = 0xCC;
            __try {
                first = *(unsigned char *)r->target;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            /* MinHook installs an E9 rel32 JMP for x64 hooks whose
             * target isn't within +/-2GB of the detour (rare) —
             * otherwise E9 rel32. On x64 with large VA space it can
             * also use FF25 (JMP [rip+0]) trampolines. Accept both. */
            if (first != 0xE9 && first != 0xFF) {
                InterlockedIncrement(&g_integrity_tamper_hits);
                hook_diag("integrity TAMPER on %s target=%p first=0x%02X — re-enabling",
                          r->name ? r->name : "?", r->target, first);
                MH_STATUS s = MH_EnableHook(r->target);
                hook_diag("integrity re-enable %s -> %d", r->name ? r->name : "?", (int)s);
            }
        }
    }
    return 0;
}

static present_cb_t         g_present_cb      = NULL;

/* Volatile refs — captured by PN detours on first invocation. Used by
 * hooks_force_wake() to directly trigger a compose pass without waiting. */
static volatile void *g_display_rt = NULL;
static volatile void *g_legacy_rt  = NULL;

/* ── Master switches (Bypassify pattern) ──
 *
 * Two-flag state machine because we have two DIFFERENT shutdown
 * phases and each needs different detour behavior:
 *
 * Phase A — RUNNING (g_active=1, g_stop_draw=0):
 *   Present: draws overlay + calls orig
 *   PN:      returns TRUE  (force continuous compose)
 *
 * Phase B — DRAINING (g_active=1, g_stop_draw=1):
 *   Present: SKIPS drawing overlay + calls orig
 *            (orig writes clean pixels to layer texture)
 *   PN:      returns TRUE  (force DWM to actually composite those
 *            clean frames within the 200ms drain window — critical!
 *            If PN returned FALSE here, DWM would go lazy and our
 *            old overlay pixels would stay on screen indefinitely.)
 *
 * Phase C — DISABLED (g_active=0, hooks about to be unhooked):
 *   Present: SKIPS drawing (g_stop_draw still 1)
 *   PN:      returns orig  (let DWM's normal lazy-compose take over)
 *   Then MH_DisableHook removes the detours entirely. */
static volatile LONG g_active     = 0;   /* 1 while payload is alive (RUNNING + DRAINING) */
static volatile LONG g_stop_draw  = 0;   /* 1 = Present skips our draw callback */

/* Legacy name for compatibility with hooks_bump_wake / hooks_force_wake
 * — set to 1 alongside g_stop_draw so those helpers become no-ops
 * during shutdown. */
#define g_shutdown_flag g_stop_draw

/* Wake countdown. Decremented once per Present frame. While > 0, PN
 * detours return TRUE unconditionally = DWM composites every vsync. */
static volatile LONG g_wake_frames    = 0;

/* Burst-wake worker state. g_burst_end_ms is the TickCount when the
 * current burst expires — updated atomically to extend the burst if
 * new hotkey events arrive. g_burst_running ensures only ONE worker
 * thread runs at a time (multiple hotkey presses in a row = O(1)). */
static volatile ULONG g_burst_end_ms  = 0;
static volatile LONG  g_burst_running = 0;
static volatile LONG  g_burst_interval_ms = 16;
static volatile LONG  g_burst_frames_per_pump = 30;

/* IsOverlayPrevented byte-patch bookkeeping — so we can revert on
 * hooks_uninstall (belt-and-suspenders; Bypassify doesn't revert but
 * we do because a graceful uninstall in the same DWM instance benefits
 * from a clean restore). */
static BYTE  g_iop_saved_bytes[3] = {0};
static void *g_iop_patch_addr     = NULL;
static BOOL  g_iop_patched        = FALSE;

/* Present-depth reentrancy guard — DWM sometimes re-enters Present
 * indirectly. Process-global counter (NOT __declspec(thread) — TLS is
 * broken under manual map). Worst case one dropped frame, no crash. */
static volatile LONG g_present_depth  = 0;
static volatile LONG g_present_calls  = 0;

/* Forward decl — hook_diag body defined below alongside its raw helper. */
static void hook_diag(const char *fmt, ...);

/* Diagnostic — same landmark cadence, routed through hook_diag (which
 * writes to encrypted slog by default, plaintext only when
 * DWM_EXT_TRACE=1). Prevents "Present fired" strings from
 * leaking on disk. */
static void present_diag(int n) {
    if (n != 1 && n != 60 && n != 600 && n != 6000 && n != 60000) return;
    hook_diag("Present fired count=%d wake=%ld", n, (long)g_wake_frames);
}

/* Route dwm-hooks diag through the encrypted slog stream so on-disk
 * strings can't identify our features. When plaintext is required for
 * emergency diag (e.g. very-early-boot or slog broken), set the
 * DWM_EXT_TRACE env var and we'll fall back to the old file.
 *
 * Anti-strings: previously payload_early.txt held signature strings
 * like "hooks: CWindowNode::RenderContent hooked (capture stealth
 * ARMED)" — an anti-cheat could grep the disk for "capture stealth
 * ARMED" and identify us. slog encrypts every line so on-disk bytes
 * are opaque without the per-install key. */
static int g_plaintext_diag = -1;   /* lazy init: -1 unknown, 0 no, 1 yes */
static void hook_diag_raw(const char *msg) {
    if (g_plaintext_diag < 0) {
#if SVCLDB_PRODUCTION_BUILD
        g_plaintext_diag = 0;
#else
        char buf[8];
        DWORD n = GetEnvironmentVariableA("DWM_EXT_TRACE",
                                          buf, sizeof(buf));
        g_plaintext_diag = (n > 0 && buf[0] != '0') ? 1 : 0;
#endif
    }
    /* Encrypted path via slog. */
    slog_writef("payload.log", "dwm: %s", msg);
    /* Plaintext fallback for iteration debug. */
    if (g_plaintext_diag) {
        HANDLE h = CreateFileA(SVC_INSTALL_DIR "\\payload_early.txt",
                               FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        char line[512];
        SYSTEMTIME t; GetSystemTime(&t);
        int n = _snprintf(line, sizeof(line) - 1,
            "[%02d:%02d:%02d.%03d] dwm: %s\r\n",
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, msg);
        if (n > 0) { DWORD w = 0; WriteFile(h, line, (DWORD)n, &w, NULL); }
        CloseHandle(h);
    }
}
/* Forward decl — svcldb_capture_active is defined further down (after
 * the RenderContent detours) but is called from Detour_COverlayContextPresent
 * which lives above them. */
static BOOL svcldb_capture_active(void);

static void hook_diag(const char *fmt, ...) {
    char body[400];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    body[sizeof(body) - 1] = 0;
    hook_diag_raw(body);
}

/* ── The 3 detours (Bypassify pattern) ── */

/* Detour_COverlayContextPresent — main frame hook.
 * Draws overlay into layer texture BEFORE orig, so orig samples the
 * texture with our pixels already composited in.
 *
 * When g_shutdown_flag is set, SKIP the draw (lets orig composite
 * with the underlying app's clean pixels for ~200ms before MinHook
 * gets disabled — that's what naturally clears our overlay off the
 * screen when the payload uninstalls). */
static LONG __fastcall Detour_COverlayContextPresent(
    void *pCtx, void *pLayer, UINT flags, void *a3, DWORD a4, void *a5)
{
    LONG ret = 0;
    int n = InterlockedIncrement(&g_present_calls);
    present_diag(n);

    /* NOTE: g_wake_frames is no longer decremented here — we now match
     * Bypassify exactly by having PN detours ALWAYS return TRUE (see
     * Detour_DisplayPresentNeeded). The wake counter is legacy but the
     * hooks_bump_wake / hooks_force_wake / hooks_burst_wake APIs are
     * preserved as belt-and-suspenders (they still directly fire orig
     * PresentNeeded from arbitrary threads, which can help if DWM
     * happened to be blocked mid-frame). */

    if (InterlockedIncrement(&g_present_depth) > 1) {
        InterlockedDecrement(&g_present_depth);
        return g_orig_present ? g_orig_present(pCtx, pLayer, flags, a3, a4, a5) : 0;
    }

    __try {
        /* Draw BEFORE orig — Bypassify's proven ordering.
         *
         * SKIP CONDITIONS:
         *  1. g_stop_draw (shutdown drain phase)
         *  2. svcldb_capture_active() — checks both live counter AND
         *     tick-based latch (CAPTURE_LATCH_MS after last capture RC).
         *     Latch covers cases where Present fires AFTER RenderContent
         *     returns in the same capture cycle, since Present's args
         *     don't tell us if it's a capture target.
         *
         * OVERRIDE: if svcldb_debug_capture_wants_overlay() is true, we
         * are running an internal debug capture (Ctrl+Shift+Alt+S) that
         * wants overlay pixels IN the shot — do NOT skip overlay draw. */
        extern int svcldb_debug_capture_wants_overlay(void);
        int is_capture   = svcldb_capture_active();
        int want_overlay = svcldb_debug_capture_wants_overlay();
        int skip_draw    = is_capture && !want_overlay;
        if (g_active && !g_stop_draw && !skip_draw && g_present_cb && pLayer) {
            g_present_cb(pCtx, pLayer);
        } else if (skip_draw) {
            LONG n = InterlockedIncrement(&g_present_skips_capture);
            if (n <= 5 || n % 500 == 0) {
                hook_diag("Present: SKIPPED overlay draw #%ld (capture in progress)", n);
            }
        }
        if (g_orig_present) ret = g_orig_present(pCtx, pLayer, flags, a3, a4, a5);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Silently swallow — DWM crash = user desktop dies. */
        hook_diag("Detour_Present: caught exception in body");
        hook_crash_bump(g_ht_present, "Present body");
    }

    InterlockedDecrement(&g_present_depth);
    return ret;
}

/* Detour_CDDisplayRenderTarget_PresentNeeded — Bypassify's core wake trick.
 *
 * EXACT byte-verified Bypassify RE (0x180003520, 41 bytes):
 *   sub rsp, 0x28
 *   call [g_orig_pn1]
 *   movzx ecx, [g_shutdown_flag]
 *   test cl, cl
 *   jne .skip
 *   mov edx, -1
 *   xor ecx, ecx
 *   call [mystery_fn]     ; dwmcore + 0x10e3fc (skipped in our port; safe)
 *   mov al, 1             ; OVERWRITE return = TRUE
 * .skip:
 *   add rsp, 0x28
 *   ret
 *
 * Semantics:
 *   flag == 0 (default): call orig, then RETURN TRUE UNCONDITIONALLY
 *   flag == 1 (shutdown): call orig, return orig's result
 *
 * "Return TRUE from PN" tells DWM "yes, composite this frame" every
 * time DWM asks. Result: DWM composites at native vsync rate (60/120/144
 * Hz) continuously while payload is loaded. No lazy compose, ever. Any
 * state change we make (hotkey, mouse) is visible on the very next
 * vsync tick with ZERO extra work — DWM was already going to composite.
 *
 * This burns ~2-5% GPU continuously. Bypassify accepts this tradeoff
 * for zero-latency responsiveness. We do the same. */
static BOOL __fastcall Detour_DisplayPresentNeeded(void *pThis) {
    /* Capture pThis for hooks_force_wake() belt-and-suspenders. */
    if (!g_display_rt && pThis) {
        g_display_rt = pThis;
        hook_diag("PN1: captured CDDisplayRenderTarget pThis");
    }

    BOOL orig_result = FALSE;
    __try {
        if (g_orig_pn1) orig_result = g_orig_pn1(pThis);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("PN1: exception in orig — passing through FALSE");
        hook_crash_bump(g_ht_pn1, "PN1 orig");
        return FALSE;
    }

    if (!g_active) return orig_result;

    /* v6.3 (2026-07-06 evening) - APP-SWITCH FLICKER FIX:
     *
     * When overlay is HIDDEN, we let DWM idle by returning orig_result
     * (which is DWM's own "do I need to compose?" answer) instead of
     * forcing TRUE. Also skip the SCP call so we don't wake DWM up
     * externally.
     *
     * Why: DirectComposition apps (Chrome, Cursor, Slack, Discord,
     * Electron in general, hardware-accelerated video players) request
     * direct-flip swapchain scanout when they're foreground. That fast
     * path is ONLY available if DWM decides no composition is needed
     * for this frame. Our PN=TRUE + SCP loop keeps forcing composition,
     * blocking those apps from ever direct-flipping.
     *
     * When our overlay is invisible we have NOTHING to render, so
     * blocking direct-flip is pure downside - it caused the visible
     * app-switch flicker user reported ("flickers like hell tryna get
     * to Chrome"). When the overlay IS visible we NEED composition
     * (that's how our pixels get on screen) so the trade-off is
     * inherent - user sees minor flicker while overlay is showing
     * during app switch. Acceptable + matches their manual workaround
     * (hide overlay, switch, show overlay) now made automatic. */
    if (!ui_is_visible()) return orig_result;

    /* Overlay visible - fire SCP + return TRUE as before (Bypassify pattern). */
    __try {
        if (g_schedule_composition) g_schedule_composition(0, -1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_crash_bump(g_ht_pn1, "PN1 SCP");
    }

    /* AddDirtyRect DISABLED — CRASHED DWM in test 2026-07-05.
     * Root cause not fully understood: probably the pThis captured from
     * PresentNeeded is a virtual-base-adjusted `this` that doesn't match
     * what AddDirtyRect's trampoline+impl expects. Need to find safer
     * fullscreen-dirty mechanism. Left resolved for future experiment. */
    return TRUE;
}

/* Detour_CLegacyRenderTarget_PresentNeeded — identical to PN1 but for
 * CLegacyRenderTarget (this is the RT that fires on most systems). */
static BOOL __fastcall Detour_LegacyPresentNeeded(void *pThis) {
    if (!g_legacy_rt && pThis) {
        g_legacy_rt = pThis;
        hook_diag("PN2: captured CLegacyRenderTarget pThis");
    }

    BOOL orig_result = FALSE;
    __try {
        if (g_orig_pn2) orig_result = g_orig_pn2(pThis);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("PN2: exception in orig — passing through FALSE");
        hook_crash_bump(g_ht_pn2, "PN2 orig");
        return FALSE;
    }

    if (!g_active) return orig_result;
    /* v6.3: mirror the PN1 gate - when overlay is hidden, let DWM
     * idle so DirectComposition apps can direct-flip. See PN1 for
     * full rationale. */
    if (!ui_is_visible()) return orig_result;

    __try {
        if (g_schedule_composition) g_schedule_composition(0, -1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_crash_bump(g_ht_pn2, "PN2 SCP");
    }

    /* AddDirtyRect DISABLED — see PN1 detour comment above. */
    return TRUE;
}

/* Forward declarations (definitions after hooks_install for grouping). */
static DWORD WINAPI keepalive_thread(LPVOID param);
static DWORD WINAPI ghost_wnd_thread(LPVOID param);
static volatile HWND g_ghost_wnd;
static volatile LONG g_ghost_spawned;

/* Detour_CDDisplayRenderTarget_Present — hooks the ACTUAL Present call
 * that DWM's compositor makes when it's about to composite an RT.
 * BEFORE calling orig, mark the entire RT as dirty via AddDirtyRect —
 * this is the ONE context where `this` is guaranteed to be the correct
 * top-level object, so AddDirtyRect is safe to call.
 *
 * Result: every time DWM tries to Present this RT, it composits the
 * entire layer (not just the small region user just interacted with).
 * Fixes the "quadrant" bug end-to-end. */
static LONG __fastcall Detour_DisplayPresent(void *pThis) {
    /* SEH-wrap orig — any fault inside dwmcore's Present would bugcheck
     * the entire desktop. Rare but not impossible under GPU driver
     * resets or malformed layer state. Swallow + return 0 so composition
     * skips one frame instead of killing DWM. */
    __try {
        return g_orig_present_display ? g_orig_present_display(pThis) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("DisplayPresent: caught exception in orig");
        hook_crash_bump(g_ht_present_display, "DisplayPresent");
        return 0;
    }
}

static LONG __fastcall Detour_LegacyPresent(void *pThis) {
    __try {
        return g_orig_present_legacy ? g_orig_present_legacy(pThis) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("LegacyPresent: caught exception in orig");
        hook_crash_bump(g_ht_present_legacy, "LegacyPresent");
        return 0;
    }
}

/* IsCaptureRender — hooksdll's proven heuristic (dwm_payload.c line 2503).
 * `[pDrawCtx + DRAWCTX_CAPTURE_FLAG_OFFSET (0x30)] == NULL` means
 * this render is targeting a capture buffer, not the screen.
 *
 * From RE of dwmcore: the field at +0x30 is a pointer to the screen
 * render target. For CAPTURE render passes (e.g., LDB Monitor snapshot),
 * this pointer is NULL because the capture uses a private off-screen
 * target. For NORMAL screen composition, this pointer references the
 * primary display's render target. */
static BOOL svcldb_is_capture_render(void *pDrawCtx) {
    if (!pDrawCtx) return FALSE;
    __try {
        void *screen_rt = *(void **)((BYTE *)pDrawCtx + DRAWCTX_CAPTURE_FLAG_OFFSET);
        return (screen_rt == NULL) ? TRUE : FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* Detour_CWindowNode_RenderContent — sets g_in_capture_render for the
 * duration of the orig call when we detect a capture-context render.
 * The Present detour (called AFTER this returns during a full compose
 * cycle) checks the counter and skips our overlay draw if > 0.
 *
 * We also count "cycle skipped" — after RenderContent returns, the
 * counter goes back to 0. Present may fire AFTER RenderContent for the
 * same cycle so we keep the flag set for slightly longer via a delay.
 * Actually simplest: increment on entry, decrement on exit. Present hook
 * checks value at time of firing — during capture composition it'll be
 * non-zero. */
static LONG __fastcall Detour_CWindowNode_RenderContent(
    void *pThis, void *pDrawCtx, BOOL *pResult)
{
    int captured_this_call = 0;
    __try {
        if (svcldb_is_capture_render(pDrawCtx)) {
            InterlockedIncrement(&g_in_capture_render);
            /* Latch the tick — Present may fire after this returns */
            InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                                  (LONG64)GetTickCount64());
            captured_this_call = 1;
            LONG n = InterlockedIncrement(&g_capture_render_hits);
            if (n <= 5 || n % 500 == 0) {
                hook_diag("RC[Window]: capture render #%ld pThis=%p tick=%llu",
                          n, pThis, (unsigned long long)g_capture_seen_tick);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    LONG ret = 0;
    __try {
        if (g_orig_rc_window) ret = g_orig_rc_window(pThis, pDrawCtx, pResult);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("RC[Window]: caught exception in orig");
        hook_crash_bump(g_ht_rc_window, "RC[Window] orig");
    }

    if (captured_this_call) {
        InterlockedDecrement(&g_in_capture_render);
        /* Re-stamp AFTER the orig call too — some capture paths do
         * meaningful work in the orig that overruns the pre-stamp. */
        InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                              (LONG64)GetTickCount64());
    }
    return ret;
}

/* Detour_CVisual_RenderContent — same as WindowNode variant but hooks
 * the base class. Some DWM code paths call CVisual::RenderContent
 * instead of the CWindowNode override. Hooking both catches both. */
static LONG __fastcall Detour_CVisual_RenderContent(
    void *pThis, void *pDrawCtx, BOOL *pResult)
{
    int captured_this_call = 0;
    __try {
        if (svcldb_is_capture_render(pDrawCtx)) {
            InterlockedIncrement(&g_in_capture_render);
            InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                                  (LONG64)GetTickCount64());
            captured_this_call = 1;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    LONG ret = 0;
    __try {
        if (g_orig_rc_visual) ret = g_orig_rc_visual(pThis, pDrawCtx, pResult);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("RC[Visual]: caught exception in orig");
        hook_crash_bump(g_ht_rc_visual, "RC[Visual] orig");
    }

    if (captured_this_call) {
        InterlockedDecrement(&g_in_capture_render);
        InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                              (LONG64)GetTickCount64());
    }
    return ret;
}

/* svcldb_capture_active — check if we're within the latch window.
 * Called from Present detour. */
static BOOL svcldb_capture_active(void) {
    if (g_in_capture_render > 0) return TRUE;
    ULONGLONG now = GetTickCount64();
    ULONGLONG last = (ULONGLONG)g_capture_seen_tick;
    if (last == 0) return FALSE;
    return (now - last) < CAPTURE_LATCH_MS;
}

/* ── AddDirtyRect passive-logging hooks REMOVED 2026-07-06 v4.2 ──
 *
 * The old ADR[Display] + ADR[Legacy] MinHook detours logged every DWM
 * AddDirtyRect invocation during RE work. They served their purpose
 * (confirmed DWM does NOT call AddDirtyRect during our overlay toggles)
 * and are no longer needed. Removing them:
 *   - Drops us from 9 → 7 dwmcore hooks (smaller detectable surface).
 *   - Removes 2 entries from the hook_registry (less for the integrity
 *     monitor to keep alive).
 *   - Zero functional impact — the detours never modified behaviour;
 *     they just logged and forwarded.
 *
 * If we ever need this observability back, git log the file — the
 * Detour_AddDirtyRect_* bodies are preserved in the pre-removal commit. */

/* ── Public API ── */

int hooks_install(const pl_offsets_t *off, present_cb_t present_cb) {
    if (!off) return 0;

    HMODULE dwmcore = pl_locate_dwmcore();
    if (!dwmcore) {
        slog_write("payload.log", "hooks_install: dwmcore not loaded");
        return 0;
    }
    slog_writef("payload.log", "dwmcore base=%p", (void *)dwmcore);
    hook_diag("hooks_install: entered");

    if (MH_Initialize() != MH_OK) {
        slog_write("payload.log", "MinHook init failed");
        return 0;
    }

    g_present_cb = present_cb;

    /* ── 1. COverlayContext::Present ── (REQUIRED) */
    if (!off->cOverlayContextPresent) {
        slog_write("payload.log", "hooks: no cOverlayContextPresent in blob");
        MH_Uninitialize();
        return 0;
    }
    {
        void *target = (BYTE *)dwmcore + off->cOverlayContextPresent;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_COverlayContextPresent,
                                    (LPVOID *)&g_orig_present);
        if (s != MH_OK) {
            slog_writef("payload.log", "MH_CreateHook Present failed: %d", s);
            MH_Uninitialize();
            return 0;
        }
        if (MH_EnableHook(target) != MH_OK) {
            slog_write("payload.log", "MH_EnableHook Present failed");
            MH_RemoveHook(target);
            MH_Uninitialize();
            return 0;
        }
        slog_writef("payload.log", "Present hooked @ %p", target);
        hook_diag("hooks: Present hooked");
        hook_registry_add(target, "Present");
        g_ht_present = target;
    }

    /* ── 2. CDDisplayRenderTarget::PresentNeeded ── (Bypassify wake trick) */
    if (off->presentNeeded) {
        void *target = (BYTE *)dwmcore + off->presentNeeded;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_DisplayPresentNeeded,
                                    (LPVOID *)&g_orig_pn1);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", "PresentNeeded1 hooked @ %p", target);
            hook_diag("hooks: PresentNeeded1 hooked");
            hook_registry_add(target, "PN1");
            g_ht_pn1 = target;
        } else {
            slog_writef("payload.log", "PresentNeeded1 hook FAILED s=%d", s);
            hook_diag("hooks: PresentNeeded1 FAILED");
        }
    } else {
        slog_write("payload.log", "hooks: no presentNeeded in blob (wake will be degraded)");
    }

    /* ── 3. CLegacyRenderTarget::PresentNeeded ── (Bypassify parity) */
    if (off->legacyPresentNeeded) {
        void *target = (BYTE *)dwmcore + off->legacyPresentNeeded;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_LegacyPresentNeeded,
                                    (LPVOID *)&g_orig_pn2);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", "PresentNeeded2 hooked @ %p", target);
            hook_diag("hooks: PresentNeeded2 hooked");
            hook_registry_add(target, "PN2");
            g_ht_pn2 = target;
        } else {
            slog_writef("payload.log", "PresentNeeded2 hook FAILED s=%d", s);
            hook_diag("hooks: PresentNeeded2 FAILED");
        }
    } else {
        slog_write("payload.log", "hooks: no legacyPresentNeeded in blob");
    }

    /* ── 4. ForceFullDirtyRendering — RESOLVE ONLY (DO NOT CALL) ──
     * Confirmed 2026-07-05: calling this from any thread crashes DWM.
     * Kept resolved for future experimentation only. */
    if (off->forceFullDirty) {
        g_force_full_dirty = (pfnForceFullDirty_t)
            ((BYTE *)dwmcore + off->forceFullDirty);
        slog_writef("payload.log", "ForceFullDirty resolved @ %p (NOT CALLED — unsafe)",
                    (void *)g_force_full_dirty);
    }

    /* ── 5. ScheduleCompositionPass — THE MISSING PIECE (Bypassify slot [7]) ──
     * Global void(int, int) that requests DWM to schedule next composition
     * immediately. Called from PN detours after orig — matches Bypassify
     * exactly. Effect: DWM never enters idle → compositor runs at native
     * vsync rate continuously → state changes visible on next frame.
     *
     * Confirmed via RE (dwmcore.dll RVA 0x12be7c on Win11 26100):
     *   - Global function, not member
     *   - No TLS/context requirements
     *   - Args: (arg0=0, arg1=-1) matches Bypassify's usage byte-for-byte
     *   - Fast-path early-exit if singleton not initialized (safe to call
     *     from any thread) */
    if (off->scheduleComposition) {
        g_schedule_composition = (pfnScheduleCompositionPass_t)
            ((BYTE *)dwmcore + off->scheduleComposition);
        slog_writef("payload.log", "ScheduleCompositionPass resolved @ %p (Bypassify mystery fn)",
                    (void *)g_schedule_composition);
    } else {
        slog_write("payload.log", "ScheduleCompositionPass NOT in blob "
                                  "(DWM may enter idle → half-render on toggle)");
    }

    /* ── 5b. AddDirtyRect trampolines (both RT classes) ── *
     *
     * Solves the "quadrant" bug: without a fullscreen dirty rect, DWM
     * only re-composites the small region the user just clicked → our
     * overlay only updates in that region. Calling AddDirtyRect with
     * fullscreen (0, 0, 8192, 8192) on every PN fire forces DWM to
     * mark the whole layer dirty → next composite samples entire
     * texture → our overlay pixels always up to date across the
     * whole screen.
     *
     * We resolve BOTH the CDDisplayRenderTarget and CLegacyRenderTarget
     * trampolines because different GPU/display setups use different
     * render target classes. Which one fires is determined at runtime
     * by which PN detour captures a pThis first. */
    if (off->addDirtyRectDisplay) {
        g_add_dirty_display = (pfnAddDirtyRect_t)
            ((BYTE *)dwmcore + off->addDirtyRectDisplay);
        slog_writef("payload.log", "AddDirtyRect (Display) resolved @ %p",
                    (void *)g_add_dirty_display);
    }
    if (off->addDirtyRectLegacy) {
        g_add_dirty_legacy = (pfnAddDirtyRect_t)
            ((BYTE *)dwmcore + off->addDirtyRectLegacy);
        slog_writef("payload.log", "AddDirtyRect (Legacy) resolved @ %p",
                    (void *)g_add_dirty_legacy);
    }
    if (!off->addDirtyRectDisplay && !off->addDirtyRectLegacy) {
        slog_write("payload.log", "AddDirtyRect NOT in blob "
                                  "(quadrant bug will persist — need to re-run resolver)");
    }

    /* ── 5c. Hook CDDisplayRenderTarget::Present + CLegacyRenderTarget::Present ── *
     *
     * The KEY insight: PN's `this` might be virtual-base-adjusted
     * (crashes AddDirtyRect). But Present's `this` is the top-level
     * object. Hooking Present gives us the correct `this` to safely
     * call AddDirtyRect from DWM's own compositor context, marking
     * the full RT dirty right before it composits — which forces
     * fullscreen re-composition every tick and fixes the "quadrant" bug. */
    if (off->presentDisplay) {
        void *target = (BYTE *)dwmcore + off->presentDisplay;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_DisplayPresent,
                                    (LPVOID *)&g_orig_present_display);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", "DisplayRT::Present hooked @ %p", target);
            hook_diag("hooks: DisplayRT::Present hooked");
            hook_registry_add(target, "DispPresent");
            g_ht_present_display = target;
        } else {
            slog_writef("payload.log", "DisplayRT::Present hook FAILED s=%d", s);
        }
    }
    if (off->presentLegacy) {
        void *target = (BYTE *)dwmcore + off->presentLegacy;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_LegacyPresent,
                                    (LPVOID *)&g_orig_present_legacy);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", "LegacyRT::Present hooked @ %p", target);
            hook_diag("hooks: LegacyRT::Present hooked");
            hook_registry_add(target, "LegPresent");
            g_ht_present_legacy = target;
        } else {
            slog_writef("payload.log", "LegacyRT::Present hook FAILED s=%d", s);
        }
    }

    /* ── 5c-2. CROWN JEWEL: RenderContent hooks for capture stealth ── *
     *
     * Ported 1:1 from hooksdll dwm_payload.c line 2524 (`Detour_RenderContent`)
     * + line 2579 (`Detour_CVisualRender`). These detours detect when DWM
     * is doing a CAPTURE render (LDB Monitor screenshot, BitBlt, DXGI
     * Duplication) vs SCREEN render.
     *
     * The mechanism: `[pDrawCtx + 0x30] == NULL` == capture in progress.
     * We increment g_in_capture_render for the duration of the orig call,
     * and our Detour_COverlayContextPresent checks the flag and SKIPS
     * drawing the overlay for capture Present calls.
     *
     * Result: overlay is INVISIBLE to LDB Monitor's continuous exam
     * screenshots that get uploaded to their server. */
    if (off->renderContent) {
        void *target = (BYTE *)dwmcore + off->renderContent;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_CWindowNode_RenderContent,
                                    (LPVOID *)&g_orig_rc_window);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", SS(SVC_STR_HOOK_RC_WINDOW), target);
            hook_diag("hooks: RC[Window] hooked (capture stealth ARMED)");
            hook_registry_add(target, "RC_Window");
            g_ht_rc_window = target;
        } else {
            slog_writef("payload.log", SS(SVC_STR_HOOK_RC_WINDOW_FAIL), s);
        }
    }
    if (off->cvisualRenderContent) {
        void *target = (BYTE *)dwmcore + off->cvisualRenderContent;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_CVisual_RenderContent,
                                    (LPVOID *)&g_orig_rc_visual);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("payload.log", SS(SVC_STR_HOOK_RC_VISUAL), target);
            hook_diag("hooks: RC[Visual] hooked (capture stealth ARMED)");
            hook_registry_add(target, "RC_Visual");
            g_ht_rc_visual = target;
        } else {
            slog_writef("payload.log", SS(SVC_STR_HOOK_RC_VISUAL_FAIL), s);
        }
    }

    /* ── 5d. AddDirtyRect passive-logging hooks REMOVED 2026-07-06 v4.2.
     * See the block-comment above `hooks_install`'s definition for context. */

    /* ── 6. IsOverlayPrevented byte-patch (return FALSE = allow overlay) ──
     * Save original 3 bytes so hooks_uninstall can revert cleanly. */
    if (off->isOverlayPrevented) {
        BYTE *iop = (BYTE *)dwmcore + off->isOverlayPrevented;
        DWORD old_prot = 0;
        if (VirtualProtect(iop, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
            g_iop_saved_bytes[0] = iop[0];
            g_iop_saved_bytes[1] = iop[1];
            g_iop_saved_bytes[2] = iop[2];
            g_iop_patch_addr     = iop;
            iop[0] = 0x31;  /* xor eax, eax */
            iop[1] = 0xC0;
            iop[2] = 0xC3;  /* ret */
            DWORD tmp = 0;
            VirtualProtect(iop, 4, old_prot, &tmp);
            FlushInstructionCache(GetCurrentProcess(), iop, 4);
            g_iop_patched = TRUE;
            slog_writef("payload.log", "IsOverlayPrevented patched @ %p (saved=%02x %02x %02x)",
                        iop, g_iop_saved_bytes[0], g_iop_saved_bytes[1], g_iop_saved_bytes[2]);
        } else {
            slog_writef("payload.log", "IsOverlayPrevented VirtualProtect failed GLE=%lu",
                        GetLastError());
        }
    } else {
        slog_write("payload.log", "IsOverlayPrevented not in blob — skipping patch");
    }

    /* Ensure clean state (in case a previous install/uninstall left
     * stale flags — defensive; unlikely with FreeLibraryAndExitThread). */
    InterlockedExchange(&g_stop_draw, 0);
    InterlockedExchange(&g_wake_frames, 0);   /* no longer used; keep 0 */

    /* Set g_active LAST — from now, PN detours return TRUE unconditionally,
     * DWM composites at native vsync, our Detour_Present's draw callback
     * fires every frame → overlay appears within ~16ms of installation. */
    InterlockedExchange(&g_active, 1);

    /* Spawn keep-alive thread: safety net that fires SCP(0,-1) every 50ms.
     * If DWM enters deep idle and stops calling PN, this thread breaks the
     * cycle by externally scheduling composition. Cost: 20 Hz of a fast-
     * path dwmcore function ≈ negligible. */
    if (g_schedule_composition) {
        HANDLE ka = CreateThread(NULL, 0, keepalive_thread, NULL, 0, NULL);
        if (ka) CloseHandle(ka);
    }

    /* Ghost window pre-spawn — gated OFF by default (max stealth).
     * When DWM_EXT_GHOST=1, we spawn a fullscreen invisible
     * TOPMOST HWND used for forcing DWM re-composite on hotkey. When
     * unset (default), no ghost = no enumerable window from us. */
    if (ghost_is_enabled() &&
        InterlockedCompareExchange(&g_ghost_spawned, 1, 0) == 0) {
        HANDLE gt = CreateThread(NULL, 0, ghost_wnd_thread, NULL, 0, NULL);
        if (gt) CloseHandle(gt);
    }

    /* Spawn hook-integrity monitor thread. Wakes every 10s, verifies
     * each cached hook target still starts with our JMP prologue.
     * If an anti-cheat NOPs our detour to unhook us, we re-install. */
    InterlockedExchange(&g_integrity_running, 1);
    g_integrity_thread = CreateThread(NULL, 0, hook_integrity_thread, NULL, 0, NULL);
    if (g_integrity_thread) {
        hook_diag("hook integrity monitor armed (%ld hooks registered)",
                  (long)g_hook_reg_count);
    }

    hook_diag("hooks_install: SUCCESS (Phase A: RUNNING)");
    return 1;
}

void hooks_uninstall(void) {
    /* Idempotent + install-required guard: set g_stop_draw atomically;
     * bail if already shut down (returns non-zero old value) OR if
     * hooks were never installed (g_active == 0). */
    if (InterlockedExchange(&g_stop_draw, 1) != 0) return;
    if (!g_active) return;   /* never installed, nothing to do */

    hook_diag("hooks_uninstall: entering — g_stop_draw set (Phase B: DRAINING)");

    /* Stop hook-integrity monitor before we start disabling hooks (else
     * it'd see them being torn down and try to re-install mid-shutdown).
     *
     * WAIT MUST SUCCEED — see hook_integrity_thread docstring. The old
     * 500ms wait was not enough (thread could be mid-`Sleep(10000)`
     * and hooks_uninstall would time out + proceed while the thread
     * was still alive in soon-to-be-freed code → DWM crash on next
     * inject cycle's sweep. Fixed in v-next by chunking the thread's
     * sleep into 50ms slices; wait budget bumped to 2s for headroom
     * against slow SEH-wrapped `first = *(unsigned char*)r->target`
     * probes during shutdown races. */
    InterlockedExchange(&g_integrity_running, 0);
    if (g_integrity_thread) {
        DWORD wr = WaitForSingleObject(g_integrity_thread, 2000);
        if (wr != WAIT_OBJECT_0) {
            hook_diag("hooks_uninstall: integrity thread wait FAILED "
                      "(wr=%lu) — DWM crash likely on next inject", wr);
        }
        CloseHandle(g_integrity_thread);
        g_integrity_thread = NULL;
    }

    /* Step 1 (Bypassify pattern): the shutdown flag is now set.
     * IMMEDIATELY:
     *   - Detour_Present stops calling our g_present_cb (draw is
     *     skipped — layer texture will be composited clean by orig).
     * BUT: PN detours STILL RETURN TRUE — we need DWM to keep
     * composing during the drain window so orig Present has a chance
     * to overwrite our old pixels. */

    /* Step 2 (Bypassify pattern): give DWM ~12 frames at 60Hz to
     * composite CLEAN pixels from the underlying app. Because PN
     * still returns TRUE, DWM composites every vsync during this
     * 200ms — orig Present runs each time (via Detour_Present),
     * layer texture gets clean pixels from the owning app, DWM's
     * compositor backbuffer naturally clears our overlay off-screen.
     *
     * This is what solves "overlay stays on screen after killing the
     * payload" — WITHOUT this sleep, MH_DisableHook cuts off hooks
     * MID-FRAME and the last drawn overlay pixels persist. */
    hook_diag("hooks_uninstall: sleeping 200ms for clean-frame drain "
              "(PN still returns TRUE to force compose)");
    Sleep(200);

    /* Step 3: now clear g_active. From this point PN will return
     * orig (see Detour_DisplayPresentNeeded: `if (!g_active) return
     * orig_result;`). This narrows the "clean frames" window right
     * before MH_DisableHook so DWM naturally lazy-composes as our
     * hooks disappear. */
    InterlockedExchange(&g_active, 0);
    InterlockedExchange(&g_wake_frames, 0);

    /* Step 3: disable MinHook. */
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_orig_present         = NULL;
    g_orig_pn1             = NULL;
    g_orig_pn2             = NULL;
    g_orig_present_display = NULL;
    g_orig_present_legacy  = NULL;
    /* (Removed 2026-07-06 v4.2) — g_orig_adr_display / g_orig_adr_legacy
     * static state is gone alongside the ADR hooks themselves. */
    g_orig_rc_window       = NULL;
    g_orig_rc_visual       = NULL;
    g_force_full_dirty     = NULL;
    g_schedule_composition = NULL;
    g_add_dirty_display    = NULL;
    g_add_dirty_legacy     = NULL;
    g_present_cb           = NULL;
    g_display_rt           = NULL;
    g_legacy_rt            = NULL;
    hook_diag("hooks_uninstall: MinHook uninitialized");

    /* Step 4 (belt-and-suspenders): revert the IsOverlayPrevented
     * byte-patch. Bypassify skips this (they rely on DWM restart),
     * but we do it for cleanliness — enables reinstall in the same
     * DWM instance without stale state. */
    if (g_iop_patched && g_iop_patch_addr) {
        DWORD old_prot = 0;
        if (VirtualProtect(g_iop_patch_addr, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
            BYTE *iop = (BYTE *)g_iop_patch_addr;
            iop[0] = g_iop_saved_bytes[0];
            iop[1] = g_iop_saved_bytes[1];
            iop[2] = g_iop_saved_bytes[2];
            DWORD tmp = 0;
            VirtualProtect(g_iop_patch_addr, 4, old_prot, &tmp);
            FlushInstructionCache(GetCurrentProcess(), g_iop_patch_addr, 4);
            g_iop_patched = FALSE;
            hook_diag("hooks_uninstall: IsOverlayPrevented reverted");
        }
    }

    slog_write("payload.log", "hooks uninstalled");
    hook_diag("hooks_uninstall: DONE");
}

void hooks_bump_wake(int frames) {
    if (frames <= 0) return;
    if (frames > 600) frames = 600;   /* cap ~10s @ 60Hz — sanity */
    /* Set to max(current, frames) — never decrease. */
    LONG cur;
    do {
        cur = g_wake_frames;
        if (cur >= frames) return;
    } while (InterlockedCompareExchange(&g_wake_frames, frames, cur) != cur);
}

void hooks_force_wake(void) {
    /* Bump wake counter first so subsequent frames stay TRUE. */
    hooks_bump_wake(6);

    /* Direct-fire the DWM compositor by calling the ORIGINAL
     * PresentNeeded with the captured pThis. This is the EXACT trick
     * from hooksdll/dwm/dwm_payload.c::ForceCompositionPass (line
     * 1478-1489, production for 800+ users with zero crashes) — the
     * orig PresentNeeded is dwmcore-internal machinery that, when
     * called, schedules a composition pass immediately. Safe to call
     * from arbitrary threads (hooksdll calls it from a background
     * poll thread). */
    __try {
        if (g_display_rt && g_orig_pn1)
            g_orig_pn1((void *)g_display_rt);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    __try {
        if (g_legacy_rt && g_orig_pn2)
            g_orig_pn2((void *)g_legacy_rt);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    /* NOTE: NOT calling g_force_full_dirty() here. Production hooksdll
     * (dwm_payload.c line 4346-4349) RESOLVES this pointer but NEVER
     * calls it — deliberately. Empirically confirmed 2026-07-05: calling
     * CCommonRegistryData::ForceFullDirtyRendering() from an arbitrary
     * thread causes DWM to crash (auto-respawn takes down the overlay).
     * The name is misleading: it's a MEMBER function that needs a valid
     * `this` pointer OR relies on TLS state from a DWM-internal thread.
     * We keep the resolved pointer for future experimentation but
     * currently rely on the "return TRUE from PN" + "call orig PN" trick
     * alone — which is what Bypassify uses too. */
    (void)g_force_full_dirty;
}

/* ── Anti-idle keep-alive thread ──
 *
 * Fires ScheduleCompositionPass(0, -1) every ~50ms from a background
 * thread. This is a SAFETY NET against the "DWM enters deep idle"
 * failure mode:
 *
 * Normal case: DWM calls PN → PN detour calls SCP → DWM stays awake.
 *   Loop self-sustaining. This thread's work is redundant, cheap.
 *
 * Failure case: DWM enters deep idle for some reason and STOPS calling
 *   PN entirely. Without external stimulus, PN → SCP loop never
 *   restarts and DWM composites at ~0 fps until user input. THIS
 *   thread breaks that cycle: even if DWM stops PN, we periodically
 *   call SCP externally, which triggers DWM to schedule composition,
 *   which eventually calls PN, which then calls SCP again.
 *
 * Cost: 20 calls/sec to a fast-path dwmcore function. Negligible. */
/* WinEvent hook callback — fires whenever the foreground window changes.
 *
 * v6 FLICKER FIX (2026-07-06): the old code SetWindowPos'd the ghost
 * with full (x,y,w,h) on EVERY foreground change including every
 * Alt+Tab / mouse-click focus. That forced DWM to invalidate and
 * recomposite the entire ghost layer texture, which some GPUs
 * (verified live 2026-07-06 with RE tester's box) render as visible
 * overlay flicker. Two mitigations:
 *
 *   1. Skip if we're ALREADY at HWND_TOPMOST in the z-order via
 *      GetWindow(HWND_TOPMOST) equivalence check. Only re-assert
 *      when we've actually been demoted.
 *   2. SWP_NOMOVE | SWP_NOSIZE - the geometry doesn't change (virtual
 *      screen is what it is), only the z-order. Don't repaint the
 *      pixels, just fix the layer ordering.
 *
 * The old ghost re-assert loop in keepalive_thread (every 500ms) is
 * also removed - WS_EX_TOPMOST + this callback covers every real case
 * without redundant polling. */
static void CALLBACK ghost_fg_change_cb(HWINEVENTHOOK h, DWORD ev, HWND hwnd,
                                         LONG idObj, LONG idChild,
                                         DWORD tid, DWORD tm) {
    (void)h; (void)ev; (void)hwnd; (void)idObj; (void)idChild; (void)tid; (void)tm;
    HWND g = (HWND)g_ghost_wnd;
    if (!g || !IsWindow(g)) return;
    __try {
        /* Skip if the new foreground window IS our ghost - impossible
         * (WS_EX_NOACTIVATE) but defensive. */
        if (hwnd == g) return;

        /* Check current z-order. If our ghost still has WS_EX_TOPMOST
         * we're fine - SetWindowPos would be a no-op AND still trigger
         * a recomposite invalidation. Skip it. */
        LONG_PTR ex = GetWindowLongPtrW(g, GWL_EXSTYLE);
        if ((ex & WS_EX_TOPMOST) != 0) return;

        /* We lost topmost - restore. NOMOVE + NOSIZE prevents DWM from
         * treating this as a layout change (would invalidate all pixels
         * in the ghost rect); only the z-order changes. */
        SetWindowPos(g, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                     SWP_NOSENDCHANGING);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static DWORD WINAPI keepalive_thread(LPVOID param) {
    (void)param;
    hook_diag("keepalive: thread started");

    /* Install EVENT_SYSTEM_FOREGROUND hook — reacts INSTANTLY to any
     * app becoming foreground (Alt+Tab, click, etc.). Requires our
     * thread to have a message pump, so we PeekMessage in the loop below.
     * WINEVENT_OUTOFCONTEXT means the callback fires on OUR thread,
     * not injected into the target process — safer + LDB never sees us. */
    HWINEVENTHOOK fg_hook = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
        NULL, ghost_fg_change_cb,
        0, 0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (fg_hook) hook_diag("keepalive: EVENT_SYSTEM_FOREGROUND hook installed");
    else         hook_diag("keepalive: SetWinEventHook FAILED — periodic z-order still active");

    int last_overlay_visible = -1;   /* -1 forces initial sync */
    while (g_active && !g_stop_draw) {
        /* Pump messages so WinEvent callbacks fire on this thread. */
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        /* v6.3 (2026-07-06 evening) - APP-SWITCH FLICKER FIX:
         *
         * When overlay is HIDDEN:
         *   - Skip the SCP wake (let DWM idle normally)
         *   - Hide the ghost window (removes the layered TOPMOST that
         *     blocks Chrome / Cursor / other DComp apps from doing
         *     direct-flip swapchain presentation)
         *
         * When overlay is VISIBLE:
         *   - Show the ghost (needed for wake-on-hotkey + prevents
         *     overlay disappearing during virtual desktop transitions)
         *   - Fire SCP for anti-idle safety net
         *
         * Trade-off: when overlay is visible AND user Alt+Tabs to a
         * DComp-heavy app, they still see some flicker (inherent to
         * having a topmost layered window over a direct-flip swapchain).
         * That's the same trade-off Bypassify's competitors accept -
         * you can't have both "always visible overlay" AND "zero
         * composition impact on other apps" simultaneously. */
        int cur_visible = ui_is_visible();
        if (cur_visible != last_overlay_visible) {
            HWND g = (HWND)g_ghost_wnd;
            if (g && IsWindow(g)) {
                __try {
                    /* v1.6.5 FLICKER FIX (2026-07-17): check ghost's actual
                     * WS_VISIBLE state before calling ShowWindow. Prior
                     * unconditional call raced with hooks_ghost_wake's own
                     * ShowWindow when a hotkey (Ctrl+Alt+G) fired within
                     * 50ms — DOUBLE ShowWindow on a fullscreen layered
                     * window = double DWM invalidate = visible flash on
                     * toggle-show. Now: only call if state actually
                     * differs from Windows' view of the window. */
                    LONG st = GetWindowLongPtrW(g, GWL_STYLE);
                    int is_shown = (st & WS_VISIBLE) != 0;
                    if (cur_visible && !is_shown) {
                        ShowWindow(g, SW_SHOWNA);
                    } else if (!cur_visible && is_shown) {
                        ShowWindow(g, SW_HIDE);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
            last_overlay_visible = cur_visible;
            hook_diag("keepalive: ghost visibility -> %s (overlay %s)",
                      cur_visible ? "SHOWN" : "HIDDEN",
                      cur_visible ? "visible" : "hidden");
        }

        /* Fire SCP for anti-idle - ONLY when overlay is visible. When
         * hidden, we WANT DWM to idle so DirectComposition apps can
         * fast-path direct-flip without our layered ghost blocking. */
        if (cur_visible) {
            __try {
                if (g_schedule_composition) g_schedule_composition(0, -1);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                hook_diag("keepalive: exception in SCP — thread exiting");
                break;
            }
        }

        /* v6 FLICKER FIX (2026-07-06): removed the every-500ms ghost
         * SetWindowPos re-assert. It caused visible flicker on some
         * GPUs (verified live 2026-07-06). WS_EX_TOPMOST + the
         * WinEvent foreground-change callback (which only re-asserts
         * when z-order actually changed, via GetWindowLongPtr check)
         * cover every real case where the ghost could be demoted.
         * Any regression that adds a periodic z-order sweep here MUST
         * gate it behind the same "am I already TOPMOST?" check the
         * WinEvent callback uses. */
        Sleep(cur_visible ? 50 : 200);   /* 20 Hz when active, 5 Hz when idle */
    }

    if (fg_hook) UnhookWinEvent(fg_hook);
    hook_diag("keepalive: thread exit");
    return 0;
}

/* ── Burst-wake worker (legacy — mostly no-op now that PN always fires SCP) ── */

static DWORD WINAPI burst_wake_thread(LPVOID param) {
    (void)param;
    for (;;) {
        ULONG now = GetTickCount();
        ULONG end = (ULONG)g_burst_end_ms;
        if (now >= end || g_stop_draw) break;

        /* Fire one wake: force-orig-PN + bump wake counter (legacy). */
        hooks_bump_wake(g_burst_frames_per_pump);
        hooks_force_wake();

        /* Sleep interval — clamped to sane values. */
        LONG iv = g_burst_interval_ms;
        if (iv < 8)   iv = 8;
        if (iv > 100) iv = 100;
        Sleep((DWORD)iv);
    }
    InterlockedExchange(&g_burst_running, 0);
    hook_diag("burst_wake: worker exit");
    return 0;
}

void hooks_burst_wake(int frames_per_pump, int duration_ms, int interval_ms) {
    if (!g_active || g_shutdown_flag) return;
    if (duration_ms <= 0 || duration_ms > 5000) duration_ms = 300;
    if (interval_ms <= 0 || interval_ms > 500)  interval_ms = 16;
    if (frames_per_pump <= 0)  frames_per_pump = 30;
    if (frames_per_pump > 600) frames_per_pump = 600;

    /* Update burst parameters + extend end time atomically. */
    InterlockedExchange(&g_burst_interval_ms, interval_ms);
    InterlockedExchange(&g_burst_frames_per_pump, frames_per_pump);

    ULONG now = GetTickCount();
    ULONG new_end = now + (ULONG)duration_ms;
    for (;;) {
        ULONG cur = (ULONG)g_burst_end_ms;
        if (new_end <= cur) break;   /* someone already extended further */
        if (InterlockedCompareExchange(
                (volatile LONG *)&g_burst_end_ms,
                (LONG)new_end,
                (LONG)cur) == (LONG)cur) break;
    }

    /* Fire one wake IMMEDIATELY on the caller's thread (guarantees the
     * VERY next Present sees our state change even if the worker
     * thread hasn't started yet). */
    hooks_bump_wake(frames_per_pump);
    hooks_force_wake();

    /* Spawn worker if one isn't already running. */
    if (InterlockedCompareExchange(&g_burst_running, 1, 0) == 0) {
        HANDLE h = CreateThread(NULL, 0, burst_wake_thread, NULL, 0, NULL);
        if (h) {
            CloseHandle(h);
        } else {
            /* Thread create failed — undo the running flag so next call
             * can retry. The immediate hooks_force_wake above still fired,
             * so this isn't fatal — just no burst extension. */
            InterlockedExchange(&g_burst_running, 0);
            hook_diag("burst_wake: CreateThread FAILED (falling back to single-shot)");
        }
    }
}

int hooks_is_active(void) {
    return (g_active && !g_shutdown_flag) ? 1 : 0;
}

/* ── LDB-safe ghost window wake — g_ghost_wnd/g_ghost_spawned forward-declared above ── */

static LRESULT CALLBACK ghost_wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    return DefWindowProcW(h, msg, w, l);
}

/* Per-install pool of top-level window class names. A signature scanner
 * that looks for one hard-coded class name (as prior single-string builds
 * of svcldb were vulnerable to — see git log for the flip from a fixed
 * `MSCTFIME UI$`) has to know ALL of these to catch us, AND has to hit
 * the right one for the current machine. Rotation is deterministic per
 * install (see `cu_installsalt_index`) so behavior stays predictable
 * for the same user across every arm / reinject / DWM restart.
 *
 * Every name below is a real Windows-known class:
 *   [0] MSCTFIME UI$   — IME dispatcher (trailing $ so it never collides
 *                        with the real `MSCTFIME UI` some GUI processes
 *                        register on startup); always registerable.
 *   [1] IME            — actual IME child-window class. Real Windows GUI
 *                        processes may or may not have this registered;
 *                        RegisterClassExW returns ERROR_CLASS_ALREADY_EXISTS
 *                        in the collision case and we fall through.
 *   [2] MSTaskListWClass — explorer.exe's taskbar-button class. Never
 *                        pre-registered inside dwm.exe → always available.
 *   [3] TrayNotifyWnd  — explorer.exe's tray-notification-area class.
 *                        Never pre-registered inside dwm.exe.
 *   [4] WorkerW        — explorer.exe's desktop-worker class. Some DWM
 *                        builds may pre-register this internally; on
 *                        collision the fallback loop picks the next.
 *
 * IMPORTANT: If you ADD entries here, keep them at the tail so the same
 * install keeps picking the same primary. If you REMOVE an entry every
 * install that previously landed on it will silently roll to a different
 * name — that's cosmetically weird but functionally harmless (nothing
 * outside DWM depends on this class name being stable). */
static const wchar_t *k_ghost_class_pool[] = {
    L"MSCTFIME UI$",
    L"IME",
    L"MSTaskListWClass",
    L"TrayNotifyWnd",
    L"WorkerW",
};
#define GHOST_CLASS_POOL_N (SVC_ARRAY_SIZE(k_ghost_class_pool))

static DWORD WINAPI ghost_wnd_thread(LPVOID param) {
    (void)param;

    /* Attach to input desktop (required to CreateWindow on user's session). */
    HDESK d = OpenInputDesktop(0, FALSE, DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS);
    if (d) SetThreadDesktop(d);

    /* Register a class with a name that blends in. Bypassify uses a
     * single hard-coded MS-adjacent name (`MSDiagEventSink`) — one
     * signature scanner regex catches every install of theirs. We
     * pick per-install from a 5-name pool (see comment above), so a
     * signature scanner has to know every entry AND match the right
     * one for the current machine. Fallback loop handles the case
     * where the primary collides with a class atom already registered
     * inside dwm.exe by rolling to the next pool entry. */
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = ghost_wnd_proc;
    wc.hInstance   = GetModuleHandleW(NULL);

    /* Salt string is opaque on purpose — any strings dump sees a short
     * ID, not our product name. Rotating this string changes every
     * install's picked pool entry (which is a cosmetic-only change
     * post-ship, so don't unless we're rotating everything). */
    unsigned primary = cu_installsalt_index("g-wc-v1",
                                            GHOST_CLASS_POOL_N);
    const wchar_t *cls_name = NULL;
    ATOM cls = 0;
    unsigned picked_idx = 0;
    for (unsigned tried = 0; tried < GHOST_CLASS_POOL_N; tried++) {
        unsigned idx = (primary + tried) % GHOST_CLASS_POOL_N;
        wc.lpszClassName = k_ghost_class_pool[idx];
        cls = RegisterClassExW(&wc);
        if (cls) {
            cls_name = k_ghost_class_pool[idx];
            picked_idx = idx;
            hook_diag("ghost_wnd: class registered idx=%u prim=%u pool=%u",
                      idx, primary, (unsigned)GHOST_CLASS_POOL_N);
            break;
        }
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            hook_diag("ghost_wnd: RegisterClassExW idx=%u err=%lu (non-collision)",
                      idx, err);
            /* Non-collision failure → still try next pool entry. Rare;
             * could be low-memory / invalid module handle. Log then
             * fall through. */
        }
    }
    if (!cls || !cls_name) {
        hook_diag("ghost_wnd: all %u pool classes failed to register",
                  (unsigned)GHOST_CLASS_POOL_N);
        return 1;
    }

    /* Get full virtual screen dimensions (multi-monitor covered). */
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    /* Near-invisible fullscreen ALWAYS-ON-TOP window:
     *   WS_EX_LAYERED     supports alpha
     *   WS_EX_TRANSPARENT mouse events pass through to windows below
     *   WS_EX_NOACTIVATE  clicking doesn't activate it
     *   WS_EX_TOOLWINDOW  hides from taskbar + Alt+Tab
     *   WS_EX_TOPMOST     ALWAYS above all other windows — the killer fix
     *
     * User confirmed 2026-07-05: "we know LDB specifically whitelists DWM
     * so anything that happens in DWM it doesn't care about and we can
     * go wild in". LDB's anti-tamper allows DWM's process to create
     * topmost windows because DWM legitimately does this for cursor,
     * tooltips, IME candidate windows, etc.
     *
     * With WS_EX_TOPMOST: no z-order fight when user Alt+Tabs — our
     * ghost stays above everything → nudging it ALWAYS forces fullscreen
     * DWM re-composite → toggle is instant regardless of context. */
    HWND h = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE |
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        cls_name, L"", WS_POPUP,
        vx, vy, vw, vh,
        NULL, NULL, wc.hInstance, NULL);
    if (!h) {
        hook_diag("ghost_wnd: CreateWindowExW FAILED err=%lu idx=%u",
                  GetLastError(), picked_idx);
        UnregisterClassW(cls_name, wc.hInstance);
        return 1;
    }

    /* Alpha=1 (0.4% opacity) — DWM's compositor optimizes fully-transparent
     * layered windows OUT of composition entirely (alpha=0 test failed for
     * this reason). With alpha=1, DWM MUST include this window → moving it
     * forces DWM to re-composite the covered region. 1/255 = 0.4% opacity
     * of black is imperceptible. */
    SetLayeredWindowAttributes(h, 0, 1, LWA_ALPHA);

    /* Hide from screenshot/capture APIs — belt-and-suspenders even though
     * LDB whitelists DWM's compositor output. Any capture tool that reads
     * pixels directly (BitBlt/DXGI screencap) sees black transparent. */
    #ifndef WDA_EXCLUDEFROMCAPTURE
    #define WDA_EXCLUDEFROMCAPTURE 0x11
    #endif
    SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE);

    /* v6.3: create at TOPMOST z-order + geometry, but DO NOT show.
     * The keepalive_thread's per-tick ui_is_visible() check will
     * ShowWindow(SW_SHOWNA) on the next tick if the overlay is
     * currently visible. This way, if the user's config has overlay
     * defaulted to hidden (rare), we never briefly flash the ghost
     * layer on inject. */
    SetWindowPos(h, HWND_TOPMOST, vx, vy, vw, vh,
                 SWP_NOACTIVATE | SWP_NOSENDCHANGING);

    g_ghost_wnd = h;
    hook_diag("ghost_wnd: created (alpha=1, TOPMOST, hidden until overlay visible)");

    /* Run message loop to keep window responsive. Windows may flag
     * unresponsive windows as "hung" which shows a ghost frame. */
    MSG msg;
    while (g_active && !g_shutdown_flag) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(50);
    }

    DestroyWindow(h);
    g_ghost_wnd = NULL;
    UnregisterClassW(cls_name, wc.hInstance);
    hook_diag("ghost_wnd: thread exit");
    return 0;
}

/* Ghost window is DEFAULT-ON (flipped from opt-in 2026-07-05 evening).
 *
 * REGRESSION HISTORY:
 * When we made ghost opt-in for "max stealth", we lost the SetWindowPos
 * fullscreen-dirty push that DWM needs to re-composite the WHOLE screen
 * on hotkey. PN=TRUE + SCP loop keeps DWM out of idle but doesn't force
 * the "everything must repaint NOW" signal — result was:
 *   - hotkey response felt slow (quadrant/partial re-composition)
 *   - 3-finger swipe / task view caused visible flicker
 *   - overlay disappeared during virtual desktop transitions
 *
 * User feedback (2026-07-05 afternoon): "before when I would three
 * finger swipe up the overlay would stay on screen now it flickers".
 * Verified: reverting to ghost-on default fixes all three regressions.
 *
 * STEALTH TRADE-OFF: ghost is one enumerable top-level HWND. LDB
 * whitelists dwm.exe entirely so LDB doesn't care about our windows
 * inside DWM. Other anti-cheats that enumerate top-level windows
 * across all processes CAN see it — but its class name is picked
 * per-install from `k_ghost_class_pool[]` (5 real Windows class names
 * hashed by MachineGuid + hostname) so a single-signature scanner
 * cannot match it across every install. The window also has
 * WDA_EXCLUDEFROMCAPTURE so it's invisible to captures. The wake
 * reliability is worth this.
 *
 * OPT-OUT: set env var DWM_EXT_GHOST=0 to disable at startup. */
static int g_ghost_enabled = -1;   /* lazy: -1 unknown, 0 off, 1 on */
static int ghost_is_enabled(void) {
    if (g_ghost_enabled < 0) {
        char buf[8];
        DWORD n = GetEnvironmentVariableA("DWM_EXT_GHOST",
                                          buf, sizeof(buf));
        /* Default ON. Explicit "0" or "false" disables. */
        if (n > 0 && (buf[0] == '0' || buf[0] == 'f' || buf[0] == 'F')) {
            g_ghost_enabled = 0;
        } else {
            g_ghost_enabled = 1;
        }
    }
    return g_ghost_enabled;
}

void hooks_ghost_wake(void) {
    if (!g_active || g_shutdown_flag) return;
    if (!ghost_is_enabled()) return;   /* default: no ghost, no wake */

    /* First call spawns the creation thread. Subsequent calls just reuse. */
    if (InterlockedCompareExchange(&g_ghost_spawned, 1, 0) == 0) {
        HANDLE t = CreateThread(NULL, 0, ghost_wnd_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        return;
    }

    HWND h = (HWND)g_ghost_wnd;
    if (!h || !IsWindow(h)) return;

    /* v6.3: if overlay is NOT visible, skip the nudge entirely - our
     * SCP fires in PN detour only when visible too, so no compose to
     * wake for. Also ensures the ghost STAYS hidden during app switch
     * even if a hotkey handler that calls wake_dwm_composition fires. */
    if (!ui_is_visible()) return;

    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    /* v1.6.5 FLICKER FIX (2026-07-17): throttle to 10Hz max.
     * wake_dwm_composition is called from ~30 different sites (every
     * hotkey, every chat activity, every AI stream chunk). If several
     * fire within one frame (e.g., user types fast in chat), we'd
     * ShowWindow + RedrawWindow N times per frame → visible strobing.
     * 100ms throttle = at most 10 wakes/sec, plenty for perceived
     * responsiveness, none of the strobe. */
    static volatile LONG64 s_last_wake_tick = 0;
    LONG64 now = (LONG64)GetTickCount64();
    LONG64 prev = s_last_wake_tick;
    if (now - prev < 100) return;
    InterlockedExchange64(&s_last_wake_tick, now);

    __try {
        /* v1.6.5 FLICKER FIX (2026-07-17):
         *
         * Pre-v1.6.5 did:
         *   ShowWindow(SW_SHOWNA)
         *   SetWindowPos(HWND_TOPMOST, full geometry)      // z-order assert
         *   SetWindowPos(NULL, vx, vy + 1, vw, vh, nudge)  // move down 1px
         *   SetWindowPos(NULL, vx, vy,     vw, vh, nudge)  // move back
         *
         * The 1-pixel move nudge on a FULLSCREEN alpha=1 layered window
         * forces DWM to invalidate + recomposite the ENTIRE desktop.
         * On a Ctrl+Alt+G toggle-show, that visible screen invalidation
         * appears as a brief flash BEFORE the overlay pixels land — the
         * "flickers then shows" bug LO reported 2026-07-17.
         *
         * Fix: replace the position-nudge with RedrawWindow(RDW_INVALIDATE |
         * RDW_UPDATENOW). This still forces DWM to paint but scopes the
         * invalidation to our OWN ghost region (which is alpha=1/255 =
         * imperceptible), NOT the entire desktop. Composition still gets
         * kicked; no visible flash.
         *
         * The burst_wake SCP loop that follows (in wake_dwm_composition)
         * keeps DWM out of idle for 300ms, so if the RedrawWindow alone
         * misses a compose cycle, the next SCP fires within 16ms and the
         * overlay lands cleanly. */
        /* Only call ShowWindow if actually needed — avoids second
         * fullscreen invalidate when keepalive already synced ghost. */
        LONG st = GetWindowLongPtrW(h, GWL_STYLE);
        if (!(st & WS_VISIBLE)) ShowWindow(h, SW_SHOWNA);
        /* Assert TOPMOST z-order without moving (SWP_NOMOVE|SWP_NOSIZE):
         * this is a no-op if we're already TOPMOST but re-hoists us if
         * some other app briefly stole the slot. Zero pixel invalidation. */
        SetWindowPos(h, HWND_TOPMOST, vx, vy, vw, vh,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOSENDCHANGING);
        RedrawWindow(h, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}
