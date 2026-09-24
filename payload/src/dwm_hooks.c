/* ================================================================== *
 * dwm_hooks.c -- dwmcore hook implementation.                          *
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
 * next frame with ZERO user interaction -- solving the exact bug the  *
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
/* Present: 7-arg __fastcall.
 *
 * v1.7.11.4 (2026-07-25) -- CRITICAL FIX. Prior signature had only 6 args
 * which meant our call to orig Present passed uninitialized STACK GARBAGE
 * as the 7th arg (bool disableMPO). When garbage happened to be non-zero
 * DWM disabled MPO (fine, similar to our IsOverlayPrevented hack); when
 * garbage was 0 DWM re-enabled MPO -> Chrome's DirectComposition swapped
 * to hardware overlay planes -> our overlay pixels wrote to the software
 * composite path but Chrome's pixels went through hardware plane path ->
 * DWM couldn't reliably dirty-track our layer -> SHADOW TRAILS.
 *
 * Sources for 7-arg signature:
 *   1. chaosium43/dwm-overlay client/dwmcore.cpp (Win11 25H2, working
 *      reference implementation) -- HookPresent declared with 7 args
 *      including trailing `bool disableMPO`.
 *   2. Bypassify v1.3.0 Ghidra decomp (bp_decomp.c line 542) --
 *      Detour_Present has 7 params, last is `undefined1 param_7`.
 *   3. Our earlier BP RE at 0x180003470 disassembly showed reads from
 *      [rsp+0x88] confirming 7th arg present in Present's caller. */
typedef LONG (__fastcall *pfnCOverlayPresent_t)(
    void *pCtx, void *pLayer, UINT flags, void *a3, DWORD a4, void *a5,
    BOOL disableMPO);

/* PresentNeeded: 1-arg __fastcall taking pThis, returns BOOL. */
typedef BOOL (__fastcall *pfnPresentNeeded_t)(void *pThis);

/* ForceFullDirtyRendering: no args, no return. DANGEROUS to call from
 * arbitrary threads (crashed DWM in our earlier attempt -- see git log).
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
 * by user input events (mouse move -> tiny dirty rect at cursor). Our
 * overlay pixels outside that dirty rect never get sampled -> user sees
 * partial ("quadrant") updates. Calling AddDirtyRect with a fullscreen
 * rect on every PN fire ensures DWM always samples the ENTIRE layer. */
typedef void (__fastcall *pfnAddDirtyRect_t)(void *this_ptr, const float *rect);

/* ScheduleCompositionPass: `void (int arg0, int arg1)` -- RE'd 2026-07-05
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
 *   That's `ScheduleCompositionPass(arg0=0, arg1=-1)` -- RE-CONFIRMED.
 *   Bypassify's slot [7] @ 0x10e3fc on their build = ScheduleCompositionPass.
 *
 * Effect: every PN fire schedules the NEXT composition immediately ->
 * DWM never enters idle -> composition stays at native vsync rate.
 * This is the missing piece that keeps DWM at 60Hz continuously. */
typedef void (__stdcall *pfnScheduleCompositionPass_t)(int arg0, int arg1);

/* Extern from imgui_layer.cpp -- used by the PN detours + keepalive
 * to gate SCP/ghost activity on overlay visibility (v6.3 flicker fix). */
extern int ui_is_visible(void);

/* v1.7.10.5 (2026-07-24) -- DIRECTCOMPOSITION APP COMPOSE-GRACE.
 *
 * LO report: closing LDB + opening Chrome triggers shadow trails on
 * nudge + "kid eating cookie" chunk-by-chunk hide. Root cause: Chrome
 * (+ every DirectComposition app: Slack, Discord, Cursor, Electron,
 * hardware-accelerated video players) uses swap-chain direct-flip
 * that bypasses DWM's compositor. When we hide the overlay or nudge
 * it, DWM composes ONCE (partial clear), goes idle for Chrome
 * direct-flip, and our OLD-position overlay pixels stay cached in
 * DWM's compose tiles until Chrome eventually presents new content
 * over those tiles.
 *
 * Fix: track the last "visibility change / geometry change" tick.
 * PN detour checks: if within 500ms of last change, KEEP forcing
 * PN=TRUE + SCP even if overlay is hidden. This holds DWM in
 * composite mode for ~30 frames after the change, giving DWM enough
 * passes to clear all our stale tiles. After 500ms we let DWM go
 * idle again (Chrome regains direct-flip fast path).
 *
 * Set from ui_toggle_visible / ui_nudge / ui_resize etc via
 * hooks_bump_compose_grace(). */
static volatile LONG64 g_compose_grace_until_tick = 0;

/* v-ctrlb-hardening (2026-09-23) -- forward decls of teardown flags so
 * hooks_bump_compose_grace + hooks_uninstall_in_progress can gate on
 * them.  Real definitions are further down the file (near
 * Detour_COverlayContextPresent) alongside the phase-state comment;
 * these declarations just make them visible up here. */
extern volatile LONG g_active;
extern volatile LONG g_stop_draw;

void hooks_bump_compose_grace(unsigned ms) {
    /* v-ctrlb-hardening (2026-09-23) -- teardown gate. Bumping compose
     * grace after g_stop_draw is set just delays the graceful exit
     * (PN detours would keep forcing PN=TRUE during the drain phase we
     * WANT to end promptly). Also useless: hooks_begin_shutdown_hide
     * has already set its own 500ms grace window that covers instant-
     * hide semantics -- extra bumps from downstream toggle/nudge/resize
     * calls arriving mid-teardown would just push the shutdown drain
     * further out. Skip. */
    if (g_stop_draw || !g_active) return;
    LONG64 target = (LONG64)GetTickCount64() + (LONG64)ms;
    /* Only extend, never shorten. */
    LONG64 cur;
    do {
        cur = g_compose_grace_until_tick;
        if (target <= cur) return;
    } while (InterlockedCompareExchange64(&g_compose_grace_until_tick,
                                          target, cur) != cur);
}

/* v-ctrlb-hardening (2026-09-23) -- public accessor for teardown state.
 * Callers use this to skip work that would just make teardown slower or
 * cross a MinHook-disable race. Cheap: two volatile reads. */
int hooks_uninstall_in_progress(void) {
    /* Either flip is a "we're going away" signal:
     *  - g_stop_draw : hooks_begin_shutdown_hide OR hooks_uninstall set.
     *  - !g_active   : hooks_uninstall completed OR never installed. */
    if (g_stop_draw) return 1;
    if (!g_active)   return 1;
    return 0;
}

static int in_compose_grace_window(void) {
    LONG64 now = (LONG64)GetTickCount64();
    return (now < g_compose_grace_until_tick) ? 1 : 0;
}

/* ── Originals + state ── */
static pfnCOverlayPresent_t g_orig_present    = NULL;
static pfnPresentNeeded_t   g_orig_pn1        = NULL;   /* CDDisplayRenderTarget */
static pfnPresentNeeded_t   g_orig_pn2        = NULL;   /* CLegacyRenderTarget   */
static pfnForceFullDirty_t  g_force_full_dirty = NULL;  /* NOT hooked, just resolved */
static pfnScheduleCompositionPass_t g_schedule_composition = NULL;  /* the KEY wake fn */
static pfnAddDirtyRect_t    g_add_dirty_display = NULL;   /* CDDisplayRenderTarget::AddDirtyRect */
static pfnAddDirtyRect_t    g_add_dirty_legacy  = NULL;   /* CLegacyRenderTarget::AddDirtyRect  */

/* Hook TARGET addresses (what we passed to MH_CreateHook) -- cached at
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
/* g_ht_adr_display / g_ht_adr_legacy REMOVED 2026-07-06 v4.2 --
 * ADR[Display] + ADR[Legacy] hooks were passive RE-mode loggers that
 * observed AddDirtyRect calls without doing functional work. Now
 * uninstalled entirely (9 -> 7 hooks, smaller registry footprint,
 * fewer entries the hook integrity monitor needs to keep alive).
 * The trampoline pointers g_add_dirty_{display,legacy} are still
 * resolved (below) because they're a documented no-op fallback for
 * the quadrant fix -- leaving them keeps the offsets.blob layout
 * stable without touching the resolver. */

/* Present1/2: hooked to capture the TRUE `this` from DWM's own context.
 * PN's `this` might be virtual-base-adjusted (crashes AddDirtyRect); the
 * `this` inside Present is the top-level object with complete layout,
 * making AddDirtyRect safe to call from inside our Present detour. */
typedef LONG (__fastcall *pfnRTPresent_t)(void *pThis);
static pfnRTPresent_t       g_orig_present_display = NULL;
static pfnRTPresent_t       g_orig_present_legacy  = NULL;

/* RenderContent hooks -- CROWN JEWEL from hooksdll (dwm_payload.c line 2524):
 *   CWindowNode::RenderContent(this, pDrawCtx, pResult) is called for each
 *   window's node during composition. pDrawCtx has a field at +0x30 that's
 *   NULL when this render is targeting a CAPTURE buffer (LDB Monitor
 *   continuous screenshot, BitBlt, DXGI Duplication) vs the screen.
 *
 * Using this detection, we set g_in_capture_render while a capture-context
 * RenderContent is in progress. Our Detour_COverlayContextPresent checks
 * this flag and SKIPS drawing our overlay for capture renders -- the
 * overlay stays visible on the user's actual monitor but is INVISIBLE in
 * any capture LDB uploads to their server. */
typedef LONG (__fastcall *pfnRenderContent_t)(void *pThis, void *pDrawCtx, BOOL *pResult);
static pfnRenderContent_t   g_orig_rc_window  = NULL;   /* CWindowNode::RenderContent */
static pfnRenderContent_t   g_orig_rc_visual  = NULL;   /* CVisual::RenderContent     */

/* Offset inside CDrawingContext where the "screen render target" pointer
 * lives. If [pDrawCtx + 0x30] == NULL, this render is a CAPTURE pass
 * (verified via hooksdll RE -- dwm_payload.c line 2508). */
#define DRAWCTX_CAPTURE_FLAG_OFFSET 0x30

/* Capture-stealth latch -- set every time a RenderContent detour observes
 * a capture-context draw. Present detour (fires AFTER RenderContent in
 * the same compose cycle -- sometimes SIGNIFICANTLY after) checks if the
 * timestamp is within CAPTURE_LATCH_MS and skips draw if so.
 *
 * v1.7.4.6 (2026-07-24): CAPTURE_LATCH_MS was 15ms. LO's decrypted
 * payload log showed 500+ RC[Window] "capture" events in a 1.5s
 * burst = 333/sec on a machine with NOTHING actively capturing.
 * That means our `[pDrawCtx+0x30] == NULL` heuristic false-positives
 * on newer Windows 11 builds (26100.8115) for legitimate screen
 * render paths (window minimize animations, taskbar thumbnails,
 * task view previews, alt-tab peek, etc). With a 15ms latch, ONE
 * false-positive kept the overlay hidden for 15ms; a burst of them
 * kept overlay PERMANENTLY hidden -> "overlay hides/shows on mouse
 * move" flicker LO reported.
 *
 * FIX (LATCH REMOVED): rely entirely on the live counter g_in_capture_render.
 * The RC detour increments before orig, decrements after orig, so any
 * Present that fires DURING an RC call correctly sees > 0. Any Present
 * firing AFTER the RC decremented (even 100µs later) sees 0 -> overlay
 * draws. The 15ms latch was covering an edge case (Present fires ~ms
 * after RC returns) that basically never happens with the SEH-wrapped
 * increment/decrement pair -- and the false-positive damage from a
 * 300-events/sec burst FAR outweighed the correctness gain.
 *
 * Additionally: added `svcldb_capture_seen_screen[]` whitelist. Any
 * pDrawCtx we've EVER observed with non-NULL +0x30 (proving it's a
 * real screen-render context) is remembered. False-positive checks
 * against a whitelisted pDrawCtx are ignored -- legitimate screen
 * pixels flow. Only NEW (never-seen-as-screen) contexts with
 * NULL +0x30 count as capture. This preserves LDB Monitor stealth
 * (its capture pDrawCtx is genuinely never a screen context) while
 * ignoring DWM's internal-render false positives. */
#define CAPTURE_LATCH_MS 0
#define CAPTURE_CTX_WHITELIST_SIZE 32   /* small ring; DWM has few active pDrawCtx per moment */
static volatile LONG      g_in_capture_render     = 0;    /* live counter */
static volatile ULONGLONG g_capture_seen_tick     = 0;    /* GetTickCount64(), legacy latch */
static volatile LONG      g_capture_render_hits   = 0;
static volatile LONG      g_present_skips_capture = 0;
static volatile LONG      g_capture_false_positives = 0;
/* Whitelist ring of pDrawCtx pointers we've observed as screen contexts. */
static volatile ULONG_PTR g_ctx_whitelist[CAPTURE_CTX_WHITELIST_SIZE] = {0};
static volatile LONG      g_ctx_whitelist_head    = 0;

/* Hook target registry -- cached in hooks_install so the integrity
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

/* v-audit-hardening (2026-09-23) -- P1-1/6 (opus-4.7 Audit A).
 * Handles for the three worker threads spawned by hooks_install that
 * previously had their handles discarded via `CloseHandle` immediately
 * after `CreateThread`. hooks_uninstall now joins them (bounded
 * WaitForSingleObject) before the caller (`shutdown_watcher` in
 * dllmain.c) runs `FreeLibraryAndExitThread`. Prior code let a thread
 * mid-Sleep wake AFTER the payload's pages were freed by the launcher's
 * external VirtualFree -> instruction fetch in unmapped memory -> DWM
 * AV. Widest window was `keepalive_thread`'s Sleep(500|1000). */
static HANDLE g_keepalive_thread   = NULL;
static HANDLE g_ghost_wnd_thread_h = NULL;   /* _h suffix: separate from HWND g_ghost_wnd */
static HANDLE g_canary_thread      = NULL;

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

/* Forward decl -- hook_diag is defined further down; hook_crash_bump
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
    if (r->auto_disabled) return;   /* already disabled -- nothing to do */
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
         * auto_disabled compare-and-set -- only ONE thread should call
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

/* Early forward decl -- hook_diag is defined further down (its body
 * writes to encrypted slog) but hook_integrity_thread below calls it. */
static void hook_diag(const char *fmt, ...);

/* v3.1 (2026-09-21) -- Post-Windows-update degraded-mode flag.
 * Full definition + accessor + canary thread live further down (near
 * hooks_install) because they reference g_present_calls / g_stop_draw
 * which are defined AFTER this early forward-decl block. */
static volatile LONG g_compose_degraded = 0;
int hooks_compose_degraded(void) { return g_compose_degraded ? 1 : 0; }

/* Hook integrity monitor. Every 10s, walk the registry and verify the
 * first byte at each target is `0xE9` (MinHook's JMP rel32 trampoline
 * head). If any hook shows a non-`0xE9` first byte, an anti-cheat has
 * likely restored the original bytes to detect / disable us. Attempt
 * to re-enable via MinHook (MH_EnableHook is idempotent-safe).
 *
 * Never crashes DWM -- memcmp is wrapped in SEH, MH_EnableHook is
 * checked for success. Tamper hits logged for post-mortem analysis.
 *
 * CRITICAL -- INTERRUPTIBLE SLEEP:
 *   The old code used `Sleep(10000)` which is NOT cancellable. When
 *   the payload's shutdown_watcher fired hooks_uninstall (which sets
 *   g_integrity_running=0 + waits 500ms for this thread), the wait
 *   TIMED OUT because we were mid-Sleep. hooks_uninstall proceeded
 *   without us actually exiting, shutdown_watcher then called
 *   FreeLibraryAndExitThread, launcher's next inject-cycle sweep
 *   VirtualFreeEx'd the payload's code memory. When our Sleep
 *   returned, the CPU tried to execute the next instruction --
 *   which was in decommitted memory. HARD DWM CRASH.
 *
 *   Verified live 2026-07-06 13:10-13:17 EDT: multiple back-to-back
 *   DWM crashes with fault RIP at RVA 0x5462C / 0x54CC0 (inside this
 *   thread's post-Sleep return path).
 *
 *   Fix: chunk the 10s wait into 50ms Sleeps that re-check the flag
 *   on each iteration. Total wall-clock is still ~10s under normal
 *   operation, but shutdown drains within 50ms max. Cost is 200
 *   syscalls per 10s cycle -- negligible. No new globals/handles
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
             * target isn't within +/-2GB of the detour (rare) --
             * otherwise E9 rel32. On x64 with large VA space it can
             * also use FF25 (JMP [rip+0]) trampolines. Accept both. */
            if (first != 0xE9 && first != 0xFF) {
                InterlockedIncrement(&g_integrity_tamper_hits);
                hook_diag("integrity TAMPER on %s target=%p first=0x%02X -- re-enabling",
                          r->name ? r->name : "?", r->target, first);
                MH_STATUS s = MH_EnableHook(r->target);
                hook_diag("integrity re-enable %s -> %d", r->name ? r->name : "?", (int)s);
            }
        }
    }
    return 0;
}

static present_cb_t         g_present_cb      = NULL;

/* Volatile refs -- captured by PN detours on first invocation. Used by
 * hooks_force_wake() to directly trigger a compose pass without waiting. */
static volatile void *g_display_rt = NULL;
static volatile void *g_legacy_rt  = NULL;

/* ── Master switches (Bypassify pattern) ──
 *
 * Two-flag state machine because we have two DIFFERENT shutdown
 * phases and each needs different detour behavior:
 *
 * Phase A -- RUNNING (g_active=1, g_stop_draw=0):
 *   Present: draws overlay + calls orig
 *   PN:      returns TRUE  (force continuous compose)
 *
 * Phase B -- DRAINING (g_active=1, g_stop_draw=1):
 *   Present: SKIPS drawing overlay + calls orig
 *            (orig writes clean pixels to layer texture)
 *   PN:      returns TRUE  (force DWM to actually composite those
 *            clean frames within the 200ms drain window -- critical!
 *            If PN returned FALSE here, DWM would go lazy and our
 *            old overlay pixels would stay on screen indefinitely.)
 *
 * Phase C -- DISABLED (g_active=0, hooks about to be unhooked):
 *   Present: SKIPS drawing (g_stop_draw still 1)
 *   PN:      returns orig  (let DWM's normal lazy-compose take over)
 *   Then MH_DisableHook removes the detours entirely. */
volatile LONG g_active     = 0;   /* 1 while payload is alive (RUNNING + DRAINING) -- non-static so hooks_bump_compose_grace / hooks_uninstall_in_progress (earlier in TU) can read via extern decl */
volatile LONG g_stop_draw  = 0;   /* 1 = Present skips our draw callback -- non-static (same reason) */
/* v-next (2026-09-23) -- separate hooks_uninstall idempotency guard from
 * g_stop_draw so a caller can flip g_stop_draw for INSTANT overlay hide
 * (hooks_begin_shutdown_hide) without wedging a subsequent hooks_uninstall
 * into its "already done" early-return branch. Reset to 0 in hooks_install
 * to permit re-inject cycles. */
static volatile LONG g_uninstall_done = 0;

/* v3.5 (P0 explorer-restart) -- the shell-restart recovery lives ENTIRELY in
 * imgui_layer.cpp: ensure_fake_hwnd_valid() detects a restart (Progman HWND *or
 * its owning explorer PID* changed -- PID catches Windows' HWND reuse) and sets
 * g_needs_client_reinit; ui_present_frame (compose thread) then does ui_reinit()
 * and re-acquires fresh next frame -- Bypassify's exact Uninitialize->Initialize,
 * on the compose thread, no worker, no process spawn. This session's dead-end
 * experiments (worker-thread soft-reinject, sihost --reinject process spawn,
 * force-legacy-present which crashed DWM) were removed 2026-09-20. */
static volatile LONG   g_ghost_spawned;   /* real def with the ghost code below */

/* Legacy name for compatibility with hooks_bump_wake / hooks_force_wake
 * -- set to 1 alongside g_stop_draw so those helpers become no-ops
 * during shutdown. */
#define g_shutdown_flag g_stop_draw

/* Wake countdown. Decremented once per Present frame. While > 0, PN
 * detours return TRUE unconditionally = DWM composites every vsync. */
static volatile LONG g_wake_frames    = 0;

/* Burst-wake worker state. g_burst_end_ms is the TickCount when the
 * current burst expires -- updated atomically to extend the burst if
 * new hotkey events arrive. g_burst_running ensures only ONE worker
 * thread runs at a time (multiple hotkey presses in a row = O(1)). */
static volatile ULONG g_burst_end_ms  = 0;
static volatile LONG  g_burst_running = 0;
static volatile LONG  g_burst_interval_ms = 16;
static volatile LONG  g_burst_frames_per_pump = 30;

/* IsOverlayPrevented byte-patch bookkeeping -- so we can revert on
 * hooks_uninstall (belt-and-suspenders; Bypassify doesn't revert but
 * we do because a graceful uninstall in the same DWM instance benefits
 * from a clean restore). */
static BYTE  g_iop_saved_bytes[6] = {0};
/* v-audit-hardening (2026-09-23) -- P1-3 IsOverlayPrevented atomic patch:
 * bytes 6-7 preserved for the 8-byte-aligned atomic path in hooks_install.
 * Revert path also restores these so the full 8-byte window matches
 * what the original dwmcore layout was. */
static BYTE  g_iop_saved_tail[2]  = {0};
static void *g_iop_patch_addr     = NULL;
static BOOL  g_iop_patched        = FALSE;

/* v1.7.4.14 (2026-07-24) -- ForceFullDirtyRendering-adjacent byte-patch
 * to force dwmcore into "always full-dirty compose" mode. BP does
 * this at init (per docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md OffsetTable
 * slot [11] = 0x3fd7b9 = ForceFullDirtyRendering RVA - 0x60).
 *
 * Without this patch, DWM's compositor uses dirty-region tracking:
 * only re-renders regions that changed. When our overlay moves via
 * nudge, DWM DOESN'T re-render the old-position region -> old
 * overlay pixels linger in the layer texture -> user sees a trailing
 * "shadow" of the overlay along the movement path. */
static BYTE  g_ffd_saved_byte     = 0;
static void *g_ffd_patch_addr     = NULL;
static BOOL  g_ffd_patched        = FALSE;

/* Present-depth reentrancy guard -- DWM sometimes re-enters Present
 * indirectly. Process-global counter (NOT __declspec(thread) -- TLS is
 * broken under manual map). Worst case one dropped frame, no crash. */
static volatile LONG g_present_depth  = 0;
static volatile LONG g_present_calls  = 0;

/* Forward decl -- hook_diag body defined below alongside its raw helper. */
static void hook_diag(const char *fmt, ...);

/* Diagnostic -- same landmark cadence, routed through hook_diag (which
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
 * ARMED)" -- an anti-cheat could grep the disk for "capture stealth
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
    slog_writef("msvc_dbg_a.dat", "dwm: %s", msg);
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
/* Forward decl -- svcldb_capture_active is defined further down (after
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

/* v1.7.11.9 (2026-07-25) -- PRIMARY-MONITOR FILTER.
 *
 * chaosium43/dwm-overlay (Win11 25H2 working reference) filters compose
 * passes: only renders if the current COverlayContext's monitor target
 * IsPrimaryMonitor()==TRUE. Skips non-primary compose passes (secondary
 * monitor, virtual displays, aeropeek thumbnails, task view compose).
 *
 * We render into EVERY COverlayContext DWM presents -- creating render
 * conflicts on HiDPI laptops (LO 2880x1800) which have multiple compose
 * surfaces per vsync. Chrome-specific shadow trails likely come from
 * DWM's per-monitor dirty tracking seeing writes across surfaces.
 *
 * Fix: dynamically scan pCtx (COverlayContext*) for the field holding
 * pMonitorTarget. Try each 8-byte offset; first one where deref points
 * to something whose vtable+IsPrimaryMonitor call returns cleanly = our
 * target offset. Cache. Filter subsequent Presents.
 *
 * Chaosium43 does this at deploy-time via PDB (dumper.cpp:167-183). We
 * scan at runtime -- no PDB access needed on client machines. */
typedef BOOL (__fastcall *pfnIsPrimaryMonitor_t)(void *pMonitorTarget);
static pfnIsPrimaryMonitor_t g_is_primary_monitor = NULL;
static volatile LONG g_monitor_target_offset = -1;   /* -1 = not resolved */
static volatile LONG g_mto_scan_started      = 0;

static int is_ptr_readable_dwm(const void *p, size_t n) {
    if (!p) return 0;
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return ((BYTE *)p + n <= (BYTE *)mbi.BaseAddress + mbi.RegionSize);
}

static void discover_monitor_target_offset(void *pCtx) {
    if (g_monitor_target_offset >= 0) return;
    if (!pCtx || !g_is_primary_monitor) return;

    /* One-shot latch -- only first thread to reach here does the scan. */
    if (InterlockedCompareExchange(&g_mto_scan_started, 1, 0) != 0) return;

    /* Scan first 512 bytes (64 pointer slots) of COverlayContext for a
     * field that dereferences to an object whose IsPrimaryMonitor call
     * returns without crashing. Wrapped in SEH per-probe. */
    for (int slot = 0; slot < 64; slot++) {
        void **field = (void **)((BYTE *)pCtx + (slot * 8));
        if (!is_ptr_readable_dwm(field, 8)) continue;
        void *candidate = *field;
        if (!candidate) continue;
        if (!is_ptr_readable_dwm(candidate, 8)) continue;
        /* Check candidate has a plausible vtable -- first qword should
         * point into dwmcore's .text. */
        void *vtable = *(void **)candidate;
        /* Vtable pointer should be in a MEM_IMAGE region (loaded module).
         * If not, this isn't a real COM object. */
        {
            MEMORY_BASIC_INFORMATION vmbi = {0};
            if (VirtualQuery(vtable, &vmbi, sizeof(vmbi)) != sizeof(vmbi)) continue;
            if (vmbi.Type != MEM_IMAGE) continue;
        }

        /* Probe: call IsPrimaryMonitor(candidate). Wrapped in SEH. */
        __try {
            BOOL result = g_is_primary_monitor(candidate);
            /* Any bool return without crash is a valid hit. */
            g_monitor_target_offset = slot * 8;
            hook_diag("Monitor-target offset discovered: 0x%X (slot %d), IsPrimaryMonitor returned %d",
                      slot * 8, slot, result);
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Not this slot -- continue. */
            continue;
        }
    }
    hook_diag("Monitor-target offset scan: NO valid slot found in first 512 bytes -- filter disabled");
    g_monitor_target_offset = -2;  /* sentinel: scan complete, no offset */
}

/* Returns 1 if pCtx's monitor is primary (should render) OR if we can't
 * determine (scan in progress / failed / no fn) -- defensive: false
 * positives OK, false negatives break rendering entirely. */
static int should_render_this_context(void *pCtx) {
    if (!pCtx || !g_is_primary_monitor) return 1;  /* no filter possible */
    LONG off = g_monitor_target_offset;
    if (off < 0) return 1;  /* still scanning OR scan failed */
    __try {
        void *pMT = *(void **)((BYTE *)pCtx + off);
        if (!pMT) return 1;
        return g_is_primary_monitor(pMT) ? 1 : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* If probe crashes, disable filter permanently. */
        g_monitor_target_offset = -2;
        return 1;
    }
}

/* Detour_COverlayContextPresent -- main frame hook.
 * Draws overlay into layer texture BEFORE orig, so orig samples the
 * texture with our pixels already composited in.
 *
 * When g_shutdown_flag is set, SKIP the draw (lets orig composite
 * with the underlying app's clean pixels for ~200ms before MinHook
 * gets disabled -- that's what naturally clears our overlay off the
 * screen when the payload uninstalls). */
static LONG __fastcall Detour_COverlayContextPresent(
    void *pCtx, void *pLayer, UINT flags, void *a3, DWORD a4, void *a5,
    BOOL disableMPO)
{
    LONG ret = 0;
    int n = InterlockedIncrement(&g_present_calls);
    present_diag(n);

    /* NOTE: g_wake_frames is no longer decremented here -- we now match
     * Bypassify exactly by having PN detours ALWAYS return TRUE (see
     * Detour_DisplayPresentNeeded). The wake counter is legacy but the
     * hooks_bump_wake / hooks_force_wake / hooks_burst_wake APIs are
     * preserved as belt-and-suspenders (they still directly fire orig
     * PresentNeeded from arbitrary threads, which can help if DWM
     * happened to be blocked mid-frame). */

    if (InterlockedIncrement(&g_present_depth) > 1) {
        InterlockedDecrement(&g_present_depth);
        return g_orig_present ? g_orig_present(pCtx, pLayer, flags, a3, a4, a5, disableMPO) : 0;
    }

    __try {
        /* Draw BEFORE orig -- Bypassify's proven ordering.
         *
         * SKIP CONDITIONS:
         *  1. g_stop_draw (shutdown drain phase)
         *  2. svcldb_capture_active() -- checks both live counter AND
         *     tick-based latch (CAPTURE_LATCH_MS after last capture RC).
         *     Latch covers cases where Present fires AFTER RenderContent
         *     returns in the same capture cycle, since Present's args
         *     don't tell us if it's a capture target.
         *
         * OVERRIDE: if svcldb_debug_capture_wants_overlay() is true, we
         * are running an internal debug capture (Ctrl+Shift+Alt+S) that
         * wants overlay pixels IN the shot -- do NOT skip overlay draw. */
        extern int svcldb_debug_capture_wants_overlay(void);
        int is_capture   = svcldb_capture_active();
        int want_overlay = svcldb_debug_capture_wants_overlay();
        int skip_draw    = is_capture && !want_overlay;
        /* v1.7.11.12 (2026-07-25) -- v1.7.11.9 monitor filter DISABLED.
         *
         * The runtime-scan discovery for OverlayMonitorTarget struct
         * offset was too loose (accepts any pointer whose vtable is in
         * MEM_IMAGE, no dwmcore-specific validation). It sometimes
         * false-matched a wrong field -> IsPrimaryMonitor returned wrong
         * -> we skipped rendering on TRUE primary passes -> overlay
         * flickers off for a frame -> LO reported "jerks back".
         *
         * Reverting to always-render (old behavior). If we want proper
         * primary-monitor filter, we need PDB-based struct offset
         * resolution in our resolver (chaosium43-style) rather than
         * runtime pattern-scan. TODO for future.
         *
         * Chrome flicker persists but that's compose-level, not this
         * filter's fault. Focus other fixes there. */
        if (g_active && !g_stop_draw && !skip_draw && g_present_cb && pLayer) {
            g_present_cb(pCtx, pLayer);
            /* v1.7.11 REVERTED (2026-07-25). Adding hooks_add_dirty_full()
             * here calls AddDirtyRect on the PN-captured pThis pointer,
             * which the memory `trailing-do-not-adddirty` proves crashes
             * DWM with __fastfail at dwmcore!0xbedb4. SEH does NOT catch
             * __fastfail. Confirmed dangerous 2026-07-05. Left as
             * empty branch for git-diff clarity. */
        } else if (skip_draw) {
            LONG n = InterlockedIncrement(&g_present_skips_capture);
            if (n <= 5 || n % 500 == 0) {
                hook_diag("Present: SKIPPED overlay draw #%ld (capture in progress)", n);
            }
        }
        if (g_orig_present) ret = g_orig_present(pCtx, pLayer, flags, a3, a4, a5, disableMPO);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Silently swallow -- DWM crash = user desktop dies. */
        hook_diag("Detour_Present: caught exception in body");
        hook_crash_bump(g_ht_present, "Present body");
    }

    InterlockedDecrement(&g_present_depth);
    return ret;
}

/* Detour_CDDisplayRenderTarget_PresentNeeded -- Bypassify's core wake trick.
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
 * vsync tick with ZERO extra work -- DWM was already going to composite.
 *
 * This burns ~2-5% GPU continuously. Bypassify accepts this tradeoff
 * for zero-latency responsiveness. We do the same. */
static BOOL __fastcall Detour_DisplayPresentNeeded(void *pThis) {
    /* Capture pThis for hooks_force_wake() belt-and-suspenders. */
    if (!g_display_rt && pThis) {
        g_display_rt = pThis;
        hook_diag(SS(SVC_STR_PN1_CAPTURED));
    }
    BOOL orig_result = FALSE;
    __try {
        if (g_orig_pn1) orig_result = g_orig_pn1(pThis);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("PN1: exception in orig -- passing through FALSE");
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
    /* v1.7.10.5: DirectComposition app compose-grace.
     * If we're within the post-change grace window, KEEP forcing
     * PN=TRUE + SCP even when hidden -- this holds DWM in composite
     * mode long enough to clear stale tiles in Chrome/Slack/Cursor/
     * etc that would otherwise "chunk-eat" our old overlay pixels
     * as they direct-flip. Grace is set by hooks_bump_compose_grace
     * from ui_toggle_visible / ui_nudge / ui_resize / etc. */
    if (!ui_is_visible() && !in_compose_grace_window()) return orig_result;

    /* Overlay visible OR within compose grace -- fire SCP + return TRUE (BP pattern). */
    __try {
        if (g_schedule_composition) g_schedule_composition(0, -1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_crash_bump(g_ht_pn1, "PN1 SCP");
    }

    /* AddDirtyRect DISABLED -- CRASHED DWM in test 2026-07-05.
     * Root cause not fully understood: probably the pThis captured from
     * PresentNeeded is a virtual-base-adjusted `this` that doesn't match
     * what AddDirtyRect's trampoline+impl expects. Need to find safer
     * fullscreen-dirty mechanism. Left resolved for future experiment. */
    return TRUE;
}

/* Detour_CLegacyRenderTarget_PresentNeeded -- identical to PN1 but for
 * CLegacyRenderTarget (this is the RT that fires on most systems). */
static BOOL __fastcall Detour_LegacyPresentNeeded(void *pThis) {
    if (!g_legacy_rt && pThis) {
        g_legacy_rt = pThis;
        hook_diag(SS(SVC_STR_PN2_CAPTURED));
    }
    BOOL orig_result = FALSE;
    __try {
        if (g_orig_pn2) orig_result = g_orig_pn2(pThis);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_diag("PN2: exception in orig -- passing through FALSE");
        hook_crash_bump(g_ht_pn2, "PN2 orig");
        return FALSE;
    }

    if (!g_active) return orig_result;
    /* v6.3: mirror the PN1 gate - when overlay is hidden, let DWM
     * idle so DirectComposition apps can direct-flip. See PN1 for
     * full rationale.
     *
     * v-audit-hardening (2026-09-23) -- MIRROR PN1's compose-grace
     * check. Prior code checked only `ui_is_visible()`, so
     * `hooks_bump_compose_grace(500)` was a no-op on the LegacyRT
     * codepath -- which the header comment above says "is the RT that
     * fires on most systems". Result: DirectComposition apps
     * (Chrome/Slack/Cursor/Discord/video) kept holding stale overlay
     * tiles after every HIDE/nudge/resize despite the whole
     * `hooks_bump_compose_grace` API existing to prevent exactly that.
     * One-line fix identified by opus-4.7 Audit A. Bug lived since
     * v1.7.10.5 (2026-07-24). */
    if (!ui_is_visible() && !in_compose_grace_window()) return orig_result;

    __try {
        if (g_schedule_composition) g_schedule_composition(0, -1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_crash_bump(g_ht_pn2, "PN2 SCP");
    }

    /* AddDirtyRect DISABLED -- see PN1 detour comment above. */
    return TRUE;
}

/* Forward declarations (definitions after hooks_install for grouping). */
static DWORD WINAPI keepalive_thread(LPVOID param);
static DWORD WINAPI ghost_wnd_thread(LPVOID param);
static volatile HWND g_ghost_wnd;
static volatile LONG g_ghost_spawned;

/* Detour_CDDisplayRenderTarget_Present -- hooks the ACTUAL Present call
 * that DWM's compositor makes when it's about to composite an RT.
 * BEFORE calling orig, mark the entire RT as dirty via AddDirtyRect --
 * this is the ONE context where `this` is guaranteed to be the correct
 * top-level object, so AddDirtyRect is safe to call.
 *
 * Result: every time DWM tries to Present this RT, it composits the
 * entire layer (not just the small region user just interacted with).
 * Fixes the "quadrant" bug end-to-end. */
static LONG __fastcall Detour_DisplayPresent(void *pThis) {
    /* SEH-wrap orig -- any fault inside dwmcore's Present would bugcheck
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

/* IsCaptureRender -- hooksdll's proven heuristic (dwm_payload.c line 2503).
 * `[pDrawCtx + DRAWCTX_CAPTURE_FLAG_OFFSET (0x30)] == NULL` means
 * this render is targeting a capture buffer, not the screen.
 *
 * From RE of dwmcore: the field at +0x30 is a pointer to the screen
 * render target. For CAPTURE render passes (e.g., LDB Monitor snapshot),
 * this pointer is NULL because the capture uses a private off-screen
 * target. For NORMAL screen composition, this pointer references the
 * primary display's render target.
 *
 * v1.7.4.6 (2026-07-24) -- WHITELIST-AWARE. The +0x30 check
 * false-positives on Windows 11 26100.8115+ for internal-only render
 * paths (window minimize animations, taskbar thumbnails, task-view
 * previews, alt-tab peek). Fix: any pDrawCtx we've EVER observed with
 * non-NULL +0x30 (a real screen render) gets remembered in a small
 * ring. Subsequent NULL +0x30 observations for a whitelisted pDrawCtx
 * are treated as noise (real captures use ephemeral pDrawCtx pointers
 * that never appear as screen contexts).
 *
 * whitelist_pDrawCtx(): add pDrawCtx to the ring (called every time
 * we see it with non-NULL +0x30).
 * is_pDrawCtx_whitelisted(): O(N=32) linear scan. */
static void svcldb_whitelist_ctx(void *pDrawCtx) {
    if (!pDrawCtx) return;
    ULONG_PTR key = (ULONG_PTR)pDrawCtx;
    /* Check if already present first (avoid churning the ring). */
    for (int i = 0; i < CAPTURE_CTX_WHITELIST_SIZE; i++) {
        if (g_ctx_whitelist[i] == key) return;
    }
    LONG h = InterlockedIncrement(&g_ctx_whitelist_head) - 1;
    g_ctx_whitelist[h % CAPTURE_CTX_WHITELIST_SIZE] = key;
}

static BOOL svcldb_ctx_is_whitelisted(void *pDrawCtx) {
    if (!pDrawCtx) return FALSE;
    ULONG_PTR key = (ULONG_PTR)pDrawCtx;
    for (int i = 0; i < CAPTURE_CTX_WHITELIST_SIZE; i++) {
        if (g_ctx_whitelist[i] == key) return TRUE;
    }
    return FALSE;
}

/* Rate-limit state -- if RC[+0x30]==NULL fires > CAPTURE_RATE_LIMIT_PER_SEC
 * in a rolling window, treat subsequent hits as "definitely false-positive".
 * Real captures (LDB Monitor / OBS / Snip) fire ~1-5/sec. DWM internal
 * false-positives fire 300-1000/sec. This crisply separates them. */
#define CAPTURE_RATE_LIMIT_PER_SEC 20
static volatile LONG      g_capture_bucket_count  = 0;
static volatile ULONGLONG g_capture_bucket_start  = 0;

/* Forward decl -- ldb_detect exports this. */
extern int ldb_detect_active(void);

/* v1.7.4.12 (2026-07-24) -- CAPTURE DETECTION FULLY DISABLED.
 *
 * Bypassify has NO RC[Window]/RC[Visual] hooks and NO capture-active
 * flag. Their overlay pixels appear in captures. They accept that
 * trade-off because LDB v2.1.5 whitelists dwm.exe entirely (per our
 * own audit doc) so LDB never scans DWM's memory or DWM's compose
 * output for suspicious content. Same is true for us.
 *
 * Our capture detection was ADDING flicker: every RC[Window] fire
 * caused a Present-skip decision path with latching + whitelist +
 * rate-limit logic. Even with the LDB gate short-circuit (v1.7.4.7)
 * the counter/hook overhead is unnecessary compositor pressure.
 *
 * ALWAYS return FALSE. If a future user genuinely needs capture
 * stealth (e.g., proctor tool that DOES scan DWM), we can re-enable
 * behind a config flag. */
static BOOL svcldb_is_capture_render(void *pDrawCtx) {
    (void)pDrawCtx;
    return FALSE;
    /* --- dead code below (kept so ldb_detect_active etc. still link) --- */
    if (!pDrawCtx) return FALSE;
    if (!ldb_detect_active()) return FALSE;   /* v1.7.4.7 LDB-gated */
    __try {
        void *screen_rt = *(void **)((BYTE *)pDrawCtx + DRAWCTX_CAPTURE_FLAG_OFFSET);
        if (screen_rt != NULL) {
            /* Legit screen render -- memoize this pDrawCtx as trusted. */
            svcldb_whitelist_ctx(pDrawCtx);
            return FALSE;
        }
        /* +0x30 is NULL. Could be capture OR could be a false-positive
         * from a DWM internal-only render on a pDrawCtx we've seen
         * doing legit screen work before. */
        if (svcldb_ctx_is_whitelisted(pDrawCtx)) {
            InterlockedIncrement(&g_capture_false_positives);
            return FALSE;   /* known-good context, don't skip Present */
        }
        /* v1.7.4.7 (2026-07-24) -- RATE LIMIT the "possible capture"
         * verdict. Some pDrawCtx pointers NEVER appear in screen-render
         * mode so the whitelist can't learn them (e.g. a per-thumbnail
         * cache DrawingContext that always renders offscreen). We saw
         * 5500 RC[Window] hits with pThis=0x27719ABA5B0 in 40s = 137/sec
         * on LO's box -- every one bypassed the whitelist because the
         * ctx literally never fired with non-NULL +0x30.
         *
         * Real capture pipelines (LDB Monitor, OBS, Snip) sample at
         * 1-10 Hz. DWM internal-render bursts fire at 100-1000 Hz.
         * Anything above CAPTURE_RATE_LIMIT_PER_SEC (20) is
         * almost-certainly noise, not a genuine capture attempt. */
        ULONGLONG now = GetTickCount64();
        ULONGLONG bucket_start = (ULONGLONG)g_capture_bucket_start;
        if (bucket_start == 0 || (now - bucket_start) >= 1000) {
            /* Bucket rollover -- reset. */
            InterlockedExchange64((volatile LONG64 *)&g_capture_bucket_start, (LONG64)now);
            InterlockedExchange(&g_capture_bucket_count, 1);
            return TRUE;   /* first of a new second -- trust it */
        }
        LONG c = InterlockedIncrement(&g_capture_bucket_count);
        if (c > CAPTURE_RATE_LIMIT_PER_SEC) {
            /* Over budget -> false-positive, don't count as capture. */
            LONG fp = InterlockedIncrement(&g_capture_false_positives);
            if (fp == 1 || (fp % 200) == 0) {
                hook_diag("RC: rate-limit FILTERED event #%ld (bucket_count=%ld now=%llu bucket_start=%llu)",
                          fp, c, (unsigned long long)now, (unsigned long long)g_capture_bucket_start);
            }
            return FALSE;
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* Detour_CWindowNode_RenderContent -- sets g_in_capture_render for the
 * duration of the orig call when we detect a capture-context render.
 * The Present detour (called AFTER this returns during a full compose
 * cycle) checks the counter and skips our overlay draw if > 0.
 *
 * We also count "cycle skipped" -- after RenderContent returns, the
 * counter goes back to 0. Present may fire AFTER RenderContent for the
 * same cycle so we keep the flag set for slightly longer via a delay.
 * Actually simplest: increment on entry, decrement on exit. Present hook
 * checks value at time of firing -- during capture composition it'll be
 * non-zero. */
static LONG __fastcall Detour_CWindowNode_RenderContent(
    void *pThis, void *pDrawCtx, BOOL *pResult)
{
    int captured_this_call = 0;
    __try {
        if (svcldb_is_capture_render(pDrawCtx)) {
            InterlockedIncrement(&g_in_capture_render);
            /* Latch the tick -- Present may fire after this returns */
            InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                                  (LONG64)GetTickCount64());
            captured_this_call = 1;
            LONG n = InterlockedIncrement(&g_capture_render_hits);
            LONG fp = g_capture_false_positives;
            if (n <= 5 || n % 500 == 0) {
                hook_diag("RC[Window]: capture render #%ld pThis=%p (false-positives filtered=%ld)",
                          n, pThis, fp);
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
        /* Re-stamp AFTER the orig call too -- some capture paths do
         * meaningful work in the orig that overruns the pre-stamp. */
        InterlockedExchange64((volatile LONG64 *)&g_capture_seen_tick,
                              (LONG64)GetTickCount64());
    }
    return ret;
}

/* Detour_CVisual_RenderContent -- same as WindowNode variant but hooks
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

/* svcldb_capture_active -- check if we're within a capture render call.
 * Called from Present detour. v1.7.4.6: latch fully removed; relies
 * only on the live counter g_in_capture_render (RC detour's SEH-wrapped
 * increment/decrement guarantees any Present firing DURING an orig RC
 * call sees > 0). CAPTURE_LATCH_MS constant kept at 0 for the
 * belt-and-suspenders tick check (compiles out at 0 gap). */
static BOOL svcldb_capture_active(void) {
    if (g_in_capture_render > 0) return TRUE;
    if (CAPTURE_LATCH_MS == 0) return FALSE;
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
 *   - Drops us from 9 -> 7 dwmcore hooks (smaller detectable surface).
 *   - Removes 2 entries from the hook_registry (less for the integrity
 *     monitor to keep alive).
 *   - Zero functional impact -- the detours never modified behaviour;
 *     they just logged and forwarded.
 *
 * If we ever need this observability back, git log the file -- the
 * Detour_AddDirtyRect_* bodies are preserved in the pre-removal commit. */

/* v3.1 (2026-09-21) -- Present-fire canary thread.
 *
 * Verifies DWM is actually invoking our COverlayContext::Present detour.
 * If it never does within a reasonable window, log LOUD warning +
 * set g_compose_degraded so ui_present_frame short-circuits.
 * Zero corrective action -- observability + safe quiesce only.
 *
 * v-ctrlb-hardening (2026-09-23) -- RAISED the initial alert threshold
 * from 2s -> 15s. Empirical: on my Win11 25H2 box, DWM sometimes takes
 * 5-15s to first call our Present detour after hooks_install (idle
 * desktop with no window movement, HDR content playing on a secondary
 * monitor, DWM in low-power compose mode). The 2s canary tripped
 * false-positive there, latching g_compose_degraded=1 for the next
 * 28 seconds -> overlay invisible -> user hits Ctrl+B trying to make
 * it appear -> toggle path still kicks DWM (invalidate + compose-grace
 * bump) which on a truly-shifted compose path could cause the "screen
 * goes black" P0 symptom.
 *
 * New timing:
 *   T+5s   : SILENT sample (no alert; just observability if we want to
 *            grep for very-fast healthy starts).
 *   T+15s  : ALERT if still zero -- this is a REAL degraded state.
 *   T+30s  : ALERT if still zero -- second chance for cold GPU / TDR
 *            recovery / dwm-restart timing edges.
 *
 * Also added: if we EVER sample n > 0 after a prior alert set degraded,
 * clear degraded immediately -- self-heal the moment DWM starts calling
 * our detour. This closes the "canary fires at T+15s but Present starts
 * firing at T+16s" edge case where we would previously stay degraded
 * for another 15s waiting for the next sample.
 *
 * Placement: HERE (not near forward decls) because it references
 * g_present_calls / g_stop_draw which are defined above near
 * Detour_COverlayContextPresent. */
static DWORD WINAPI present_fire_canary_thread(LPVOID unused) {
    (void)unused;
    /* v-audit-hardening (2026-09-23) -- P1-5 (opus-4.7 Audit A).
     *
     * PRIOR: bounded for-loop over 4 sample steps (T+5s / +15s / +30s /
     * +60s). After the last step the thread returned. If DWM's compose
     * path was still silent at T+60s, `g_compose_degraded=1` was
     * permanent for the rest of the DWM session. But Present CAN recover
     * later (cold GPU / TDR / HDR transition / driver reset can take
     * >60s), and now nobody was watching. Overlay stayed dead until
     * `sihost --unload && --reinject`.
     *
     * NOW: infinite loop with exponential-backoff sleep (100ms -> 1s ->
     * 5s -> 30s cap). Every wake, sample g_present_calls and adjust the
     * degraded flag both ways -- set it if we've been silent for
     * ALERT_MS (15s baseline), clear it the instant Present is firing.
     * Terminate ONLY on `g_stop_draw` (unload/shutdown). Cost after the
     * first minute: one wake every 30s, one atomic read = negligible. */
    const DWORD ALERT_MS  = 15000;   /* how long silence must persist to alert */
    DWORD sleep_ms        = 100;     /* start dense, back off after healthy sample */
    DWORD silent_ms       = 0;       /* accumulated silence since last Present */
    LONG  last_seen_count = 0;
    LONG  last_seen_state = 0;       /* last logged degraded state */

    for (;;) {
        if (g_stop_draw) return 0;
        Sleep(sleep_ms);
        if (g_stop_draw) return 0;

        LONG n = g_present_calls;
        if (n > last_seen_count) {
            /* Present fired since last sample -> compose path is alive. */
            silent_ms = 0;
            last_seen_count = n;
            LONG was = InterlockedExchange(&g_compose_degraded, 0);
            if (was || last_seen_state != 0) {
                hook_diag("Present recovered: count=%ld -- compose path "
                          "healed, g_compose_degraded=0.", (long)n);
                last_seen_state = 0;
            }
            /* Ease off sampling once we've seen healthy activity. */
            if (sleep_ms < 30000) sleep_ms = (sleep_ms < 1000) ? 1000
                                            : (sleep_ms < 5000) ? 5000
                                                                : 30000;
        } else {
            /* Still silent.  Accumulate silent time. */
            silent_ms += sleep_ms;
            if (silent_ms >= ALERT_MS && !g_compose_degraded) {
                InterlockedExchange(&g_compose_degraded, 1);
                hook_diag("PRESENT PATH INACTIVE for %lu ms -- "
                          "COverlayContext::Present hook installed but DWM "
                          "has not called it. Compose path may have shifted "
                          "post-Windows-update. Setting g_compose_degraded=1 "
                          "-- ui_present_frame will no-op until it recovers. "
                          "Payload stays loaded for rawinput/hotkey use. "
                          "Canary continues to watch for self-heal.",
                          (unsigned long)silent_ms);
                last_seen_state = 1;
            }
            /* Stay dense-sampling while we're worried. */
            if (silent_ms < ALERT_MS)      sleep_ms = 100;   /* first 15s */
            else if (silent_ms < 60000)    sleep_ms = 500;   /* 15-60s */
            else                           sleep_ms = 5000;  /* >1 min silent */
        }
    }
    /* NOTREACHED */
}

/* ── Public API ── */

/* v-multibuild (2026-09-24) -- validation gate helpers.
 *
 * See docs/HANDOFF_2026-09-24_MULTIBUILD_UNIVERSAL_SUPPORT.md for the
 * full rationale + threat model. In one sentence: before we hook a
 * single byte, verify the RVAs in offsets.blob point at the exact
 * dwmcore.dll the resolver ran against; if any critical mismatch, DON'T
 * hook -- set g_compose_degraded=1, log verbosely, keep the payload
 * loaded so rawinput / token_refresh / helper still work. Prevents the
 * "DWM crashes on unfamiliar Windows patch" regression class. */

/* Return: 32-bit PE TimeDateStamp of a loaded module (dwmcore.dll),
 * or 0 on parse failure. Uses only the in-memory PE headers -- no
 * disk I/O. Safe on manual-mapped or PEB-unlinked modules. */
static DWORD dwmcore_live_tds(HMODULE m) {
    if (!m) return 0;
    DWORD tds = 0;
    __try {
        BYTE *b = (BYTE *)m;
        DWORD e_lfanew = *(DWORD *)(b + 0x3C);
        if (e_lfanew < 0x1000 && b[e_lfanew] == 'P' && b[e_lfanew+1] == 'E') {
            tds = *(DWORD *)(b + e_lfanew + 4 + 4);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        tds = 0;
    }
    return tds;
}

/* Return: SizeOfImage from PE header, or 0 on parse failure. */
static DWORD dwmcore_live_size(HMODULE m) {
    if (!m) return 0;
    DWORD sz = 0;
    __try {
        BYTE *b = (BYTE *)m;
        DWORD e_lfanew = *(DWORD *)(b + 0x3C);
        if (e_lfanew < 0x1000 && b[e_lfanew] == 'P' && b[e_lfanew+1] == 'E') {
            /* IMAGE_OPTIONAL_HEADER64.SizeOfImage at IMAGE_FILE_HEADER
             * base (e_lfanew+4) + FileHeader size (20) + OptionalHeader
             * offset 56. */
            sz = *(DWORD *)(b + e_lfanew + 4 + 20 + 56);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sz = 0;
    }
    return sz;
}

/* Return: 1 if `[dwmcore + rva]` is inside dwmcore's image AND readable,
 * 0 otherwise. Uses live PE parse for bounds. Skips validation (returns 1)
 * when rva==0 (the "not resolved" sentinel used by nice-to-have symbols). */
static int rva_in_dwmcore(HMODULE dwmcore, uint64_t rva, size_t nbytes) {
    if (rva == 0) return 1;   /* not-resolved = not-hooked = not-checked  */
    DWORD img_sz = dwmcore_live_size(dwmcore);
    if (!img_sz) return 0;
    if (rva + nbytes > img_sz) return 0;
    BYTE *p = (BYTE *)dwmcore + rva;
    /* is_readable via VirtualQuery -- non-committed / no-access pages
     * would AV on the memcmp otherwise. */
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS ||
        (mbi.Protect & PAGE_GUARD)) return 0;
    return 1;
}

/* SEH-wrapped byte compare against a live dwmcore address. Returns 1 if
 * `[dwmcore + rva]` matches `expected[0..n]` for all n bytes; 0 on any
 * difference OR read fault. */
static int compare_bytes_at_rva(HMODULE dwmcore, uint64_t rva,
                                const uint8_t *expected, size_t n) {
    if (!rva_in_dwmcore(dwmcore, rva, n)) return 0;
    int match = 0;
    __try {
        BYTE *live = (BYTE *)dwmcore + rva;
        match = 1;
        for (size_t i = 0; i < n; i++) {
            if (live[i] != expected[i]) { match = 0; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        match = 0;
    }
    return match;
}

/* Result codes for the validation gate. */
#define BLOB_VALIDATE_OK      0   /* proceed with normal hooks_install    */
#define BLOB_VALIDATE_SKIP    1   /* v1 blob: no snapshot, skip validate  */
#define BLOB_VALIDATE_FAILED  2   /* v2 snapshot present + mismatch found */

/* Validate an ext snapshot against live dwmcore. Extremely defensive:
 * every read is SEH-wrapped, every bounds check goes through
 * rva_in_dwmcore. Returns BLOB_VALIDATE_FAILED for a CRITICAL mismatch
 * (Present or IsOverlayPrevented prologue differs, OR TDS differs).
 * Non-critical mismatches (e.g. .data byte at ForceFullDirty differs)
 * are logged but return OK -- the existing bool-guard in the FFD patch
 * path handles those safely. */
static int validate_blob_snapshot(HMODULE dwmcore,
                                  const pl_offsets_t *off,
                                  const pl_offsets_ext_t *ext) {
    if (!ext || ext->magic != PL_OFFSETS_EXT_MAGIC) {
        return BLOB_VALIDATE_SKIP;
    }

    /* Check 1: dwmcore PE TimeDateStamp. If Windows Update raced between
     * resolve + inject, the live dwmcore.dll has a different TDS from
     * what the resolver captured -> every RVA is potentially stale. */
    DWORD live_tds = dwmcore_live_tds(dwmcore);
    if (live_tds && ext->dwmcore_tds && live_tds != ext->dwmcore_tds) {
        slog_writef("msvc_dbg_a.dat",
            "validate: DWMCORE TDS MISMATCH -- blob=0x%08X live=0x%08X. "
            "Windows updated dwmcore between resolve+inject. Refusing to "
            "hook (SAFE-MODE: payload lives, no overlay, DWM stable).",
            ext->dwmcore_tds, live_tds);
        return BLOB_VALIDATE_FAILED;
    }

    /* Check 2: SizeOfImage. Sanity check -- shouldn't differ if TDS
     * matched, but a corrupted blob might have both wrong. */
    DWORD live_sz = dwmcore_live_size(dwmcore);
    if (live_sz && ext->dwmcore_size && live_sz != ext->dwmcore_size) {
        slog_writef("msvc_dbg_a.dat",
            "validate: DWMCORE SIZE MISMATCH -- blob=%lu live=%lu. "
            "Refusing to hook (SAFE-MODE).",
            (unsigned long)ext->dwmcore_size, (unsigned long)live_sz);
        return BLOB_VALIDATE_FAILED;
    }

    /* Check 3: Present prologue matches at the resolved RVA. This is
     * THE CRITICAL check -- if bytes don't match, our MH_CreateHook
     * would rewrite garbage as a JMP and DWM would AV on next call.
     *
     * We compare 8 bytes (not the full 32) because MinHook overwrites
     * only the first 5-14 bytes of the target; if those match, the
     * function-start is what we think it is. If the *rest* differs
     * (rare but possible if MS shipped a compiler upgrade that reordered
     * the prologue tail), we still hook correctly. */
    if (off->cOverlayContextPresent) {
        int match = compare_bytes_at_rva(dwmcore, off->cOverlayContextPresent,
                                         ext->prologue_present, 8);
        if (!match) {
            /* Dump bytes for diagnostics. */
            uint8_t live_bytes[16] = {0};
            __try {
                BYTE *p = (BYTE *)dwmcore + off->cOverlayContextPresent;
                for (int i = 0; i < 16; i++) live_bytes[i] = p[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            slog_writef("msvc_dbg_a.dat",
                "validate: Present prologue MISMATCH @ RVA=0x%llX. "
                "blob=%02X %02X %02X %02X %02X %02X %02X %02X  "
                "live=%02X %02X %02X %02X %02X %02X %02X %02X. "
                "Refusing to hook (SAFE-MODE: DWM stays alive).",
                (unsigned long long)off->cOverlayContextPresent,
                ext->prologue_present[0], ext->prologue_present[1],
                ext->prologue_present[2], ext->prologue_present[3],
                ext->prologue_present[4], ext->prologue_present[5],
                ext->prologue_present[6], ext->prologue_present[7],
                live_bytes[0], live_bytes[1], live_bytes[2], live_bytes[3],
                live_bytes[4], live_bytes[5], live_bytes[6], live_bytes[7]);
            return BLOB_VALIDATE_FAILED;
        }
    }

    /* Check 4: IsOverlayPrevented prologue. Same rationale -- byte-patch
     * writes 6 bytes at [rva + patch_off]; if the initial prologue bytes
     * disagree, the shape detector might pick a different offset than
     * the resolver saw + our patch corrupts unrelated instructions. */
    if (off->isOverlayPrevented) {
        int match = compare_bytes_at_rva(dwmcore, off->isOverlayPrevented,
                                         ext->prologue_iop, 8);
        if (!match) {
            uint8_t live_bytes[16] = {0};
            __try {
                BYTE *p = (BYTE *)dwmcore + off->isOverlayPrevented;
                for (int i = 0; i < 16; i++) live_bytes[i] = p[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            slog_writef("msvc_dbg_a.dat",
                "validate: IsOverlayPrevented prologue MISMATCH @ RVA=0x%llX. "
                "blob=%02X %02X %02X %02X %02X %02X %02X %02X  "
                "live=%02X %02X %02X %02X %02X %02X %02X %02X. "
                "Refusing to hook (SAFE-MODE).",
                (unsigned long long)off->isOverlayPrevented,
                ext->prologue_iop[0], ext->prologue_iop[1],
                ext->prologue_iop[2], ext->prologue_iop[3],
                ext->prologue_iop[4], ext->prologue_iop[5],
                ext->prologue_iop[6], ext->prologue_iop[7],
                live_bytes[0], live_bytes[1], live_bytes[2], live_bytes[3],
                live_bytes[4], live_bytes[5], live_bytes[6], live_bytes[7]);
            return BLOB_VALIDATE_FAILED;
        }
    }

    /* Check 5 (non-critical): bounds-check remaining resolved RVAs. Log
     * any that fall outside dwmcore -- doesn't fail the gate (the
     * existing prologue-shape detection + is_readable in imgui_layer
     * handles per-symbol degradation), but a support diag if things
     * look weird. */
    struct { uint64_t rva; const char *name; } noncritical[] = {
        { off->presentNeeded,        "presentNeeded"        },
        { off->legacyPresentNeeded,  "legacyPresentNeeded"  },
        { off->forceFullDirty,       "forceFullDirty"       },
        { off->scheduleComposition,  "scheduleComposition"  },
        { off->addDirtyRectDisplay,  "addDirtyRectDisplay"  },
        { off->addDirtyRectLegacy,   "addDirtyRectLegacy"   },
        { off->isPrimaryMonitor,     "isPrimaryMonitor"     },
    };
    for (size_t i = 0; i < sizeof(noncritical)/sizeof(noncritical[0]); i++) {
        if (noncritical[i].rva &&
            !rva_in_dwmcore(dwmcore, noncritical[i].rva, 1)) {
            slog_writef("msvc_dbg_a.dat",
                "validate: %s RVA=0x%llX OUT-OF-BOUNDS (image size %lu). "
                "Non-critical -- will skip that hook, DWM stays alive.",
                noncritical[i].name,
                (unsigned long long)noncritical[i].rva,
                (unsigned long)dwmcore_live_size(dwmcore));
        }
    }

    slog_writef("msvc_dbg_a.dat",
        "validate: blob snapshot MATCH -- proceeding to install hooks "
        "(TDS=0x%08X size=%lu)",
        live_tds, (unsigned long)live_sz);
    return BLOB_VALIDATE_OK;
}

int hooks_install(const pl_offsets_t *off, present_cb_t present_cb) {
    if (!off) return 0;

    HMODULE dwmcore = pl_locate_dwmcore();
    if (!dwmcore) {
        slog_write("msvc_dbg_a.dat", SS(SVC_STR_HK_DWMCORE_MISSING));
        return 0;
    }
    slog_writef("msvc_dbg_a.dat", SS(SVC_STR_HK_DWMCORE_BASE), (void *)dwmcore);
    hook_diag(SS(SVC_STR_HK_INSTALL_ENTERED));

    /* v-multibuild (2026-09-24) -- load ext + validate BEFORE we touch
     * MinHook or write a single byte into dwmcore. Extension is optional
     * -- v1 blobs pass through unchanged (SKIP result). v2 blobs get a
     * full prologue-cross-check; any mismatch -> safe-mode return. */
    {
        pl_offsets_t discard = {0};
        pl_offsets_ext_t ext = {0};
        (void)pl_offsets_load_v2(&discard, &ext);   /* only care about ext */

        int v = validate_blob_snapshot(dwmcore, off, &ext);
        if (v == BLOB_VALIDATE_FAILED) {
            /* Announce degraded mode. Payload stays loaded but no hooks
             * are installed, no bytes patched. Ui_present_frame respects
             * g_compose_degraded and short-circuits (no D3D, no vtable
             * walks). Rawinput / hotkeys / token_refresh / helper stay
             * fully live. */
            InterlockedExchange(&g_compose_degraded, 1);
            slog_write("msvc_dbg_a.dat",
                "hooks: SAFE-MODE (validation failed). Payload loaded, "
                "no dwmcore hooks/patches, DWM untouched. Rawinput + "
                "hotkeys + token_refresh + helper remain active.");
            /* Return 1 so dllmain continues its init flow (peb_unlink,
             * rawinput hook install, etc.). Hooks_uninstall handles
             * "never really installed" safely (idempotent). */
            return 1;
        }
        /* SKIP or OK -> proceed normally. */
    }

    if (MH_Initialize() != MH_OK) {
        slog_write("msvc_dbg_a.dat", SS(SVC_STR_HK_MINHOOK_FAIL));
        return 0;
    }

    g_present_cb = present_cb;

    /* ── 1. COverlayContext::Present ── (REQUIRED) */
    if (!off->cOverlayContextPresent) {
        slog_write("msvc_dbg_a.dat", "hooks: no cOverlayContextPresent in blob");
        MH_Uninitialize();
        return 0;
    }
    {
        void *target = (BYTE *)dwmcore + off->cOverlayContextPresent;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_COverlayContextPresent,
                                    (LPVOID *)&g_orig_present);
        if (s != MH_OK) {
            slog_writef("msvc_dbg_a.dat", "MH_CreateHook Present failed: %d", s);
            MH_Uninitialize();
            return 0;
        }
        if (MH_EnableHook(target) != MH_OK) {
            slog_write("msvc_dbg_a.dat", "MH_EnableHook Present failed");
            MH_RemoveHook(target);
            MH_Uninitialize();
            return 0;
        }
        slog_writef("msvc_dbg_a.dat", "Present hooked @ %p", target);
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
            slog_writef("msvc_dbg_a.dat", "PresentNeeded1 hooked @ %p", target);
            hook_diag("hooks: PresentNeeded1 hooked");
            hook_registry_add(target, "PN1");
            g_ht_pn1 = target;
        } else {
            slog_writef("msvc_dbg_a.dat", "PresentNeeded1 hook FAILED s=%d", s);
            hook_diag("hooks: PresentNeeded1 FAILED");
        }
    } else {
        slog_write("msvc_dbg_a.dat", "hooks: no presentNeeded in blob (wake will be degraded)");
    }

    /* ── 3. CLegacyRenderTarget::PresentNeeded ── (Bypassify parity) */
    if (off->legacyPresentNeeded) {
        void *target = (BYTE *)dwmcore + off->legacyPresentNeeded;
        MH_STATUS s = MH_CreateHook(target, (LPVOID)Detour_LegacyPresentNeeded,
                                    (LPVOID *)&g_orig_pn2);
        if (s == MH_OK && MH_EnableHook(target) == MH_OK) {
            slog_writef("msvc_dbg_a.dat", "PresentNeeded2 hooked @ %p", target);
            hook_diag("hooks: PresentNeeded2 hooked");
            hook_registry_add(target, "PN2");
            g_ht_pn2 = target;
        } else {
            slog_writef("msvc_dbg_a.dat", "PresentNeeded2 hook FAILED s=%d", s);
            hook_diag("hooks: PresentNeeded2 FAILED");
        }
    } else {
        slog_write("msvc_dbg_a.dat", "hooks: no legacyPresentNeeded in blob");
    }

    /* ── 4. ForceFullDirtyRendering -- RESOLVE ONLY (DO NOT CALL) ──
     * Confirmed 2026-07-05: calling this from any thread crashes DWM.
     * Kept resolved for future experimentation only.
     *
     * v1.7.4.14 (2026-07-24) -- BUT patch the STATIC BYTE 0x60 before
     * it. Per BP RE (docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md) they patch
     * a byte at RVA 0x3fd7b9 to 1 at init, which is ForceFullDirty
     * RVA (0x3fd819) minus 0x60. This byte is a static bool that
     * dwmcore reads inside its compose logic -- when 1, dwmcore takes
     * "always full-dirty" render paths -> every compose re-renders
     * the whole layer texture -> old-position overlay pixels get
     * overwritten by natural compose -> NO TRAILING/SHADOW BUG. */
    /* v1.7.9 (2026-07-24) -- FORCE-FULL-DIRTY PATCH REMOVED.
     * Ghidra RE'd Bypassify's full DwmInit: they hook 4 functions total
     * (Present, PN1, PN2, IsOverlayPrevented). They do NOT touch the
     * ForceFullDirty byte AT ALL. Our patch adds compose overhead
     * (dwmcore always taking full-dirty paths) which hurts frame-time
     * consistency. Trail-clearing is handled by our RedrawWindow
     * cascade in imgui_layer.cpp instead. */
    if (off->forceFullDirty) {
        /* v1.7.11.14 (2026-07-25) -- WPT-TRACE-DRIVEN patch to force
         * dwmcore into "always full-dirty compose" mode. See BP RE
         * writeup for original rationale. Byte in .rdata resolved by
         * chaosium43-style `SymFromName(dwmcore!Force
         * FullDirtyRendering)` -> patch first byte from 0x00 -> 0x01.
         *
         * v3.1 (2026-09-21) -- SEMANTIC-CHANGE GUARD (post-KB5124008/
         * KB5129195 crash-loop). Windows 11 25H2 build 26200.9457
         * ships a new dwmcore where the resolved byte's initial value
         * is 0x34 (not 0x00). Same symbol name, different data layout
         * -- the field's type/purpose changed. Blindly setting it to
         * 0x01 corrupts dwmcore state -> DWM AVs inside its own
         * compositor a few minutes later.
         *
         * FIX: only apply patch when the original byte is a valid
         * bool (0x00 or 0x01). Any other value = symbol resolution
         * landed on a re-purposed field, skip patch entirely. Chrome
         * trailing behavior degrades gracefully (v11.2.2 removed
         * this patch outright once already -- we survived without
         * it) but DWM stays alive. */
        BYTE *ffd_flag = (BYTE *)dwmcore + off->forceFullDirty;
        BYTE orig_byte = 0xFF;
        __try { orig_byte = ffd_flag[0]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { orig_byte = 0xFF; }

        if (orig_byte != 0x00 && orig_byte != 0x01) {
            slog_writef("msvc_dbg_a.dat",
                "ForceFullDirty flag @ %p SKIPPED patch: original byte 0x%02X "
                "is not a bool (0x00/0x01) -- dwmcore layout changed post-Windows"
                " update, patching would corrupt state. Chrome trailing may "
                "return but DWM stays stable.",
                ffd_flag, orig_byte);
        } else {
            DWORD old_prot = 0;
            if (VirtualProtect(ffd_flag, 1, PAGE_EXECUTE_READWRITE, &old_prot)) {
                g_ffd_saved_byte = ffd_flag[0];
                g_ffd_patch_addr = ffd_flag;
                ffd_flag[0] = 1;
                DWORD tmp = 0;
                VirtualProtect(ffd_flag, 1, old_prot, &tmp);
                FlushInstructionCache(GetCurrentProcess(), ffd_flag, 1);
                g_ffd_patched = TRUE;
                slog_writef("msvc_dbg_a.dat",
                    "ForceFullDirty flag @ %p patched DIRECT: 0x%02X -> 0x01 "
                    "(bool-guarded, dwmcore-layout-safe)",
                    ffd_flag, g_ffd_saved_byte);
            } else {
                slog_writef("msvc_dbg_a.dat",
                    "ForceFullDirty flag VirtualProtect FAILED gle=%lu",
                    GetLastError());
            }
        }
    }

    /* ── 5. ScheduleCompositionPass -- THE MISSING PIECE (Bypassify slot [7]) ──
     * Global void(int, int) that requests DWM to schedule next composition
     * immediately. Called from PN detours after orig -- matches Bypassify
     * exactly. Effect: DWM never enters idle -> compositor runs at native
     * vsync rate continuously -> state changes visible on next frame.
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
        slog_writef("msvc_dbg_a.dat", "ScheduleCompositionPass resolved @ %p (Bypassify mystery fn)",
                    (void *)g_schedule_composition);
    } else {
        slog_write("msvc_dbg_a.dat", "ScheduleCompositionPass NOT in blob "
                                  "(DWM may enter idle -> half-render on toggle)");
    }

    /* v1.7.11.9 (2026-07-25) -- IsPrimaryMonitor for chaosium43-parity
     * primary-monitor filter. Enables discover_monitor_target_offset() +
     * should_render_this_context() in Present detour. Without this fn,
     * filter is disabled + we render every compose pass (old behavior). */
    if (off->isPrimaryMonitor) {
        g_is_primary_monitor = (pfnIsPrimaryMonitor_t)
            ((BYTE *)dwmcore + off->isPrimaryMonitor);
        slog_writef("msvc_dbg_a.dat", "IsPrimaryMonitor resolved @ %p (primary-monitor filter armed)",
                    (void *)g_is_primary_monitor);
    } else {
        slog_write("msvc_dbg_a.dat", "IsPrimaryMonitor NOT in blob -- primary-monitor filter DISABLED");
    }

    /* ── 5b. AddDirtyRect trampolines (both RT classes) ── *
     *
     * Solves the "quadrant" bug: without a fullscreen dirty rect, DWM
     * only re-composites the small region the user just clicked -> our
     * overlay only updates in that region. Calling AddDirtyRect with
     * fullscreen (0, 0, 8192, 8192) on every PN fire forces DWM to
     * mark the whole layer dirty -> next composite samples entire
     * texture -> our overlay pixels always up to date across the
     * whole screen.
     *
     * We resolve BOTH the CDDisplayRenderTarget and CLegacyRenderTarget
     * trampolines because different GPU/display setups use different
     * render target classes. Which one fires is determined at runtime
     * by which PN detour captures a pThis first. */
    if (off->addDirtyRectDisplay) {
        g_add_dirty_display = (pfnAddDirtyRect_t)
            ((BYTE *)dwmcore + off->addDirtyRectDisplay);
        slog_writef("msvc_dbg_a.dat", "AddDirtyRect (Display) resolved @ %p",
                    (void *)g_add_dirty_display);
    }
    if (off->addDirtyRectLegacy) {
        g_add_dirty_legacy = (pfnAddDirtyRect_t)
            ((BYTE *)dwmcore + off->addDirtyRectLegacy);
        slog_writef("msvc_dbg_a.dat", "AddDirtyRect (Legacy) resolved @ %p",
                    (void *)g_add_dirty_legacy);
    }
    if (!off->addDirtyRectDisplay && !off->addDirtyRectLegacy) {
        slog_write("msvc_dbg_a.dat", "AddDirtyRect NOT in blob "
                                  "(quadrant bug will persist -- need to re-run resolver)");
    }

    /* ── 5c. Hook CDDisplayRenderTarget::Present + CLegacyRenderTarget::Present ── *
     *
     * The KEY insight: PN's `this` might be virtual-base-adjusted
     * (crashes AddDirtyRect). But Present's `this` is the top-level
     * object. Hooking Present gives us the correct `this` to safely
     * call AddDirtyRect from DWM's own compositor context, marking
     * the full RT dirty right before it composits -- which forces
     * fullscreen re-composition every tick and fixes the "quadrant" bug. */
    /* v1.7.9 (2026-07-24) -- DisplayRT::Present + LegacyRT::Present
     * HOOKS REMOVED. Ghidra RE proved Bypassify does NOT hook these.
     * Our detours were pass-throughs (call orig + SEH) with an old
     * comment claiming AddDirtyRect purpose that was never coded.
     * Pure overhead -- every dwmcore Present cycle went through 2
     * extra detours doing nothing. Removing = fewer per-frame stack
     * frames + better frame-time consistency. Detour functions kept
     * in this file (unused) for reference / future re-enable. */
    (void)Detour_DisplayPresent;
    (void)Detour_LegacyPresent;

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
    /* v11.2.2 (2026-07-24) -- RC[Window] + RC[Visual] hooks REMOVED.
     *
     * Bypassify does not hook CWindowNode::RenderContent or
     * CVisual::RenderContent. They only have 4 hooks total (Present,
     * PN1, PN2, IsOverlayPrevented). RC hooks were our capture-stealth
     * mechanism BUT svcldb_is_capture_render() returns FALSE always
     * (was disabled in v1.7.4.12 to fix flicker) -- so RC hooks fire
     * for EVERY DWM render pass, take our __try/__except path, and
     * return, adding zero functional value AND per-frame overhead.
     *
     * At high DWM render frequency (multiple windows updating), this
     * overhead may accumulate + interact with DWM's dirty-region
     * tracking in ways that cause the "second-use degradation" LO
     * reported ("first time works, subsequent uses show shadow flicker
     * + hotkey lag").
     *
     * BP-1:1 strip: don't install these hooks at all. Capture stealth
     * is provided by IsOverlayPrevented=TRUE (v1.7.4.11) forcing the
     * software compositor path, which is enough for LDB v2.1.5's
     * DWM-whitelist model. If a future proctor tool scans DWM output
     * directly, we can re-add these behind a config flag. */
    (void)Detour_CWindowNode_RenderContent;   /* keep symbol referenced so unused-warning stays silent */
    (void)Detour_CVisual_RenderContent;

    /* ── 5d. AddDirtyRect passive-logging hooks REMOVED 2026-07-06 v4.2.
     * See the block-comment above `hooks_install`'s definition for context. */

    /* ── 6. IsOverlayPrevented byte-patch -- CRITICAL FIX v1.7.4.11 ──
     *
     * Save original 6 bytes so hooks_uninstall can revert cleanly.
     *
     * v1.7.4.11 (2026-07-24) -- SEMANTIC INVERSION. Pre-v1.7.4.11 we
     * patched to `xor eax,eax; ret` = returns FALSE. Comment claimed
     * "return FALSE = allow overlay". That read the function name
     * BACKWARD. `IsOverlayPrevented` asks: "is HARDWARE OVERLAY
     * (Multiplane Overlay) prevented?" Return semantics:
     *   TRUE  = "yes, hardware overlay is prevented" -> DWM MUST use
     *           software compositor path -> every app's pixels flow
     *           through the shared composited surface -> our injected
     *           pixels (drawn LAST via Present hook) end up on TOP
     *           of every app in that surface.
     *   FALSE = "no, hardware overlay is NOT prevented" -> DWM is
     *           free to give DirectComposition apps (Chrome, Cursor,
     *           terminal, Slack, Discord, Electron in general) their
     *           OWN hardware overlay plane, composited by the GPU
     *           bypassing our injected surface entirely -> our overlay
     *           ends up BEHIND those apps.
     *
     * LO's screenshot from 2026-07-24 showed BP's overlay literally
     * above EVERYTHING (Chrome, terminal, Cursor, everything) with
     * zero flicker. RE of BP's Detour_IsOverlayPrevented (0x180003460)
     * confirmed they return TRUE while their shutdown_flag is 0. We
     * were returning the OPPOSITE. This one-bit-flip is why their
     * overlay stayed above and ours dropped behind. Same reason ours
     * flickered on mouse move -- the RC[Window] capture-detection
     * false-positives only surface when DirectComposition apps are
     * getting hardware plane placement (which our FALSE patch was
     * enabling).
     *
     * Patch: `mov eax, 1; ret` = `B8 01 00 00 00 C3` (6 bytes).
     * Full 32-bit return so ANY caller convention sees TRUE, not
     * just the low byte. Matches semantics of BP's detour when their
     * shutdown_flag == 0 (their active state).
     *
     * v3.1 (2026-09-21) -- POST-Windows-update PROLOGUE-SHAPE GUARD.
     * On Windows 11 26200.9457+ (KB5124008/KB5129195 family) Microsoft
     * rewrote `IsOverlayPrevented` from a trivial one-instruction
     * getter (`8A 81 28 01 00 00` = `mov al, [rcx+128]`) to a much
     * larger function whose FIRST 6 bytes are `FF 15 XX XX XX XX` =
     * `call qword [rip+X]` -- an indirect call to a critical
     * initializer whose return value gates the rest of the function.
     *
     * Old byte-patch (overwrite bytes 0..5 with `mov eax,1; ret`)
     * SKIPS that call entirely. The initializer's side-effects don't
     * happen; other dwmcore code paths that depend on that state
     * eventually AV.
     *
     * FIX: detect the new prologue shape. If new (`FF 15 ...`), patch
     * starting at OFFSET 6 (the byte AFTER the call, currently a NOP
     * for padding). We still return TRUE, but the initial call and
     * its side effects execute first. Function tail (test eax; conditional
     * branch) never runs but the important initializer does.
     *
     * If old prologue (`8A 81 ...`), fall through to legacy offset-0 patch.
     * Any other unrecognized prologue: SKIP entirely (safer to let
     * IsOverlayPrevented behave natively than to guess). */
    if (off->isOverlayPrevented) {
        BYTE *iop = (BYTE *)dwmcore + off->isOverlayPrevented;
        BYTE fp[8] = {0};
        BOOL readable = FALSE;
        __try { for (int i = 0; i < 8; i++) fp[i] = iop[i]; readable = TRUE; }
        __except (EXCEPTION_EXECUTE_HANDLER) { readable = FALSE; }

        if (!readable) {
            slog_writef("msvc_dbg_a.dat",
                "IsOverlayPrevented @ %p UNREADABLE -- skipping patch", iop);
        } else {
            /* Prologue shape detection:
             *   Old getter form: fp[0]=0x8A fp[1]=0x81            (mov al, [rcx+imm32])
             *   Old getter form: fp[0]=0x0F fp[1]=0xB6            (movzx eax, byte [...])
             *   Old getter form: fp[0]=0x8B fp[1]=0x01            (mov eax, [rcx])
             *   New CFG form   : fp[0]=0xFF fp[1]=0x15            (call qword [rip+imm32])
             *   New CET form   : fp[0]=0xF3 fp[1]=0x0F fp[2]=0x1E fp[3]=0xFA (endbr64) -> old getter after
             */
            int patch_off = -1;
            const char *shape = "unknown";
            if (fp[0] == 0xFF && fp[1] == 0x15) {
                /* NEW form: skip past 6-byte call + preserve subsequent
                 * padding bytes. Land the 6-byte return stub at offset 6. */
                patch_off = 6;
                shape = "NEW-CFG-CALL (post-KB5124008): patching at offset 6 to preserve initial call side-effects";
            } else if (fp[0] == 0xF3 && fp[1] == 0x0F && fp[2] == 0x1E && fp[3] == 0xFA) {
                /* CET endbr64 (4 bytes) then original getter -- patch AFTER endbr64. */
                patch_off = 4;
                shape = "CET-ENDBR64: patching at offset 4 to preserve endbr64";
            } else if (fp[0] == 0x8A || fp[0] == 0x0F || fp[0] == 0x8B) {
                /* Old getter form -- safe to patch at offset 0 (entire
                 * function was just a getter, no init side-effects). */
                patch_off = 0;
                shape = "OLD-GETTER: patching at offset 0 (legacy path)";
            } else {
                slog_writef("msvc_dbg_a.dat",
                    "IsOverlayPrevented @ %p UNKNOWN prologue shape "
                    "(first 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X) -- "
                    "SKIPPING patch. DWM's native overlay-plane behavior "
                    "will be used; DirectComposition apps may render on top "
                    "of our overlay but DWM stays stable.",
                    iop, fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]);
            }

            if (patch_off >= 0) {
                BYTE *iop_patch = iop + patch_off;
                DWORD old_prot = 0;
                if (VirtualProtect(iop_patch, 8, PAGE_EXECUTE_READWRITE, &old_prot)) {
                    /* v-audit-hardening (2026-09-23) -- P1-3 (opus-4.7 Audit A).
                     *
                     * PRIOR: 6 sequential byte stores (iop_patch[0..5] = ...).
                     * A concurrent DWM compose thread executing
                     * IsOverlayPrevented mid-write could observe a partially-
                     * patched instruction stream (e.g. new mov + old orig[5..])
                     * and decode garbage -> DWM AV. FlushInstructionCache
                     * happens only at the end, so per-store visibility depends
                     * on TSO. Bypassify v1.3 had the same pattern and it was
                     * traced to a small handful of DWM crashes across 800+
                     * installs (~0.01% arm cycles).
                     *
                     * NOW: pack the 6-byte stub + preserve bytes 6-7 into a
                     * single 8-byte value, write via InterlockedExchange64
                     * (atomic on x64 for aligned 8-byte stores per Intel SDM
                     * Vol 3A 8.1.1). Concurrent readers either see full old
                     * 6-byte instruction stream OR full new 6-byte stub;
                     * never a torn hybrid.
                     *
                     * NOTE: patch site alignment. iop_patch might not be
                     * 8-byte-aligned (function prologues are 16-byte aligned
                     * but our +offset lands inside). The Intel SDM guarantee
                     * only holds for aligned stores. If unaligned, we fall
                     * back to the sequential-byte path. That's still safer
                     * than nothing because MOST DWM users hit this while
                     * dwmcore is quiescent (compose thread idle) -- the race
                     * window we're closing is the rare mid-compose install/
                     * revert. */
                    for (int i = 0; i < 6; i++) g_iop_saved_bytes[i] = iop_patch[i];
                    g_iop_patch_addr = iop_patch;

                    /* Save bytes 6-7 too so revert can restore all 8. */
                    BYTE tail6 = iop_patch[6], tail7 = iop_patch[7];
                    g_iop_saved_tail[0] = tail6;
                    g_iop_saved_tail[1] = tail7;

                    if (((ULONG_PTR)iop_patch & 0x7) == 0) {
                        /* 8-byte aligned -- atomic write. */
                        LONG64 stub = 0;
                        BYTE *sb = (BYTE *)&stub;
                        sb[0] = 0xB8; sb[1] = 0x01; sb[2] = 0x00;
                        sb[3] = 0x00; sb[4] = 0x00; sb[5] = 0xC3;
                        sb[6] = tail6; sb[7] = tail7;   /* preserve */
                        InterlockedExchange64((LONG64 *)iop_patch, stub);
                    } else {
                        /* Unaligned -- fall back to sequential store. Still
                         * safer than crashing on unknown prologue; the race
                         * window is unchanged from prior code. */
                        iop_patch[0] = 0xB8;
                        iop_patch[1] = 0x01;
                        iop_patch[2] = 0x00;
                        iop_patch[3] = 0x00;
                        iop_patch[4] = 0x00;
                        iop_patch[5] = 0xC3;
                    }
                    DWORD tmp = 0;
                    VirtualProtect(iop_patch, 8, old_prot, &tmp);
                    FlushInstructionCache(GetCurrentProcess(), iop_patch, 8);
                    g_iop_patched = TRUE;
                    slog_writef("msvc_dbg_a.dat",
                        "IsOverlayPrevented patched @ %p (base=%p +0x%X) "
                        "shape=[%s]. Original 6 bytes at patch site: "
                        "%02X %02X %02X %02X %02X %02X",
                        iop_patch, iop, patch_off, shape,
                        g_iop_saved_bytes[0], g_iop_saved_bytes[1], g_iop_saved_bytes[2],
                        g_iop_saved_bytes[3], g_iop_saved_bytes[4], g_iop_saved_bytes[5]);
                } else {
                    slog_writef("msvc_dbg_a.dat", SS(SVC_STR_IOP_VP_FAIL),
                                GetLastError());
                }
            }
        }
    } else {
        slog_write("msvc_dbg_a.dat", SS(SVC_STR_IOP_NOT_IN_BLOB));
    }

    /* Ensure clean state (in case a previous install/uninstall left
     * stale flags -- defensive; unlikely with FreeLibraryAndExitThread). */
    InterlockedExchange(&g_stop_draw, 0);
    InterlockedExchange(&g_wake_frames, 0);   /* no longer used; keep 0 */
    /* v-next (2026-09-23) -- reset the separated hooks_uninstall idempotency
     * guard. Was previously conflated with g_stop_draw (see the guard in
     * hooks_uninstall below); now separate so hooks_begin_shutdown_hide can
     * flip g_stop_draw for instant overlay hide WITHOUT wedging a subsequent
     * hooks_uninstall into the "already done" early-return branch. */
    InterlockedExchange(&g_uninstall_done, 0);

    /* Set g_active LAST -- from now, PN detours return TRUE unconditionally,
     * DWM composites at native vsync, our Detour_Present's draw callback
     * fires every frame -> overlay appears within ~16ms of installation. */
    InterlockedExchange(&g_active, 1);

    /* Spawn keep-alive thread: safety net that fires SCP(0,-1) every 50ms.
     * If DWM enters deep idle and stops calling PN, this thread breaks the
     * cycle by externally scheduling composition. Cost: 20 Hz of a fast-
     * path dwmcore function ≈ negligible.
     *
     * v-audit-hardening (2026-09-23) -- P1-1/6 (opus-4.7 Audit A).
     * Handle kept in g_keepalive_thread so hooks_uninstall can join it
     * before FreeLibraryAndExitThread. Prior CloseHandle discarded the
     * handle -> thread mid-Sleep(500|1000) could wake AFTER the
     * payload's pages were freed -> crash-DWM class of bug. */
    if (g_schedule_composition) {
        g_keepalive_thread = CreateThread(NULL, 0, keepalive_thread, NULL, 0, NULL);
    }

    /* Ghost window pre-spawn -- gated OFF by default (max stealth).
     * When DWM_EXT_GHOST=1, we spawn a fullscreen invisible
     * TOPMOST HWND used for forcing DWM re-composite on hotkey. When
     * unset (default), no ghost = no enumerable window from us.
     *
     * v-audit-hardening: same handle-keeping pattern as keepalive_thread. */
    if (ghost_is_enabled() &&
        InterlockedCompareExchange(&g_ghost_spawned, 1, 0) == 0) {
        g_ghost_wnd_thread_h = CreateThread(NULL, 0, ghost_wnd_thread, NULL, 0, NULL);
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

    /* v3.1 (2026-09-21) -- Present-fire canary thread.
     *
     * Post-Windows-update crash-loop diagnosis (KB5124008 / KB5129195,
     * build 26200.9457) showed a state where hooks install SUCCESS
     * per logs but `COverlayContext::Present` never fires -- DWM's
     * compose path shifted to a different function, our hook is
     * effectively dead, and we run silent until DWM AVs on some
     * other state we corrupted.
     *
     * This canary just measures Present fire count at T+2s / T+10s /
     * T+30s. If still 0 at T+2s, log LOUD warning + set the "compose
     * path degraded" flag. Payload stays loaded (rawinput + hotkeys
     * still work) but ui_present_frame becomes a no-op safeguard.
     *
     * No corrective action -- just observability. The FIX for
     * "compose path moved" requires re-RE'ing dwmcore on that build,
     * which is separate work. What matters HERE is: if we detect the
     * degraded state, we STOP being ambiguous about it -- log
     * screams, ship-block flag flies, future inject attempts can
     * short-circuit into no-hook mode. */
    /* v-audit-hardening: keep the canary handle so uninstall can join it. */
    g_canary_thread = CreateThread(NULL, 0, present_fire_canary_thread, NULL, 0, NULL);

    hook_diag(SS(SVC_STR_HK_INSTALL_SUCCESS));
    return 1;
}

/* v-next (2026-09-23) -- INSTANT overlay hide, decoupled from teardown.
 *
 * Sets g_stop_draw = 1 so Detour_Present's next fire (typically <16ms at
 * 60Hz) skips the g_present_cb call -- our overlay is instantly gone from
 * the layer texture. Bumps compose-grace so DWM keeps forcing composition
 * (via PN still returning TRUE for the grace window), which guarantees
 * DWM's compositor actually paints the underlying-app pixels over our
 * stale overlay tiles instead of going lazy and leaving them on screen.
 *
 * See hooks_begin_shutdown_hide header comment in dwm_hooks.h for the full
 * "why" -- essentially, this exists so shutdown_watcher can hide the
 * overlay AT t=0 (event fires) rather than at t=~2500ms (after sequential
 * subsystem stops). */
void hooks_begin_shutdown_hide(void) {
    /* Flip the "skip our draw callback" flag. Detour_Present's next
     * fire (typically 1 vsync = 16ms @ 60Hz) will see g_stop_draw = 1
     * and take the orig-only path -- overlay pixels stop being written
     * to the layer texture. Idempotent -- safe if already 1. */
    InterlockedExchange(&g_stop_draw, 1);
    /* Force DWM to keep composing for 500ms so it actually paints
     * underlying app pixels over the tiles that were holding our stale
     * overlay. Without this, DWM's lazy compose leaves our old pixels
     * on screen until something else triggers a compose pass. Same
     * mechanism ui_toggle_visible / ui_nudge use post-change. */
    hooks_bump_compose_grace(500);
    hook_diag("hooks_begin_shutdown_hide: g_stop_draw=1, compose grace=500ms "
              "(overlay off screen in ~1 vsync)");
}

void hooks_uninstall(void) {
    /* v-next (2026-09-23) -- idempotency guard is now separated from
     * g_stop_draw. Old pattern:
     *   if (InterlockedExchange(&g_stop_draw, 1) != 0) return;
     * fused "someone else set g_stop_draw" with "we already tore down"
     * -- which is fine when hooks_uninstall is the ONLY writer of the
     * flag, but wrong now that hooks_begin_shutdown_hide sets it early
     * to make the overlay disappear before slow subsystem teardown runs.
     * Split gives us: hooks_begin_shutdown_hide -> hide only; then
     * hooks_uninstall -> real teardown (idempotent via g_uninstall_done). */
    if (InterlockedExchange(&g_uninstall_done, 1) != 0) return;
    InterlockedExchange(&g_stop_draw, 1);   /* idempotent; may already be 1 */
    if (!g_active) return;   /* never installed, nothing to do */

    hook_diag("hooks_uninstall: entering -- g_stop_draw set (Phase B: DRAINING)");

    /* Stop hook-integrity monitor before we start disabling hooks (else
     * it'd see them being torn down and try to re-install mid-shutdown).
     *
     * WAIT MUST SUCCEED -- see hook_integrity_thread docstring. The old
     * 500ms wait was not enough (thread could be mid-`Sleep(10000)`
     * and hooks_uninstall would time out + proceed while the thread
     * was still alive in soon-to-be-freed code -> DWM crash on next
     * inject cycle's sweep. Fixed in v-next by chunking the thread's
     * sleep into 50ms slices; wait budget bumped to 2s for headroom
     * against slow SEH-wrapped `first = *(unsigned char*)r->target`
     * probes during shutdown races. */
    InterlockedExchange(&g_integrity_running, 0);
    if (g_integrity_thread) {
        DWORD wr = WaitForSingleObject(g_integrity_thread, 2000);
        if (wr != WAIT_OBJECT_0) {
            hook_diag("hooks_uninstall: integrity thread wait FAILED "
                      "(wr=%lu) -- DWM crash likely on next inject", wr);
        }
        CloseHandle(g_integrity_thread);
        g_integrity_thread = NULL;
    }

    /* v-audit-hardening (2026-09-23) -- P1-1/6 (opus-4.7 Audit A).
     *
     * Join the three worker threads whose handles prior code discarded
     * immediately after CreateThread. Each thread's loop checks g_stop_draw
     * (set at the top of hooks_uninstall via `InterlockedExchange(&g_stop_draw, 1)`
     * OR previously by `hooks_begin_shutdown_hide`) and exits within one
     * sleep window. Wait budget is 2s per thread -- covers the widest
     * Sleep windows (keepalive's Sleep(1000) when overlay hidden;
     * canary's new dynamic 100-30000ms sleep already chunk-checks
     * g_stop_draw before AND after each Sleep). If the wait times out,
     * log LOUD but proceed -- the alternative (spin forever) risks the
     * whole payload getting stuck on unload.
     *
     * Terminated: keepalive_thread (Sleep 500/1000, 20Hz cadence),
     *             ghost_wnd_thread (window message pump; g_stop_draw
     *             kills its loop AND UnhookWinEvent releases the OS
     *             callback so it can't dispatch into freed code),
     *             canary_thread (Sleep 100-30000, always checks stop
     *             before each nap).
     *
     * Without these joins, the thread mid-Sleep at
     * FreeLibraryAndExitThread time would wake into unmapped memory
     * (the launcher VirtualFrees our pages externally in the manual-map
     * layout) and AV. Classic use-after-free-into-payload class.  This
     * fix closes the entire class in one shot. */
    if (g_keepalive_thread) {
        DWORD wr = WaitForSingleObject(g_keepalive_thread, 2000);
        if (wr != WAIT_OBJECT_0) {
            hook_diag("hooks_uninstall: keepalive_thread wait TIMEOUT "
                      "(wr=%lu) -- may crash on next unload cycle", wr);
        }
        CloseHandle(g_keepalive_thread);
        g_keepalive_thread = NULL;
    }
    if (g_ghost_wnd_thread_h) {
        /* Ghost thread message pump listens for WM_QUIT via
         * PostThreadMessage; also honors g_stop_draw internally. */
        DWORD tid = GetThreadId(g_ghost_wnd_thread_h);
        if (tid) PostThreadMessageW(tid, WM_QUIT, 0, 0);
        DWORD wr = WaitForSingleObject(g_ghost_wnd_thread_h, 2000);
        if (wr != WAIT_OBJECT_0) {
            hook_diag("hooks_uninstall: ghost_wnd_thread wait TIMEOUT "
                      "(wr=%lu) -- may crash on next unload cycle", wr);
        }
        CloseHandle(g_ghost_wnd_thread_h);
        g_ghost_wnd_thread_h = NULL;
    }
    if (g_canary_thread) {
        DWORD wr = WaitForSingleObject(g_canary_thread, 2000);
        if (wr != WAIT_OBJECT_0) {
            hook_diag("hooks_uninstall: canary_thread wait TIMEOUT "
                      "(wr=%lu) -- may crash on next unload cycle", wr);
        }
        CloseHandle(g_canary_thread);
        g_canary_thread = NULL;
    }

    /* Step 1 (Bypassify pattern): the shutdown flag is now set.
     * IMMEDIATELY:
     *   - Detour_Present stops calling our g_present_cb (draw is
     *     skipped -- layer texture will be composited clean by orig).
     * BUT: PN detours STILL RETURN TRUE -- we need DWM to keep
     * composing during the drain window so orig Present has a chance
     * to overwrite our old pixels. */

    /* Step 2 (Bypassify pattern): give DWM ~12 frames at 60Hz to
     * composite CLEAN pixels from the underlying app. Because PN
     * still returns TRUE, DWM composites every vsync during this
     * 200ms -- orig Present runs each time (via Detour_Present),
     * layer texture gets clean pixels from the owning app, DWM's
     * compositor backbuffer naturally clears our overlay off-screen.
     *
     * This is what solves "overlay stays on screen after killing the
     * payload" -- WITHOUT this sleep, MH_DisableHook cuts off hooks
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
    /* (Removed 2026-07-06 v4.2) -- g_orig_adr_display / g_orig_adr_legacy
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
    hook_diag(SS(SVC_STR_HK_UNINSTALL_MHUNINIT));

    /* Step 4 (belt-and-suspenders): revert the IsOverlayPrevented
     * byte-patch. Bypassify skips this (they rely on DWM restart),
     * but we do it for cleanliness -- enables reinstall in the same
     * DWM instance without stale state.
     *
     * v1.7.4.11: patch is now 6 bytes (mov eax,1; ret) instead of 3
     * (xor eax,eax; ret). Revert restores the original 6 bytes so
     * dwmcore's IsOverlayPrevented behaves natively again. */
    if (g_iop_patched && g_iop_patch_addr) {
        DWORD old_prot = 0;
        if (VirtualProtect(g_iop_patch_addr, 8, PAGE_EXECUTE_READWRITE, &old_prot)) {
            BYTE *iop = (BYTE *)g_iop_patch_addr;
            /* v-audit-hardening (2026-09-23) -- P1-3 (opus-4.7 Audit A):
             * atomic revert path.  If the patch was applied via the
             * aligned 8-byte atomic store (see hooks_install), the
             * corresponding aligned 8-byte revert is a single store the
             * CPU cannot tear.  Otherwise fall back to sequential bytes
             * (same window as prior code -- no regression, and this
             * branch only triggers on unaligned patch sites which are
             * rare).  See install-side header comment for full rationale. */
            if (((ULONG_PTR)iop & 0x7) == 0) {
                LONG64 orig = 0;
                BYTE *ob = (BYTE *)&orig;
                for (int i = 0; i < 6; i++) ob[i] = g_iop_saved_bytes[i];
                ob[6] = g_iop_saved_tail[0];
                ob[7] = g_iop_saved_tail[1];
                InterlockedExchange64((LONG64 *)iop, orig);
            } else {
                for (int i = 0; i < 6; i++) iop[i] = g_iop_saved_bytes[i];
            }
            DWORD tmp = 0;
            VirtualProtect(g_iop_patch_addr, 8, old_prot, &tmp);
            FlushInstructionCache(GetCurrentProcess(), g_iop_patch_addr, 8);
            g_iop_patched = FALSE;
            hook_diag(SS(SVC_STR_HK_UNINSTALL_IOP_REVERT));
        }
    }

    /* v1.7.4.14: revert the ForceFullDirty flag byte-patch. */
    if (g_ffd_patched && g_ffd_patch_addr) {
        DWORD old_prot = 0;
        if (VirtualProtect(g_ffd_patch_addr, 1, PAGE_EXECUTE_READWRITE, &old_prot)) {
            ((BYTE *)g_ffd_patch_addr)[0] = g_ffd_saved_byte;
            DWORD tmp = 0;
            VirtualProtect(g_ffd_patch_addr, 1, old_prot, &tmp);
            FlushInstructionCache(GetCurrentProcess(), g_ffd_patch_addr, 1);
            g_ffd_patched = FALSE;
            hook_diag("hooks_uninstall: ForceFullDirty flag byte reverted (was 0x%02X)",
                      g_ffd_saved_byte);
        }
    }

    slog_write("msvc_dbg_a.dat", SS(SVC_STR_HK_UNINSTALLED));
    hook_diag("hooks_uninstall: DONE");
}

/* v1.7.4.12 (2026-07-24) -- WAKE APIs NEUTERED.
 *
 * Bypassify has ZERO code calling anything like hooks_bump_wake,
 * hooks_force_wake, hooks_burst_wake. Their PN detour returns TRUE
 * every time DWM asks -> DWM composes every vsync -> their draw fires
 * on Present with fresh state. No external nudges needed.
 *
 * Our wake APIs were belt-and-suspenders from the era when we
 * didn't fully understand PN=TRUE. They've caused every flicker
 * report since. Kept as no-ops so callers don't need to be edited
 * out one-by-one -- they just do nothing. */
void hooks_bump_wake(int frames) { (void)frames; }
void hooks_force_wake(void)      { }

/* ── Anti-idle keep-alive thread ──
 *
 * Fires ScheduleCompositionPass(0, -1) every ~50ms from a background
 * thread. This is a SAFETY NET against the "DWM enters deep idle"
 * failure mode:
 *
 * Normal case: DWM calls PN -> PN detour calls SCP -> DWM stays awake.
 *   Loop self-sustaining. This thread's work is redundant, cheap.
 *
 * Failure case: DWM enters deep idle for some reason and STOPS calling
 *   PN entirely. Without external stimulus, PN -> SCP loop never
 *   restarts and DWM composites at ~0 fps until user input. THIS
 *   thread breaks that cycle: even if DWM stops PN, we periodically
 *   call SCP externally, which triggers DWM to schedule composition,
 *   which eventually calls PN, which then calls SCP again.
 *
 * Cost: 20 calls/sec to a fast-path dwmcore function. Negligible. */
/* WinEvent hook callback -- fires whenever the foreground window changes.
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

    /* Install EVENT_SYSTEM_FOREGROUND hook -- reacts INSTANTLY to any
     * app becoming foreground (Alt+Tab, click, etc.). Requires our
     * thread to have a message pump, so we PeekMessage in the loop below.
     * WINEVENT_OUTOFCONTEXT means the callback fires on OUR thread,
     * not injected into the target process -- safer + LDB never sees us. */
    HWINEVENTHOOK fg_hook = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
        NULL, ghost_fg_change_cb,
        0, 0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (fg_hook) hook_diag("keepalive: EVENT_SYSTEM_FOREGROUND hook installed");
    else         hook_diag("keepalive: SetWinEventHook FAILED -- periodic z-order still active");

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
                     * 50ms -- DOUBLE ShowWindow on a fullscreen layered
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

        /* v1.7.4.12 (2026-07-24) -- SCP KILLED.
         *
         * Bypassify has NO independent SCP-firing thread. They rely
         * PURELY on PN=TRUE in the PresentNeeded detour to keep DWM
         * composing every vsync. Our keepalive SCP was ADDITIONAL
         * compose pressure on top of PN=TRUE + DWM's own compose
         * ticks. On high-refresh monitors this piled up into flicker.
         *
         * Zero SCP calls from keepalive_thread now. Thread only
         * remains to keep the WinEvent hook message pump running
         * for ghost visibility sync (which is off-by-default in
         * v1.7.4.12, so the thread mostly no-ops).
         *
         * If DWM ever truly idles with our hook armed, the PN detour
         * fires TRUE on next PN call -> DWM composes -> we draw. No
         * external SCP needed. */

        Sleep(cur_visible ? 500 : 1000);   /* very-low-freq idle */
    }

    if (fg_hook) UnhookWinEvent(fg_hook);
    hook_diag("keepalive: thread exit");
    return 0;
}

/* ── Burst-wake worker (legacy -- mostly no-op now that PN always fires SCP) ── */

static DWORD WINAPI burst_wake_thread(LPVOID param) {
    (void)param;
    for (;;) {
        ULONG now = GetTickCount();
        ULONG end = (ULONG)g_burst_end_ms;
        if (now >= end || g_stop_draw) break;

        /* Fire one wake: force-orig-PN + bump wake counter (legacy). */
        hooks_bump_wake(g_burst_frames_per_pump);
        hooks_force_wake();

        /* Sleep interval -- clamped to sane values. */
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
    /* v1.7.4.12: NO-OP. See hooks_bump_wake comment.
     * PN=TRUE alone drives DWM compose every vsync -- no burst needed. */
    (void)frames_per_pump; (void)duration_ms; (void)interval_ms;
    return;
    /* --- dead code below preserved so callers still link cleanly --- */
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
            /* Thread create failed -- undo the running flag so next call
             * can retry. The immediate hooks_force_wake above still fired,
             * so this isn't fatal -- just no burst extension. */
            InterlockedExchange(&g_burst_running, 0);
            hook_diag("burst_wake: CreateThread FAILED (falling back to single-shot)");
        }
    }
}

int hooks_is_active(void) {
    return (g_active && !g_shutdown_flag) ? 1 : 0;
}

/* ── LDB-safe ghost window wake -- g_ghost_wnd/g_ghost_spawned forward-declared above ── */

static LRESULT CALLBACK ghost_wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    return DefWindowProcW(h, msg, w, l);
}

/* Per-install pool of top-level window class names. A signature scanner
 * that looks for one hard-coded class name (as prior single-string builds
 * of svcldb were vulnerable to -- see git log for the flip from a fixed
 * `MSCTFIME UI$`) has to know ALL of these to catch us, AND has to hit
 * the right one for the current machine. Rotation is deterministic per
 * install (see `cu_installsalt_index`) so behavior stays predictable
 * for the same user across every arm / reinject / DWM restart.
 *
 * Every name below is a real Windows-known class:
 *   [0] MSCTFIME UI$   -- IME dispatcher (trailing $ so it never collides
 *                        with the real `MSCTFIME UI` some GUI processes
 *                        register on startup); always registerable.
 *   [1] IME            -- actual IME child-window class. Real Windows GUI
 *                        processes may or may not have this registered;
 *                        RegisterClassExW returns ERROR_CLASS_ALREADY_EXISTS
 *                        in the collision case and we fall through.
 *   [2] MSTaskListWClass -- explorer.exe's taskbar-button class. Never
 *                        pre-registered inside dwm.exe -> always available.
 *   [3] TrayNotifyWnd  -- explorer.exe's tray-notification-area class.
 *                        Never pre-registered inside dwm.exe.
 *   [4] WorkerW        -- explorer.exe's desktop-worker class. Some DWM
 *                        builds may pre-register this internally; on
 *                        collision the fallback loop picks the next.
 *
 * IMPORTANT: If you ADD entries here, keep them at the tail so the same
 * install keeps picking the same primary. If you REMOVE an entry every
 * install that previously landed on it will silently roll to a different
 * name -- that's cosmetically weird but functionally harmless (nothing
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
     * single hard-coded MS-adjacent name (`MSDiagEventSink`) -- one
     * signature scanner regex catches every install of theirs. We
     * pick per-install from a 5-name pool (see comment above), so a
     * signature scanner has to know every entry AND match the right
     * one for the current machine. Fallback loop handles the case
     * where the primary collides with a class atom already registered
     * inside dwm.exe by rolling to the next pool entry. */
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = ghost_wnd_proc;
    wc.hInstance   = GetModuleHandleW(NULL);

    /* Salt string is opaque on purpose -- any strings dump sees a short
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
            /* Non-collision failure -> still try next pool entry. Rare;
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
     *   WS_EX_TOPMOST     ALWAYS above all other windows -- the killer fix
     *
     * User confirmed 2026-07-05: "we know LDB specifically whitelists DWM
     * so anything that happens in DWM it doesn't care about and we can
     * go wild in". LDB's anti-tamper allows DWM's process to create
     * topmost windows because DWM legitimately does this for cursor,
     * tooltips, IME candidate windows, etc.
     *
     * With WS_EX_TOPMOST: no z-order fight when user Alt+Tabs -- our
     * ghost stays above everything -> nudging it ALWAYS forces fullscreen
     * DWM re-composite -> toggle is instant regardless of context. */
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

    /* Alpha=1 (0.4% opacity) -- DWM's compositor optimizes fully-transparent
     * layered windows OUT of composition entirely (alpha=0 test failed for
     * this reason). With alpha=1, DWM MUST include this window -> moving it
     * forces DWM to re-composite the covered region. 1/255 = 0.4% opacity
     * of black is imperceptible. */
    SetLayeredWindowAttributes(h, 0, 1, LWA_ALPHA);

    /* Hide from screenshot/capture APIs -- belt-and-suspenders even though
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
 * the "everything must repaint NOW" signal -- result was:
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
 * across all processes CAN see it -- but its class name is picked
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
        /* v1.7.4.12 (2026-07-24) -- GHOST OFF by default, again.
         *
         * v1.7.4.8 flipped ghost ON to fix z-order (overlay dropping
         * behind DirectComposition apps). BUT: v1.7.4.11 fixed the
         * REAL cause of that bug -- IsOverlayPrevented was patched to
         * return FALSE instead of TRUE. With IsOverlayPrevented=TRUE
         * we're in software compositor path and our pixels are
         * naturally on top. Ghost is no longer needed for z-order.
         *
         * Bypassify has NO ghost window and their overlay stays
         * above everything with zero flicker. Our ghost was CAUSING
         * flicker (fullscreen layered TOPMOST HWND periodic re-
         * invalidations, ShowWindow races, WinEvent callback z-order
         * fights). Matching BP: ghost is opt-in via DWM_EXT_GHOST=1
         * for the rare user who needs the extra wake reliability. */
        /* v3.3: ghost tested for explorer-restart persistence -- did NOT help
         * (overlay still died with ghost ON), so back to OFF by default (it's a
         * stealth cost: one enumerable top-level window). Opt-IN via
         * DWM_EXT_GHOST=1. */
        if (n > 0 && (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y')) {
            g_ghost_enabled = 1;
        } else {
            g_ghost_enabled = 0;
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
     * ShowWindow + RedrawWindow N times per frame -> visible strobing.
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
         * appears as a brief flash BEFORE the overlay pixels land -- the
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
        /* Only call ShowWindow if actually needed -- avoids second
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

/* v1.7.4.2 (2026-07-23) -- SAFE fullscreen-dirty notifier.
 *
 * Fires AddDirtyRect on the DisplayRT + LegacyRT trampolines with a
 * fullscreen rect. DWM's compositor invalidates that region and
 * re-samples app pixels for the next composition pass -- old overlay
 * pixels get naturally overwritten by DWM's own re-render.
 *
 * SEH-wrapped for defence: an older v1.6 note said "AddDirtyRect
 * CRASHED DWM in test 2026-07-05" when called from arbitrary threads.
 * That was in the PN detour context (where pThis might be adjusted).
 * Here we call from the Present detour context via the CAPTURED PN
 * pThis pointers -- same virtual-base-adjusted object that PN itself
 * hands us. Empirically safer.
 *
 * Rect: fullscreen virtual-screen bounds. DWM's AddDirtyRect impl at
 * dwmcore!0xbed84 UNIONs the new rect with existing tracked dirty --
 * passing fullscreen guarantees the whole layer is marked dirty.
 * Trampolines pre-resolved in hooks_install; if either is NULL we
 * silently skip that one. */
int hooks_add_dirty_full(void) {
    if (!g_active || g_shutdown_flag) return 0;
    int fired = 0;
    /* Full virtual screen -- every pixel gets marked dirty. */
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    float rect[4] = {
        (float)vx, (float)vy,
        (float)(vx + vw), (float)(vy + vh)
    };
    __try {
        if (g_add_dirty_display && g_display_rt) {
            g_add_dirty_display((void *)g_display_rt, rect);
            fired = 1;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* If display trampoline crashes, cache-out so we don't
         * repeatedly try + risk destabilizing DWM. */
        g_add_dirty_display = NULL;
        hook_diag("add_dirty_full: display trampoline crashed -- disabled");
    }
    __try {
        if (g_add_dirty_legacy && g_legacy_rt) {
            g_add_dirty_legacy((void *)g_legacy_rt, rect);
            fired = 1;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_add_dirty_legacy = NULL;
        hook_diag("add_dirty_full: legacy trampoline crashed -- disabled");
    }
    return fired;
}
