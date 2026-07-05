/* ================================================================== *
 * dwm_hooks.h — dwmcore hooking API for the payload.                  *
 *                                                                    *
 * Architecture (2026-07-04, RE'd 1:1 from Bypassify v1.3.0 payload   *
 * plus the production hooksdll/dwm/dwm_payload.c pattern):           *
 *                                                                    *
 *   HOOK #1  COverlayContext::Present   (MinHook install)            *
 *     - Draw our overlay INTO the layer texture BEFORE orig          *
 *     - Skipped when g_shutdown_flag is set (see below)              *
 *                                                                    *
 *   HOOK #2  CDDisplayRenderTarget::PresentNeeded  (MinHook install) *
 *     - Capture pThis on first call → g_display_rt                   *
 *     - Call orig(pThis) unconditionally                             *
 *     - If g_wake_active (g_wake_frames_remaining > 0):              *
 *         → return TRUE  (Bypassify's core "force compose" trick)   *
 *       This forces DWM to composite THIS frame regardless of        *
 *       whether the compositor thinks anything changed. Result:      *
 *       our UI state changes (hotkey toggles, opacity bumps, etc.)   *
 *       are visible on the NEXT vsync tick without needing user      *
 *       interaction to trigger a re-composition.                     *
 *     - Otherwise: return orig result (respects DWM's normal         *
 *       lazy-compose behavior when we don't need a wake).            *
 *                                                                    *
 *   HOOK #3  CLegacyRenderTarget::PresentNeeded  (MinHook install)   *
 *     - IDENTICAL pattern to HOOK #2. Some GPU/render paths use the  *
 *       legacy render target; hooking both catches both.             *
 *                                                                    *
 *   PATCH #1  IsOverlayPrevented  (byte-patch xor eax,eax; ret)      *
 *     - Return FALSE unconditionally → allow overlay planes.         *
 *     - Reverted to original bytes on hooks_uninstall.               *
 *                                                                    *
 * SHUTDOWN FLOW (Bypassify pattern — solves "overlay stays on screen *
 * after kill"):                                                      *
 *   1. Set g_shutdown_flag = 1 (atomic).                             *
 *      Instantly: Detour_Present stops drawing our overlay.          *
 *      Instantly: PN1/PN2 stop returning TRUE (revert to orig lazy). *
 *   2. Sleep(200) — during ~12 frames at 60Hz, orig Present          *
 *      composites the layer texture with CLEAN pixels from the       *
 *      owning app; our overlay pixels are naturally overwritten in   *
 *      DWM's compositor backbuffer.                                  *
 *   3. MH_DisableHook(NULL) → MH_Uninitialize().                     *
 *   4. Revert the IsOverlayPrevented byte-patch.                     *
 *                                                                    *
 * See docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md for the full RE writeup.    *
 * ================================================================== */
#ifndef SVCLDB_DWM_HOOKS_H
#define SVCLDB_DWM_HOOKS_H

#include "blob_read.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Present callback. Receives pCtx (COverlayContext this) + pLayer
 * (the layer being presented — walk its vtable for the D3D texture). */
typedef void (*present_cb_t)(void *pCtx, void *pLayer);

/* Install all hooks + byte-patch. Returns 1 on success. */
int  hooks_install(const pl_offsets_t *off, present_cb_t present_cb);

/* Cooperative shutdown: sets shutdown flag, sleeps 200ms, disables
 * hooks, reverts byte-patch. Safe to call from any thread. */
void hooks_uninstall(void);

/* ── Force-wake API (Bypassify's "return TRUE from PN" pattern) ── */

/* Set the wake counter to `frames`. While the counter is > 0, our PN1
 * and PN2 detours return TRUE unconditionally, forcing DWM to
 * composite every vsync at native refresh rate. Counter decrements
 * once per Detour_Present call (~60/120/144 Hz depending on monitor).
 *
 * Call this whenever the UI state changes (hotkey toggle, nudge,
 * resize, opacity/font bump, etc.) — it guarantees the change is
 * visible on the very next frame with zero user interaction.
 *
 * `frames = 6` (~100ms at 60Hz) is a good default: enough to
 * guarantee visibility of a discrete change, short enough that it
 * doesn't waste GPU when the UI is idle.
 *
 * Idempotent — calling multiple times just resets to `frames` (never
 * decreases). */
void hooks_bump_wake(int frames);

/* Direct-fire the DWM compositor from ANY thread. Calls the ORIGINAL
 * CDDisplayRenderTarget::PresentNeeded(pThis) and
 * CLegacyRenderTarget::PresentNeeded(pThis) with the captured pThis
 * pointers, PLUS ForceFullDirtyRendering() to bust dwmcore's
 * dirty-region cache — this combination is dwmcore-internal machinery
 * that DIRECTLY triggers a full composition pass regardless of what
 * DWM thinks is dirty.
 *
 * Combines with hooks_bump_wake for maximum wake reliability:
 *   1. hooks_bump_wake(N) marks the next N frames as "must return TRUE"
 *   2. hooks_force_wake() immediately triggers the first frame + busts
 *      dirty tracking so that first frame re-composites EVERY region
 *
 * Safe to call before any Present has fired (no-op if pThis pointers
 * haven't been captured yet). */
void hooks_force_wake(void);

/* Burst-wake: spawns (or reuses) a background thread that fires
 * hooks_force_wake() every `interval_ms` for `duration_ms` total.
 * Each fire also bumps wake_frames to at least `frames_per_pump`.
 *
 * Fire-and-forget: returns immediately (does NOT block the caller —
 * so hotkey threads can call this without stalling).
 *
 * Why the burst pattern is necessary: a single hooks_force_wake()
 * triggers ONE composition pass. If DWM was idle (which happens
 * whenever nothing on screen is animating), that first frame comes
 * back from a cold compositor pipeline — often with partial-fill
 * pixels ("half render" bug). A burst of ~18 forced composites over
 * 300ms guarantees the compositor pipeline is fully warm and our
 * overlay renders cleanly.
 *
 * If a burst is already in progress, this call EXTENDS it (no thread
 * pileup, no lost pumps). Multiple hotkey presses in rapid succession
 * cost O(1) — same single worker thread. */
void hooks_burst_wake(int frames_per_pump, int duration_ms, int interval_ms);

/* True if hooks are installed AND not in shutdown mode. */
int  hooks_is_active(void);

/* Wake via ghost window movement (LDB-safe).
 *
 * Creates + owns a hidden fullscreen invisible window (class name
 * "MSCTFIME UI" — a common Windows IME infrastructure class name that
 * LDB won't flag as suspicious). On wake, moves this ghost window
 * by 1 pixel then back → DWM sees CVisual::SetOffset for a fullscreen
 * visual → re-composites the entire screen region.
 *
 * Unlike nudging the ForegroundWindow (which would trigger LDB's
 * anti-tamper watching WM_WINDOWPOSCHANGED), this never touches ANY
 * other process's window. LDB and other target apps never receive
 * any messages from our wake — DWM sees the visual dirty in its own
 * composition tree, that's it.
 *
 * Fire-and-forget: safe from any thread. First call spawns the ghost
 * window creation thread (idempotent). Subsequent calls just SetWindowPos
 * the already-existing window. */
void hooks_ghost_wake(void);

#ifdef __cplusplus
}
#endif

#endif
