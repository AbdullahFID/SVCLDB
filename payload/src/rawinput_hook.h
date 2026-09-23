/* ================================================================== *
 * rawinput_hook.h -- HWND_MESSAGE window + RegisterRawInputDevices +   *
 * GetAsyncKeyState polling fallback. Delivers global hotkey events    *
 * from inside dwm.exe without stealing focus from any target app.     *
 *                                                                    *
 * Two parallel delivery paths -- whichever fires first wins (250 ms   *
 * debounce prevents duplicate callbacks):                            *
 *   1. WM_INPUT via RIDEV_INPUTSINK -- works when DWM has interactive *
 *      window-station access. Not always available on Win11 kiosk    *
 *      builds and inside Protected Process Light contexts.           *
 *   2. GetAsyncKeyState polling @ 60 Hz -- reads kernel-global key    *
 *      state (win32k!gafAsyncKeyState) which is not gated on session *
 *      or process protection. Confirmed working from DWM 2026-07-04. *
 * ================================================================== */
#ifndef SVCLDB_RAWINPUT_HOOK_H
#define SVCLDB_RAWINPUT_HOOK_H

#include "../../shared/config_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hotkey callback -- invoked from a worker thread. `action` is a
 * svc_hotkey_action_t index (0-based). Callback must NOT block. */
typedef void (*hotkey_cb_t)(int action);

/* Start the listener. `hotkeys` MUST point to at least SVC_HK_COUNT
 * uints (typically &cfg->hotkeys[0]). Zero-valued slots are ignored.
 * Codes packed as (mod << 16) | vk; mod bits: 1=ctrl 2=shift 4=alt.
 * Spawns two threads (WM_INPUT worker + poll thread).
 * Returns 1 on success. */
int  rawin_start(const unsigned *hotkeys, hotkey_cb_t cb);

void rawin_stop(void);

/* v3.2 (P0: overlay/mouse die on explorer restart). Stop + restart the input
 * subsystem so the poll thread, WM_INPUT worker, and low-level keyboard/mouse
 * hooks re-attach to the CURRENT input desktop. Called by the shell-restart
 * soft-reinject worker AND the secure-desktop watcher. No-op (returns 0) if
 * rawin_start was never called; returns 0 if another re-attach is already in
 * progress (re-entrancy guard); returns 1 if this call ran the stop/start. */
int  rawin_restart(void);

/* v3.0.1 (SEB secure-desktop). Background watcher: polls the active input
 * desktop name every 250ms and calls rawin_restart() when it changes, so the
 * input subsystem follows SEB / WinLogon / UAC desktop switches. Started once
 * after rawin_start(); stopped (before rawin_stop) on clean unload. */
void rawin_start_desktop_watch(void);
void rawin_stop_desktop_watch(void);

/* v3.0.1 (SEB Architecture B). Named-pipe server that receives key events from
 * the SYSTEM-hosted secure-desktop input helper and runs them through the local
 * hotkey match+fire path. Started once after rawin_start; stopped on unload. */
void rawin_start_seb_pipe(void);
void rawin_stop_seb_pipe(void);

/* v15.1.8 (2026-09-22) -- TRUE iff the ACTIVE INPUT DESKTOP is NOT the
 * normal "\\Default" (i.e. we're on a secure / isolated desktop like
 * SEB / LDB / WinLogon Secure Desktop). Used by ground.cpp to route
 * UIA queries through the SYSTEM winlogon helper (which can see the
 * isolated desktop's UIA tree) instead of the payload's DWM-N context
 * (which cannot). Non-blocking cached read (updated by the deskwatch
 * thread every ~250ms). Safe from any thread. */
int  rawin_is_isolated_desktop(void);

/* v3.3 (2026-09-23) -- hk_table publishing lives in the LAUNCHER now
 * (see launcher/src/config_write.c :: config_write_hk_table). The
 * payload doesn't touch _hk.bin -- DWM's virtual account can't lock
 * the DACL and the launcher already writes the authoritative table on
 * every arm path. No payload-side entry point is needed. */

#ifdef __cplusplus
}
#endif

#endif
