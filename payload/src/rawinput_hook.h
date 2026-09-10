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

#ifdef __cplusplus
}
#endif

#endif
