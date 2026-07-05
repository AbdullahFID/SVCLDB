/* ================================================================== *
 * inject.h — DWM payload injection.                                   *
 * ================================================================== */
#ifndef SVCLDB_INJECT_H
#define SVCLDB_INJECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Attempts to inject dwm_payload.dll into dwm.exe via CreateRemoteThread
 * + LoadLibraryW. Returns 1 on success, 0 on failure (err populated).
 * If already-injected, returns 1 with no work done. */
int inject_dwm_payload(const char *payload_dll_path, char *err, size_t err_sz);

/* Signal cooperative unload via Global\SVCLDB_Shutdown named event.
 * Returns 1 if signaled, 0 if event doesn't exist (payload not running). */
int inject_signal_unload(void);

/* True if <dwm_payload> is currently loaded inside dwm.exe. */
int inject_is_loaded(void);

/* Find dwm.exe PID (0 on failure). */
unsigned long inject_find_dwm_pid(void);

#ifdef __cplusplus
}
#endif

#endif
