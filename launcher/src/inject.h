/* ================================================================== *
 * inject.h — DWM payload injection.                                   *
 * ================================================================== */
#ifndef SVCLDB_INJECT_H
#define SVCLDB_INJECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy: inject a DLL from a disk path. Used only for debug tooling.
 * Prefer inject_dwm_payload_from_resource in production. */
int inject_dwm_payload(const char *payload_dll_path, char *err, size_t err_sz);

/* Primary path: inject the DLL embedded as RCDATA `resource_id` in
 * the launcher exe itself. `self` is HMODULE of the launcher
 * (typically GetModuleHandleA(NULL)). Zero disk footprint — payload
 * bytes come straight from our own PE .rsrc section. */
int inject_dwm_payload_from_resource(void *self, int resource_id,
                                     char *err, size_t err_sz);

/* Resource ID we use for the embedded payload DLL. Kept as a macro
 * so build.bat's .rc generator can reference the same number. */
#define SVC_PAYLOAD_RCDATA_ID  101

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
