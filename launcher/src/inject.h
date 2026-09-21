/* ================================================================== *
 * inject.h -- DWM payload injection.                                   *
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
 * (typically GetModuleHandleA(NULL)). Zero disk footprint -- payload
 * bytes come straight from our own PE .rsrc section. */
int inject_dwm_payload_from_resource(void *self, int resource_id,
                                     char *err, size_t err_sz);

/* Resource ID we use for the embedded payload DLL. Kept as a macro
 * so build.bat's .rc generator can reference the same number. */
#define SVC_PAYLOAD_RCDATA_ID  101

/* v3.0.2 (2026-09-21): resource ID for the wl_input helper DLL
 * (manual-mapped into winlogon.exe for isolated-desktop input). */
#define SVC_HELPER_RCDATA_ID   102

/* Manual-map the wl_input helper (RCDATA `resource_id`) into
 * winlogon.exe in the current session. Same shellcode + PE mapping
 * machinery as the payload path but targets a different host and
 * skips the payload-shutdown-event teardown wait. Returns 1 on
 * success. Safe to call when a prior helper instance is running --
 * we signal Global\NetSvcCoord_Halt first so the old instance's
 * watch + reader threads exit before we map the new one. */
int inject_helper_from_resource(void *self, int resource_id,
                                char *err, size_t err_sz);

/* Signal the helper's Global\NetSvcCoord_Halt event so its watch and
 * reader threads see `superseded()` and exit cleanly. Returns 1 if
 * signaled, 0 if the event didn't exist (helper not running). Used
 * by --unload and by a fresh inject to hot-swap without a reboot. */
int inject_helper_signal_unload(void);

/* Find the winlogon.exe PID in the current interactive session. Zero
 * on failure. Winlogon is always non-PPL and always present in every
 * interactive session, making it a universal host. */
unsigned long inject_find_winlogon_pid_in_session(void);

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
