/* ================================================================== *
 * common.h — Shared types, macros, product constants.                *
 *                                                                    *
 * Included by every C/C++ file in the project. Kept tiny.            *
 * ================================================================== */
#ifndef SVCLDB_COMMON_H
#define SVCLDB_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Product identity (kept opaque — no "CloakGPT" / "LDB" strings) ─── */
#define SVC_PRODUCT_NAME       "sihost"
#define SVC_PRODUCT_VERSION    "1.0.0"
/* NOTE: NOT under C:\ProgramData\Microsoft\ — that path has kernel-level
 * write restrictions (WDAC/MIC/policy) that block dwm.exe SYSTEM writes
 * despite normal ACL granting SYSTEM FullControl. Verified empirically
 * 2026-07-04: DllMain wrote to C:\Windows\Temp\ + C:\ProgramData\ root
 * fine, but silently failed on C:\ProgramData\Microsoft\WSMonitoring\. */
#define SVC_INSTALL_DIR        "C:\\ProgramData\\WinAudioSvc"
#define SVC_LAUNCHER_EXE       "sihost.exe"
#define SVC_PAYLOAD_DLL        "dwmapiext.dll"
#define SVC_RESOLVER_EXE       "dllhost32.exe"
#define SVC_CONFIG_FILE        "config.dat"      /* encrypted launcher-written config */
#define SVC_OFFSETS_BLOB       "offsets.blob"    /* resolver output for payload */
#define SVC_STATE_FILE         "state.dat"       /* payload's live state + coord IPC */

/* Named event used by the launcher (via --unload) to signal the payload
 * inside dwm.exe that it should cooperatively unload. Name is
 * deliberately innocuous — matches Windows internal shutdown-notif
 * conventions (Global\DwmCompositor* is a legit namespace). Avoid
 * leaking product identity strings into the binary. */
#define SVC_SHUTDOWN_EVENT_NAME  "Global\\DwmCompositorShutdownRelease"

/* ─── OAuth callback listener port ─── *
 * Uses 9274 (same as main app) because that's what's whitelisted on the
 * shared Supabase project. Do NOT run svcldb + main app launcher at the
 * same time — they'd fight for the port. (In practice: mutually exclusive
 * anyway since svcldb is LDB-only and main app skips LDB.) */
#define SVC_CALLBACK_PORT      9274

/* ─── Detection target ─── */
#define SVC_LDB_EXE_NAME       "LockDownBrowser.exe"
#define SVC_LDB_OEM_EXE_NAME   "LockDownBrowserOEM.exe"

/* ─── Housekeeping macros ─── */
#define SVC_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define SVC_UNUSED(x)     ((void)(x))

/* ─── Production build flag ─── *
 *
 * When 1: ALL plaintext-fallback log paths are compiled out. The
 * DWM_EXT_TRACE env-var check becomes dead code (returns 0). Only the
 * AES-256-GCM encrypted `.log` streams are written to disk.
 *
 * When 0 (dev): DWM_EXT_TRACE=1 unlocks the plaintext mirror to
 * payload_early.txt for iteration debugging.
 *
 * Toggle via `/DSVCLDB_PRODUCTION_BUILD=1` in build.bat (default in
 * production). Do NOT ever ship with this = 0. */
#ifndef SVCLDB_PRODUCTION_BUILD
#define SVCLDB_PRODUCTION_BUILD 1
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Zero-alloc, bounded string helpers. */
static inline void svc_secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_COMMON_H */
