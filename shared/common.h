/* ================================================================== *
 * common.h -- Shared types, macros, product constants.                *
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
/* v3.0.3 (2026-09-21): needed for svc_write_locked_sentinel below.
 * <sddl.h> = ConvertStringSecurityDescriptor..., <aclapi.h> =
 * SetSecurityInfo + SE_FILE_OBJECT + PROTECTED_DACL_SECURITY_INFORMATION.
 * Both are lightweight system headers. All C compilation units that
 * include common.h already link advapi32.lib. */
#include <sddl.h>
#include <aclapi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Product identity (kept opaque -- no "CloakGPT" / "LDB" strings) ─── */
#define SVC_PRODUCT_NAME       "sihost"
#define SVC_PRODUCT_VERSION    "1.0.0"
/* NOTE: NOT under C:\ProgramData\Microsoft\ -- that path has kernel-level
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
 * deliberately innocuous -- matches Windows internal shutdown-notif
 * conventions (Global\DwmCompositor* is a legit namespace). Avoid
 * leaking product identity strings into the binary. */
#define SVC_SHUTDOWN_EVENT_NAME  "Global\\DwmCompositorShutdownRelease"

/* ─── OAuth callback listener port ─── *
 * Uses 9274 (same as main app) because that's what's whitelisted on the
 * shared Supabase project. Do NOT run svcldb + main app launcher at the
 * same time -- they'd fight for the port. (In practice: mutually exclusive
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

/* ─── Dev bypass for auth (handshake + sub_check) ─── *
 *
 * When 1: init_thread SKIPS handshake_verify() + sub_check_start().
 * Lets developers iterate on the payload without re-authenticating
 * through the Electron UI every rebuild (which involves Google OAuth,
 * subscription check, etc -- painful for the ~30-second edit-compile-
 * test cycle).
 *
 * Toggle at compile time via:
 *   set SVCLDB_DEV_AUTH=1
 *   build.bat            (build.bat maps env-var -> /D flag)
 *
 * Default is 0 (production). MUST be removed / disabled before shipping.
 * Grep pre-release:
 *   Get-ChildItem payload,shared,launcher -Recurse -Include *.c,*.h,*.bat |
 *     Select-String -Pattern 'SVCLDB_DEV_BYPASS|SVCLDB_DEV_AUTH'
 * Must return zero SET matches (`#define ... 1` or `set SVCLDB_DEV_AUTH=1`). */
#ifndef SVCLDB_DEV_BYPASS_AUTH
#define SVCLDB_DEV_BYPASS_AUTH 0
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Zero-alloc, bounded string helpers. */
static inline void svc_secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* v3.0.3 (2026-09-21) -- write a sentinel file with a locked-down DACL
 * that grants FULL_CONTROL only to SYSTEM + BUILTIN\Administrators.
 * Every other principal (Users, INTERACTIVE, etc.) is implicitly denied
 * write, which prevents any non-admin process from forging the
 * .dwm_user_panic / .dwm_clean_shutdown sentinels to permanently disarm
 * the resurrection watchdogs (helper's sentinel_thread + svchelper's
 * respawnWatchdog).
 *
 * Flow: CreateFile with WRITE_DAC (creator owner always granted, so this
 * succeeds from any legitimate writer identity — payload/DWM-N, launcher/
 * admin, helper/SYSTEM) → WriteFile the body → SetSecurityInfo to LOCK
 * DOWN the DACL to SYSTEM+Admins only + mark it PROTECTED (blocks
 * inherited ACEs from parent directory). Any subsequent forgery attempt
 * from a non-admin caller fails at CreateFile(GENERIC_WRITE) with
 * ACCESS_DENIED. Sentinel readers use GetFileAttributesA which needs only
 * parent-dir traversal (FILE_LIST_DIRECTORY), so cross-privilege reads
 * still work as expected.
 *
 * SDDL breakdown:
 *   D:P            -- DACL, PROTECTED (no inheritance from parent dir).
 *   (A;;GA;;;SY)   -- Allow GENERIC_ALL to LOCAL_SYSTEM.
 *   (A;;GA;;;BA)   -- Allow GENERIC_ALL to BUILTIN\Administrators.
 * Everyone else: not listed = implicit deny.
 *
 * Returns 1 on success (file created + written), 0 on any hard failure.
 * The DACL lockdown is best-effort — logs are the caller's responsibility.
 *
 * Threat model closed: closes the "non-admin sentinel-file DoS" gap
 * identified during the 2026-09-21 stealth audit — a hostile user-space
 * process CAN'T create/overwrite these sentinels to permanently disable
 * our resurrection watchdogs. See
 * docs/HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md. */
static inline int svc_write_locked_sentinel(const char *path,
                                             const void *body,
                                             DWORD body_len) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE | WRITE_DAC, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;

    if (body && body_len > 0) {
        DWORD written = 0;
        (void)WriteFile(f, body, body_len, &written, NULL);
        (void)FlushFileBuffers(f);
    }

    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sd_size = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &sd, &sd_size)) {
        BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
        PACL dacl = NULL;
        if (GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted)
            && dacl_present) {
            (void)SetSecurityInfo(
                f, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, dacl, NULL);
        }
        LocalFree(sd);
    }

    CloseHandle(f);
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_COMMON_H */
