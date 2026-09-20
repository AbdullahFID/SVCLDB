/* ================================================================== *
 * obf_names.h -- Per-box derived, camouflaged names for every named   *
 * kernel object svcldb creates (pipes, mutexes, the shutdown event).  *
 *                                                                    *
 * WHY THIS EXISTS (v3 red-team hardening, 2026-09-19)                 *
 *                                                                    *
 * A NON-ADMIN hunter cannot read dwm.exe memory, but it CAN, with no  *
 * elevation at all:                                                   *
 *   (a) enumerate EVERY named pipe on the box via                     *
 *       FindFirstFile("\\.\pipe\*") -- SpecterOps `listpipes`, etc.   *
 *   (b) enumerate the session + global BaseNamedObjects directories   *
 *       (WinObj-style NtQueryDirectoryObject) to list mutex/event     *
 *       names, and                                                    *
 *   (c) probe a known name and distinguish EXISTS-but-ACCESS_DENIED   *
 *       (GLE=5) from NOT_FOUND (GLE=2) -- the existence leak.          *
 *                                                                    *
 * Pre-v3 svcldb shipped FIXED, IDENTIFYING names:                     *
 *   \\.\pipe\svcldb_token_v1        <- literal product codename       *
 *   \\.\pipe\svcldb_ocr_v1          <- literal product codename       *
 *   Global\svcldb_ocr_daemon_v1_mutex                                 *
 *   Local\DwmCompositorGuardRelease (plaintext, not even str_enc'd)   *
 * Any pipe enumeration screamed "svcldb" with zero effort.            *
 *                                                                    *
 * FIX: derive each object's name at runtime from a per-machine secret *
 * (HKLM\...\Cryptography\MachineGuid) via SHA-256 with a per-purpose  *
 * salt, formatted as a canonical lowercase GUID. Result:              *
 *   - No product string ever lands in the binary (names are computed, *
 *     never stored) -- beats even str_enc.                            *
 *   - The name is DIFFERENT on every machine, so there is no shared   *
 *     constant IOC to publish/probe across installs.                  *
 *   - A GUID-named pipe/object is statistically INDISTINGUISHABLE     *
 *     from the dozens of legit GUID-named pipes Windows/COM/RPC       *
 *     already keep open -- flagging it means flagging all of them.    *
 *                                                                    *
 * CROSS-LANGUAGE CONTRACT                                             *
 * The Electron side (ui/src/lib/obf-names.js) MUST derive byte-for-   *
 * byte identical names (same MachineGuid input, same salts, same      *
 * SHA-256, same 16-byte->GUID formatting) or the token-refresh pipe,  *
 * OCR pipe, and status probe break. See that file + the salts below;  *
 * both sides are pinned to the SAME salt constants. A mismatch is a   *
 * silent loss of functionality, so any change here must be mirrored   *
 * there and re-verified with the cross-language check.                *
 * ================================================================== */
#ifndef SVCLDB_OBF_NAMES_H
#define SVCLDB_OBF_NAMES_H

#ifdef __cplusplus
extern "C" {
#endif

/* Each accessor returns a pointer to a process-lifetime static buffer
 * holding the fully-qualified object name. First call computes +
 * caches; subsequent calls return the cache. Thread-safe for the
 * read-after-first-init pattern svcldb uses (all first-touch happens
 * during single-threaded init). Never returns NULL -- a registry-read
 * failure falls back to a fixed (still non-identifying) GUID so the
 * IPC endpoints always agree and functionality never breaks. */

/* "\\.\pipe\<guid>" -- payload<->Electron JWT refresh pipe. */
const char *obf_pipe_token(void);

/* "\\.\pipe\<guid>" -- OCR/redact daemon pipe (launcher server;
 * payload + Electron clients). */
const char *obf_pipe_ocr(void);

/* "Local\<guid>" -- payload double-init guard mutex (session-scoped). */
const char *obf_mutex_initguard(void);

/* "Global\<guid>" -- OCR daemon single-instance mutex (launcher). */
const char *obf_mutex_ocrdaemon(void);

/* "Global\<guid>" -- cooperative shutdown event.
 * NOTE (v3): defined for completeness / future migration, but the
 * shutdown event is NOT yet wired to this in the payload/launcher/UI.
 * It is currently str_enc'd (no static leak) and is not pipe-style
 * enumerable, so it is a lower-priority, higher-blast-radius rename
 * (touches the user-visible "is injected?" status probe on both the C
 * and Electron sides). Migrate only with the cross-language check +
 * an injected end-to-end status test. */
const char *obf_event_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_OBF_NAMES_H */
