/* ================================================================== *
 * sec_attr.h -- SDDL-based SECURITY_ATTRIBUTES helpers.               *
 *                                                                    *
 * v3.2 (2026-09-23) -- consolidated after medium-IL red-team pass    *
 * proved default-DACL objects (pipes, mutexes, non-shutdown events)  *
 * were connectable/openable from unprivileged Users. All named       *
 * objects in the codebase should use these helpers so future audits  *
 * can grep one location.                                             *
 *                                                                    *
 * Usage pattern (caller frees sd via LocalFree AFTER Create*):       *
 *   SECURITY_ATTRIBUTES sa; PSECURITY_DESCRIPTOR sd = NULL;          *
 *   if (svc_build_admin_sys_sa(&sa, &sd)) {                          *
 *     h = CreateEventA(&sa, ...);                                    *
 *     LocalFree(sd);                                                 *
 *   } else {                                                          *
 *     h = CreateEventA(NULL, ...);   // fallback: default DACL       *
 *   }                                                                 *
 * ================================================================== */
#ifndef SVCLDB_SEC_ATTR_H
#define SVCLDB_SEC_ATTR_H

#include <windows.h>

/* Build a SECURITY_ATTRIBUTES whose DACL grants FULL access ONLY to
 * BUILTIN\Administrators and NT AUTHORITY\SYSTEM. Everyone else gets
 * ACCESS_DENIED on Open*. Returns 1 on success, 0 on failure (caller
 * should treat failure as "use default DACL" -- see usage note above).
 *
 * Owner is left as the creating process's default (SYSTEM for
 * payload-in-dwm, Administrators for elevated launcher). */
int svc_build_admin_sys_sa(SECURITY_ATTRIBUTES *out_sa,
                           PSECURITY_DESCRIPTOR *out_sd);

/* Same as above but for NAMED PIPES specifically -- adds explicit
 * "3" bits (READ_DATA | WRITE_DATA | CREATE_PIPE_INSTANCE) so that
 * ConnectNamedPipe + client CreateFile checks work from Admins/SYS
 * but hard-fail from anyone else. Bare GA is fine for events/mutexes
 * but pipes need object-specific mask bits.
 *
 * SDDL string:
 *   D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;S-1-5-90-0)
 * FA = FILE_ALL_ACCESS (which for pipes = full pipe access).
 * BA = BUILTIN\Administrators
 * SY = NT AUTHORITY\SYSTEM
 * S-1-5-90-0 = Window Manager\Window Manager Group (covers dwm.exe
 *              which runs under DWM-<n> virtual accounts that are
 *              NOT in Admins or SYSTEM).
 * v3.2 (2026-09-23) -- WMG added after live repro proved DWM cannot
 * create pipes with a DACL that excludes its own token SIDs. Users
 * still cannot open (no WD/AU/IU in the DACL). */
int svc_build_pipe_admin_sys_sa(SECURITY_ATTRIBUTES *out_sa,
                                PSECURITY_DESCRIPTOR *out_sd);

/* Read-only DACL for the bind_secret file. Grants FILE_GENERIC_READ
 * to Admins, SYSTEM, and Window Manager Group (S-1-5-90-0). Users
 * are excluded => cannot compute HMAC-derived names.
 *
 *   D:PAI(A;;FR;;;BA)(A;;FR;;;SY)(A;;FR;;;S-1-5-90-0)
 *
 * PAI = SDDL_PROTECTED | SDDL_AUTO_INHERITED -- blocks ProgramData's
 * inherited "Users:Read" grant that would otherwise re-open the file
 * to medium-IL processes. */
int svc_build_bind_secret_sa(SECURITY_ATTRIBUTES *out_sa,
                              PSECURITY_DESCRIPTOR *out_sd);

/* v3.4 (2026-09-23) -- DACL for the payload's append-mode log files
 * (payload.log, ai.log, http.log, and the winlogon helper's wl_input.log
 * when WL_DIAG is on).
 *
 * Problem: when the payload creates a fresh payload.log via CreateFileA
 * (OPEN_ALWAYS) without an explicit SD, Windows applies the parent-dir
 * inheritance + CREATOR OWNER. CREATOR OWNER resolves to the current
 * DWM virtual account (Window Manager\DWM-<N>). ProgramData's inheritance
 * grants BUILTIN\Users:Write, but DWM-N is NOT a member of BUILTIN\Users
 * -- it's a member of Window Manager\Window Manager Group (S-1-5-90-0).
 * Result: only THE SPECIFIC DWM-N instance that created the file has
 * FullControl. When DWM crashes and respawns as DWM-<N+1>, the new
 * virtual account cannot open the pre-existing log for FILE_APPEND_DATA
 * -- CreateFile silently returns ACCESS_DENIED and every slog_write call
 * after the DWM crash turns into /dev/null (visible symptom: payload.log
 * LastWriteTime frozen at the crash moment; every fresh inject appears
 * silent even though the payload is running fine).
 *
 * Fix: grant FullControl to the Window Manager Group itself, not to
 * individual DWM-N SIDs. Every DWM instance (past, present, future) is
 * a member of that group, so the ACL survives shell restarts.
 *
 *   D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)
 *
 * P (protected) blocks the parent-dir DACL from re-inheriting a
 * CREATOR OWNER entry on later modifications; we want a stable,
 * self-contained ACL that doesn't drift.
 *
 * Ownership stays whatever CreateFile set (usually the creating DWM-N
 * or the launcher's Admin token) -- doesn't matter for access checks
 * once WMG is in the DACL.
 *
 * Passed to CreateFileA in shared/log_secure.c slog_write on file
 * creation; also applied post-hoc to any pre-existing log files by
 * the launcher's heal_log_dacls() at every arm entry. */
int svc_build_log_file_sa(SECURITY_ATTRIBUTES *out_sa,
                          PSECURITY_DESCRIPTOR *out_sd);

/* v3.4 (2026-09-23) -- One-shot healer: reset the DACL on an existing
 * on-disk file to match svc_build_log_file_sa's SDDL. Silent no-op if
 * the file doesn't exist. Requires the calling process to hold WRITE_DAC
 * on the file, which is guaranteed for the launcher (elevated Admin,
 * which bypasses DACL for owned files + can take ownership if needed).
 * Returns 1 on success, 0 on any failure (logged but non-fatal -- next
 * write will just still fail from the new DWM-N until the file rotates).
 *
 * WHY the launcher does this rather than the payload: SetNamedSecurityInfo
 * requires WRITE_DAC or the SeSecurityPrivilege, which DWM-<N> virtual
 * accounts do NOT hold. The payload cannot self-heal an inaccessible log
 * file; only the elevated launcher can. Hence this heal function must be
 * invoked from the launcher-side arm entry, before the payload starts
 * trying to write. */
int svc_heal_log_dacl(const char *path);

#endif /* SVCLDB_SEC_ATTR_H */
