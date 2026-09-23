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

#endif /* SVCLDB_SEC_ATTR_H */
