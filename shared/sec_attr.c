/* ================================================================== *
 * sec_attr.c -- see sec_attr.h.                                       *
 * ================================================================== */
#include "common.h"
#include "sec_attr.h"
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

int svc_build_admin_sys_sa(SECURITY_ATTRIBUTES *out_sa,
                           PSECURITY_DESCRIPTOR *out_sd) {
    if (!out_sa || !out_sd) return 0;
    *out_sd = NULL;
    out_sa->nLength = sizeof(*out_sa);
    out_sa->bInheritHandle = FALSE;
    out_sa->lpSecurityDescriptor = NULL;
    /* SDDL:
     *   D:                 -- DACL follows
     *   (A;;GA;;;BA)       -- Allow (A) Generic All (GA) to BUILTIN\Administrators (BA)
     *   (A;;GA;;;SY)       -- Allow Generic All to NT AUTHORITY\SYSTEM (SY)
     *   (A;;GA;;;S-1-5-90-0) -- Allow Generic All to Window Manager\Window Manager Group
     *                        (covers dwm.exe which runs under DWM-<n>
     *                        virtual account -- NOT in BA nor SY.
     *                        Without this, DWM cannot CREATE objects
     *                        with this DACL (verified live 2026-09-23:
     *                        CreateNamedPipe returned gle=5 without WMG).
     *                        Users still excluded => cannot open. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;S-1-5-90-0)",
            SDDL_REVISION_1, out_sd, NULL)) {
        return 0;
    }
    out_sa->lpSecurityDescriptor = *out_sd;
    return 1;
}

int svc_build_pipe_admin_sys_sa(SECURITY_ATTRIBUTES *out_sa,
                                PSECURITY_DESCRIPTOR *out_sd) {
    if (!out_sa || !out_sd) return 0;
    *out_sd = NULL;
    out_sa->nLength = sizeof(*out_sa);
    out_sa->bInheritHandle = FALSE;
    out_sa->lpSecurityDescriptor = NULL;
    /* Pipes need FILE_ALL_ACCESS (FA) not just Generic All -- Windows
     * treats named-pipe DACLs through the file object subsystem.
     * With FA both server-side ConnectNamedPipe + client-side CreateFile
     * work from Admins/SYS, but Users get ACCESS_DENIED. WMG added so
     * DWM can create pipes (payload runs in dwm.exe under DWM-<n>
     * virtual account). */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;S-1-5-90-0)",
            SDDL_REVISION_1, out_sd, NULL)) {
        return 0;
    }
    out_sa->lpSecurityDescriptor = *out_sd;
    return 1;
}

int svc_build_bind_secret_sa(SECURITY_ATTRIBUTES *out_sa,
                              PSECURITY_DESCRIPTOR *out_sd) {
    if (!out_sa || !out_sd) return 0;
    *out_sd = NULL;
    out_sa->nLength = sizeof(*out_sa);
    out_sa->bInheritHandle = FALSE;
    out_sa->lpSecurityDescriptor = NULL;
    /* FR = FILE_GENERIC_READ. PAI = Protected DACL (blocks parent
     * inheritance) + Auto-Inherited (informational). ProgramData
     * grants Users:Read via inheritance; PAI blocks that so Users
     * cannot read even if the file lives under ProgramData. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:PAI(A;;FR;;;BA)(A;;FR;;;SY)(A;;FR;;;S-1-5-90-0)",
            SDDL_REVISION_1, out_sd, NULL)) {
        return 0;
    }
    out_sa->lpSecurityDescriptor = *out_sd;
    return 1;
}

int svc_build_log_file_sa(SECURITY_ATTRIBUTES *out_sa,
                          PSECURITY_DESCRIPTOR *out_sd) {
    if (!out_sa || !out_sd) return 0;
    *out_sd = NULL;
    out_sa->nLength = sizeof(*out_sa);
    out_sa->bInheritHandle = FALSE;
    out_sa->lpSecurityDescriptor = NULL;
    /* FA = FILE_ALL_ACCESS. P = Protected DACL (no inheritance from
     * ProgramData -- keeps the ACL stable across parent-dir tweaks).
     * SY + BA gives elevated tools (launcher, dlog tail, support export)
     * full access. S-1-5-90-0 (Window Manager Group) covers every past
     * and future DWM-<N> virtual account so the file stays writable
     * across DWM crashes / shell restarts -- the whole point of this
     * SA (see sec_attr.h docstring). */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)",
            SDDL_REVISION_1, out_sd, NULL)) {
        return 0;
    }
    out_sa->lpSecurityDescriptor = *out_sd;
    return 1;
}

#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")

int svc_heal_log_dacl(const char *path) {
    if (!path || !*path) return 0;
    /* Silent no-op if the file doesn't exist yet -- nothing to heal. */
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return 1;

    /* Build the target DACL from the same SDDL svc_build_log_file_sa uses
     * so on-disk healed files match freshly-created ones byte-for-byte
     * in their ACL. */
    PSECURITY_DESCRIPTOR psd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)",
            SDDL_REVISION_1, &psd, NULL)) {
        return 0;
    }
    BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
    PACL dacl = NULL;
    int rc = 0;
    if (GetSecurityDescriptorDacl(psd, &dacl_present, &dacl, &dacl_defaulted)
            && dacl_present) {
        /* PROTECTED_DACL_SECURITY_INFORMATION mirrors the "P" flag in
         * the SDDL string above -- ensures existing inherited ACEs get
         * stripped when we overwrite. Without this, a parent-dir DACL
         * change would silently re-add a Users-inheritance entry that
         * doesn't cover Window Manager Group. */
        DWORD r = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        rc = (r == ERROR_SUCCESS) ? 1 : 0;
    }
    LocalFree(psd);
    return rc;
}
