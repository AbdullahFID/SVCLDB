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
