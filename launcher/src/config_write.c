/* ================================================================== *
 * config_write.c -- Machine-bound config file used by launcher+payload*
 * ================================================================== */

#include "../../shared/common.h"
#include "config_write.h"
#include "../../shared/crypto_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/hk_table.h"   /* v3.3 (2026-09-23) -- shared hk table */
#include "../../shared/sec_attr.h"   /* v14.2 (2026-09-23) -- WMG-writable DACL */

#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

#define CONFIG_PATH   SVC_INSTALL_DIR "\\" SVC_CONFIG_FILE

/* v14.2 (2026-09-23) -- One-shot DACL healer for config.dat, mirroring
 * shared/sec_attr.c::svc_heal_log_dacl. Called at the top of every
 * config_write so existing installs get their config.dat DACL widened
 * to include Window Manager Group (WMG, S-1-5-90-0) -- required so the
 * payload (running inside dwm.exe as DWM-<N> virtual account) can
 * cfg_persist() after an autonomous refresh_token rotation. Pre-fix,
 * cfg_persist got ACCESS_DENIED on MoveFileEx and every rotated rt was
 * discarded on payload reload / reboot -- silent regression of the v14
 * autonomous-refresh guarantee.
 *
 * Also strips BUILTIN\Users:Read (default ProgramData inheritance), which
 * closes the v3.1 accepted-residual medium-IL read of config.dat -- the
 * file contains encrypted JWTs + refresh tokens; even encrypted, Users
 * shouldn't be able to enumerate it. */
static void config_heal_dacl(void) {
    if (GetFileAttributesA(CONFIG_PATH) == INVALID_FILE_ATTRIBUTES) return;
    PSECURITY_DESCRIPTOR psd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)",
            SDDL_REVISION_1, &psd, NULL)) {
        return;
    }
    BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
    PACL dacl = NULL;
    if (GetSecurityDescriptorDacl(psd, &dacl_present, &dacl, &dacl_defaulted)
            && dacl_present) {
        DWORD r = SetNamedSecurityInfoA((LPSTR)CONFIG_PATH, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        if (r == ERROR_SUCCESS) {
            slog_writef("msvc_dbg_b.dat", "config_heal_dacl: healed %s", CONFIG_PATH);
        } else {
            slog_writef("msvc_dbg_b.dat", "config_heal_dacl: SetNamedSecurityInfo gle=%lu",
                        (unsigned long)r);
        }
    }
    LocalFree(psd);
}

int config_write(const svc_config_t *cfg) {
    if (!cfg) return 0;
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);

    uint8_t cipher[sizeof(svc_config_t) + 64];
    size_t clen = 0;
    if (!cu_wrap_encrypt(cfg, sizeof(*cfg), cipher, sizeof(cipher), &clen)) {
        slog_launcher("config_write: wrap_encrypt failed");
        return 0;
    }

    /* v14.2 (2026-09-23) -- Explicit SA on create so a fresh install's
     * config.dat is born with the correct DACL (SYSTEM+Admins+WMG FA,
     * no Users). Existing installs get widened via config_heal_dacl()
     * below (called after CloseHandle to avoid touching an open handle). */
    SECURITY_ATTRIBUTES sa = {0};
    PSECURITY_DESCRIPTOR sd = NULL;
    int have_sa = svc_build_log_file_sa(&sa, &sd);
    HANDLE h = CreateFileA(CONFIG_PATH, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           have_sa ? &sa : NULL);
    if (sd) LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("msvc_dbg_b.dat", "config_write: create %s failed %lu",
                    CONFIG_PATH, GetLastError());
        svc_secure_zero(cipher, sizeof(cipher));
        return 0;
    }
    DWORD w = 0;
    BOOL ok = WriteFile(h, cipher, (DWORD)clen, &w, NULL);
    CloseHandle(h);
    svc_secure_zero(cipher, sizeof(cipher));
    if (!ok || w != clen) return 0;
    /* v14.2: heal DACL after write. Idempotent -- CREATE_ALWAYS just
     * overwrote in place if the file existed; on brand-new install we
     * already set the SA correctly. Only matters for upgraders whose
     * pre-v14.2 config.dat had the default-DACL Users:Read entry. */
    config_heal_dacl();
    slog_writef("msvc_dbg_b.dat", "config_write ok bytes=%u", (unsigned)clen);
    return 1;
}

void config_delete(void) {
    DeleteFileA(CONFIG_PATH);
}

/* v3.3 (2026-09-23) -- publish the plaintext hotkey table for the
 * winlogon helper's LL hook. Sibling to config_write; runs on every
 * arm path so the helper always sees the latest bindings + flags.
 *
 * DACL: launcher runs elevated (Admin, and after sihost injects itself
 * effectively SYSTEM too), so svc_write_locked_sentinel's SYSTEM+Admins-
 * only lockdown works cleanly here. The payload doesn't need write
 * access to this file (its own LL hook reads cfg in-process); only the
 * winlogon helper reads it, and winlogon is SYSTEM so it passes the
 * DACL. Non-admin hostile app cannot forge or delete it. */
int config_write_hk_table(const svc_config_t *cfg) {
    if (!cfg) return 0;
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    svc_hk_table_t t;
    memset(&t, 0, sizeof(t));
    t.magic   = SVC_HK_TABLE_MAGIC;
    t.version = SVC_HK_TABLE_VERSION;
    t.count   = SVC_HK_TABLE_COUNT;
    if (cfg->overlay_flags & SVC_OVFLAG_SILENT_MODS)
        t.flags |= SVC_HK_TABLE_F_SILENT_MODS;
    for (int i = 0; i < SVC_HK_COUNT && i < (int)SVC_HK_TABLE_COUNT; i++)
        t.hotkeys[i] = cfg->hotkeys[i];
    int ok = svc_write_locked_sentinel(SVC_HK_TABLE_PATH, &t, (DWORD)sizeof(t));
    slog_writef("msvc_dbg_b.dat",
                "config_write_hk_table: %s flags=0x%X slots=%d",
                ok ? "OK" : "FAILED", (unsigned)t.flags, SVC_HK_COUNT);
    return ok;
}
