/* ================================================================== *
 * config_write.c -- Machine-bound config file used by launcher+payload*
 * ================================================================== */

#include "../../shared/common.h"
#include "config_write.h"
#include "../../shared/crypto_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/hk_table.h"   /* v3.3 (2026-09-23) -- shared hk table */

#include <stdio.h>
#include <string.h>

#define CONFIG_PATH   SVC_INSTALL_DIR "\\" SVC_CONFIG_FILE

int config_write(const svc_config_t *cfg) {
    if (!cfg) return 0;
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);

    uint8_t cipher[sizeof(svc_config_t) + 64];
    size_t clen = 0;
    if (!cu_wrap_encrypt(cfg, sizeof(*cfg), cipher, sizeof(cipher), &clen)) {
        slog_launcher("config_write: wrap_encrypt failed");
        return 0;
    }
    HANDLE h = CreateFileA(CONFIG_PATH, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("launcher.log", "config_write: create %s failed %lu",
                    CONFIG_PATH, GetLastError());
        svc_secure_zero(cipher, sizeof(cipher));
        return 0;
    }
    DWORD w = 0;
    BOOL ok = WriteFile(h, cipher, (DWORD)clen, &w, NULL);
    CloseHandle(h);
    svc_secure_zero(cipher, sizeof(cipher));
    if (!ok || w != clen) return 0;
    slog_writef("launcher.log", "config_write ok bytes=%u", (unsigned)clen);
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
    slog_writef("launcher.log",
                "config_write_hk_table: %s flags=0x%X slots=%d",
                ok ? "OK" : "FAILED", (unsigned)t.flags, SVC_HK_COUNT);
    return ok;
}
