/* ================================================================== *
 * config_write.c -- Machine-bound config file used by launcher+payload*
 * ================================================================== */

#include "../../shared/common.h"
#include "config_write.h"
#include "../../shared/crypto_util.h"
#include "../../shared/log_secure.h"

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
