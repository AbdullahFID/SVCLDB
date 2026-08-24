#include "../../shared/common.h"
#include "config_read.h"
#include "../../shared/crypto_util.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>

#define CONFIG_PATH SVC_INSTALL_DIR "\\" SVC_CONFIG_FILE

static svc_config_t g_cfg;
static volatile LONG g_loaded = 0;
static CRITICAL_SECTION g_cs;
static volatile LONG g_cs_init = 0;

static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
        InterlockedExchange(&g_cs_init, 2);
    } else {
        while (g_cs_init != 2) Sleep(0);
    }
}

int cfg_read(svc_config_t *out) {
    if (!out) return 0;
    HANDLE h = CreateFileA(CONFIG_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("payload.log", "cfg_read: no config at %s (GLE=%lu)", CONFIG_PATH, GetLastError());
        return 0;
    }
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 29 || sz > sizeof(svc_config_t) + 128) {
        CloseHandle(h);
        slog_writef("payload.log", "cfg_read: bad size %lu", sz);
        return 0;
    }
    uint8_t cipher[sizeof(svc_config_t) + 128];
    DWORD r = 0;
    BOOL ok = ReadFile(h, cipher, sz, &r, NULL);
    CloseHandle(h);
    if (!ok || r != sz) { svc_secure_zero(cipher, sizeof(cipher)); return 0; }

    uint8_t plain[sizeof(svc_config_t)];
    size_t plen = 0;
    if (!cu_wrap_decrypt(cipher, sz, plain, sizeof(plain), &plen)) {
        svc_secure_zero(cipher, sizeof(cipher));
        slog_write("payload.log", "cfg_read: decrypt failed (wrong machine?)");
        return 0;
    }
    svc_secure_zero(cipher, sizeof(cipher));
    if (plen != sizeof(svc_config_t)) {
        svc_secure_zero(plain, sizeof(plain));
        slog_writef("payload.log", "cfg_read: plaintext size mismatch %zu vs %zu",
                    plen, sizeof(svc_config_t));
        return 0;
    }
    memcpy(out, plain, sizeof(*out));
    svc_secure_zero(plain, sizeof(plain));
    slog_writef("payload.log", "cfg_read: ok provider=%d model=%s",
                out->provider, out->model);
    return 1;
}

const svc_config_t *cfg_get(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        if (cfg_read(&g_cfg)) g_loaded = 2;
        else                  g_loaded = 3;
    }
    LeaveCriticalSection(&g_cs);
    return g_loaded == 2 ? &g_cfg : NULL;
}

/* v14 (2026-08-24) — Update ONLY the access_token field in the cached
 * config. Called by token_refresh_server.c's pipe handler when Electron
 * pushes a refreshed Supabase JWT. All other fields untouched — this
 * is intentionally scoped to the token so we don't stomp mid-session
 * user mutations to `tier`, `provider`, etc. (see on_hotkey's mutable
 * cast pattern in dllmain.c).
 *
 * Caller must have already validated the incoming token (HMAC verify).
 * We enforce ONLY: nonzero length and fits the buffer with room for
 * NUL. `new_token` need not be NUL-terminated at `new_len`; we copy
 * exactly `new_len` bytes then write our own terminator.
 *
 * Returns 1 on success, 0 on invalid input or if the config hasn't
 * been loaded yet (nothing to update). */
int cfg_update_access_token(const char *new_token, size_t new_len) {
    if (!new_token || new_len == 0) return 0;
    if (new_len >= sizeof(g_cfg.access_token)) return 0;
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    memcpy(g_cfg.access_token, new_token, new_len);
    g_cfg.access_token[new_len] = 0;
    /* Zero any trailing bytes from a previously-longer token so a
     * hex dump of the cfg doesn't reveal partial old JWTs. */
    if (new_len + 1 < sizeof(g_cfg.access_token)) {
        svc_secure_zero(&g_cfg.access_token[new_len + 1],
                        sizeof(g_cfg.access_token) - new_len - 1);
    }
    LeaveCriticalSection(&g_cs);
    return 1;
}

void cfg_cleanup(void) {
    if (g_cs_init != 2) return;
    EnterCriticalSection(&g_cs);
    svc_secure_zero(&g_cfg, sizeof(g_cfg));
    g_loaded = 0;
    LeaveCriticalSection(&g_cs);
}
