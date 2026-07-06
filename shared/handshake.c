/* ================================================================== *
 * handshake.c — Implementation of handshake token derivation and     *
 * verification. Linked into BOTH launcher and payload.               *
 * ================================================================== */

#include "handshake.h"
#include "crypto_util.h"
#include "common.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* Max access_token length we're willing to hash. Supabase JWTs are
 * ~3KB in practice; we allow 4KB (matches svc_config_t.access_token
 * buffer size) plus salt on the stack. */
#define HS_MAX_AT_LEN   4096

int handshake_compute(const char *access_token,
                      const char *hwid,
                      int64_t     epoch_day,
                      uint8_t     out_token[SVCLDB_HANDSHAKE_TOKEN_LEN]) {
    if (!access_token || !hwid || !out_token) return 0;
    if (access_token[0] == 0 || hwid[0] == 0) return 0;

    size_t at_len = strnlen(access_token, HS_MAX_AT_LEN);
    if (at_len == 0 || at_len >= HS_MAX_AT_LEN) return 0;

    /* sig_key = SHA-256(access_token || SALT) — 32 bytes.
     * Stack-allocated buffer to avoid heap in payload context (where
     * malloc through the manual-mapped CRT works but is riskier than
     * a simple stack alloca). */
    static const char SALT[] = SVCLDB_HANDSHAKE_SALT;
    const size_t salt_len = sizeof(SALT) - 1;
    uint8_t key_input[HS_MAX_AT_LEN + sizeof(SALT)];
    memcpy(key_input, access_token, at_len);
    memcpy(key_input + at_len, SALT, salt_len);

    uint8_t sig_key[32];
    int ok = cu_sha256(key_input, at_len + salt_len, sig_key);
    svc_secure_zero(key_input, at_len + salt_len);
    if (!ok) {
        svc_secure_zero(sig_key, sizeof(sig_key));
        return 0;
    }

    /* Message = "<hwid>:<epoch_day_decimal>" */
    char msg[128];
    int  msg_n = _snprintf(msg, sizeof(msg) - 1, "%s:%lld",
                            hwid, (long long)epoch_day);
    if (msg_n <= 0 || (size_t)msg_n >= sizeof(msg)) {
        svc_secure_zero(sig_key, sizeof(sig_key));
        svc_secure_zero(msg, sizeof(msg));
        return 0;
    }

    ok = cu_hmac_sha256(sig_key, sizeof(sig_key),
                        msg, (size_t)msg_n, out_token);

    svc_secure_zero(sig_key, sizeof(sig_key));
    svc_secure_zero(msg, sizeof(msg));
    return ok;
}

int handshake_verify(const char *access_token,
                     const char *hwid,
                     const uint8_t token[SVCLDB_HANDSHAKE_TOKEN_LEN]) {
    if (!access_token || !hwid || !token) return 0;

    int64_t today = handshake_current_epoch_day();
    uint8_t expected[SVCLDB_HANDSHAKE_TOKEN_LEN];

    /* Try today first (hot path). */
    if (handshake_compute(access_token, hwid, today, expected)) {
        if (cu_ct_eq(expected, token, SVCLDB_HANDSHAKE_TOKEN_LEN) == 0) {
            svc_secure_zero(expected, sizeof(expected));
            return 1;
        }
    }

    /* Grace: yesterday. Covers midnight crossings when Electron
     * generated the token late-night and the user opens LDB early
     * morning without re-launching CloakGPT.exe. */
#if SVCLDB_HANDSHAKE_GRACE_DAYS >= 1
    if (handshake_compute(access_token, hwid, today - 1, expected)) {
        if (cu_ct_eq(expected, token, SVCLDB_HANDSHAKE_TOKEN_LEN) == 0) {
            svc_secure_zero(expected, sizeof(expected));
            return 1;
        }
    }
#endif

    svc_secure_zero(expected, sizeof(expected));
    return 0;
}

int64_t handshake_current_epoch_day(void) {
    return (int64_t)(time(NULL) / 86400);
}
