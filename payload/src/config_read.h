#ifndef SVCLDB_CONFIG_READ_H
#define SVCLDB_CONFIG_READ_H

#include "../../shared/config_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Read + decrypt config file. Returns 1 on success. */
int  cfg_read(svc_config_t *out);

/* Cache-accessing variant. First call loads; subsequent return the cached copy. */
const svc_config_t *cfg_get(void);

/* v14 (2026-08-24) -- Update ONLY the access_token field in the cached
 * config. Used by token_refresh_server.c's pipe handler to receive
 * fresh JWTs from Electron mid-session, so sub_check.c doesn't hit
 * 401 on expired tokens. Thread-safe under the config CS. Returns 1
 * on success; 0 if the config isn't loaded yet or the input is
 * invalid (empty / too long / NULL). All other cfg fields are left
 * untouched -- this is not a full re-read. */
int  cfg_update_access_token(const char *new_token, size_t new_len);

/* v2.0.1 (2026-09-10) -- Thread-safe snapshot of the current
 * access_token into a caller-supplied buffer, taken under the config
 * critical section. Prevents torn reads in ai_provider ai_ask_metered
 * and sub_check's Supabase poll during a concurrent
 * cfg_update_access_token (token-refresh pipe push) -- pre-fix a
 * ~50 microsecond memcpy window could yield a half-old / half-new JWT
 * to the caller's _snprintf, producing a malformed Authorization
 * header and a spurious HTTP 401. Returns strlen(access_token) on
 * success and NUL-terminates `out`; returns 0 if cfg not loaded, args
 * are invalid, or out_sz can't fit the current token. Caller SHOULD
 * svc_secure_zero the buffer when done. */
size_t cfg_copy_access_token(char *out, size_t out_sz);

/* Securely zero cached config. Called on payload shutdown. */
void cfg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
