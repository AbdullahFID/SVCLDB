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

/* v14 (2026-09-19) -- Payload-side JWT refresh API.
 *
 * Motivation: with Electron closed, only the payload can keep the JWT
 * alive. Once token_refresh_client's background thread has POSTed to
 * Supabase's `/auth/v1/token?grant_type=refresh_token` endpoint and
 * received the rotated {access_token, refresh_token, expires_in}
 * response, it must:
 *   (a) update cfg->access_token + cfg->refresh_token + cfg->token_expires_at
 *       so subsequent sub_check + AI requests use the fresh token,
 *   (b) persist the whole cfg back to disk so a payload reload (post-DWM
 *       crash, post-reboot) sees the LATEST refresh_token (Supabase rotates
 *       these on every use -- the old one is one-shot).
 *
 * All three cfg_update_* helpers are symmetric with cfg_update_access_token:
 * scoped under g_cs, zero any trailing bytes, no other fields touched. */
int    cfg_update_refresh_token(const char *new_token, size_t new_len);
size_t cfg_copy_refresh_token  (char *out, size_t out_sz);
void   cfg_update_token_expires_at(long long expires_at);
long long cfg_get_token_expires_at(void);

/* v14 (2026-09-19) -- Persist the current cached cfg back to config.dat.
 * Encrypts via cu_wrap_encrypt (machine-bound AES-256-GCM, same wrap key
 * as cfg_read uses to decrypt). Atomic write: writes to config.dat.tmp
 * first, then MoveFileEx replaces to avoid a torn read if we crash mid-
 * write. Called by token_refresh_client after a successful JWT refresh
 * so the fresh (rotated) refresh_token survives a reboot / payload
 * reload -- Supabase's refresh_tokens are ONE-SHOT: the moment you use
 * one, it's invalidated and the response returns a NEW one.
 *
 * Returns 1 on success. On failure (encrypt fails / write fails / cfg
 * not loaded) logs to payload.log and returns 0; in-memory cfg is left
 * untouched. */
int cfg_persist(void);

/* Securely zero cached config. Called on payload shutdown. */
void cfg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
