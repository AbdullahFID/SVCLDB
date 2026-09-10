/* ================================================================== *
 * oauth.h -- Supabase OAuth PKCE flow (native).                        *
 *                                                                    *
 * 1. Generate PKCE verifier (32 rand -> base64url)                    *
 * 2. Open browser to Supabase auth URL with challenge                *
 * 3. Listen on 127.0.0.1:9285 for /callback?code=...                 *
 * 4. POST to Supabase /auth/v1/token to exchange code for tokens     *
 * 5. Return session { access_token, refresh_token, user_id, email,   *
 *    expires_at } signed with HWID-derived HMAC                      *
 * ================================================================== */
#ifndef SVCLDB_OAUTH_H
#define SVCLDB_OAUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     access_token [4096];
    char     refresh_token[4096];
    char     user_id      [64];
    char     email        [256];
    char     display_name [256];
    long long expires_at;      /* unix epoch seconds */
    long long created_at;      /* unix epoch seconds -- used for staleness */
    uint8_t  signature[32];    /* HMAC-SHA256 over the fields, keyed by HWID */
} oauth_session_t;

/* Blocking OAuth flow. Opens browser, waits up to 5 min for callback.
 * Returns 1 on success (out populated), 0 on failure (err populated). */
int  oauth_run(oauth_session_t *out, char *err, size_t err_sz);

/* Refresh a session using its refresh_token. Updates *sess in-place.
 * Returns 1 on success. */
int  oauth_refresh(oauth_session_t *sess, char *err, size_t err_sz);

/* Sign / verify a session using HMAC(HWID-derived key). */
void oauth_sign_session  (oauth_session_t *sess);
int  oauth_verify_session(const oauth_session_t *sess);

/* True if access_token expires within 5 minutes. */
int  oauth_expired(const oauth_session_t *sess);
/* True if session was created > 24 hours ago (forces re-login). */
int  oauth_stale  (const oauth_session_t *sess);

#ifdef __cplusplus
}
#endif

#endif
