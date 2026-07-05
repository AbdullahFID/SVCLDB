/* ================================================================== *
 * license.h — Subscription check (via Supabase REST) + storage.       *
 *                                                                    *
 * Session is persisted to disk (machine-bound-encrypted) so re-launch*
 * doesn't force re-login unless session is stale / expired.          *
 * ================================================================== */
#ifndef SVCLDB_LICENSE_H
#define SVCLDB_LICENSE_H

#include "oauth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int         active;
    int         is_lifetime;
    char        plan  [64];
    char        status[64];
    long long   expires_at;   /* unix epoch seconds, 0 = none */
} license_status_t;

/* Load session from disk. Returns 1 if a valid + signed session was found.
 * On load, session is verified (HWID signature) and expired/stale sessions
 * are cleared (returns 0 for those). */
int  license_load_session(oauth_session_t *out);
int  license_save_session(const oauth_session_t *sess);
void license_clear       (void);

/* Full login flow: load-or-oauth. Runs oauth_run if no valid session on disk.
 * Returns 1 on success. */
int  license_login(oauth_session_t *out, char *err, size_t err_sz);

/* Query Supabase for the user's subscription status. */
int  license_check_subscription(const oauth_session_t *sess,
                                license_status_t *out,
                                char *err, size_t err_sz);

#ifdef __cplusplus
}
#endif

#endif
