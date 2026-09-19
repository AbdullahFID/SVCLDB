/* ================================================================== *
 * token_refresh_client.h -- v14 (2026-09-19)                          *
 *                                                                    *
 * Payload-side JWT auto-refresh. Runs a background thread that       *
 * periodically checks how much life the cached access_token has left *
 * and, when it drops below the refresh lead time (~15 min), POSTs    *
 * cfg->refresh_token to Supabase's                                    *
 *                                                                    *
 *   POST {SUPABASE_URL}/auth/v1/token?grant_type=refresh_token       *
 *                                                                    *
 * endpoint to get a rotated {access_token, refresh_token, expires_in} *
 * response. Updates cfg + persists to disk so a payload reload sees  *
 * the fresh refresh_token (Supabase rotates these on every use --      *
 * losing the rotated one means the next refresh is 400 invalid_grant *
 * and the user is locked out).                                       *
 *                                                                    *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────  *
 *                                                                    *
 * Pre-v14, ONLY Electron's `ui/src/license/revalidation.js` refreshed *
 * the JWT and pushed it into the payload via                         *
 * `\\.\pipe\svcldb_token_v1` (see token_refresh_server.c).            *
 *                                                                    *
 * That works while svchelper.exe is running. But real users close    *
 * svchelper after inject to keep only sihost.exe visible during an   *
 * exam. In that state:                                                *
 *   * No revalidation loop is running.                                *
 *   * The cached JWT expires at ~1h.                                  *
 *   * sub_check.c hits 401, burns its 9-min grace, self-unloads.     *
 *   * User loses the overlay mid-exam with "session expired".        *
 *                                                                    *
 * Sam reported this bug THREE separate times before v14. Each prior  *
 * "fix" assumed Electron was alive to push tokens. v14 gives the     *
 * payload full autonomy so the overlay survives Electron being       *
 * closed for the entire duration of the refresh_token's Supabase-    *
 * side lifetime (default 30 days on the free tier, gets bumped on    *
 * every successful refresh).                                          *
 *                                                                    *
 * ── COORDINATION WITH ELECTRON'S REFRESH (WHEN BOTH RUN) ────────────  *
 *                                                                    *
 * When svchelper is open, BOTH sides can try to refresh. Supabase    *
 * refresh_tokens are one-shot: the loser of the race gets            *
 * 400 invalid_grant on their POST. To reduce collisions:              *
 *                                                                    *
 *   * Electron refreshes at T-12min (REFRESH_WAKE_LEAD_S =           *
 *     12*60 in ui/src/license/revalidation.js).                       *
 *   * Payload refreshes at T-6min (see REFRESH_LEAD_S below).         *
 *                                                                    *
 * Electron wins the common case; payload is the fallback. If         *
 * Electron's push (via token_refresh_server) lands, cfg->access_token *
 * + cfg->refresh_token + cfg->token_expires_at get updated and our   *
 * next tick sees the token is fresh again -> skips. If Electron is    *
 * closed / crashed / the push is dropped, the payload takes over.    *
 *                                                                    *
 * On the rare 400 invalid_grant (we lost the race), we back off and  *
 * hope the pipe push lands before our next attempt.                   *
 * ================================================================== */
#ifndef SVCLDB_TOKEN_REFRESH_CLIENT_H
#define SVCLDB_TOKEN_REFRESH_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start the auto-refresh thread. Idempotent (safe to call twice).
 * MUST be called AFTER cfg_get() has succeeded (cfg supplies both
 * `refresh_token` and `token_expires_at`). Cheap when the config
 * doesn't include a refresh_token -- the thread wakes, sees the
 * empty field, logs once and idles. */
void token_refresh_client_start(void);

/* Signal the thread to exit and join (max ~2s wait). MUST be called
 * from shutdown_watcher BEFORE cfg_cleanup so an in-flight refresh
 * response doesn't touch NULL cfg. Called AFTER sub_check_stop and
 * AFTER token_refresh_stop (Electron pipe server) so we drain the
 * whole auth stack coherently. */
void token_refresh_client_stop(void);

#ifdef __cplusplus
}
#endif

#endif
