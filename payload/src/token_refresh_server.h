/* ================================================================== *
 * token_refresh_server.h -- v14 (2026-08-24)                          *
 *                                                                    *
 * Payload-side named-pipe server that lets Electron push a refreshed *
 * Supabase JWT into `cfg->access_token` while the payload is running. *
 * Fixes the ~1-hour "silent overlay disappears" bug where sub_check's *
 * cached JWT expired mid-session and Supabase returned 401 ->           *
 * self-unload.                                                        *
 *                                                                    *
 * See token_refresh_server.c for wire protocol + threat model.        *
 * ================================================================== */
#ifndef SVCLDB_TOKEN_REFRESH_SERVER_H
#define SVCLDB_TOKEN_REFRESH_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Spawn the pipe-listener thread. Idempotent (safe to call twice).
 * MUST be called AFTER cfg_get() has succeeded (init_thread ordering:
 * hooks_install -> cfg_get -> sub_check_start -> token_refresh_start). */
void token_refresh_start(void);

/* Signal the listener to exit, close the current pipe handle to
 * unblock any in-flight ConnectNamedPipe, and join the thread (max
 * 5s wait). MUST be called from shutdown_watcher BEFORE cfg_cleanup
 * so an in-flight handler doesn't see NULL cfg. */
void token_refresh_stop(void);

#ifdef __cplusplus
}
#endif

#endif
