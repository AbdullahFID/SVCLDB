/* ================================================================== *
 * sub_check.h — Payload-side runtime subscription re-check.           *
 *                                                                    *
 * Runs a background thread inside dwm.exe that polls Supabase every  *
 * SUB_CHECK_INTERVAL_MS and self-triggers a cooperative unload if    *
 * the user's subscription becomes inactive (or 3 consecutive network *
 * failures suggest the token is dead / offline).                     *
 *                                                                    *
 * Defense in depth: the Electron UI does the same check via          *
 * ui/src/license/revalidation.js, but if the user closes the UI      *
 * completely, that timer stops firing. This ensures the payload      *
 * self-uninstalls hooks within ~30 min of losing subscription even   *
 * when nothing else is watching.                                     *
 *                                                                    *
 * On expiry: SetEvent(SVC_SHUTDOWN_EVENT_NAME) → dllmain's           *
 * shutdown_watcher unloads hooks cleanly. Same path as the launcher's*
 * --unload flag.                                                     *
 * ================================================================== */
#ifndef SVCLDB_SUB_CHECK_H
#define SVCLDB_SUB_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/* Spawn the background poller. Called once from init_thread after
 * hooks are installed. Idempotent — repeated calls are no-ops. */
void sub_check_start(void);

/* Signal the poller to exit + join. Called from the shutdown_watcher
 * path so we don't leak the thread. */
void sub_check_stop(void);

#ifdef __cplusplus
}
#endif

#endif
