#ifndef SVCLDB_LDB_DETECT_H
#define SVCLDB_LDB_DETECT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Poll every 2s for LockDownBrowser.exe (or OEM variant) starting/stopping.
 * When start detected: calls on_arm().
 * When exit detected: calls on_disarm().
 * Runs in its own background thread -- spawn once at DllMain init. */
typedef void (*ldb_state_cb)(void);
int  ldb_detect_start(ldb_state_cb on_arm, ldb_state_cb on_disarm);
void ldb_detect_stop (void);
int  ldb_detect_active(void);      /* 1 if LDB currently running */

#ifdef __cplusplus
}
#endif

#endif
