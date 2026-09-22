/* ================================================================== *
 * solve.h -- AutoSolver solve cycle (hold-to-solve).                    *
 *                                                                    *
 * Flow (see docs plan section 5.2): capture clean DWM backbuffer ->     *
 * budget downscale + red grid -> UIA anchors -> ask model for a JSON    *
 * answer+actions in image space -> parse -> drop navigation actions ->  *
 * either DISPLAY-ONLY (dot/overlay show the answer; stealth default) or *
 * move+click via humanized injection. Fully self-contained in the       *
 * payload; runs with svchelper (Electron) closed.                      *
 * ================================================================== */
#ifndef SVCLDB_AUTOSOLVER_SOLVE_H
#define SVCLDB_AUTOSOLVER_SOLVE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Spawn a worker that runs ONE solve cycle. No-op if one is in flight.
 * Bound to the hold-to-solve trigger (SVC_HK_ASK / SVC_HK_QUICK_ASK) when
 * AutoSolver mode is enabled. */
void solve_launch(void);

/* Abort an in-flight solve (ESC / emergency). */
void solve_cancel(void);

int  solve_is_running(void);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_AUTOSOLVER_SOLVE_H */
