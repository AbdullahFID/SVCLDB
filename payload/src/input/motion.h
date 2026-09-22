/* ================================================================== *
 * motion.h -- Humanized mouse motion (Sigma-Lognormal, anti-behavioral *
 * -detection). Ported from hooksdll/lumio/src/autosolver.js section     *
 * 4.5. Operates in physical screen pixels via inject.c.                *
 *                                                                    *
 * Two-phase model: one ballistic stroke to ~95% of the distance, a     *
 * log-normal re-targeting pause, then a corrective stroke to the exact  *
 * target (sub-movement count ~= 2, the human range vs ~15 for a naive   *
 * single-Bezier). Peak velocity at u~=0.35, OU jitter that decays to 0  *
 * at the target (exact landing), signal-dependent tremor, ~15%          *
 * overshoot-and-correct on long fast reaches. All timing is log-normal. *
 * ================================================================== */
#ifndef SVCLDB_INPUT_MOTION_H
#define SVCLDB_INPUT_MOTION_H

#ifdef __cplusplus
extern "C" {
#endif

/* Cooperative cancel -- checked between sub-steps + settles so ESC/Stop
 * aborts within ~1 sub-step. */
void mot_set_cancel(int on);
int  mot_cancelled(void);

/* Glide the cursor from its current position to (gx,gy) in physical
 * screen px. humanize=0 does a direct move + tiny settle. Ends exactly
 * on target so UIA-snapped coordinates land pixel-perfect. */
void mot_glide_to_screen(int gx, int gy, int humanize);

/* Press+release the button at the current cursor position. button:
 * 0=left, 1=right, 2=middle. count>1 for double/triple click. Dwell is
 * log-normal (~85 ms median) when humanize. */
void mot_click_in_place(int button, int count, int humanize);

/* Emit `amount` wheel notches. direction: "up"/"down". */
void mot_scroll_ticks(const char *direction, int amount);

/* Drag from (x1,y1) to (x2,y2), physical screen px. */
void mot_drag_screen(int x1, int y1, int x2, int y2, int humanize);

/* Log-normal sleep helper (median ms, shape sigma, clamped) -- exposed
 * so actions.c can share the same right-skewed dwell distribution. */
double mot_lognormal_ms(double median, double sigma, double lo, double hi);
void   mot_precise_sleep(double ms);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_MOTION_H */
