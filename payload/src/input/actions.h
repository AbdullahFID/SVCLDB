/* ================================================================== *
 * actions.h -- High-level input dispatch shared by AutoSolver + Agent.  *
 *                                                                    *
 * Mirrors hooksdll executeActions: image-space coords in, humanized     *
 * UIA-snapped input out. Wraps a batch with the synth guard + secure    *
 * routing + DPI awareness.                                             *
 * ================================================================== */
#ifndef SVCLDB_INPUT_ACTIONS_H
#define SVCLDB_INPUT_ACTIONS_H

#include "coords.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    svc_monitor_t mon;
    double render_scale;   /* imageW / mon.width (the shot the model saw) */
    int    humanize;       /* 1 = Sigma-Lognormal glide + log-normal dwell */
    int    uia_snap;       /* 1 = snap clicks to UIA element center */
    int    secure;         /* 1 = route injection via the winlogon helper */
    int    wpm;            /* typing speed (default 220 chars/min ~ 44 wpm feel) */
} act_ctx_t;

void act_begin(act_ctx_t *ctx);
void act_end(act_ctx_t *ctx);
void act_cancel(void);        /* abort an in-flight batch (ESC/Stop) */

void act_click_image (act_ctx_t *ctx, int img_x, int img_y, int button, int count);
void act_move_image  (act_ctx_t *ctx, int img_x, int img_y);
void act_scroll_image(act_ctx_t *ctx, int img_x, int img_y, const char *dir, int amount);
void act_drag_image  (act_ctx_t *ctx, int x1, int y1, int x2, int y2);

void act_type (act_ctx_t *ctx, const char *utf8);
void act_press(act_ctx_t *ctx, const char *spec);   /* "ctrl+a", "enter", ... */
void act_wait (int ms);
void act_interpause(act_ctx_t *ctx);

/* image-space -> absolute screen px (for dot-jump / UIA snap externally). */
void act_image_to_screen(act_ctx_t *ctx, int img_x, int img_y, int *sx, int *sy);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_ACTIONS_H */
