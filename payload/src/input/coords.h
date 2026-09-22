/* ================================================================== *
 * coords.h -- Coordinate-space transforms for input injection.        *
 *                                                                    *
 * Three spaces (see docs/HANDOFF_AUTOSOLVER_AGENTMODE_SVCLDB_PLAN_    *
 * 2026-09-22.md section 4.1):                                         *
 *                                                                    *
 *   IMAGE-SPACE   px of the downscaled screenshot the model saw       *
 *                 (monitor-local, top-left origin)                    *
 *       | / render_scale  (= imageW / monitor.width, <= 1)            *
 *   NATIVE        monitor-local physical px                           *
 *       | + monitor origin - virtual-desktop origin                   *
 *   VIRTUAL-DESK  physical px over the whole desktop                  *
 *       | * 65535 / (vd.w - 1)                                        *
 *   ABS           SendInput MOUSEEVENTF_ABSOLUTE|VIRTUALDESK 0..65535  *
 *                                                                    *
 * Everything is in PHYSICAL pixels; call coords_make_thread_dpi_aware *
 * on the worker thread first so GetSystemMetrics / monitor rects /    *
 * SendInput-ABS all agree.                                            *
 * ================================================================== */
#ifndef SVCLDB_INPUT_COORDS_H
#define SVCLDB_INPUT_COORDS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int  left, top, width, height;  /* monitor rect in virtual-desktop physical px */
    UINT dpi;                        /* effective dpi (informational, 96 if unknown) */
} svc_monitor_t;

/* Make the CURRENT thread Per-Monitor-V2 DPI aware so metrics, monitor
 * rects and SendInput-ABS coordinates all agree in physical pixels.
 * Cheap; safe to call at the top of every worker thread that injects. */
void coords_make_thread_dpi_aware(void);

/* Virtual-desktop bounding rect (physical px). */
void coords_virtual_desktop(RECT *out);

/* Monitor under a screen point. Returns 1 on success (fills *out). */
int  coords_monitor_at(int screen_x, int screen_y, svc_monitor_t *out);

/* Monitor under the current cursor; falls back to primary. Returns 1. */
int  coords_monitor_under_cursor(svc_monitor_t *out);

/* Primary monitor. Returns 1. */
int  coords_primary_monitor(svc_monitor_t *out);

/* image-space (monitor-local px of the downscaled shot) -> SendInput ABS
 * normalized 0..65535 over the virtual desktop. Clamps to the monitor. */
void coords_image_to_abs(const svc_monitor_t *mon, double render_scale,
                         int img_x, int img_y, int *out_nx, int *out_ny);

/* image-space -> absolute screen point (physical px, vd-space). Clamps. */
void coords_image_to_screen(const svc_monitor_t *mon, double render_scale,
                            int img_x, int img_y, int *out_sx, int *out_sy);

/* absolute screen point -> SendInput ABS normalized 0..65535. */
void coords_screen_to_abs(int screen_x, int screen_y, int *out_nx, int *out_ny);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_COORDS_H */
