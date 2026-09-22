/* ================================================================== *
 * coords.c -- Coordinate-space transforms (see coords.h).             *
 * ================================================================== */
#include "coords.h"

/* Per-Monitor-V2 context value (Win10 1607+). Defined here so we don't
 * depend on a recent SDK's winuser.h having the macro. */
#ifndef SVC_DPI_PMV2
#define SVC_DPI_PMV2  ((HANDLE)(LONG_PTR)-4)
#endif

static int clampi(int v, int lo, int hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

void coords_make_thread_dpi_aware(void) {
    HMODULE u = GetModuleHandleA("user32.dll");
    if (!u) return;
    typedef HANDLE (WINAPI *fn_t)(HANDLE);
    fn_t p = (fn_t)GetProcAddress(u, "SetThreadDpiAwarenessContext");
    if (p) p(SVC_DPI_PMV2);
}

void coords_virtual_desktop(RECT *out) {
    if (!out) return;
    out->left   = GetSystemMetrics(SM_XVIRTUALSCREEN);
    out->top    = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w       = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h       = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0) w = GetSystemMetrics(SM_CXSCREEN);
    if (h <= 0) h = GetSystemMetrics(SM_CYSCREEN);
    out->right  = out->left + w;
    out->bottom = out->top  + h;
}

static UINT monitor_dpi(HMONITOR mon) {
    /* GetDpiForMonitor lives in shcore.dll; load dynamically so we don't
     * force a shcore import. Failure -> 96 (informational only; the math
     * uses physical pixels and never divides by this). */
    HMODULE sh = LoadLibraryA("shcore.dll");
    UINT dx = 96, dy = 96;
    if (sh) {
        typedef HRESULT (WINAPI *fn_t)(HMONITOR, int, UINT*, UINT*);
        fn_t p = (fn_t)GetProcAddress(sh, "GetDpiForMonitor");
        if (p) p(mon, 0 /*MDT_EFFECTIVE_DPI*/, &dx, &dy);
        FreeLibrary(sh);
    }
    return dx ? dx : 96;
}

static int fill_from_hmon(HMONITOR hmon, svc_monitor_t *out) {
    MONITORINFO mi; mi.cbSize = sizeof(mi);
    if (!hmon || !GetMonitorInfoA(hmon, &mi)) return 0;
    out->left   = mi.rcMonitor.left;
    out->top    = mi.rcMonitor.top;
    out->width  = mi.rcMonitor.right  - mi.rcMonitor.left;
    out->height = mi.rcMonitor.bottom - mi.rcMonitor.top;
    out->dpi    = monitor_dpi(hmon);
    return out->width > 0 && out->height > 0;
}

int coords_monitor_at(int screen_x, int screen_y, svc_monitor_t *out) {
    if (!out) return 0;
    POINT pt = { screen_x, screen_y };
    HMONITOR hmon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    return fill_from_hmon(hmon, out);
}

int coords_primary_monitor(svc_monitor_t *out) {
    if (!out) return 0;
    POINT pt = { 0, 0 };
    HMONITOR hmon = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
    return fill_from_hmon(hmon, out);
}

int coords_monitor_under_cursor(svc_monitor_t *out) {
    if (!out) return 0;
    POINT pt;
    if (GetCursorPos(&pt) && coords_monitor_at(pt.x, pt.y, out)) return 1;
    return coords_primary_monitor(out);
}

void coords_screen_to_abs(int screen_x, int screen_y, int *out_nx, int *out_ny) {
    RECT vd; coords_virtual_desktop(&vd);
    int vw = vd.right  - vd.left;
    int vh = vd.bottom - vd.top;
    if (vw < 2) vw = 2;
    if (vh < 2) vh = 2;
    long gx = screen_x - vd.left;
    long gy = screen_y - vd.top;
    long nx = (long)(( (double)gx / (double)(vw - 1) ) * 65535.0 + 0.5);
    long ny = (long)(( (double)gy / (double)(vh - 1) ) * 65535.0 + 0.5);
    if (out_nx) *out_nx = (int)clampi((int)nx, 0, 65535);
    if (out_ny) *out_ny = (int)clampi((int)ny, 0, 65535);
}

void coords_image_to_screen(const svc_monitor_t *mon, double render_scale,
                            int img_x, int img_y, int *out_sx, int *out_sy) {
    if (!mon) { if (out_sx) *out_sx = img_x; if (out_sy) *out_sy = img_y; return; }
    double rs = (render_scale > 0.0001) ? render_scale : 1.0;
    int nx = (int)((double)img_x / rs + 0.5);   /* native monitor-local */
    int ny = (int)((double)img_y / rs + 0.5);
    nx = clampi(nx, 0, mon->width  > 0 ? mon->width  - 1 : 0);
    ny = clampi(ny, 0, mon->height > 0 ? mon->height - 1 : 0);
    if (out_sx) *out_sx = mon->left + nx;
    if (out_sy) *out_sy = mon->top  + ny;
}

void coords_image_to_abs(const svc_monitor_t *mon, double render_scale,
                         int img_x, int img_y, int *out_nx, int *out_ny) {
    int sx, sy;
    coords_image_to_screen(mon, render_scale, img_x, img_y, &sx, &sy);
    coords_screen_to_abs(sx, sy, out_nx, out_ny);
}
